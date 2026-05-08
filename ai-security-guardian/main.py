"""
AI-Security-Guardian 主入口（Phase 8：集成与部署）
对应架构文档 §11 部署架构 + Phase 8 提示词 A 节（主入口集成）

本模块的职责：
    1. 初始化全部核心模块（采集 / 特征 / 检测 / 融合 / 响应 / 审计）
    2. 串联完整检测流水线（数据包、Web 日志两条入口）
    3. **威胁情报前置过滤**：在特征提取与模型推理前先查黑名单
    4. 模型加载采用"单模型失败不拖垮整体"的容错策略
    5. 融合决策对结果进行投票 / 加权，单引擎异常不影响其他引擎
    6. 可选：接入 Phase 7 Flask 工厂（`web.app.create_app`）与前端联动
    7. Redis 作为缓存 / 轻量消息队列；Redis 不可用时自动降级到内存
    8. 优雅关闭：SIGINT / SIGTERM 统一走 shutdown() 清理

设计约束：
    - 不重做 Phase 0 ~ Phase 7 的任何现有模块
    - Docker 容器默认入口仍是 `python -m web.app`（Web/API 层，无需 root）
    - 本文件作为"完整检测链路"入口：`python main.py`，需要抓包权限时使用
    - 所有密钥 / Redis 密码 / 管理员密码 / API Key 必须来自环境变量
    - 任何一个子模块异常都不应该导致进程退出；记录日志并继续主循环
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# 核心模块（复用 Phase 1-6 的现有实现）
from src.audit.security_logger import SecurityLogger
from src.audit.log_paths import resolve_audit_log_dir
from src.observability.guardian_metrics import GuardianMetricsCollector
from src.registry import ModelRegistry
from src.collectors.log_collector import LogCollector
from src.collectors.packet_collector import PacketCollector
from src.collectors.threat_intel import ThreatIntelCollector
from src.decision.fusion_engine import FusionEngine
from src.detectors.anomaly_detector import AnomalyDetector
from src.detectors.base import DetectionResult
from src.detectors.ddos_detector import DDoSDetector
from src.detectors.intrusion_detector import IntrusionDetector
from src.detectors.web_detector import WebAttackDetector
from src.features.flow_window_aggregator import (
    FlowWindowAggregator,
    FlowWindowAggregatorConfig,
)
from src.features.web_features import WebFeatureExtractor
from src.response.responder import SecurityResponder
from src.utils.env_loader import load_dotenv_file
from src.utils.redis_client import RedisClient

logger = logging.getLogger("main")

load_dotenv_file()

CRITICAL_MODEL_FAMILIES = (
    ("ddos", "DDoS"),
    ("intrusion", "Intrusion"),
    ("web_attack", "WebAttack"),
    ("anomaly", "Anomaly"),
)


# =====================================================================
# 运行时配置（从环境变量读取，避免硬编码）
# =====================================================================
@dataclass
class RuntimeConfig:
    """主入口运行期配置。所有字段都可被环境变量覆盖。"""

    dry_run: bool = True
    enable_packet_capture: bool = True
    enable_web_log: bool = True
    enable_flask: bool = False

    packet_interface: Optional[str] = None
    web_log_path: str = "/var/log/nginx/access.log"
    loop_interval_sec: float = 1.0
    max_packets_per_tick: int = 50

    # 实时流聚合（network_flow_v1 / FlowWindowAggregator）
    flow_min_packets: int = 2
    flow_idle_timeout_sec: float = 5.0
    flow_agg_window_sec: float = 10.0
    # discard | emit_low_confidence（单包流空闲超时后策略）
    single_packet_idle_policy: str = "discard"

    model_dir: str = "models/saved"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    log_dir: str = "logs/dev"
    log_integrity_enabled: bool = True
    require_redis_available: bool = False
    require_models_ready: bool = False

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        """读取环境变量，未设置则使用默认值。"""
        return cls(
            dry_run=os.environ.get("DRY_RUN", "true").lower() == "true",
            enable_packet_capture=os.environ.get(
                "ENABLE_PACKET_CAPTURE", "true"
            ).lower() == "true",
            enable_web_log=os.environ.get("ENABLE_WEB_LOG", "true").lower()
            == "true",
            enable_flask=os.environ.get("ENABLE_FLASK", "false").lower()
            == "true",
            packet_interface=os.environ.get("PACKET_INTERFACE") or None,
            web_log_path=os.environ.get(
                "WEB_LOG_PATH", "/var/log/nginx/access.log"
            ),
            loop_interval_sec=float(os.environ.get("LOOP_INTERVAL_SEC", "1.0")),
            max_packets_per_tick=int(
                os.environ.get("MAX_PACKETS_PER_TICK", "50")
            ),
            flow_min_packets=int(os.environ.get("FLOW_MIN_PACKETS", "2")),
            flow_idle_timeout_sec=float(
                os.environ.get("FLOW_IDLE_TIMEOUT_SEC", "5.0")
            ),
            flow_agg_window_sec=float(
                os.environ.get("FLOW_AGG_WINDOW_SEC", "10.0")
            ),
            single_packet_idle_policy=os.environ.get(
                "SINGLE_PACKET_IDLE_POLICY", "discard"
            ),
            model_dir=os.environ.get("MODEL_DIR", "models/saved"),
            redis_host=os.environ.get("REDIS_HOST", "localhost"),
            redis_port=int(os.environ.get("REDIS_PORT", "6379")),
            redis_db=int(os.environ.get("REDIS_DB", "0")),
            redis_password=os.environ.get("REDIS_PASSWORD", ""),
            log_dir=resolve_audit_log_dir(),
            log_integrity_enabled=os.environ.get(
                "LOG_INTEGRITY_ENABLED", "true"
            ).lower() == "true",
            require_redis_available=os.environ.get(
                "REQUIRE_REDIS_AVAILABLE", "false"
            ).lower()
            == "true",
            require_models_ready=os.environ.get(
                "REQUIRE_MODELS_READY", "false"
            ).lower()
            == "true",
        )


# =====================================================================
# 主控制器
# =====================================================================
class SecurityGuardian:
    """AI 安全守卫主控制器（Phase 8 集成层）。

    关键设计：
        - 所有子模块在构造时即实例化，但**模型加载是延迟的**，
          由 :pymeth:`load_models` 统一在主循环前尝试，失败即降级。
        - :pymeth:`process_packet` / :pymeth:`process_packet_batch` /
          :pymeth:`process_web_log` 全部具备容错，单条流量异常不会影响主循环。
        - :pymeth:`shutdown` 幂等，可被信号处理器和 finally 同时调用。
    """

    # Redis Streams 通道与容量（所有告警共享，便于多消费者按 group 订阅）
    _ALERT_STREAM: str = "guardian:alerts"
    _ALERT_STREAM_GROUP: str = "guardian:web"
    _ALERT_STREAM_MAXLEN: int = 10_000

    def __init__(self, cfg: Optional[RuntimeConfig] = None) -> None:
        self.cfg: RuntimeConfig = cfg or RuntimeConfig.from_env()
        self._running: bool = False
        self._shutdown_complete: bool = False
        self._shutdown_lock = threading.Lock()

        # ---- 审计日志（首先启动，保证后续故障都能留痕）------------------
        self.security_logger = SecurityLogger(
            log_dir=self.cfg.log_dir, enable_integrity=self.cfg.log_integrity_enabled
        )

        # ---- 缓存 / 队列（Redis，失败自动回退到内存）-------------------
        self.redis = RedisClient(
            host=self.cfg.redis_host,
            port=self.cfg.redis_port,
            db=self.cfg.redis_db,
            password=self.cfg.redis_password,
        )
        # 预创建 consumer group，便于 Web 层启动后立即开始消费（不存在亦不报错）
        try:
            self.redis.stream_ensure_group(
                self._ALERT_STREAM, self._ALERT_STREAM_GROUP
            )
        except Exception as exc:  # noqa: BLE001 - Streams 不可用不影响主流程
            logger.debug("[Guardian] Streams group 初始化失败: %s", exc)

        # ---- 采集器 ----------------------------------------------------
        self.packet_collector: Optional[PacketCollector] = None
        if self.cfg.enable_packet_capture:
            self.packet_collector = PacketCollector(
                interface=self.cfg.packet_interface
            )

        self.web_log_collector: Optional[LogCollector] = None
        if self.cfg.enable_web_log:
            self.web_log_collector = LogCollector(
                log_path=self.cfg.web_log_path, log_type="web"
            )

        # ---- 威胁情报（前置过滤）---------------------------------------
        self.threat_intel = ThreatIntelCollector(
            abuseipdb_key=os.environ.get("ABUSEIPDB_API_KEY", ""),
            virustotal_key=os.environ.get("VIRUSTOTAL_API_KEY", ""),
            external_http_timeout=float(os.environ.get("THREAT_INTEL_HTTP_TIMEOUT", "5")),
            external_wait_sec=float(os.environ.get("THREAT_INTEL_EXTERNAL_WAIT_SEC", "0.45")),
        )
        self._ioc_db_app = None
        if not self.cfg.enable_flask:
            self._bind_ioc_database()

        # ---- 特征提取器 ------------------------------------------------
        self.flow_aggregator = FlowWindowAggregator(
            FlowWindowAggregatorConfig(
                min_flow_packets=self.cfg.flow_min_packets,
                flow_idle_timeout_sec=self.cfg.flow_idle_timeout_sec,
                aggregation_window_sec=self.cfg.flow_agg_window_sec,
                single_packet_idle_policy=self.cfg.single_packet_idle_policy,
            )
        )
        self.web_extractor = WebFeatureExtractor()

        # ---- 实时链路可观测计数（读取失败不抛、不阻断循环）------------
        self._packet_queue_read_errors: int = 0
        self._metrics = GuardianMetricsCollector()
        self._prev_malformed: int = 0
        self._prev_single_disc: int = 0
        self._prev_partial_disc: int = 0

        # ---- 检测引擎（4 个）------------------------------------------
        self.ddos_detector = DDoSDetector()
        # use_deep_learning=False：优先加载随机森林备选模型（CPU 友好）
        self.intrusion_detector = IntrusionDetector(use_deep_learning=False)
        self.web_detector = WebAttackDetector()
        self.anomaly_detector = AnomalyDetector()

        self.model_registry = ModelRegistry(
            self.cfg.model_dir,
            audit_sink=self.security_logger,
        )

        # ---- 融合决策 --------------------------------------------------
        self.fusion_engine = FusionEngine()

        # ---- 响应引擎（dry_run 来自环境变量）--------------------------
        self.responder = SecurityResponder(
            dry_run=self.cfg.dry_run,
            security_logger=self.security_logger,
        )

        # ---- Flask（可选，用于向前端广播告警）------------------------
        self._flask_app = None
        self._push_alert_fn = None
        if self.cfg.enable_flask:
            self._try_attach_flask()

        logger.info(
            "[Guardian] 模块初始化完成 dry_run=%s redis_mode=%s flask=%s",
            self.cfg.dry_run,
            self.redis.mode,
            bool(self._push_alert_fn),
        )

    def _bind_ioc_database(self) -> None:
        """绑定 DATABASE_URL 上的 IOC 表，启动时灌入内存前置缓存。"""
        uri = (os.environ.get("DATABASE_URL") or "").strip()
        if not uri or ":memory:" in uri:
            return
        try:
            from flask import Flask
            from web.database import db, init_db_tables

            root = Path(__file__).resolve().parent
            mini = Flask(__name__)
            mini.root_path = str(root)
            mini.config["SQLALCHEMY_DATABASE_URI"] = uri
            mini.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
            db.init_app(mini)
            import web.models  # noqa: F401

            with mini.app_context():
                init_db_tables(mini)
                n = self.threat_intel.refresh_local_from_db()
            self.threat_intel.bind_flask_app(mini)
            self._ioc_db_app = mini
            logger.info("[Guardian] IOC 数据库已绑定，内存加载 %d 条", n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Guardian] IOC 数据库绑定失败（仅内存黑名单）: %s", exc)

    # ------------------------------------------------------------------
    # Flask 集成（可选；不影响独立运行）
    # ------------------------------------------------------------------
    def _try_attach_flask(self) -> None:
        """尝试加载 Phase 7 工厂函数；失败仅记录日志，不影响主流程。"""
        try:
            # 延迟导入，避免纯检测链路场景下拉起 Flask 依赖
            from web.app import create_app, push_alert  # noqa: WPS433

            app, _socketio = create_app()
            self._flask_app = app
            self._push_alert_fn = push_alert
            self.threat_intel = app.extensions["guardian_threat_intel"]
            self._ioc_db_app = app
            logger.info("[Guardian] 已接入 Phase 7 Flask 工厂，告警将广播到前端")
        except Exception as exc:  # noqa: BLE001 - 无 Flask 时降级到独立模式
            logger.warning("[Guardian] 未启用 Flask 告警广播: %s", exc)
            self._flask_app = None
            self._push_alert_fn = None

    # ------------------------------------------------------------------
    # 模型加载（单模型失败不拖垮整体）
    # ------------------------------------------------------------------
    def load_models(self) -> Dict[str, bool]:
        """经 ModelRegistry 解析路径并逐个加载；单个失败仅记录日志，其余继续。

        Returns:
            dict[str, bool]: 各引擎是否成功加载。
        """
        plan = [
            (family, label, detector)
            for (family, label), detector in zip(
                CRITICAL_MODEL_FAMILIES,
                (
                    self.ddos_detector,
                    self.intrusion_detector,
                    self.web_detector,
                    self.anomaly_detector,
                ),
            )
        ]
        results: Dict[str, bool] = {}
        for family, label, detector in plan:
            path = self.model_registry.resolve_load_path(family)
            try:
                ok = self.model_registry.try_load_detector(family, detector)
                results[label] = ok
                if ok:
                    logger.info(
                        "[Guardian] 模型加载成功: %s (%s)",
                        label,
                        path or "(registry path)",
                    )
                elif path is None:
                    logger.warning(
                        "[Guardian] 未找到模型路径，跳过 %s（请检查 models/saved 布局或训练产物）",
                        label,
                    )
                    self.security_logger.log_system(
                        f"模型路径缺失: {label} family={family}", level="warning"
                    )
                else:
                    logger.error(
                        "[Guardian] 模型加载失败 %s（将降级跳过此引擎）path=%s",
                        label,
                        path,
                    )
            except Exception as exc:  # noqa: BLE001 - 加载失败不应拖垮系统
                results[label] = False
                logger.error(
                    "[Guardian] 模型加载异常 %s: %s（将降级跳过此引擎）",
                    label,
                    exc,
                )
                self.security_logger.log_system(
                    f"模型加载异常: {label}: {exc}", level="error"
                )

        loaded = sum(1 for v in results.values() if v)
        logger.info("[Guardian] 模型加载汇总：成功 %d / 共 %d", loaded, len(plan))

        try:
            self._metrics.set_model_load_state(expected=len(plan), loaded=loaded)
            self._metrics.flush_to_redis(self.redis, min_interval_sec=0.0)
            self._metrics.write_status_file(
                os.environ.get("GUARDIAN_STATUS_FILE", "logs/guardian_status.json")
            )
        except Exception:  # noqa: BLE001
            pass

        # Web 规则引擎恒可用（规则永远兜底），即使 ML 模型加载失败也不影响检测
        # IntrusionDetector / AnomalyDetector / DDoSDetector 未就绪时
        # detect() 会返回 None，由融合决策层统一跳过。
        return results

    # ------------------------------------------------------------------
    # 流量入口 1：数据包
    # ------------------------------------------------------------------
    def process_packet(self, pkt: Dict[str, Any]) -> None:
        """处理单个数据包（经聚合器，与主循环批量路径一致）。"""
        self.process_packet_batch([pkt])

    def process_packet_batch(self, packets: List[Dict[str, Any]]) -> None:
        """批量处理数据包：威胁情报过滤 → 流窗口聚合 → 检测；异常不抛出。

        允许 ``packets`` 为空：仍会推进聚合器时钟并刷新空闲超时流。
        """
        now = time.time()
        try:
            self._metrics.record_packets_seen(len(packets))
        except Exception:  # noqa: BLE001
            pass

        filtered: List[Dict[str, Any]] = []
        ti_drops = 0
        for pkt in packets:
            try:
                src_ip = str(pkt.get("src_ip", ""))
                if src_ip and self._is_threat_intel_hit(src_ip):
                    ti_drops += 1
                    continue
                filtered.append(pkt)
            except Exception as exc:  # noqa: BLE001
                logger.error("[Guardian] 单包前置处理异常: %s", exc, exc_info=True)
                continue

        if ti_drops:
            try:
                self._metrics.record_threat_intel_drops(ti_drops)
            except Exception:  # noqa: BLE001
                pass

        try:
            flow_features = self.flow_aggregator.tick(filtered, now=now)
        except Exception as exc:  # noqa: BLE001
            logger.error("[Guardian] 流窗口聚合异常: %s", exc, exc_info=True)
            return

        try:
            c = self.flow_aggregator.counters
            self._metrics.record_aggregator_deltas(
                c.malformed_packet_skips - self._prev_malformed,
                c.single_packet_discarded - self._prev_single_disc,
                c.partial_flow_discarded - self._prev_partial_disc,
            )
            self._prev_malformed = c.malformed_packet_skips
            self._prev_single_disc = c.single_packet_discarded
            self._prev_partial_disc = c.partial_flow_discarded
        except Exception:  # noqa: BLE001
            pass

        for feat in flow_features:
            try:
                t0 = time.perf_counter()
                results = self._safe_detect_many(feat)
                final = self.fusion_engine.fuse(results)
                try:
                    self._metrics.record_detection_latency_ms(
                        (time.perf_counter() - t0) * 1000.0
                    )
                except Exception:  # noqa: BLE001
                    pass
                if final.threat_type != "normal":
                    self._on_threat(final)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "[Guardian] 单条流特征检测/融合异常: %s", exc, exc_info=True
                )
                continue

    # ------------------------------------------------------------------
    # 流量入口 2：Web 日志
    # ------------------------------------------------------------------
    def process_web_log(self, log_entry: Dict[str, Any]) -> None:
        """处理单条 Web 访问日志；任何异常都不得抛出到主循环。"""
        try:
            src_ip = str(log_entry.get("src_ip", ""))

            if src_ip and self._is_threat_intel_hit(src_ip):
                try:
                    self._metrics.record_threat_intel_drops(1)
                except Exception:  # noqa: BLE001
                    pass
                return

            web_feat = self.web_extractor.extract(log_entry)
            try:
                result = self.web_detector.detect(web_feat)
            except Exception as exc:  # noqa: BLE001
                logger.error("[Guardian] WebAttackDetector 异常: %s", exc)
                return

            if result and result.threat_type != "normal":
                self._on_threat(result)
        except Exception as exc:  # noqa: BLE001
            logger.error("[Guardian] Web 日志处理异常: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # 威胁情报前置过滤
    # ------------------------------------------------------------------
    def _is_threat_intel_hit(self, ip: str) -> bool:
        """命中威胁情报则直接触发响应 + 审计日志，并返回 True。"""
        try:
            intel = self.threat_intel.check_ip(ip)
        except Exception as exc:  # noqa: BLE001 - 情报查询失败不阻断主流程
            logger.debug("[Guardian] 威胁情报查询异常: %s", exc)
            return False

        if not intel or not intel.get("is_malicious"):
            return False

        ioc_val = str(intel.get("ioc_value") or ip)
        src = str(intel.get("source", "unknown"))
        srcs = intel.get("sources") or []
        src_part = f" merged_sources={srcs}" if srcs else ""
        result = DetectionResult(
            threat_type="threat_intel",
            threat_level="high",
            confidence=0.95,
            details=(
                f"威胁情报命中: IOC={ioc_val} source={src}{src_part}"
            ).strip(),
            source_ip=ip,
            raw_data={"intel": {k: v for k, v in intel.items() if k != "metadata"}},
        )
        self._on_threat(result)
        return True

    # ------------------------------------------------------------------
    # 多引擎检测（逐个 try；单引擎异常不影响其它引擎）
    # ------------------------------------------------------------------
    def _safe_detect_many(
        self, features: Dict[str, Any]
    ) -> List[Optional[DetectionResult]]:
        """逐个调用 4 个检测引擎，捕获异常后继续下一个。"""
        engines = [
            ("DDoSDetector", self.ddos_detector),
            ("IntrusionDetector", self.intrusion_detector),
            ("AnomalyDetector", self.anomaly_detector),
        ]
        out: List[Optional[DetectionResult]] = []
        for name, engine in engines:
            if not getattr(engine, "is_ready", False):
                continue
            try:
                out.append(engine.detect(features))
            except Exception as exc:  # noqa: BLE001
                logger.error("[Guardian] %s 推理异常: %s", name, exc)
                out.append(None)
        return out

    # ------------------------------------------------------------------
    # 威胁处置：响应 + 审计 + Web 广播
    # ------------------------------------------------------------------
    def _on_threat(self, result: DetectionResult) -> None:
        """统一处置入口：执行响应 → 写审计日志 → 可选广播到前端。"""
        try:
            self._metrics.record_alert()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.responder.respond(result)
        except Exception as exc:  # noqa: BLE001
            logger.error("[Guardian] 响应执行异常: %s", exc)

        try:
            self.security_logger.log_event(
                event_type=result.threat_type,
                level=result.threat_level,
                details={"detection": result.details, "raw": result.raw_data},
                source_ip=result.source_ip,
                confidence=float(result.confidence),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("[Guardian] 审计日志写入异常: %s", exc)

        # 可选：通过 Redis Streams 跨进程共享（带 consumer group + ack 语义）
        # 失败时由 RedisClient 自动降级到内存，不会抛到上层
        stream_ok = False
        try:
            sid = self.redis.stream_add(
                self._ALERT_STREAM,
                {
                    "alert_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc)
                    .astimezone()
                    .isoformat(timespec="seconds"),
                    "type": result.threat_type,
                    "level": result.threat_level,
                    "confidence": float(result.confidence),
                    "source_ip": result.source_ip,
                    "details": result.details,
                },
                maxlen=self._ALERT_STREAM_MAXLEN,
            )
            stream_ok = sid is not None
        except Exception as exc:  # noqa: BLE001
            logger.debug("[Guardian] Redis Streams 推送失败（已降级）: %s", exc)
            stream_ok = False
        try:
            self._metrics.record_redis_stream_write(stream_ok)
        except Exception:  # noqa: BLE001
            pass

        # 可选：广播到 Phase 7 前端
        if self._flask_app and self._push_alert_fn:
            try:
                self._push_alert_fn(
                    self._flask_app,
                    {
                        "threat_type": result.threat_type,
                        "level": result.threat_level,
                        "confidence": float(result.confidence),
                        "source_ip": result.source_ip,
                        "details": result.details,
                        "title": result.details,
                        "summary": result.details,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("[Guardian] 前端广播失败: %s", exc)

    def _drain_network_packets_this_tick(self) -> None:
        """本 tick 从采集队列批量取包并送入聚合器；读取异常记入计数并继续。"""
        if self.packet_collector is None:
            return
        try:
            packets = self.packet_collector.get_packets(
                max_count=self.cfg.max_packets_per_tick
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("[Guardian] 数据包队列读取异常: %s", exc)
            self._packet_queue_read_errors += 1
            try:
                self._metrics.record_queue_read_error()
            except Exception:  # noqa: BLE001
                pass
            packets = []
        self.process_packet_batch(packets)

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------
    def run(self) -> None:
        """主运行循环。"""
        self._running = True
        self.security_logger.log_system("AI-Security-Guardian 启动", level="info")
        logger.info("[Guardian] 系统已启动，开始监控...")

        if self.packet_collector is not None:
            try:
                self.packet_collector.start()
            except PermissionError:
                logger.error(
                    "[Guardian] 抓包权限不足（请用管理员/sudo 运行），该入口已禁用"
                )
                self.security_logger.log_system(
                    "PacketCollector 权限不足，已禁用该采集入口", level="warning"
                )
                self.packet_collector = None
            except Exception as exc:  # noqa: BLE001
                logger.error("[Guardian] PacketCollector 启动失败: %s", exc)
                self.packet_collector = None

        try:
            while self._running:
                # 1) 网络数据包入口（含空批量，用于推进空闲超时）
                if self.packet_collector is not None:
                    self._drain_network_packets_this_tick()

                # 2) Web 日志入口
                if self.web_log_collector is not None:
                    try:
                        web_logs = self.web_log_collector.read_new_lines()
                    except Exception as exc:  # noqa: BLE001
                        logger.error("[Guardian] Web 日志读取异常: %s", exc)
                        web_logs = []
                    for entry in web_logs:
                        self.process_web_log(entry)

                time.sleep(self.cfg.loop_interval_sec)

                try:
                    self.responder.scheduler.tick(self.responder)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("[Guardian] 响应调度 tick 异常: %s", exc)

                try:
                    self._metrics.set_collection_flags(
                        self.packet_collector is not None,
                        self.web_log_collector is not None,
                    )
                    self._metrics.flush_to_redis(self.redis)
                    status_path = os.environ.get(
                        "GUARDIAN_STATUS_FILE", "logs/guardian_status.json"
                    )
                    self._metrics.write_status_file(status_path)
                except Exception:  # noqa: BLE001
                    pass

        except KeyboardInterrupt:
            logger.info("[Guardian] 收到 Ctrl+C，准备优雅关闭")
        finally:
            self.shutdown()

    # ------------------------------------------------------------------
    # 优雅关闭（幂等）
    # ------------------------------------------------------------------
    def shutdown(self) -> None:
        """幂等的关闭流程，所有子模块的停止都被 try 包裹。"""
        with self._shutdown_lock:
            if self._shutdown_complete:
                return
            self._running = False
            self._shutdown_complete = True

        logger.info("[Guardian] 开始优雅关闭...")
        try:
            self.security_logger.log_system("AI-Security-Guardian 关闭中", level="info")
        except Exception as exc:  # noqa: BLE001
            logger.debug("[Guardian] 关闭审计日志写入失败: %s", exc)

        if self.packet_collector is not None:
            try:
                self.packet_collector.stop()
            except Exception as exc:  # noqa: BLE001
                logger.error("[Guardian] PacketCollector 停止异常: %s", exc)

        # 尝试回写审计缓冲（如有）
        try:
            drained = self.security_logger.drain_buffer()
            if drained:
                logger.info("[Guardian] 审计缓冲回写成功 %d 条", drained)
        except Exception:  # noqa: BLE001
            pass

        try:
            self.security_logger.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("[Guardian] 审计日志 handler 释放失败: %s", exc)

        logger.info("[Guardian] 系统已停止")


# =====================================================================
# 顶层入口
# =====================================================================
def _configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    )


def _install_signal_handlers(guardian: SecurityGuardian) -> None:
    """SIGINT / SIGTERM 统一走 shutdown()。"""
    def handler(signum, _frame):  # noqa: ANN001
        logger.info("[Guardian] 捕获信号 %s，开始优雅关闭", signum)
        guardian.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    # Windows 的 signal 模块不支持 SIGTERM，兼容写法
    term = getattr(signal, "SIGTERM", None)
    if term is not None:
        try:
            signal.signal(term, handler)
        except (ValueError, OSError):
            pass


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-Security-Guardian 主入口（Phase 8）"
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="演练模式：响应动作仅打印，不实际执行 iptables",
    )
    parser.add_argument(
        "--no-packet-capture",
        dest="no_packet_capture",
        action="store_true",
        help="禁用抓包（在无 libpcap 或无权限环境下使用）",
    )
    parser.add_argument(
        "--no-web-log",
        dest="no_web_log",
        action="store_true",
        help="禁用 Web 日志采集",
    )
    parser.add_argument(
        "--enable-flask",
        dest="enable_flask",
        action="store_true",
        help="接入 Phase 7 Flask 工厂，告警实时广播到前端",
    )
    return parser.parse_args()


def _enforce_runtime_guards(guardian: SecurityGuardian, loaded: Dict[str, bool]) -> None:
    """生产落地保护：关键依赖不满足时 fail-fast 退出。"""
    if guardian.cfg.require_redis_available and not guardian.redis.is_available:
        raise RuntimeError(
            "启动失败：REQUIRE_REDIS_AVAILABLE=true 但 Redis 不可用（当前为内存降级模式）。"
        )
    if guardian.cfg.require_models_ready:
        missing = sorted([name for name, ok in loaded.items() if not ok])
        if missing:
            raise RuntimeError(
                "启动失败：REQUIRE_MODELS_READY=true 且模型未就绪。"
                f" missing={missing}"
            )


def main() -> None:
    _configure_logging()

    args = _parse_args()
    cfg = RuntimeConfig.from_env()
    # CLI 参数可覆盖环境变量
    if args.dry_run:
        cfg.dry_run = True
    if args.no_packet_capture:
        cfg.enable_packet_capture = False
    if args.no_web_log:
        cfg.enable_web_log = False
    if args.enable_flask:
        cfg.enable_flask = True

    logger.info("=" * 60)
    logger.info("AI-Security-Guardian 启动中 (Phase 8)")
    logger.info(
        "配置: dry_run=%s packet=%s web_log=%s flask=%s redis=%s:%s",
        cfg.dry_run,
        cfg.enable_packet_capture,
        cfg.enable_web_log,
        cfg.enable_flask,
        cfg.redis_host,
        cfg.redis_port,
    )
    logger.info("=" * 60)

    guardian = SecurityGuardian(cfg=cfg)
    loaded = guardian.load_models()
    _enforce_runtime_guards(guardian, loaded)

    _install_signal_handlers(guardian)

    guardian.run()


if __name__ == "__main__":
    main()
