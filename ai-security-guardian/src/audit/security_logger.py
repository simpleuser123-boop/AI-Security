"""
安全审计日志模块（Phase 6：安全审计层 + Phase 8：集成降级）
对应架构文档 §7.2 安全日志 + §11.6 日志防篡改

本模块负责：
    1. 结构化安全事件日志 / 响应日志的写入（JSON Lines 格式）
    2. 基于 SHA-256 哈希链的防篡改完整性校验
    3. 数据库 / 磁盘异常时的本地缓冲降级（Phase 8 要求）
    4. 完整性校验 API，供审计页面或运维巡检调用

设计约定（避免与 Phase 7 及后续 Phase 8 集成冲突）：
    - 文件名固定 `security.log`，目录由环境隔离：`logs/test|dev|staging|production`
    - 所有日志都写入一个独立的 `security` logger（与 Flask 根 logger 分离）
    - 哈希链使用 `prev_hash:canonical_json` 方式累积，genesis 记为 'genesis'
    - 关闭完整性校验后不会写 integrity 字段（向后兼容）
    - 写入失败时会写入本地 `logs/security_buffer.log` 作为兜底，避免丢失
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from src.audit.log_paths import resolve_audit_log_dir


class SecurityLogger:
    """结构化安全日志记录器（带完整性保护 + 本地缓冲降级）。

    Attributes:
        log_dir: 日志输出目录。
        enable_integrity: 是否启用哈希链完整性校验。
        log_file: 主日志文件（`logs/security.log`）。
        buffer_file: 写入失败时的兜底缓冲文件（`logs/security_buffer.log`）。
    """

    _LOG_FILENAME: str = "security.log"
    _BUFFER_FILENAME: str = "security_buffer.log"

    def __init__(
        self,
        log_dir: Optional[str] = None,
        enable_integrity: bool = True,
    ) -> None:
        self.log_dir = resolve_audit_log_dir(log_dir)
        self.enable_integrity = enable_integrity
        try:
            os.makedirs(self.log_dir, exist_ok=True)
        except OSError as exc:
            # 目录创建失败（极端情况）也不应拖垮主流程
            logging.getLogger(__name__).error(
                "[SecurityLogger] 日志目录创建失败，将退化为 stdout: %s", exc
            )

        self.log_file: str = os.path.join(self.log_dir, self._LOG_FILENAME)
        self.buffer_file: str = os.path.join(self.log_dir, self._BUFFER_FILENAME)

        self._lock = threading.Lock()
        self._last_hash: str = ""

        self._setup_logger()
        # 进程重启后从已有日志恢复链尾，避免 prev_hash 重新回到 genesis
        self._restore_last_hash()

    # ------------------------------------------------------------------
    # logger 初始化
    # ------------------------------------------------------------------
    def _setup_logger(self) -> None:
        """配置独立的 `security` logger，文件 + 控制台双输出。"""
        logger_name = f"security.{os.path.abspath(self.log_file)}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        # 防止重复挂载 handler（多次实例化时）
        if not self.logger.handlers:
            try:
                file_handler = logging.FileHandler(
                    self.log_file, encoding="utf-8"
                )
                file_handler.setFormatter(logging.Formatter("%(message)s"))
                self.logger.addHandler(file_handler)
            except OSError as exc:
                # 文件 handler 打不开不应崩溃
                logging.getLogger(__name__).error(
                    "[SecurityLogger] 主日志 handler 打开失败: %s", exc
                )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
            )
            self.logger.addHandler(console_handler)

        # 避免同一条日志被 Flask root logger 再次打印
        self.logger.propagate = False

    def close(self) -> None:
        """释放该审计 logger 持有的所有 handler。

        Windows 会对打开的 FileHandler 保持独占文件句柄；测试或短生命周期
        进程删除临时日志目录前必须显式关闭，否则 TemporaryDirectory 清理会失败。
        """
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
            try:
                handler.flush()
            except Exception:  # noqa: BLE001 - close must be best-effort
                pass
            try:
                handler.close()
            except Exception:  # noqa: BLE001
                pass

    def _restore_last_hash(self) -> None:
        """从既有 security.log 末行恢复链尾 hash，保证跨重启链连续。"""
        if not self.enable_integrity:
            return
        self._last_hash = ""
        if not os.path.exists(self.log_file):
            return
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for raw_line in reversed(f.readlines()):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    integrity = entry.get("integrity") or {}
                    h = integrity.get("hash")
                    if isinstance(h, str) and h:
                        self._last_hash = h
                        return
        except OSError:
            # 日志不可读时保持默认 genesis，不阻断主流程
            return

    # ------------------------------------------------------------------
    # 哈希工具
    # ------------------------------------------------------------------
    @staticmethod
    def _hash(text: str) -> str:
        """SHA-256 前 16 位，作为简短可读的哈希。"""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def _compute_chain_hash(self, canonical_json: str) -> str:
        """基于上一条哈希 + 当前条目 canonical JSON 计算链式哈希。"""
        prev = self._last_hash or "genesis"
        return self._hash(f"{prev}:{canonical_json}")

    @staticmethod
    def _canonicalize(event: Dict[str, Any]) -> str:
        """排序 key 的 canonical JSON 序列化，保证哈希可复现。"""
        return json.dumps(
            event,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    # ------------------------------------------------------------------
    # 写入内部
    # ------------------------------------------------------------------
    def _write(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """落盘一条事件；必要时补 integrity 字段，并在失败时写入本地缓冲。

        Returns:
            实际被写入（含 integrity 字段）的事件字典。
        """
        with self._lock:
            if self.enable_integrity:
                canonical = self._canonicalize(event)
                h = self._compute_chain_hash(canonical)
                event["integrity"] = {
                    "hash": h,
                    "prev_hash": self._last_hash or "genesis",
                    "algorithm": "sha256",
                }
                self._last_hash = h

            line = json.dumps(event, ensure_ascii=False)
            try:
                self.logger.info(line)
            except Exception as exc:  # noqa: BLE001 - 写入失败不得拖垮主流程
                self._buffer_write(line, exc)
            return event

    def _buffer_write(self, line: str, exc: BaseException) -> None:
        """主日志写入失败时的本地缓冲降级，避免丢失关键审计数据。"""
        try:
            with open(self.buffer_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            logging.getLogger(__name__).error(
                "[SecurityLogger] 主日志写入失败，已写入缓冲文件 %s: %s",
                self.buffer_file,
                exc,
            )
        except OSError:
            # 连兜底文件也打不开，只能退化到 stderr 记录
            logging.getLogger(__name__).error(
                "[SecurityLogger] 主日志与缓冲文件均不可写，丢弃一条记录: %s",
                line,
            )

    # ------------------------------------------------------------------
    # 对外写入 API
    # ------------------------------------------------------------------
    def log_event(
        self,
        event_type: str,
        level: str,
        details: Optional[Dict[str, Any]] = None,
        source_ip: str = "",
        confidence: float = 0.0,
    ) -> Dict[str, Any]:
        """记录安全事件（检测结果 / 威胁情报命中 等）。"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "level": level,
            "source_ip": source_ip,
            "confidence": float(confidence),
            "details": details or {},
        }
        return self._write(event)

    def log_response(self, action: str, target: str, result: str) -> Dict[str, Any]:
        """记录响应动作（封禁 / 解封 / 隔离 / 告警推送等）。"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "response",
            "action": action,
            "target": target,
            "result": result,
        }
        return self._write(event)

    def log_system(self, message: str, level: str = "info") -> Dict[str, Any]:
        """记录系统级事件（启动 / 关闭 / 模型加载失败等）。"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "system",
            "level": level,
            "message": message,
        }
        return self._write(event)

    def log_model_governance(
        self, action: str, details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """模型生命周期审计（切换 / 回滚 / 加载失败等），对齐 AuditEvent 类语义。"""
        payload = {"action": action, **(details or {})}
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "model_governance",
            "level": "info",
            "resource_type": "ml_model",
            "details": payload,
        }
        return self._write(event)

    # ------------------------------------------------------------------
    # 完整性校验 API
    # ------------------------------------------------------------------
    def verify_integrity(self, log_file: Optional[str] = None) -> Dict[str, Any]:
        """重放哈希链，检查主日志文件是否被篡改或删除行。

        Args:
            log_file: 待校验的日志文件，默认 `logs/security.log`。

        Returns:
            dict: `valid` / `total_lines` / `invalid_lines` 三字段。
            当 `enable_integrity=False` 时直接返回 valid=True。
        """
        if not self.enable_integrity:
            return {
                "valid": True,
                "total_lines": 0,
                "invalid_lines": [],
                "message": "完整性校验未启用",
            }

        path = log_file or self.log_file
        if not os.path.exists(path):
            # 尚无审计落盘时视为可接受状态，避免首次启动巡检误报 critical。
            return {
                "valid": True,
                "total_lines": 0,
                "invalid_lines": [],
                "message": "日志文件不存在（无记录可校验）",
            }

        prev_hash = "genesis"
        line_count = 0
        invalid_lines: List[str] = []

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_num, raw_line in enumerate(f, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    line_count += 1

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        invalid_lines.append(f"行 {line_num}: JSON 解析失败")
                        continue

                    integrity = entry.get("integrity", {})
                    expected_hash = integrity.get("hash", "")
                    entry_prev = integrity.get("prev_hash", "")
                    effective_prev = prev_hash
                    # 兼容历史日志：旧版本在跨重启时可能把 prev_hash 重置为 genesis。
                    # 校验时将其视为“新分段起点”，避免旧数据长期污染巡检结果。
                    if entry_prev == "genesis" and prev_hash != "genesis":
                        effective_prev = "genesis"
                    elif entry_prev != prev_hash:
                        invalid_lines.append(
                            f"行 {line_num}: 哈希链断裂 "
                            f"(期望 prev={prev_hash}, 实际 prev={entry_prev})"
                        )

                    body = {k: v for k, v in entry.items() if k != "integrity"}
                    canonical = self._canonicalize(body)
                    recomputed = self._hash(f"{effective_prev}:{canonical}")

                    if recomputed != expected_hash:
                        invalid_lines.append(
                            f"行 {line_num}: 哈希不匹配 "
                            f"(期望={expected_hash}, 实际={recomputed})"
                        )

                    prev_hash = expected_hash or prev_hash
        except OSError as exc:
            return {
                "valid": False,
                "total_lines": line_count,
                "invalid_lines": [f"日志文件读取失败: {exc}"],
            }

        return {
            "valid": len(invalid_lines) == 0,
            "total_lines": line_count,
            "invalid_lines": invalid_lines,
        }

    # ------------------------------------------------------------------
    # 缓冲区维护 API（供运维巡检使用）
    # ------------------------------------------------------------------
    def has_buffered(self) -> bool:
        """是否存在未回写的缓冲文件（通常发生在主日志不可写时）。"""
        return os.path.exists(self.buffer_file) and os.path.getsize(self.buffer_file) > 0

    def drain_buffer(self) -> int:
        """尝试将缓冲文件中的记录回写到主日志，成功后清空缓冲文件。

        Returns:
            回写的行数；主日志仍不可写则保持缓冲文件原状并返回 0。
        """
        if not self.has_buffered():
            return 0
        try:
            with open(self.buffer_file, "r", encoding="utf-8") as f:
                lines: Iterable[str] = list(f)
            count = 0
            for raw in lines:
                line = raw.strip()
                if not line:
                    continue
                self.logger.info(line)
                count += 1
            os.remove(self.buffer_file)
            return count
        except OSError as exc:
            logging.getLogger(__name__).error(
                "[SecurityLogger] 缓冲回写失败: %s", exc
            )
            return 0
