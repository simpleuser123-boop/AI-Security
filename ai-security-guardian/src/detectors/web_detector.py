"""
Web 攻击检测引擎（规则引擎 + 机器学习 双重策略）
对应架构文档 §5.4.3 Web 攻击检测

检测策略：
    第一步 规则引擎快速匹配：覆盖 SQL 注入 / XSS / 命令注入 / 路径遍历。
    第二步 ML 文本分类兜底：规则未命中时调用 TF-IDF + 朴素贝叶斯模型。

【安全加固】
    - 多层 URL 解码防绕过：对输入 URL 进行至多 5 轮 urllib.parse.unquote，
      避免攻击者通过 %252e%252e%2f 等多重编码绕过规则匹配。
    - 禁止使用 eval / exec / os.system / subprocess。
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Dict, Optional, Pattern
from urllib.parse import unquote

import joblib

from src.schema.feature_schemas import validate_payload_against_schema
from src.schema.manifest import ManifestLoadError, ModelManifest, resolve_model_entry

from .base import BaseDetector, DetectionResult
from .inference_meta import set_inference_meta

logger = logging.getLogger(__name__)


class WebAttackDetector(BaseDetector):
    """
    Web 攻击检测引擎。

    规则引擎覆盖以下 4 类常见 Web 攻击：
        - sql_injection
        - xss
        - command_injection
        - path_traversal

    规则未命中时，会交给 ML 模型做文本分类（如果已加载）。
    """

    # 每类攻击对应的关键字/正则模式
    RULES: Dict[str, Pattern[str]] = {
        "sql_injection": re.compile(
            r"("
            r"union\s+select"
            r"|select\s+.+\s+from"
            r"|insert\s+into"
            r"|drop\s+table"
            r"|delete\s+from"
            r"|or\s+1\s*=\s*1"
            r"|and\s+1\s*=\s*1"
            r"|'\s*or\s*'"
            r"|xp_cmdshell"
            r"|information_schema"
            r"|sleep\s*\("
            r"|benchmark\s*\("
            r"|extractvalue\s*\("
            r"|updatexml\s*\("
            r")",
            re.IGNORECASE,
        ),
        "xss": re.compile(
            r"("
            r"<\s*script"
            r"|</\s*script\s*>"
            r"|javascript\s*:"
            r"|on(?:error|load|click|mouseover|focus|toggle|start)\s*="
            r"|alert\s*\("
            r"|document\.(?:cookie|domain|write)"
            r"|window\.(?:location|open)"
            r"|eval\s*\("
            r"|<\s*svg[^>]*on"
            r"|<\s*img[^>]*onerror"
            r")",
            re.IGNORECASE,
        ),
        "command_injection": re.compile(
            r"("
            r";\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl)\b"
            r"|\|\s*(?:cat|ls|id|whoami|nc|bash|sh)\b"
            r"|`\s*(?:cat|ls|id|whoami)"
            r"|\$\(\s*(?:cat|ls|id|whoami|curl|wget)"
            r"|&&\s*(?:cat|ls|id|whoami|rm)\b"
            r")",
            re.IGNORECASE,
        ),
        "path_traversal": re.compile(
            r"("
            r"\.\./"
            r"|\.\.\\"
            r"|%2e%2e%2f"
            r"|%2e%2e/"
            r"|%252e%252e"
            r"|\.\.%2f"
            r"|/etc/passwd"
            r"|/etc/shadow"
            r"|/proc/self"
            r"|c:\\windows\\system32"
            r")",
            re.IGNORECASE,
        ),
    }

    RULE_CONFIDENCE: float = 0.95
    ML_CONFIDENCE_THRESHOLD: float = 0.7
    MAX_DECODE_ITERATIONS: int = 5

    def __init__(self) -> None:
        self.ml_model = None
        self._manifest: Optional[ModelManifest] = None

    def clear_ml_state(self) -> None:
        self.ml_model = None
        self._manifest = None

    def load_model(self, model_path: str) -> None:
        """
        加载 TF-IDF + 朴素贝叶斯 Pipeline 模型及 ``*.model_manifest.json``。

        Args:
            model_path: 模型文件路径，如 'models/saved/web_attack_nb_v1.pkl'。
        """
        self.clear_ml_state()
        try:
            ap, manifest = resolve_model_entry(model_path)
        except ManifestLoadError as exc:
            logger.error("[AUDIT] Web ML 拒绝加载（manifest 无效）: %s", exc)
            raise
        if not os.path.isfile(ap):
            raise FileNotFoundError(ap)
        if manifest.model_input_mode != "text_sklearn_pipeline":
            raise ManifestLoadError("WebAttackDetector 需要 model_input_mode=text_sklearn_pipeline")
        if manifest.schema_name != "web_request_v1":
            raise ManifestLoadError("WebAttackDetector 需要 schema_name=web_request_v1")
        self._manifest = manifest
        self.ml_model = joblib.load(ap)
        logger.info(
            "[WebAttackDetector] ML+manifest 加载成功 schema=%s (%s)",
            self._manifest.schema_name,
            ap,
        )

    @property
    def is_ready(self) -> bool:
        """规则引擎永远可用，因此恒为 True。"""
        return True

    # ------------------------------------------------------------------
    # 安全工具方法
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_url(url: str) -> str:
        """
        多层 URL 解码（最多 5 轮）以抵御编码绕过。

        攻击者常利用 `%252e%252e%2f` 这样的嵌套编码绕过只做一次 urldecode 的
        规则引擎。本方法持续调用 urllib.parse.unquote，直到解码结果稳定
        或达到最大轮次。

        Args:
            url: 待解码的原始 URL。

        Returns:
            解码后的字符串。若解码途中出现异常则返回当前阶段结果。
        """
        if not isinstance(url, str):
            return ""

        decoded = url
        for _ in range(WebAttackDetector.MAX_DECODE_ITERATIONS):
            try:
                new_decoded = unquote(decoded)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[WebAttackDetector] URL 解码异常: %s", exc)
                break
            if new_decoded == decoded:
                break
            decoded = new_decoded
        return decoded

    # ------------------------------------------------------------------
    # 检测主流程
    # ------------------------------------------------------------------
    def detect(self, features: Dict) -> Optional[DetectionResult]:
        """
        对输入 Web 请求特征进行攻击检测。

        Args:
            features: 特征字典，优先使用 'url_raw'，其次 'url'。
                      可选字段 'src_ip' 用于标记来源。

        Returns:
            DetectionResult（永不返回 None，因为规则引擎始终可用）。
        """
        t0 = time.perf_counter()

        def finish(
            res: Optional[DetectionResult],
            *,
            model_version: Optional[str] = None,
            schema_version: Optional[str] = None,
        ) -> Optional[DetectionResult]:
            return set_inference_meta(
                res,
                engine="WebAttackDetector",
                manifest=self._manifest,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                model_version=model_version,
                schema_version=schema_version,
            )

        url = features.get("url_raw") or features.get("url") or ""
        src_ip = str(features.get("src_ip", "") or "").strip()
        if not src_ip:
            wr = features.get("web_request_v1")
            if isinstance(wr, dict):
                src_ip = str(wr.get("src_ip", "") or "").strip()

        decoded_url = self._decode_url(url)

        # 1) 规则引擎快速通道（对解码后的 URL 进行匹配）
        for attack_type, pattern in self.RULES.items():
            if pattern.search(decoded_url):
                logger.info(
                    "[WebAttackDetector] 规则命中 type=%s url=%s ip=%s",
                    attack_type,
                    url,
                    src_ip,
                )
                return finish(
                    DetectionResult(
                        threat_type="web_attack",
                        threat_level="high",
                        confidence=self.RULE_CONFIDENCE,
                        details=f"规则引擎命中：{attack_type}",
                        source_ip=src_ip,
                        raw_data={
                            "rule": attack_type,
                            "url_raw": url,
                            "url_decoded": decoded_url,
                        },
                    ),
                    model_version="rule_engine",
                    schema_version="",
                )

        # 2) ML 文本分类兜底（须通过 web_request_v1 契约 + manifest.feature_columns）
        if self.ml_model is not None and self._manifest is not None:
            merged = dict(features)
            merged["url"] = url or merged.get("url") or ""
            merged["decoded_url"] = decoded_url
            merged["url_decoded"] = decoded_url
            merged.setdefault("http_method", merged.get("method", "GET"))
            merged.setdefault("method", merged.get("http_method", "GET"))
            merged.setdefault("status_code", merged.get("status_code", 200))
            merged["src_ip"] = src_ip or merged.get("src_ip", "")

            ok_schema, schema_errs = validate_payload_against_schema(
                "web_request_v1", merged
            )
            if not ok_schema:
                logger.warning(
                    "[AUDIT] Web ML 降级为仅规则：web_request_v1 契约失败 %s ip=%s",
                    schema_errs,
                    src_ip,
                )
            else:
                cols = self._manifest.feature_columns
                if not cols:
                    logger.warning("[AUDIT] Web ML manifest feature_columns 为空，跳过 ML")
                else:
                    text_key = cols[0]
                    text_val = str(merged.get(text_key, "") or "")
                    if not text_val.strip():
                        logger.warning(
                            "[AUDIT] Web ML 降级：缺文本列 %r（与 manifest 顺序对齐） ip=%s",
                            text_key,
                            src_ip,
                        )
                    else:
                        try:
                            prediction = self.ml_model.predict([text_val])[0]
                            proba = self.ml_model.predict_proba([text_val])[0]
                            max_prob = float(max(proba))
                        except Exception as exc:
                            logger.error("[WebAttackDetector] ML 推理失败: %s", exc)
                            prediction = "normal"
                            max_prob = 0.0

                        if str(prediction).lower() != "normal":
                            threat_level = (
                                "medium"
                                if max_prob > self.ML_CONFIDENCE_THRESHOLD
                                else "low"
                            )
                            logger.info(
                                "[WebAttackDetector] ML 命中 type=%s confidence=%.4f",
                                prediction,
                                max_prob,
                            )
                            return finish(
                                DetectionResult(
                                    threat_type="web_attack",
                                    threat_level=threat_level,
                                    confidence=max_prob,
                                    details=f"ML 检测：{prediction}",
                                    source_ip=src_ip,
                                    raw_data={
                                        "ml_prediction": str(prediction),
                                        "url_raw": url,
                                        "url_decoded": decoded_url,
                                        "manifest_version": self._manifest.version,
                                    },
                                ),
                            )

        # 3) 规则未命中且 ML 未检出攻击，视为正常
        return finish(
            DetectionResult(
                threat_type="normal",
                threat_level="low",
                confidence=0.9,
                details="Web 检测：未命中任何攻击规则",
                source_ip=src_ip,
                raw_data={"url_raw": url, "url_decoded": decoded_url},
            ),
            model_version=(
                self._manifest.version if self._manifest is not None else "rules_only"
            ),
            schema_version=(
                self._manifest.schema_version if self._manifest is not None else ""
            ),
        )
