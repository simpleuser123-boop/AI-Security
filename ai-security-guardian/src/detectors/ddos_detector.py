"""
DDoS 检测引擎
对应架构文档 §5.4.1 DDoS 检测（随机森林首选方案）

加载须伴随 ``*.model_manifest.json``；禁止无清单静默上线。
生产可信 tabular：在线字段须完整覆盖 feature_columns；NSL-KDD 原型须
``trust_tier=prototype_nsl_kdd`` + ``NSLKDDAdapter``，并在每次推理审计零填充列。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from src.schema.feature_schemas import (
    production_tabular_keys_present,
    validate_payload_against_schema,
)
from src.schema.inference_guard import ml_degraded_normal
from src.schema.manifest import ManifestLoadError, ModelManifest, resolve_model_entry
from src.schema.nsl_kdd_adapter import NSLKDDAdapter, NSL_KDD_FEATURE_COLUMNS

from .base import BaseDetector, DetectionResult
from .inference_meta import set_inference_meta

logger = logging.getLogger(__name__)


class DDoSDetector(BaseDetector):
    """DDoS 检测引擎（随机森林 + manifest 契约）。"""

    HIGH_CONFIDENCE_THRESHOLD: float = 0.8

    def __init__(self) -> None:
        self.model = None
        self._manifest: Optional[ModelManifest] = None

    def clear_ml_state(self) -> None:
        self.model = None
        self._manifest = None

    def load_model(self, model_path: str) -> None:
        self.clear_ml_state()
        try:
            ap, manifest = resolve_model_entry(model_path)
        except ManifestLoadError as exc:
            logger.error("[AUDIT] DDoS 模型拒绝加载（manifest 无效）: %s", exc)
            raise
        if not os.path.isfile(ap):
            raise FileNotFoundError(ap)
        model = joblib.load(ap)
        n_feat = getattr(model, "n_features_in_", len(manifest.feature_columns))
        if int(n_feat) != len(manifest.feature_columns):
            raise ManifestLoadError(
                f"模型 n_features_in_={n_feat} 与 manifest feature_columns={len(manifest.feature_columns)} 不一致"
            )
        self._manifest = manifest
        self.model = model
        logger.info(
            "[DDoSDetector] 模型+manifest 加载成功 trust_tier=%s schema=%s (%s)",
            manifest.trust_tier,
            manifest.schema_name,
            ap,
        )

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self._manifest is not None

    def detect(self, features: Dict) -> Optional[DetectionResult]:
        t0 = time.perf_counter()

        def finish(res: Optional[DetectionResult]) -> Optional[DetectionResult]:
            return set_inference_meta(
                res,
                engine="DDoSDetector",
                manifest=self._manifest,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not self.is_ready or self._manifest is None:
            logger.debug("[DDoSDetector] 模型未加载，返回 None")
            return finish(None)

        m = self._manifest
        src_ip = str(features.get("src_ip", "") or "").strip()
        if not src_ip:
            nf = features.get("network_flow_v1")
            if isinstance(nf, dict):
                src_ip = str(nf.get("src_ip", "") or "").strip()

        ok_schema, schema_errs = validate_payload_against_schema(
            "network_flow_v1", features
        )
        if not ok_schema:
            logger.warning(
                "[AUDIT] DDoS network_flow_v1 契约失败: %s ip=%s",
                schema_errs,
                src_ip,
            )
            return finish(
                ml_degraded_normal(
                    engine="DDoSDetector",
                    reason="network_flow_v1 契约失败: " + "; ".join(schema_errs),
                    source_ip=src_ip,
                    extra={"schema_errors": schema_errs},
                )
            )

        if m.trust_tier == "production" and m.adapter is None:
            ok_keys, missing = production_tabular_keys_present(
                m.feature_columns, features
            )
            if not ok_keys:
                logger.warning(
                    "[AUDIT] DDoS 生产 ML 缺字段（拒绝静默填 0）: %s ip=%s",
                    missing,
                    src_ip,
                )
                return finish(
                    ml_degraded_normal(
                        engine="DDoSDetector",
                        reason="在线特征缺字段: " + ", ".join(missing),
                        source_ip=src_ip,
                        extra={"missing_columns": missing},
                    )
                )
            feature_vector: List[float] = []
            flat: Dict[str, Any] = dict(features)
            nf = features.get("network_flow_v1")
            if isinstance(nf, dict):
                for k, v in nf.items():
                    if k not in ("schema_name", "schema_version", "schema"):
                        flat.setdefault(k, v)
            for col in m.feature_columns:
                feature_vector.append(float(flat[col]))
            X = np.array([feature_vector], dtype=np.float64)
        elif m.trust_tier == "prototype_nsl_kdd" and m.adapter == "nsl_kdd_v1":
            vec, audit = NSLKDDAdapter.build_vector_in_order(features, m.feature_columns)
            if audit.get("zero_filled_columns"):
                logger.warning(
                    "[AUDIT] DDoS NSL-KDD 原型推理（零填充/无编码列）cols=%s ip=%s",
                    audit["zero_filled_columns"],
                    src_ip,
                )
            X = np.array([vec], dtype=np.float64)
        else:
            logger.error("[AUDIT] DDoS manifest trust/adapter 组合不受支持")
            return finish(
                ml_degraded_normal(
                    engine="DDoSDetector",
                    reason="manifest trust_tier/adapter 不受支持",
                    source_ip=src_ip,
                )
            )

        try:
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
        except Exception as exc:
            logger.error("[DDoSDetector] 模型推理失败: %s", exc)
            return finish(None)

        class_labels = list(getattr(self.model, "classes_", []))
        raw_extra: Dict[str, Any] = {"prediction": str(prediction)}
        if m.trust_tier == "prototype_nsl_kdd":
            raw_extra["trust_tier"] = m.trust_tier
            raw_extra["nsl_kdd_adapter"] = m.adapter

        if str(prediction).lower() == "normal":
            normal_prob = float(
                probabilities[class_labels.index(prediction)]
                if prediction in class_labels
                else probabilities[0]
            )
            return finish(
                DetectionResult(
                    threat_type="normal",
                    threat_level="low",
                    confidence=normal_prob,
                    details="DDoS 检测：正常流量",
                    source_ip=src_ip,
                    raw_data=raw_extra,
                )
            )

        if prediction in class_labels:
            attack_prob = float(probabilities[class_labels.index(prediction)])
        else:
            attack_prob = float(np.max(probabilities))

        threat_level = "high" if attack_prob > self.HIGH_CONFIDENCE_THRESHOLD else "medium"
        logger.info(
            "[DDoSDetector] 检出 DDoS：class=%s confidence=%.4f level=%s ip=%s",
            prediction,
            attack_prob,
            threat_level,
            src_ip,
        )
        raw_extra["proba"] = probabilities.tolist()
        return finish(
            DetectionResult(
                threat_type="ddos",
                threat_level=threat_level,
                confidence=attack_prob,
                details=f"DDoS 攻击检测：类别={prediction}",
                source_ip=src_ip,
                raw_data=raw_extra,
            )
        )
