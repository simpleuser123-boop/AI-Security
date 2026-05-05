"""
网络入侵检测引擎
对应架构文档 §5.4.2 入侵检测

须加载 ``*.model_manifest.json``；feature_columns 须与磁盘上的
intrusion_feature_cols_v1.pkl 完全一致（顺序敏感）。
NSL-KDD 原型策略与 DDoS 相同，禁止无清单上线。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Dict, List, Optional

import joblib
import numpy as np

from src.schema.feature_schemas import (
    production_tabular_keys_present,
    validate_payload_against_schema,
)
from src.schema.inference_guard import ml_degraded_normal
from src.schema.manifest import ManifestLoadError, ModelManifest, resolve_model_entry
from src.schema.nsl_kdd_adapter import NSLKDDAdapter

from .base import BaseDetector, DetectionResult
from .inference_meta import set_inference_meta

logger = logging.getLogger(__name__)


class IntrusionDetector(BaseDetector):
    """网络入侵检测引擎（CNN+LSTM / 随机森林双模式）。"""

    _THREAT_LEVEL_MAP = {
        "dos": "high",
        "probe": "medium",
        "r2l": "high",
        "u2r": "critical",
    }

    _SCALER_FILENAME = "intrusion_scaler_v1.pkl"
    _LABEL_ENCODER_FILENAME = "intrusion_label_encoder_v1.pkl"
    _FEATURE_COLS_FILENAME = "intrusion_feature_cols_v1.pkl"

    def __init__(self, use_deep_learning: bool = False) -> None:
        self.use_deep_learning = use_deep_learning
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns: Optional[List[str]] = None
        self._manifest: Optional[ModelManifest] = None

    def clear_ml_state(self) -> None:
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = None
        self._manifest = None

    def load_model(self, model_path: str) -> None:
        self.clear_ml_state()
        try:
            ap, manifest = resolve_model_entry(model_path)
        except ManifestLoadError as exc:
            logger.error("[AUDIT] Intrusion 模型拒绝加载（manifest 无效）: %s", exc)
            raise
        model_dir = os.path.dirname(ap)

        if self.use_deep_learning:
            import tensorflow as tf  # noqa: WPS433

            model = tf.keras.models.load_model(ap)
            logger.info("[IntrusionDetector] CNN+LSTM 模型加载成功: %s", ap)
        else:
            model = joblib.load(ap)
            logger.info("[IntrusionDetector] 随机森林模型加载成功: %s", ap)

        scaler = joblib.load(os.path.join(model_dir, self._SCALER_FILENAME))
        label_encoder = joblib.load(
            os.path.join(model_dir, self._LABEL_ENCODER_FILENAME)
        )
        disk_cols: List[str] = joblib.load(
            os.path.join(model_dir, self._FEATURE_COLS_FILENAME)
        )
        if disk_cols != manifest.feature_columns:
            raise ManifestLoadError(
                "manifest.feature_columns 与 intrusion_feature_cols_v1.pkl 不一致（顺序须完全相同）"
            )
        self.model = model
        self.scaler = scaler
        self.label_encoder = label_encoder
        self.feature_columns = list(manifest.feature_columns)
        self._manifest = manifest
        logger.info(
            "[IntrusionDetector] manifest 与配套文件校验通过 trust_tier=%s",
            manifest.trust_tier,
        )

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None and self._manifest is not None

    def detect(self, features: Dict) -> Optional[DetectionResult]:
        t0 = time.perf_counter()

        def finish(res: Optional[DetectionResult]) -> Optional[DetectionResult]:
            return set_inference_meta(
                res,
                engine="IntrusionDetector",
                manifest=self._manifest,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not self.is_ready or self.feature_columns is None or self._manifest is None:
            logger.debug("[IntrusionDetector] 引擎未就绪，返回 None")
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
                "[AUDIT] Intrusion network_flow_v1 契约失败: %s ip=%s",
                schema_errs,
                src_ip,
            )
            return finish(
                ml_degraded_normal(
                    engine="IntrusionDetector",
                    reason="network_flow_v1 契约失败: " + "; ".join(schema_errs),
                    source_ip=src_ip,
                    extra={"schema_errors": schema_errs},
                )
            )

        if m.trust_tier == "production" and m.adapter is None:
            ok_keys, missing = production_tabular_keys_present(
                self.feature_columns, features
            )
            if not ok_keys:
                logger.warning(
                    "[AUDIT] Intrusion 生产 ML 缺字段: %s ip=%s", missing, src_ip
                )
                return finish(
                    ml_degraded_normal(
                        engine="IntrusionDetector",
                        reason="在线特征缺字段: " + ", ".join(missing),
                        source_ip=src_ip,
                        extra={"missing_columns": missing},
                    )
                )
            flat: Dict = dict(features)
            nf = features.get("network_flow_v1")
            if isinstance(nf, dict):
                for k, v in nf.items():
                    if k not in ("schema_name", "schema_version", "schema"):
                        flat.setdefault(k, v)
            feature_vector = [float(flat[c]) for c in self.feature_columns]
        elif m.trust_tier == "prototype_nsl_kdd" and m.adapter == "nsl_kdd_v1":
            vec, audit = NSLKDDAdapter.build_vector_in_order(features, self.feature_columns)
            if audit.get("zero_filled_columns"):
                logger.warning(
                    "[AUDIT] Intrusion NSL-KDD 原型推理 zero_fill=%s ip=%s",
                    audit["zero_filled_columns"],
                    src_ip,
                )
            feature_vector = vec
        else:
            return finish(
                ml_degraded_normal(
                    engine="IntrusionDetector",
                    reason="manifest trust_tier/adapter 不受支持",
                    source_ip=src_ip,
                )
            )

        X = np.array([feature_vector], dtype=np.float32)

        try:
            X_scaled = self.scaler.transform(X)
        except Exception as exc:
            logger.error("[IntrusionDetector] 特征标准化失败: %s", exc)
            return finish(None)

        try:
            if self.use_deep_learning:
                X_reshaped = X_scaled.reshape(1, 1, X_scaled.shape[1])
                probabilities = self.model.predict(X_reshaped, verbose=0)[0]
                pred_idx = int(np.argmax(probabilities))
                prediction = self.label_encoder.inverse_transform([pred_idx])[0]
                confidence = float(probabilities[pred_idx])
            else:
                raw_prediction = self.model.predict(X_scaled)[0]
                probabilities = self.model.predict_proba(X_scaled)[0]
                if isinstance(raw_prediction, (int, np.integer)):
                    pred_idx = int(raw_prediction)
                    prediction = self.label_encoder.inverse_transform([pred_idx])[0]
                else:
                    prediction = str(raw_prediction)
                    pred_idx = list(self.model.classes_).index(raw_prediction)
                confidence = float(probabilities[pred_idx])
        except Exception as exc:
            logger.error("[IntrusionDetector] 模型推理失败: %s", exc)
            return finish(None)

        raw_data: Dict = {"prediction": str(prediction)}
        if m.trust_tier == "prototype_nsl_kdd":
            raw_data["trust_tier"] = m.trust_tier

        if str(prediction).lower() == "normal":
            return finish(
                DetectionResult(
                    threat_type="normal",
                    threat_level="low",
                    confidence=confidence,
                    details="入侵检测：正常网络行为",
                    source_ip=src_ip,
                    raw_data=raw_data,
                )
            )

        threat_level = self._THREAT_LEVEL_MAP.get(str(prediction).lower(), "medium")
        logger.info(
            "[IntrusionDetector] 检出入侵 class=%s confidence=%.4f level=%s ip=%s",
            prediction,
            confidence,
            threat_level,
            src_ip,
        )
        return finish(
            DetectionResult(
                threat_type="intrusion",
                threat_level=threat_level,
                confidence=confidence,
                details=f"入侵检测：类别={prediction}",
                source_ip=src_ip,
                raw_data=raw_data,
            )
        )
