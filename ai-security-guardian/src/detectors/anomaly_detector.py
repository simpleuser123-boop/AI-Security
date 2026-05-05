"""
异常行为检测引擎
对应架构文档 §5.4.4 异常行为检测

Isolation Forest / Autoencoder 须加载 ``anomaly_if_v1.model_manifest.json``。
生产 tabular：manifest.feature_columns 顺序即推理矩阵列顺序，禁止缺键静默填 0。
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

from .base import BaseDetector, DetectionResult
from .inference_meta import set_inference_meta

logger = logging.getLogger(__name__)


class AnomalyDetector(BaseDetector):
    """异常行为检测引擎（Isolation Forest + Autoencoder）。"""

    _IF_FILENAME = "anomaly_if_v1.pkl"
    _AE_DIRNAME = "anomaly_ae_v1"
    _AE_SCALER_FILENAME = "anomaly_ae_scaler_v1.pkl"
    _AE_THRESHOLD_FILENAME = "anomaly_ae_threshold_v1.pkl"

    _DEFAULT_FEATURE_ORDER: List[str] = [
        "pkt_len_mean",
        "flow_byte_count",
        "flow_pkt_count",
        "window_unique_dst_port",
        "syn_count",
    ]

    _SINGLE_MODEL_SCORE: float = 0.5
    _HIGH_SCORE_THRESHOLD: float = 0.7

    def __init__(self) -> None:
        self.if_model = None
        self.ae_model = None
        self.ae_scaler = None
        self.ae_threshold: Optional[float] = None
        self._manifest: Optional[ModelManifest] = None
        self._feature_order: List[str] = list(self._DEFAULT_FEATURE_ORDER)

    def clear_ml_state(self) -> None:
        self.if_model = None
        self.ae_model = None
        self.ae_scaler = None
        self.ae_threshold = None
        self._manifest = None
        self._feature_order = list(self._DEFAULT_FEATURE_ORDER)

    def load_model(self, model_path: str) -> None:
        self.clear_ml_state()
        try:
            ap, manifest = resolve_model_entry(model_path)
        except ManifestLoadError as exc:
            logger.error("[AUDIT] Anomaly 模型拒绝加载（manifest 无效）: %s", exc)
            raise

        if manifest.model_input_mode != "tabular":
            raise ManifestLoadError("AnomalyDetector 仅支持 model_input_mode=tabular")

        model_dir = os.path.dirname(ap)

        if_path = os.path.join(model_dir, self._IF_FILENAME)
        if_model = None
        if os.path.exists(if_path):
            if_model = joblib.load(if_path)
            n_if = getattr(if_model, "n_features_in_", len(manifest.feature_columns))
            if int(n_if) != len(manifest.feature_columns):
                raise ManifestLoadError(
                    f"IF n_features_in_={n_if} 与 manifest 列数 {len(manifest.feature_columns)} 不一致"
                )
            logger.info("[AnomalyDetector] Isolation Forest 加载成功: %s", if_path)
        else:
            logger.warning("[AnomalyDetector] 未找到 Isolation Forest 模型: %s", if_path)

        ae_dir = os.path.join(model_dir, self._AE_DIRNAME)
        ae_scaler_path = os.path.join(model_dir, self._AE_SCALER_FILENAME)
        ae_threshold_path = os.path.join(model_dir, self._AE_THRESHOLD_FILENAME)
        ae_model = None
        ae_scaler = None
        ae_threshold: Optional[float] = None
        if (
            os.path.exists(ae_dir)
            and os.path.exists(ae_scaler_path)
            and os.path.exists(ae_threshold_path)
        ):
            import tensorflow as tf  # noqa: WPS433

            ae_model = tf.keras.models.load_model(ae_dir)
            ae_scaler = joblib.load(ae_scaler_path)
            ae_threshold = float(joblib.load(ae_threshold_path))
            logger.info(
                "[AnomalyDetector] Autoencoder 加载成功: %s (threshold=%.6f)",
                ae_dir,
                ae_threshold,
            )
        else:
            logger.warning("[AnomalyDetector] 未找到 Autoencoder 模型文件")

        self._manifest = manifest
        self._feature_order = list(manifest.feature_columns)
        self.if_model = if_model
        self.ae_model = ae_model
        self.ae_scaler = ae_scaler
        self.ae_threshold = ae_threshold

    @property
    def is_ready(self) -> bool:
        return self.if_model is not None or self.ae_model is not None

    def detect(self, features: Dict) -> Optional[DetectionResult]:
        t0 = time.perf_counter()

        def finish(res: Optional[DetectionResult]) -> Optional[DetectionResult]:
            return set_inference_meta(
                res,
                engine="AnomalyDetector",
                manifest=self._manifest,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not self.is_ready:
            logger.debug("[AnomalyDetector] 双模型均未加载，返回 None")
            return finish(None)

        m = self._manifest
        src_ip = str(features.get("src_ip", "") or "").strip()
        if not src_ip:
            nf = features.get("network_flow_v1")
            if isinstance(nf, dict):
                src_ip = str(nf.get("src_ip", "") or "").strip()

        if m is not None:
            ok_schema, schema_errs = validate_payload_against_schema(
                "network_flow_v1", features
            )
            if not ok_schema:
                logger.warning(
                    "[AUDIT] Anomaly network_flow_v1 契约失败: %s ip=%s",
                    schema_errs,
                    src_ip,
                )
                return finish(
                    ml_degraded_normal(
                        engine="AnomalyDetector",
                        reason="network_flow_v1 契约失败: " + "; ".join(schema_errs),
                        source_ip=src_ip,
                        extra={"schema_errors": schema_errs},
                    )
                )

        order = self._feature_order if m is not None else self._DEFAULT_FEATURE_ORDER

        if m is not None and m.trust_tier != "production":
            logger.warning("[AUDIT] Anomaly 仅支持 trust_tier=production（拒绝 NSL 原型混淆）")
            return finish(
                ml_degraded_normal(
                    engine="AnomalyDetector",
                    reason="manifest trust_tier 必须为 production",
                    source_ip=src_ip,
                )
            )

        if m is not None:
            ok_keys, missing = production_tabular_keys_present(order, features)
            if not ok_keys:
                logger.warning(
                    "[AUDIT] Anomaly 生产 ML 缺字段: %s ip=%s", missing, src_ip
                )
                return finish(
                    ml_degraded_normal(
                        engine="AnomalyDetector",
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

        if m is not None:
            feature_values = [float(flat[k]) for k in order]
        else:
            # 单测直接注入子模型、未走 load_model 时无 manifest
            feature_values = [float(flat.get(k, 0) or 0) for k in self._DEFAULT_FEATURE_ORDER]
        X = np.array([feature_values], dtype=np.float32)

        anomaly_score = 0.0
        model_hits: List[str] = []

        if self.if_model is not None:
            try:
                if_pred = self.if_model.predict(X)[0]
                if int(if_pred) == -1:
                    anomaly_score += self._SINGLE_MODEL_SCORE
                    model_hits.append("IsolationForest")
            except Exception as exc:
                logger.error("[AnomalyDetector] IsolationForest 推理失败: %s", exc)

        if (
            self.ae_model is not None
            and self.ae_scaler is not None
            and self.ae_threshold is not None
        ):
            try:
                X_scaled = self.ae_scaler.transform(X)
                reconstruction = self.ae_model.predict(X_scaled, verbose=0)
                mse = float(np.mean(np.power(X_scaled - reconstruction, 2), axis=1)[0])
                if mse > self.ae_threshold:
                    anomaly_score += self._SINGLE_MODEL_SCORE
                    model_hits.append(f"Autoencoder(mse={mse:.6f})")
            except Exception as exc:
                logger.error("[AnomalyDetector] Autoencoder 推理失败: %s", exc)

        if anomaly_score <= 0:
            return finish(
                DetectionResult(
                    threat_type="normal",
                    threat_level="low",
                    confidence=0.9,
                    details="异常检测：行为正常",
                    source_ip=src_ip,
                    raw_data={"anomaly_score": 0.0},
                )
            )

        threat_level = "high" if anomaly_score > self._HIGH_SCORE_THRESHOLD else "medium"
        confidence = min(anomaly_score, 1.0)
        details = (
            f"异常行为检测：综合异常分数={anomaly_score:.2f}，"
            f"命中模型=[{', '.join(model_hits)}]"
        )
        logger.info(
            "[AnomalyDetector] 检出异常 score=%.2f level=%s hits=%s ip=%s",
            anomaly_score,
            threat_level,
            model_hits,
            src_ip,
        )
        return finish(
            DetectionResult(
                threat_type="anomaly",
                threat_level=threat_level,
                confidence=confidence,
                details=details,
                source_ip=src_ip,
                raw_data={"anomaly_score": anomaly_score, "hits": model_hits},
            )
        )
