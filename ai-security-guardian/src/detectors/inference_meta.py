"""为检测结果附加推理可观测字段（engine / model_version / schema_version / latency_ms）。"""
from __future__ import annotations

from typing import Optional

from src.detectors.base import DetectionResult
from src.schema.manifest import ModelManifest


def set_inference_meta(
    result: Optional[DetectionResult],
    *,
    engine: str,
    manifest: Optional[ModelManifest],
    latency_ms: float,
    model_version: Optional[str] = None,
    schema_version: Optional[str] = None,
) -> Optional[DetectionResult]:
    """
    写入 ``raw_data['_inference']``：engine、model_version、schema_version、
    confidence（与 DetectionResult.confidence 一致）、latency_ms。
    """
    if result is None:
        return None
    mv = (
        model_version
        if model_version is not None
        else (manifest.version if manifest is not None else "none")
    )
    sv = (
        schema_version
        if schema_version is not None
        else (manifest.schema_version if manifest is not None else "")
    )
    result.raw_data["_inference"] = {
        "engine": engine,
        "model_version": mv,
        "schema_version": sv,
        "confidence": float(result.confidence),
        "latency_ms": round(float(latency_ms), 3),
    }
    return result
