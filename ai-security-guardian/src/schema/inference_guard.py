"""ML 推理降级结果构造（统一写入 raw_data 供融合/审计）。"""
from __future__ import annotations

from typing import Any, Dict, Optional

from src.detectors.base import DetectionResult


def ml_degraded_normal(
    *,
    engine: str,
    reason: str,
    source_ip: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> DetectionResult:
    return DetectionResult(
        threat_type="normal",
        threat_level="low",
        confidence=0.0,
        details=f"{engine} ML 降级：{reason}",
        source_ip=source_ip or "",
        raw_data={
            "ml_degraded": True,
            "engine": engine,
            "reason": reason,
            **(extra or {}),
        },
    )
