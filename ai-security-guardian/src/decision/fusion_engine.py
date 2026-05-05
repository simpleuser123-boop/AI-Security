"""
多模型融合决策引擎
对应架构文档 §5.5 融合决策层

核心职责：
    1. 接收多个检测引擎的结果列表，过滤掉空结果与 normal 结果。
    2. 以威胁等级作为权重，对置信度进行加权融合。
    3. 取最高威胁等级作为基础等级。
    4. 多引擎联动升级：当 2 个或以上引擎同时报警时，
       威胁等级自动升级（low→medium→high→critical）。
    5. 输出单个融合后的 DetectionResult，details 字段包含所有引擎的诊断信息。
"""
from __future__ import annotations

import logging
from typing import List, Optional

from ..detectors.base import DetectionResult

logger = logging.getLogger(__name__)


class FusionEngine:
    """多引擎融合决策。"""

    # 威胁等级权重
    LEVEL_WEIGHTS = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
    }

    # 等级升级映射
    LEVEL_UPGRADE = {
        "low": "medium",
        "medium": "high",
        "high": "critical",
        "critical": "critical",  # 已是最高等级
    }

    def fuse(self, results: List[Optional[DetectionResult]]) -> DetectionResult:
        """
        对多个检测引擎的结果进行融合。

        Args:
            results: 各检测引擎返回的 DetectionResult 列表，
                     允许包含 None（未就绪）或 threat_type=='normal' 的条目。

        Returns:
            融合后的 DetectionResult。若无有效威胁则返回 normal 结果。
        """
        valid_results: List[DetectionResult] = [
            r for r in results if r is not None and r.threat_type != "normal"
        ]

        if not valid_results:
            return DetectionResult(
                threat_type="normal",
                threat_level="low",
                confidence=1.0,
                details="所有引擎判定为正常",
                source_ip="",
                raw_data={"engine_count": len([r for r in results if r is not None])},
            )

        # 加权融合置信度
        total_weight = 0.0
        weighted_confidence = 0.0
        threat_types = []
        seen_types = set()

        for r in valid_results:
            weight = self.LEVEL_WEIGHTS.get(r.threat_level, 0.5)
            total_weight += weight
            weighted_confidence += r.confidence * weight
            if r.threat_type not in seen_types:
                seen_types.add(r.threat_type)
                threat_types.append(r.threat_type)

        fused_confidence = (
            weighted_confidence / total_weight if total_weight > 0 else 0.0
        )
        fused_confidence = min(max(fused_confidence, 0.0), 1.0)

        # 取最高威胁等级
        highest = max(
            valid_results,
            key=lambda r: self.LEVEL_WEIGHTS.get(r.threat_level, 0.0),
        )
        base_level = highest.threat_level

        # 多引擎联动升级
        if len(valid_results) >= 2:
            final_level = self.LEVEL_UPGRADE.get(base_level, base_level)
            upgrade_note = (
                f"；多引擎联动升级 {base_level}→{final_level}"
                if final_level != base_level
                else ""
            )
        else:
            final_level = base_level
            upgrade_note = ""

        details_parts = [r.details for r in valid_results]
        details = (
            f"融合 {len(valid_results)} 个引擎结果："
            + " | ".join(details_parts)
            + upgrade_note
        )

        source_ip = next(
            (r.source_ip for r in valid_results if r.source_ip), highest.source_ip
        )

        logger.info(
            "[FusionEngine] 融合完成 engines=%d level=%s→%s confidence=%.4f",
            len(valid_results),
            base_level,
            final_level,
            fused_confidence,
        )

        return DetectionResult(
            threat_type=" + ".join(threat_types),
            threat_level=final_level,
            confidence=round(fused_confidence, 4),
            details=details,
            source_ip=source_ip,
            raw_data={
                "engine_count": len(valid_results),
                "base_level": base_level,
                "upgraded": final_level != base_level,
                "sub_results": [
                    {
                        "threat_type": r.threat_type,
                        "threat_level": r.threat_level,
                        "confidence": r.confidence,
                        "source_ip": r.source_ip,
                    }
                    for r in valid_results
                ],
            },
        )
