"""
src.detectors 包初始化
对应架构文档 §5 威胁检测层

导出常用的检测结果数据类和检测引擎基类，便于其他模块直接从 `src.detectors` 导入。
"""
from .base import BaseDetector, DetectionResult

__all__ = [
    "BaseDetector",
    "DetectionResult",
]
