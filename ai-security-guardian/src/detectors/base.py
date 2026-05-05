"""
检测引擎基类与检测结果数据类
对应架构文档 §5.3 检测引擎抽象接口

本模块定义了所有检测引擎的统一数据契约：
    - DetectionResult：单次检测输出的结构化结果
    - BaseDetector：所有检测引擎必须继承的抽象基类

后续 DDoS / 入侵 / Web 攻击 / 异常行为四类检测引擎都基于本模块构建。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DetectionResult:
    """
    单次检测结果。

    Attributes:
        threat_type: 威胁类型，取值范围：
            'ddos' | 'intrusion' | 'web_attack' | 'anomaly' | 'normal'
            融合引擎可能会输出 'A + B' 这种拼接后的复合类型。
        threat_level: 威胁等级，取值范围：
            'low' | 'medium' | 'high' | 'critical'
        confidence: 置信度，区间 [0.0, 1.0]
        details: 对本次检测结果的人类可读文字描述
        source_ip: 触发本次检测的来源 IP，默认空字符串
        raw_data: 原始数据（如特征字典），默认空字典
    """

    threat_type: str
    threat_level: str
    confidence: float
    details: str
    source_ip: str = ""
    raw_data: dict = field(default_factory=dict)


class BaseDetector(ABC):
    """
    检测引擎抽象基类。

    所有具体检测引擎（DDoSDetector / IntrusionDetector /
    WebAttackDetector / AnomalyDetector）必须继承本类并实现
    `detect` 与 `load_model` 方法。

    统一接口的目的是：
        - 让融合决策引擎以统一方式调用所有引擎
        - 让主控制器能够统一进行模型加载、健康检查和容错降级
    """

    @abstractmethod
    def detect(self, features: Any) -> Optional[DetectionResult]:
        """
        对输入特征执行检测。

        Args:
            features: 输入特征，通常为 dict。也可以是模型专属的结构化数据。

        Returns:
            DetectionResult: 检测结果。
            None: 模型未加载或无法判定时返回 None，交由上层容错处理。
        """
        raise NotImplementedError

    @abstractmethod
    def load_model(self, model_path: str) -> None:
        """
        从指定路径加载检测引擎所需的模型文件。

        模型路径必须通过参数传入，禁止在实现中硬编码。

        Args:
            model_path: 模型文件（或目录）的绝对/相对路径。
        """
        raise NotImplementedError

    def clear_ml_state(self) -> None:
        """由 ModelRegistry 在加载失败或重载前清理 ML 状态（规则引擎子类可为空操作）。"""
        return

    @property
    def is_ready(self) -> bool:
        """
        检测引擎是否已就绪。

        子类应根据内部 model / scaler 等状态重写此属性，
        默认返回 True 以兼容无需模型的规则引擎。
        """
        return True
