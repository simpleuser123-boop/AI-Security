"""
特征工程模块
对应架构文档 §4
"""
from .flow_features import FlowFeatureExtractor
from .flow_window_aggregator import (
    FlowWindowAggregator,
    FlowWindowAggregatorConfig,
    FlowWindowAggregatorCounters,
)
from .web_features import WebFeatureExtractor
from .pipeline import FeaturePipeline

__all__ = [
    'FlowFeatureExtractor',
    'FlowWindowAggregator',
    'FlowWindowAggregatorConfig',
    'FlowWindowAggregatorCounters',
    'WebFeatureExtractor',
    'FeaturePipeline',
]
