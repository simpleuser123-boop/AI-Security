"""
NSL-KDD 41 维与在线 ``network_flow_v1`` 的显式适配（仅原型可信边界）。

可映射字段从在线流统计推导；不可映射字段不得在无审计时当作生产可信输入。
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .feature_schemas import _flatten_network_flow_features

NSL_KDD_FEATURE_COLUMNS: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


# NSL 列名 -> 在线 network_flow_v1 字段名（语义为近似/代理，非 KDD 原始定义）
_MAPPABLE_FROM_FLOW: Dict[str, str] = {
    "duration": "flow_duration",
    # 单向流总字节近似到 src_bytes；dst_bytes 无独立观测
    "src_bytes": "flow_byte_count",
    "count": "flow_pkt_count",
    # 窗口内不同目的端口数，作为 srv_count 的弱代理（验收见文档）
    "srv_count": "window_unique_dst_port",
}

# 显式常量映射（无在线字段，原型下填 0 并审计）
_CONSTANT_ZERO: Dict[str, float] = {
    "land": 0.0,
    "wrong_fragment": 0.0,
    "urgent": 0.0,
    "hot": 0.0,
    "num_failed_logins": 0.0,
    "logged_in": 0.0,
    "num_compromised": 0.0,
    "root_shell": 0.0,
    "su_attempted": 0.0,
    "num_root": 0.0,
    "num_file_creations": 0.0,
    "num_shells": 0.0,
    "num_access_files": 0.0,
    "num_outbound_cmds": 0.0,
    "is_host_login": 0.0,
    "is_guest_login": 0.0,
}

# 训练期 factorize 的类别列：在线无编码表，原型默认 0 并审计
_CATEGORICAL_NSL_NO_ONLINE_ENCODING = frozenset({"protocol_type", "service", "flag"})

# 其余数值列：无可靠在线对应时以 0 填充并审计（KDD 主机统计等）
_UNMAPPED_NUMERIC = [
    c
    for c in NSL_KDD_FEATURE_COLUMNS
    if c not in _MAPPABLE_FROM_FLOW
    and c not in _CONSTANT_ZERO
    and c not in _CATEGORICAL_NSL_NO_ONLINE_ENCODING
]


class NSLKDDAdapter:
    """
    将 ``network_flow_v1`` 扁平特征映射为 NSL-KDD 顺序向量。

    ``mappable_fields`` / ``unmapped_fields`` 用于验收与审计日志。
    """

    MAPPABLE_FIELDS: Dict[str, str] = dict(_MAPPABLE_FROM_FLOW)
    UNMAPPED_FIELDS: List[str] = sorted(
        frozenset(_CONSTANT_ZERO) | _CATEGORICAL_NSL_NO_ONLINE_ENCODING | frozenset(_UNMAPPED_NUMERIC)
    )

    @classmethod
    def describe(cls) -> Dict[str, Any]:
        return {
            "mappable_nsl_to_flow": dict(_MAPPABLE_FROM_FLOW),
            "constant_zero": list(_CONSTANT_ZERO.keys()),
            "categorical_zero_without_encoding": sorted(_CATEGORICAL_NSL_NO_ONLINE_ENCODING),
            "unmapped_numeric_zero": _UNMAPPED_NUMERIC,
        }

    @staticmethod
    def _float(x: Any) -> float:
        try:
            if x is None:
                return 0.0
            return float(x)
        except (TypeError, ValueError):
            return 0.0

    @classmethod
    def build_vector_in_order(
        cls,
        features: Mapping[str, Any],
        feature_columns: Sequence[str],
    ) -> Tuple[List[float], Dict[str, Any]]:
        """
        按 ``feature_columns`` 顺序构造一行 NSL 风格数值向量（用于与训练矩阵对齐）。

        Returns:
            (row, audit) audit 含 ``zero_filled_columns``、``mapped_from_flow``。
        """
        flat = _flatten_network_flow_features(features)
        row: List[float] = []
        zero_filled: List[str] = []
        mapped_from_flow: Dict[str, Any] = {}

        for col in feature_columns:
            if col not in NSL_KDD_FEATURE_COLUMNS:
                raise ValueError(f"未知 NSL 特征列: {col!r}")

            if col in _MAPPABLE_FROM_FLOW:
                src_f = _MAPPABLE_FROM_FLOW[col]
                val = flat.get(src_f)
                num = cls._float(val)
                row.append(num)
                mapped_from_flow[col] = {"from": src_f, "value": num}
                continue

            if col in _CONSTANT_ZERO:
                row.append(float(_CONSTANT_ZERO[col]))
                zero_filled.append(col)
                continue

            if col in _CATEGORICAL_NSL_NO_ONLINE_ENCODING:
                row.append(0.0)
                zero_filled.append(f"{col}(categorical_no_encoder)")
                continue

            row.append(0.0)
            zero_filled.append(f"{col}(kdd_host_stat_unavailable)")

        audit = {
            "adapter": "nsl_kdd_v1",
            "zero_filled_columns": zero_filled,
            "mapped_from_flow": mapped_from_flow,
        }
        return row, audit
