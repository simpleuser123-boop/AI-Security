"""
版本化特征 schema 定义与运行时校验。

契约 JSON 位于同目录 ``json/*.json``，供训练 / 在线 / 审计引用同一来源。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Set, Tuple

_SCHEMA_DIR = Path(__file__).resolve().parent / "json"

SCHEMA_IDS: Tuple[str, ...] = (
    "network_flow_v1",
    "web_request_v1",
    "system_behavior_v1",
    "ioc_match_v1",
)


def _load_schema_doc(schema_id: str) -> dict:
    if schema_id not in SCHEMA_IDS:
        raise KeyError(f"未知 schema_id: {schema_id}，已知: {SCHEMA_IDS}")
    path = _SCHEMA_DIR / f"{schema_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"缺少 schema 文件: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _flatten_web_features(features: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(features)
    wr = features.get("web_request_v1")
    if isinstance(wr, dict):
        for k, v in wr.items():
            if k == "schema":
                continue
            out.setdefault(k, v)
    if "url" not in out or out.get("url") in (None, ""):
        raw = out.get("url_raw")
        if raw is not None:
            out["url"] = raw
    if "method" not in out or out.get("method") in (None, ""):
        m = features.get("http_method") or features.get("method")
        if m is not None:
            out["method"] = str(m).upper()
    return out


def _flatten_network_flow_features(features: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(features)
    nf = features.get("network_flow_v1")
    if isinstance(nf, dict):
        for k, v in nf.items():
            if k in ("schema_name", "schema_version", "schema"):
                continue
            out.setdefault(k, v)
    return out


def validate_payload_against_schema(
    schema_id: str,
    payload: Mapping[str, Any],
) -> Tuple[bool, List[str]]:
    """
    校验 payload 是否满足 schema 的 required_fields（禁止静默视为合规）。

    Returns:
        (ok, reasons) — ok 为 False 时 reasons 为人类可读原因列表。
    """
    doc = _load_schema_doc(schema_id)
    required: Mapping[str, Any] = doc.get("required_fields") or {}

    if schema_id == "web_request_v1":
        flat = _flatten_web_features(payload)
    elif schema_id == "network_flow_v1":
        flat = _flatten_network_flow_features(payload)
    else:
        flat = dict(payload)

    errors: List[str] = []
    for field, spec in required.items():
        policy = (spec or {}).get("policy", "forbid_silent_fill")
        if field not in flat:
            errors.append(f"缺少必填字段 {field!r}（policy={policy}）")
            continue
        val = flat[field]
        if val is None:
            errors.append(f"必填字段 {field!r} 为 null（禁止静默填充）")
            continue
        if field.endswith("_ip") or spec.get("type") == "string":
            if isinstance(val, str) and val.strip() == "":
                errors.append(f"必填字段 {field!r} 为空串（禁止静默填充）")
        if spec.get("type") == "number" and isinstance(val, str):
            errors.append(f"必填字段 {field!r} 类型应为 number，实际为 str")

    return (len(errors) == 0, errors)


def attach_network_flow_v1_block(feat: MutableMapping[str, Any]) -> None:
    """在流特征字典上附加 ``network_flow_v1`` 契约块（就地修改）。"""
    keys = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
        "flow_pkt_count",
        "flow_byte_count",
        "flow_duration",
        "flow_pkt_rate",
        "flow_byte_rate",
        "window_unique_dst_ip",
        "window_unique_dst_port",
        "window_protocol_dist",
        "pkt_len_mean",
        "pkt_len_std",
        "pkt_len_max",
        "pkt_len_min",
        "syn_count",
        "ack_count",
        "fin_count",
        "rst_count",
        "flow_low_confidence",
    ]
    block: Dict[str, Any] = {"schema_name": "network_flow_v1", "schema_version": "1"}
    for k in keys:
        if k in feat:
            block[k] = feat[k]
    feat["network_flow_v1"] = block


def production_tabular_keys_present(
    feature_columns: List[str],
    features: Mapping[str, Any],
) -> Tuple[bool, List[str]]:
    """
    生产可信 tabular 推理：``feature_columns`` 每个键必须出现在 features 中且值非 None。

    禁止用 0 填充缺失键冒充合规。
    """
    flat = _flatten_network_flow_features(features)
    missing: List[str] = []
    for col in feature_columns:
        if col not in flat:
            missing.append(col)
            continue
        if flat[col] is None:
            missing.append(f"{col}(null)")
    return (len(missing) == 0, missing)
