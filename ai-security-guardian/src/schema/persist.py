"""训练侧写入 ``*.model_manifest.json``。"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from .manifest import manifest_path_for_model_file


def write_model_manifest(
    model_path: str,
    *,
    model_name: str,
    version: str,
    schema_name: str,
    schema_version: str,
    feature_columns: List[str],
    training_dataset: str,
    metrics: Mapping[str, Any],
    artifact_files: Mapping[str, str],
    training_data_description: Optional[str] = None,
    created_at: Optional[str] = None,
    published_at: Optional[str] = None,
    evaluation_report: Optional[Mapping[str, Any]] = None,
    trust_tier: str = "production",
    adapter: Optional[str] = None,
    model_input_mode: str = "tabular",
    extra: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    写入 ``{stem}.model_manifest.json`` 到模型同目录。

    Returns:
        写入的 manifest 绝对路径。
    """
    timestamp = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload: Dict[str, Any] = {
        "model_name": model_name,
        "version": version,
        "schema_name": schema_name,
        "schema_version": schema_version,
        "feature_columns": list(feature_columns),
        "training_dataset": training_dataset,
        "training_data_description": training_data_description
        or f"Training data source: {training_dataset}",
        "metrics": dict(metrics),
        "created_at": timestamp,
        "published_at": published_at or timestamp,
        "artifact_files": dict(artifact_files),
        "trust_tier": trust_tier,
        "model_input_mode": model_input_mode,
    }
    if evaluation_report is not None:
        payload["evaluation_report"] = dict(evaluation_report)
    if adapter is not None:
        payload["adapter"] = adapter
    if extra:
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v

    out = manifest_path_for_model_file(model_path)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return out
