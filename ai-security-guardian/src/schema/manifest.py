"""
model_manifest.json 规范与加载校验。

与模型同名的清单文件：``{model_stem}.model_manifest.json``（与 .pkl 同目录）。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

REQUIRED_MANIFEST_KEYS: tuple[str, ...] = (
    "model_name",
    "version",
    "schema_name",
    "schema_version",
    "feature_columns",
    "training_dataset",
    "training_data_description",
    "metrics",
    "created_at",
    "published_at",
    "artifact_files",
    "evaluation_report",
)

ALLOWED_TRUST_TIERS = frozenset({"production", "prototype_nsl_kdd"})
ALLOWED_INPUT_MODES = frozenset({"tabular", "text_sklearn_pipeline"})


class ManifestLoadError(ValueError):
    """清单缺失、字段非法或与模型不一致。"""


@dataclass
class ModelManifest:
    """已校验的模型清单（可信边界元数据）。"""

    model_name: str
    version: str
    schema_name: str
    schema_version: str
    feature_columns: List[str]
    training_dataset: str
    training_data_description: str
    metrics: Dict[str, Any]
    created_at: str
    published_at: str
    artifact_files: Dict[str, str]
    trust_tier: str = "production"
    adapter: Optional[str] = None
    model_input_mode: str = "tabular"
    raw: Dict[str, Any] = field(default_factory=dict)


def manifest_path_for_model_file(model_path: str) -> str:
    p = Path(os.path.abspath(model_path))
    return str(p.parent / f"{p.stem}.model_manifest.json")


def load_manifest_for_model_path(model_path: str) -> ModelManifest:
    mpath = manifest_path_for_model_file(model_path)
    if not os.path.isfile(mpath):
        raise ManifestLoadError(f"缺少模型清单（拒绝静默上线）: {mpath}")
    with open(mpath, encoding="utf-8") as f:
        data = json.load(f)
    return validate_manifest_dict(data, model_path=model_path, manifest_path=mpath)


VERSION_MANIFEST_NAME = "manifest.json"


def _infer_primary_artifact_basename(
    data: Mapping[str, Any], version_dir: str
) -> str:
    """从版本目录 ``manifest.json`` 解析主权重文件名（须与 artifact_files 一致）。"""
    pa = data.get("primary_artifact")
    if isinstance(pa, str) and pa.strip():
        return os.path.basename(pa.strip().replace("\\", "/"))

    arts = data.get("artifact_files")
    if not isinstance(arts, dict):
        raise ManifestLoadError("artifact_files 非法")

    for key in ("model", "primary", "weights", "pipeline"):
        rel = arts.get(key)
        if isinstance(rel, str) and rel and not rel.endswith(("/", "\\")):
            base = os.path.basename(rel)
            ap = os.path.normpath(os.path.join(version_dir, rel))
            if os.path.isfile(ap):
                return base

    for cand in ("model.pkl", "pipeline.pkl"):
        ap = os.path.join(version_dir, cand)
        if not os.path.isfile(ap):
            continue
        for rel in arts.values():
            if not isinstance(rel, str) or not rel:
                continue
            if os.path.basename(rel) == cand and os.path.isfile(
                os.path.normpath(os.path.join(version_dir, rel))
            ):
                return cand

    raise ManifestLoadError(
        "版本目录 manifest 无法解析主 artifact；请在 manifest.json 增加 "
        "\"primary_artifact\": \"model.pkl\" 或在 artifact_files 中声明 model/pipeline"
    )


def load_manifest_from_version_dir(version_dir: str) -> tuple[str, ModelManifest]:
    """
    从 ``<version_dir>/manifest.json`` 加载并校验，返回 ``(主模型绝对路径, ModelManifest)``。

    目录布局示例：``models/saved/ddos/v1/manifest.json`` + ``model.pkl``。
    """
    vd = os.path.abspath(version_dir)
    if not os.path.isdir(vd):
        raise ManifestLoadError(f"版本目录不存在: {vd}")
    mpath = os.path.join(vd, VERSION_MANIFEST_NAME)
    if not os.path.isfile(mpath):
        raise ManifestLoadError(f"缺少 {VERSION_MANIFEST_NAME}: {mpath}")
    with open(mpath, encoding="utf-8") as f:
        data = json.load(f)
    base = _infer_primary_artifact_basename(data, vd)
    model_path = os.path.join(vd, base)
    if not os.path.isfile(model_path):
        raise ManifestLoadError(f"主模型文件不存在: {model_path}")
    return model_path, validate_manifest_dict(
        data, model_path=model_path, manifest_path=mpath
    )


def resolve_model_entry(model_path: str) -> tuple[str, ModelManifest]:
    """
    统一入口：``model_path`` 为 ``.pkl`` 文件（旧式，同目录 ``*.model_manifest.json``）
    或为版本目录（内含 ``manifest.json``）。
    """
    ap = os.path.abspath(model_path)
    if os.path.isdir(ap):
        return load_manifest_from_version_dir(ap)
    if not os.path.isfile(ap):
        raise FileNotFoundError(ap)
    return ap, load_manifest_for_model_path(ap)


def validate_manifest_dict(
    data: Mapping[str, Any],
    *,
    model_path: str,
    manifest_path: str,
) -> ModelManifest:
    missing = [k for k in REQUIRED_MANIFEST_KEYS if k not in data]
    if missing:
        raise ManifestLoadError(f"manifest 缺键: {missing} ({manifest_path})")

    fc = data["feature_columns"]
    if not isinstance(fc, list) or not fc:
        raise ManifestLoadError("feature_columns 必须为非空 list")
    if not all(isinstance(x, str) and x for x in fc):
        raise ManifestLoadError("feature_columns 必须全为非空字符串")

    artifacts = data["artifact_files"]
    if not isinstance(artifacts, dict) or not artifacts:
        raise ManifestLoadError("artifact_files 必须为非空 object")

    trust = str(data.get("trust_tier", "production"))
    if trust not in ALLOWED_TRUST_TIERS:
        raise ManifestLoadError(f"非法 trust_tier: {trust}")

    mode = str(data.get("model_input_mode", "tabular"))
    if mode not in ALLOWED_INPUT_MODES:
        raise ManifestLoadError(f"非法 model_input_mode: {mode}")

    metrics = data["metrics"]
    if not isinstance(metrics, dict):
        raise ManifestLoadError("metrics 必须为 object")
    _validate_evaluation_metrics(metrics, "metrics", manifest_path)

    eval_report = data["evaluation_report"]
    if not isinstance(eval_report, dict):
        raise ManifestLoadError("evaluation_report 必须为 object")
    _validate_evaluation_report(eval_report, data, manifest_path)

    model_dir = os.path.dirname(os.path.abspath(model_path))
    model_base = os.path.basename(model_path)
    # 主权重文件必须在 artifact_files 中显式声明且 basename 一致
    primary = None
    for _k, rel in artifacts.items():
        if not isinstance(rel, str) or not rel:
            continue
        if os.path.basename(rel) == model_base:
            primary = rel
            break
    if primary is None:
        raise ManifestLoadError(
            f"artifact_files 必须包含指向主模型文件的条目（basename={model_base!r}）"
        )
    abs_primary = os.path.normpath(os.path.join(model_dir, primary))
    if not os.path.isfile(abs_primary):
        raise ManifestLoadError(f"artifact 主文件路径无效: {abs_primary}")
    if os.path.abspath(abs_primary) != os.path.abspath(model_path):
        raise ManifestLoadError(
            f"manifest 主模型路径与 load_model 参数不一致: {abs_primary} != {model_path}"
        )

    for key, rel in artifacts.items():
        if not isinstance(rel, str) or not rel:
            raise ManifestLoadError(f"artifact_files[{key!r}] 非法")
        ap = os.path.normpath(os.path.join(model_dir, rel))
        if rel.endswith(("/", "\\")) or os.path.isdir(ap):
            continue
        if not os.path.isfile(ap):
            raise ManifestLoadError(f"artifact 不存在: {key} -> {ap}")

    m = ModelManifest(
        model_name=str(data["model_name"]),
        version=str(data["version"]),
        schema_name=str(data["schema_name"]),
        schema_version=str(data["schema_version"]),
        feature_columns=list(fc),
        training_dataset=str(data["training_dataset"]),
        training_data_description=str(data["training_data_description"]),
        metrics=dict(metrics),
        created_at=str(data["created_at"]),
        published_at=str(data["published_at"]),
        artifact_files={str(k): str(v) for k, v in artifacts.items()},
        trust_tier=trust,
        adapter=(None if data.get("adapter") in (None, "") else str(data["adapter"])),
        model_input_mode=mode,
        raw=dict(data),
    )

    if m.schema_name not in {
        "network_flow_v1",
        "web_request_v1",
        "system_behavior_v1",
        "ioc_match_v1",
    }:
        raise ManifestLoadError(f"未知 schema_name: {m.schema_name}")

    if m.trust_tier == "production" and m.model_input_mode == "tabular":
        from .nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS

        if set(m.feature_columns) == set(NSL_KDD_FEATURE_COLUMNS):
            raise ManifestLoadError(
                "feature_columns 为 NSL-KDD 41 维但 trust_tier=production。"
                "NSL-KDD 与在线 network_flow_v1 不对齐，请将 trust_tier 设为 "
                "'prototype_nsl_kdd' 并设置 adapter='nsl_kdd_v1'，或改用生产 schema 重训。"
            )

    if m.trust_tier == "prototype_nsl_kdd":
        from .nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS

        if set(m.feature_columns) != set(NSL_KDD_FEATURE_COLUMNS):
            raise ManifestLoadError(
                "prototype_nsl_kdd 要求 feature_columns 与 NSL-KDD 41 维集合一致"
            )
        if len(m.feature_columns) != len(NSL_KDD_FEATURE_COLUMNS):
            raise ManifestLoadError(
                "prototype_nsl_kdd 要求 feature_columns 长度等于 41"
            )
        if m.adapter != "nsl_kdd_v1":
            raise ManifestLoadError("prototype_nsl_kdd 必须 adapter=nsl_kdd_v1")
        if m.schema_name != "network_flow_v1":
            raise ManifestLoadError(
                "prototype_nsl_kdd 期望 schema_name=network_flow_v1（在线流入口契约）"
            )

    return m


def _validate_evaluation_metrics(
    metrics: Mapping[str, Any],
    field_name: str,
    manifest_path: str,
) -> None:
    from .evaluation import REQUIRED_EVALUATION_METRICS

    missing = [k for k in REQUIRED_EVALUATION_METRICS if k not in metrics]
    if missing:
        raise ManifestLoadError(f"{field_name} 缺少评估指标 {missing}: {manifest_path}")
    for key in REQUIRED_EVALUATION_METRICS:
        value = metrics[key]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ManifestLoadError(f"{field_name}.{key} 必须为数字")
        if not 0.0 <= float(value) <= 1.0:
            raise ManifestLoadError(f"{field_name}.{key} 必须位于 [0, 1]")


def _validate_evaluation_report(
    report: Mapping[str, Any],
    data: Mapping[str, Any],
    manifest_path: str,
) -> None:
    required = (
        "model_name",
        "model_version",
        "schema",
        "data_source",
        "training_data_description",
        "evaluation_data_description",
        "metrics",
    )
    missing = [k for k in required if k not in report]
    if missing:
        raise ManifestLoadError(f"evaluation_report 缺键 {missing}: {manifest_path}")
    if str(report["model_name"]) != str(data["model_name"]):
        raise ManifestLoadError("evaluation_report.model_name 与 manifest.model_name 不一致")
    if str(report["model_version"]) != str(data["version"]):
        raise ManifestLoadError("evaluation_report.model_version 与 manifest.version 不一致")
    schema = report["schema"]
    if not isinstance(schema, dict):
        raise ManifestLoadError("evaluation_report.schema 必须为 object")
    if str(schema.get("name")) != str(data["schema_name"]):
        raise ManifestLoadError("evaluation_report.schema.name 与 schema_name 不一致")
    if str(schema.get("version")) != str(data["schema_version"]):
        raise ManifestLoadError("evaluation_report.schema.version 与 schema_version 不一致")
    if not str(report["data_source"]).strip():
        raise ManifestLoadError("evaluation_report.data_source 不能为空")
    if not str(report["training_data_description"]).strip():
        raise ManifestLoadError("evaluation_report.training_data_description 不能为空")
    if not str(report["evaluation_data_description"]).strip():
        raise ManifestLoadError("evaluation_report.evaluation_data_description 不能为空")
    rmetrics = report["metrics"]
    if not isinstance(rmetrics, dict):
        raise ManifestLoadError("evaluation_report.metrics 必须为 object")
    _validate_evaluation_metrics(rmetrics, "evaluation_report.metrics", manifest_path)
