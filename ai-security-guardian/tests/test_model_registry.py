"""R3：ModelRegistry 版本目录、热切换、失败保留、回滚与 manifest 家族校验。"""
from __future__ import annotations

import json
import os
import sys

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.detectors.ddos_detector import DDoSDetector  # noqa: E402
from src.registry.model_registry import ModelRegistry  # noqa: E402
from src.schema.nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS  # noqa: E402


EVAL_METRICS = {
    "accuracy": 0.9,
    "precision": 0.9,
    "recall": 0.9,
    "f1": 0.9,
    "fpr": 0.1,
    "fnr": 0.1,
}


def _write_ddos_manifest_json(
    version_dir: str,
    *,
    version: str,
    schema_name: str = "network_flow_v1",
    trust_tier: str = "prototype_nsl_kdd",
) -> None:
    pkl = os.path.join(version_dir, "model.pkl")
    payload = {
        "model_name": "ddos_test",
        "version": version,
        "schema_name": schema_name,
        "schema_version": "1",
        "feature_columns": list(NSL_KDD_FEATURE_COLUMNS),
        "training_dataset": "NSL-KDD",
        "training_data_description": "NSL-KDD unit-test fixture.",
        "metrics": dict(EVAL_METRICS),
        "created_at": "2026-01-01T00:00:00Z",
        "published_at": "2026-01-01T00:00:00Z",
        "artifact_files": {"model": "model.pkl"},
        "evaluation_report": {
            "model_name": "ddos_test",
            "model_version": version,
            "schema": {"name": schema_name, "version": "1"},
            "data_source": "NSL-KDD unit-test fixture",
            "training_data_description": "NSL-KDD unit-test fixture.",
            "evaluation_data_description": "Deterministic unit-test evaluation set.",
            "metrics": dict(EVAL_METRICS),
        },
        "trust_tier": trust_tier,
        "adapter": "nsl_kdd_v1",
        "model_input_mode": "tabular",
    }
    with open(os.path.join(version_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _train_rf_at(path: str) -> None:
    X = [[0.0] * 41]
    y = ["normal"]
    clf = RandomForestClassifier(n_estimators=1, random_state=0)
    clf.fit(X, y)
    joblib.dump(clf, path)


def test_promote_success_switches_current(tmp_path):
    root = tmp_path / "saved"
    ddos = root / "ddos"
    v1 = ddos / "v1"
    v2 = ddos / "v2"
    v1.mkdir(parents=True)
    v2.mkdir(parents=True)
    _train_rf_at(str(v1 / "model.pkl"))
    _write_ddos_manifest_json(str(v1), version="v1-label")
    _train_rf_at(str(v2 / "model.pkl"))
    _write_ddos_manifest_json(str(v2), version="v2-label")
    (ddos / "current.txt").write_text("v1\n", encoding="utf-8")

    reg = ModelRegistry(str(root), audit_sink=None)
    det = DDoSDetector()
    assert reg.try_load_detector("ddos", det) is True
    assert reg.promote_version("ddos", "v2", det) is True
    assert reg.get_current_version_id("ddos") == "v2"
    cur_txt = ddos / "current.txt"
    assert cur_txt.read_text(encoding="utf-8").strip() == "v2"


def test_promote_load_failure_keeps_previous_service(tmp_path):
    root = tmp_path / "saved"
    ddos = root / "ddos"
    v1 = ddos / "v1"
    v2 = ddos / "v2"
    v1.mkdir(parents=True)
    v2.mkdir(parents=True)
    _train_rf_at(str(v1 / "model.pkl"))
    _write_ddos_manifest_json(str(v1), version="v1")
    _write_ddos_manifest_json(str(v2), version="v2")
    (v2 / "model.pkl").write_bytes(b"not a real joblib")
    (ddos / "current.txt").write_text("v1\n", encoding="utf-8")

    reg = ModelRegistry(str(root), audit_sink=None)
    det = DDoSDetector()
    assert reg.try_load_detector("ddos", det) is True
    assert reg.promote_version("ddos", "v2", det) is False
    assert det.is_ready is True
    feats = {
        "src_ip": "1.1.1.1",
        "protocol": "TCP",
        "flow_pkt_count": 5,
        "flow_byte_count": 1200,
        "flow_duration": 0.5,
        "window_unique_dst_port": 2,
    }
    r = det.detect(feats)
    assert r is not None
    assert r.raw_data.get("_inference", {}).get("model_version") == "v1"


def test_rollback_inference_version(tmp_path):
    root = tmp_path / "saved"
    ddos = root / "ddos"
    for vid, label in (("v1", "first"), ("v2", "second")):
        d = ddos / vid
        d.mkdir(parents=True)
        _train_rf_at(str(d / "model.pkl"))
        _write_ddos_manifest_json(str(d), version=label)
    (ddos / "current.txt").write_text("v1\n", encoding="utf-8")

    reg = ModelRegistry(str(root), audit_sink=None)
    det = DDoSDetector()
    assert reg.try_load_detector("ddos", det) is True
    assert reg.promote_version("ddos", "v2", det) is True
    assert reg.rollback("ddos", det) is True
    r = det.detect(
        {
            "src_ip": "1.1.1.1",
            "protocol": "TCP",
            "flow_pkt_count": 5,
            "flow_byte_count": 1200,
            "flow_duration": 0.5,
            "window_unique_dst_port": 2,
        }
    )
    assert r is not None
    assert r.raw_data["_inference"]["model_version"] == "first"


def test_promote_rejects_manifest_schema_policy(tmp_path):
    """production + NSL 41 列在全局 manifest 校验阶段即拒绝，不得上线。"""
    root = tmp_path / "saved"
    ddos = root / "ddos"
    v1 = ddos / "v1"
    v2 = ddos / "v2"
    v1.mkdir(parents=True)
    v2.mkdir(parents=True)
    _train_rf_at(str(v1 / "model.pkl"))
    _write_ddos_manifest_json(str(v1), version="v1")
    _train_rf_at(str(v2 / "model.pkl"))
    _write_ddos_manifest_json(
        str(v2), version="v2", schema_name="network_flow_v1", trust_tier="production"
    )
    (ddos / "current.txt").write_text("v1\n", encoding="utf-8")

    reg = ModelRegistry(str(root), audit_sink=None)
    det = DDoSDetector()
    assert reg.try_load_detector("ddos", det) is True
    assert reg.promote_version("ddos", "v2", det) is False
    assert reg.get_current_version_id("ddos") in (None, "v1")


def test_resolve_legacy_flat_pkl(tmp_path):
    pkl = tmp_path / "ddos_rf_v1.pkl"
    _train_rf_at(str(pkl))
    from src.schema.persist import write_model_manifest  # noqa: WPS433

    write_model_manifest(
        str(pkl),
        model_name="d",
        version="legacy-v",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=list(NSL_KDD_FEATURE_COLUMNS),
        training_dataset="NSL-KDD",
        training_data_description="NSL-KDD unit-test fixture.",
        metrics=dict(EVAL_METRICS),
        evaluation_report={
            "model_name": "d",
            "model_version": "legacy-v",
            "schema": {"name": "network_flow_v1", "version": "1"},
            "data_source": "NSL-KDD unit-test fixture",
            "training_data_description": "NSL-KDD unit-test fixture.",
            "evaluation_data_description": "Deterministic unit-test evaluation set.",
            "metrics": dict(EVAL_METRICS),
        },
        artifact_files={"model": "ddos_rf_v1.pkl"},
        trust_tier="prototype_nsl_kdd",
        adapter="nsl_kdd_v1",
    )
    reg = ModelRegistry(str(tmp_path), audit_sink=None)
    path = reg.resolve_load_path("ddos")
    assert path and path.endswith("ddos_rf_v1.pkl")
    det = DDoSDetector()
    assert reg.try_load_detector("ddos", det) is True
