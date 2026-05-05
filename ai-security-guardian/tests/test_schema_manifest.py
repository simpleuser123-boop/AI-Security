"""R3: schema 契约与 model_manifest 校验。"""
from __future__ import annotations

import os
import sys
import json
import re

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.schema.feature_schemas import (  # noqa: E402
    production_tabular_keys_present,
    validate_payload_against_schema,
)
from src.schema.manifest import ManifestLoadError  # noqa: E402
from src.schema.nsl_kdd_adapter import NSL_KDD_FEATURE_COLUMNS, NSLKDDAdapter  # noqa: E402
from src.schema.persist import write_model_manifest  # noqa: E402
from src.detectors.ddos_detector import DDoSDetector  # noqa: E402
from src.detectors.web_detector import WebAttackDetector  # noqa: E402


EVAL_METRICS = {
    "accuracy": 0.99,
    "precision": 0.99,
    "recall": 0.99,
    "f1": 0.99,
    "fpr": 0.01,
    "fnr": 0.01,
}


def _evaluation_report(model_name: str, version: str, schema_name: str, schema_version: str):
    return {
        "model_name": model_name,
        "model_version": version,
        "schema": {"name": schema_name, "version": schema_version},
        "data_source": "unit_test_dataset",
        "training_data_description": "Small deterministic unit-test dataset.",
        "evaluation_data_description": "Small deterministic unit-test evaluation set.",
        "metrics": dict(EVAL_METRICS),
    }


def test_schema_required_field_missing_fails():
    ok, errs = validate_payload_against_schema(
        "network_flow_v1",
        {"protocol": "TCP", "flow_pkt_count": 1, "flow_byte_count": 100},
    )
    assert ok is False
    assert any("src_ip" in e for e in errs)


def test_feature_column_order_matches_inference_vector():
    flow = {
        "src_ip": "10.0.0.1",
        "protocol": "TCP",
        "flow_pkt_count": 10,
        "flow_byte_count": 500,
        "flow_duration": 1.2,
        "window_unique_dst_port": 3,
    }
    cols = ["duration", "count", "srv_count"]  # 子集顺序即推理行向量顺序
    vec, _audit = NSLKDDAdapter.build_vector_in_order(flow, cols)
    assert vec == pytest.approx([1.2, 10.0, 3.0])


def test_production_tabular_missing_key():
    ok, miss = production_tabular_keys_present(
        ["pkt_len_mean", "flow_byte_count"],
        {"pkt_len_mean": 1.0},
    )
    assert ok is False
    assert "flow_byte_count" in miss


def test_manifest_missing_refuses_ddos_load(tmp_path):
    pkl = tmp_path / "m.pkl"
    X = [[0.0] * 41]
    y = ["normal"]
    clf = RandomForestClassifier(n_estimators=1, random_state=0)
    clf.fit(X, y)
    joblib.dump(clf, pkl)
    det = DDoSDetector()
    with pytest.raises(ManifestLoadError):
        det.load_model(str(pkl))


def test_manifest_prototype_nsl_kdd_loads_and_detect_audit(tmp_path):
    pkl = tmp_path / "m.pkl"
    X = [[0.0] * 41]
    y = ["normal"]
    clf = RandomForestClassifier(n_estimators=1, random_state=0)
    clf.fit(X, y)
    joblib.dump(clf, pkl)
    write_model_manifest(
        str(pkl),
        model_name="t",
        version="1",
        schema_name="network_flow_v1",
        schema_version="1",
        feature_columns=list(NSL_KDD_FEATURE_COLUMNS),
        training_dataset="NSL-KDD",
        training_data_description="NSL-KDD unit-test fixture.",
        metrics=dict(EVAL_METRICS),
        evaluation_report=_evaluation_report("t", "1", "network_flow_v1", "1"),
        artifact_files={"model": "m.pkl"},
        trust_tier="prototype_nsl_kdd",
        adapter="nsl_kdd_v1",
    )
    det = DDoSDetector()
    det.load_model(str(pkl))
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
    assert r.threat_type == "normal"


def test_manifest_schema_production_conflict(tmp_path):
    pkl = tmp_path / "m.pkl"
    pkl.write_bytes(b"0")
    data = {
        "model_name": "x",
        "version": "1",
        "schema_name": "network_flow_v1",
        "schema_version": "1",
        "feature_columns": list(NSL_KDD_FEATURE_COLUMNS),
        "training_dataset": "NSL-KDD",
        "training_data_description": "NSL-KDD unit-test fixture.",
        "metrics": dict(EVAL_METRICS),
        "created_at": "2026-01-01T00:00:00Z",
        "published_at": "2026-01-01T00:00:00Z",
        "artifact_files": {"model": "m.pkl"},
        "evaluation_report": _evaluation_report("x", "1", "network_flow_v1", "1"),
        "trust_tier": "production",
    }
    with pytest.raises(ManifestLoadError):
        from src.schema.manifest import validate_manifest_dict

        validate_manifest_dict(
            data, model_path=str(pkl), manifest_path=str(tmp_path / "x.json")
        )


def test_web_ml_requires_manifest(tmp_path):
    from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: WPS433
    from sklearn.naive_bayes import MultinomialNB  # noqa: WPS433
    from sklearn.pipeline import Pipeline  # noqa: WPS433

    pipe = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=20)),
            ("nb", MultinomialNB()),
        ]
    )
    pipe.fit(["hello normal", "union select"], ["normal", "sql_injection"])
    pkl = tmp_path / "web.pkl"
    joblib.dump(pipe, pkl)
    write_model_manifest(
        str(pkl),
        model_name="web_attack_nb_v1",
        version="1",
        schema_name="web_request_v1",
        schema_version="1",
        feature_columns=["decoded_url"],
        training_dataset="builtin",
        training_data_description="Curated unit-test web samples.",
        metrics=dict(EVAL_METRICS),
        evaluation_report=_evaluation_report("web_attack_nb_v1", "1", "web_request_v1", "1"),
        artifact_files={"model": "web.pkl"},
        trust_tier="production",
        model_input_mode="text_sklearn_pipeline",
    )
    det = WebAttackDetector()
    det.load_model(str(pkl))
    # 规则未命中时走 ML； benign URL 避免规则抢先
    r = det.detect(
        {
            "src_ip": "10.0.0.5",
            "url_raw": "/api/health?ok=1",
            "http_method": "GET",
            "status_code": 200,
            "decoded_url": "/api/health?ok=1",
        }
    )
    assert r is not None
    assert r.source_ip == "10.0.0.5"


def test_saved_model_manifests_include_governance_fields():
    manifest_dir = os.path.join(PROJECT_ROOT, "models", "saved")
    paths = [
        os.path.join(manifest_dir, name)
        for name in os.listdir(manifest_dir)
        if name.endswith(".model_manifest.json")
    ]
    assert paths
    timestamp_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    metric_keys = {"accuracy", "precision", "recall", "f1", "fpr", "fnr"}
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["version"]
        assert timestamp_re.match(data["published_at"])
        assert data["training_dataset"]
        assert data["training_data_description"]
        assert metric_keys.issubset(data["metrics"])
        for key in metric_keys:
            assert 0.0 <= float(data["metrics"][key]) <= 1.0
        report = data["evaluation_report"]
        assert report["model_version"] == data["version"]
        assert report["schema"] == {
            "name": data["schema_name"],
            "version": data["schema_version"],
        }
        assert report["data_source"]
        assert report["training_data_description"]
        assert report["evaluation_data_description"]
        assert metric_keys.issubset(report["metrics"])
