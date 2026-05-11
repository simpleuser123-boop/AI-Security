"""pytest 版 v1.0 验收场景（与 scripts/verify_v1.py 共享逻辑）。"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

from tests.e2e.verify_scenarios import (
    check_01_normal_web_no_alert,
    check_02_sqli_web_attack_high,
    check_03_double_encoded_xss_high,
    check_04_cmd_injection_high,
    check_05_ioc_threat_intel_high,
    check_06_syn_surge_anomaly_or_ddos,
    check_07_model_missing_other_engines_continue,
    check_08_redis_downgrade_memory_mode,
    check_09_audit_tamper_fails_integrity,
    check_10_web_restart_alerts_queryable,
    check_11_auth_rejects_bad_password,
)

REQUIRED_PRODUCTION_MODELS = (
    "intrusion_rf_v1.pkl",
    "ddos_rf_v1.pkl",
    "web_attack_nb_v1.pkl",
    "anomaly_if_v1.pkl",
)


@pytest.fixture
def production_e2e_guard():
    if os.environ.get("GUARDIAN_REDIS_DISABLE_CONNECT", "").lower() == "true":
        raise AssertionError(
            "production_e2e must not run with GUARDIAN_REDIS_DISABLE_CONNECT=true"
        )
    model_dir = Path(os.environ.get("MODEL_DIR", "models/saved"))
    missing = [
        name for name in REQUIRED_PRODUCTION_MODELS if not (model_dir / name).is_file()
    ]
    if missing:
        raise AssertionError(
            f"production_e2e requires complete model artifacts in {model_dir}: missing {missing}"
        )


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_01_normal_web():
    check_01_normal_web_no_alert()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_02_sqli():
    check_02_sqli_web_attack_high()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_03_double_xss():
    check_03_double_encoded_xss_high()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_04_cmd_injection():
    check_04_cmd_injection_high()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_05_ioc_local_blacklist():
    check_05_ioc_threat_intel_high()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_06_syn_or_anomaly():
    check_06_syn_surge_anomaly_or_ddos()


@pytest.mark.degradation_e2e
def test_07_model_degrade(tmp_path):
    check_07_model_missing_other_engines_continue(tmp_path)


@pytest.mark.degradation_e2e
def test_08_redis_memory_fallback():
    check_08_redis_downgrade_memory_mode()


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_09_audit_tamper(tmp_path):
    check_09_audit_tamper_fails_integrity(tmp_path)


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_10_web_restart_alerts(monkeypatch, tmp_path):
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    check_10_web_restart_alerts_queryable(monkeypatch, tmp_path)


@pytest.mark.production_e2e
@pytest.mark.usefixtures("production_e2e_guard")
def test_11_auth_rejects_bad_password(monkeypatch, tmp_path):
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    check_11_auth_rejects_bad_password(monkeypatch, tmp_path)
