"""pytest 版 v1.0 验收场景（与 scripts/verify_v1.py 共享逻辑）。"""
from __future__ import annotations

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
)


def test_01_normal_web():
    check_01_normal_web_no_alert()


def test_02_sqli():
    check_02_sqli_web_attack_high()


def test_03_double_xss():
    check_03_double_encoded_xss_high()


def test_04_cmd_injection():
    check_04_cmd_injection_high()


def test_05_ioc_local_blacklist():
    check_05_ioc_threat_intel_high()


def test_06_syn_or_anomaly():
    check_06_syn_surge_anomaly_or_ddos()


def test_07_model_degrade(tmp_path):
    check_07_model_missing_other_engines_continue(tmp_path)


def test_08_redis_memory_fallback():
    check_08_redis_downgrade_memory_mode()


def test_09_audit_tamper(tmp_path):
    check_09_audit_tamper_fails_integrity(tmp_path)


def test_10_web_restart_alerts(monkeypatch, tmp_path):
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    check_10_web_restart_alerts_queryable(monkeypatch, tmp_path)
