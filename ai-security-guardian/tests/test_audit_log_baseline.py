"""Audit log archive and baseline rebuild workflow tests."""
from __future__ import annotations

import json
from pathlib import Path

from scripts.archive_security_audit_log import archive_security_log
from src.audit.security_logger import SecurityLogger


def _read_json_lines(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_archive_rebuilds_genesis_baseline_and_preserves_archive(tmp_path):
    log_dir = tmp_path / "logs" / "test"
    logger = SecurityLogger(log_dir=str(log_dir), enable_integrity=True)
    logger.log_system("seed-a", level="info")
    logger.log_event("threat_detected", "warning", {"rule": "demo"})

    result = archive_security_log(
        str(log_dir),
        reason="unit-rotation",
        env="test",
        operator="pytest",
        ticket="SEC-1",
    )

    archive = Path(result["archived_log"])
    metadata = Path(result["metadata_file"])
    assert archive.exists()
    assert metadata.exists()
    assert result["entries_archived"] == 2
    assert result["pre_archive_integrity"]["valid"] is True
    assert result["baseline_valid"] is True

    baseline = _read_json_lines(log_dir / "security.log")
    assert len(baseline) == 1
    assert baseline[0]["event_type"] == "system"
    assert baseline[0]["integrity"]["prev_hash"] == "genesis"
    assert "audit log baseline rebuilt" in baseline[0]["message"]

    archive_events = _read_json_lines(archive)
    assert [event["event_type"] for event in archive_events] == [
        "system",
        "threat_detected",
    ]

    manifest = json.loads(metadata.read_text(encoding="utf-8"))
    assert manifest["audit_env"] == "test"
    assert manifest["operator"] == "pytest"
    assert manifest["ticket"] == "SEC-1"
    assert manifest["archive_sha256"] == result["archive_sha256"]


def test_archive_uses_env_specific_directory_without_mixing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    test_dir = tmp_path / "logs" / "test"
    prod_dir = tmp_path / "logs" / "production"
    SecurityLogger(log_dir=str(test_dir), enable_integrity=True).log_system(
        "test-only", level="info"
    )
    prod_logger = SecurityLogger(log_dir=str(prod_dir), enable_integrity=True)
    prod_logger.log_system("prod-only", level="info")
    prod_before = (prod_dir / "security.log").read_text(encoding="utf-8")

    result = archive_security_log(reason="test-rotation", env="test")

    assert Path(result["log_dir"]).name == "test"
    assert (prod_dir / "security.log").read_text(encoding="utf-8") == prod_before
    prod_check = SecurityLogger(
        log_dir=str(prod_dir), enable_integrity=True
    ).verify_integrity()
    assert prod_check["valid"] is True


def test_legacy_root_security_log_is_archived_into_env_baseline(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    legacy_dir = tmp_path / "logs"
    legacy_logger = SecurityLogger(log_dir=str(legacy_dir), enable_integrity=True)
    legacy_logger.log_system("legacy-entry", level="info")
    legacy_log = legacy_dir / "security.log"
    legacy_before = legacy_log.read_text(encoding="utf-8")

    result = archive_security_log(reason="legacy-migration", env="test")

    assert result["legacy_source"] is True
    assert result["source_log"].endswith(str(Path("logs") / "security.log"))
    assert legacy_log.read_text(encoding="utf-8") == legacy_before

    env_log = tmp_path / "logs" / "test" / "security.log"
    assert env_log.exists()
    baseline = _read_json_lines(env_log)
    assert len(baseline) == 1
    assert baseline[0]["integrity"]["prev_hash"] == "genesis"

    archive = Path(result["archived_log"])
    archived_events = _read_json_lines(archive)
    assert archived_events[0]["message"] == "legacy-entry"
