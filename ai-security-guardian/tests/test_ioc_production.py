"""威胁情报生产化：IOC 过期、多源合并、外部超时降级、本地高置信命中。"""
from __future__ import annotations

import uuid
from datetime import timedelta
import time
from unittest.mock import MagicMock, patch

import pytest

from tests.auth_helpers import configure_test_admin


def _flask_app(monkeypatch, tmp_path):
    db_file = tmp_path / "ioc_prod.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    configure_test_admin(monkeypatch)

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def test_expired_ioc_not_in_memory_or_hit(monkeypatch, tmp_path):
    from web.database import db
    from web.models import IOC
    from src.collectors.ioc_repository import utc_now
    from src.collectors.threat_intel import ThreatIntelCollector

    app = _flask_app(monkeypatch, tmp_path)
    with app.app_context():
        past = utc_now() - timedelta(hours=1)
        db.session.add(
            IOC(
                id=uuid.uuid4().hex,
                ioc_type="ip",
                value="9.9.9.9",
                sources=["manual"],
                score=99,
                expires_at=past,
                hits=0,
            )
        )
        db.session.commit()

        ti: ThreatIntelCollector = app.extensions["guardian_threat_intel"]
        n = ti.refresh_local_from_db()
        assert n == 0
        r = ti.check_ip("9.9.9.9")
        assert r["is_malicious"] is False
        assert r["source"] == "none"


def test_merge_sources_and_max_score(monkeypatch, tmp_path):
    from web.database import db
    from src.collectors.ioc_repository import IOCRepository

    app = _flask_app(monkeypatch, tmp_path)
    with app.app_context():
        repo = IOCRepository(db.session)
        repo.upsert_merge(
            ioc_type="ip",
            value="10.0.0.1",
            source="manual",
            score=40,
        )
        db.session.commit()
        repo.upsert_merge(
            ioc_type="ip",
            value="10.0.0.1",
            source="abuseipdb",
            score=90,
        )
        db.session.commit()
        row = repo.find_active_dict("ip", "10.0.0.1")
        assert row is not None
        assert set(row["sources"]) == {"abuseipdb", "manual"}
        assert row["score"] == 90


@pytest.mark.slow
def test_external_wait_timeout_degraded(monkeypatch, tmp_path):
    monkeypatch.delenv("THREAT_INTEL_MOCK", raising=False)

    def slow_get(*_a, **_k):
        time.sleep(0.3)
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {"data": {"abuseConfidenceScore": 99}}
        return m

    from src.collectors.threat_intel import ThreatIntelCollector

    with patch("src.collectors.ioc_providers.requests.get", side_effect=slow_get):
        ti = ThreatIntelCollector(
            abuseipdb_key="k",
            virustotal_key="",
            external_http_timeout=5.0,
            external_wait_sec=0.05,
            mock_external=False,
        )
        r = ti.check_ip("1.2.3.4")
    assert r["is_malicious"] is False
    assert r.get("degraded") is True
    assert r.get("reason") == "external_timeout"


def test_local_db_hit_before_external(monkeypatch, tmp_path):
    from web.database import db
    from src.collectors.ioc_repository import IOCRepository
    from src.collectors.threat_intel import ThreatIntelCollector

    app = _flask_app(monkeypatch, tmp_path)
    with app.app_context():
        IOCRepository(db.session).upsert_merge(
            ioc_type="ip",
            value="10.10.10.10",
            source="manual",
            score=88,
        )
        db.session.commit()

        ti = ThreatIntelCollector(
            abuseipdb_key="should-not-be-called",
            mock_external=False,
        )
        ti.bind_flask_app(app)
        with patch("src.collectors.ioc_providers.requests.get") as mock_get:
            r = ti.check_ip("10.10.10.10")
        mock_get.assert_not_called()
        assert r["is_malicious"] is True
        assert r["source"] == "local_db"
        assert r["ioc_value"] == "10.10.10.10"
        assert "manual" in (r.get("sources") or [])
