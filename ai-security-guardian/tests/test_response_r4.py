"""R4 响应闭环：SSRF、Webhook 重试、定时解封、人工待办、DB 持久化。"""
from __future__ import annotations

import dataclasses
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import os
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.detectors.base import DetectionResult  # noqa: E402
from src.response.host_isolation import NullHostIsolationProvider  # noqa: E402
from src.response.notifier import AlertNotifier, WebhookNotificationChannel  # noqa: E402
from src.response.persistence import (  # noqa: E402
    FlaskSqlalchemyResponsePersistence,
    build_persistence_app,
)
from src.response.responder import SecurityResponder  # noqa: E402
from src.response.responder import STATUS_SCHEDULED_UNBLOCKED  # noqa: E402
from src.response.webhook_url import check_webhook_url_safe  # noqa: E402


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/api",
        "http://localhost/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/x",
        "http://10.0.0.1/x",
        "ftp://example.com/x",
        "",
    ],
)
def test_webhook_url_ssrf_rejected(url: str):
    r = check_webhook_url_safe(url)
    assert r.ok is False


def test_webhook_url_public_https_ok(monkeypatch):
    monkeypatch.setattr(
        "src.response.webhook_url.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    r = check_webhook_url_safe("https://example.com/webhook")
    assert r.ok is True


def test_webhook_notifier_retries_then_audit(monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK", raising=False)
    monkeypatch.setattr(
        "src.response.webhook_url.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    ch = WebhookNotificationChannel("https://example.com/hook")
    notifier = AlertNotifier([ch], max_retries=3, retry_backoff_sec=0.0, sleep_fn=lambda _s: None)

    class _FakeFp:
        def read(self):
            return b""

        def close(self) -> None:
            return

    class _FakeOk:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

        def getcode(self):
            return 200

    seq = {"n": 0}

    def _fake_urlopen(_req, **_kw):
        seq["n"] += 1
        if seq["n"] < 3:
            import urllib.error

            raise urllib.error.HTTPError(
                "https://example.com/hook", 500, "err", {}, _FakeFp()
            )
        return _FakeOk()

    with patch("src.response.notifier.urllib.request.urlopen", side_effect=_fake_urlopen):
        out = notifier.notify_all("s", "b", meta={})
    assert any(x.ok for x in out)


def test_high_ban_schedules_unblock_and_tick_writes_unban(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    r = SecurityResponder(dry_run=True)
    r._ban_ip("192.0.2.44", duration=timedelta(seconds=1))
    assert r.is_banned("192.0.2.44")
    assert r.scheduler._mem_tasks, "expected scheduled_unblock task"  # noqa: SLF001
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    for i, t in enumerate(r.scheduler._mem_tasks):  # noqa: SLF001
        if t.task_type == "scheduled_unblock":
            r.scheduler._mem_tasks[i] = dataclasses.replace(t, run_at=past)
            break
    n = r.scheduler.tick(r, now=datetime.now(timezone.utc))
    assert n >= 1
    un = [x for x in r.response_actions if x.get("action") == "unban_ip"]
    assert un, "unban should be recorded"
    assert un[-1].get("status") == STATUS_SCHEDULED_UNBLOCKED


def test_critical_null_isolation_creates_manual_pending(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    r = SecurityResponder(
        dry_run=True,
        isolation=NullHostIsolationProvider(),
    )
    res = DetectionResult(
        threat_type="x",
        threat_level="critical",
        confidence=1.0,
        details="t",
        source_ip="192.0.2.77",
        raw_data={},
    )
    r.respond(res)
    rows = [x for x in r.response_actions if x.get("action") == "isolation_manual_pending"]
    assert rows
    assert rows[-1].get("status") == "pending"


def test_response_action_and_unban_persisted_sqlite(monkeypatch, tmp_path):
    db_file = tmp_path / "r4.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    import web.models  # noqa: F401

    app = build_persistence_app(f"sqlite:///{db_file.as_posix()}")
    with app.app_context():
        from web.database import db

        db.create_all()

    persist = FlaskSqlalchemyResponsePersistence(app)
    aid = uuid.uuid4().hex
    with app.app_context():
        from web.database import db
        from web.models import Alert

        db.session.add(
            Alert(
                id=aid,
                timestamp=datetime.now(timezone.utc),
                source_ip="192.0.2.88",
                threat_type="t",
                level="high",
                status="open",
            )
        )
        db.session.commit()

    r = SecurityResponder(
        dry_run=True,
        persistence=persist,
        alert_id_from_result=lambda res: aid,
    )
    r._ban_ip("192.0.2.88", duration=timedelta(seconds=1))
    past = datetime.now(timezone.utc) + timedelta(seconds=2)
    with app.app_context():
        from web.database import db
        from web.models import ResponseScheduleTask

        row = (
            db.session.query(ResponseScheduleTask)
            .order_by(ResponseScheduleTask.id.desc())
            .first()
        )
        assert row is not None
        row.run_at = past - timedelta(seconds=3)
        db.session.commit()
    r.scheduler.tick(r, now=past)

    with app.app_context():
        from web.models import ResponseAction

        rows = (
            ResponseAction.query.filter(ResponseAction.alert_id == aid)
            .order_by(ResponseAction.id.asc())
            .all()
        )
        types = [x.action_type for x in rows]
        assert "ban_ip" in types
        assert "unban_ip" in types
