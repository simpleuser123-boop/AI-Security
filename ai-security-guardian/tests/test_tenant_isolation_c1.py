from __future__ import annotations

import importlib.util
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _build_test_app(monkeypatch, tmp_path):
    db_file = tmp_path / f"c1_{uuid.uuid4().hex}.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path / f"audit_{uuid.uuid4().hex}"))
    monkeypatch.setenv("ALERT_STREAM_CONSUMER_AUTOSTART", "false")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _jwt_headers(app, *, username: str, tenant_id: str, role: str = "admin"):
    from flask_jwt_extended import create_access_token

    with app.app_context():
        token = create_access_token(
            identity=username,
            additional_claims={"role": role, "tenant_id": tenant_id},
        )
    return {"Authorization": f"Bearer {token}"}


def _seed_tenant(app, tenant_id: str, suffix: str):
    from web.database import db
    from web.models import Membership, Organization, Role, Tenant, User

    with app.app_context():
        db.session.add(Tenant(id=tenant_id, name=suffix, slug=suffix, status="active"))
        db.session.add(
            Organization(
                id=f"org_{suffix}",
                tenant_id=tenant_id,
                name=f"{suffix} Org",
                slug="default",
                status="active",
            )
        )
        db.session.add(
            Role(
                id=f"role_{suffix}_admin",
                tenant_id=tenant_id,
                name="admin",
                scope="tenant",
                permissions=["admin"],
            )
        )
        db.session.add(
            User(
                id=f"user_{suffix}_admin",
                email=f"{suffix}@example.test",
                username=f"{suffix}-admin",
                status="active",
            )
        )
        db.session.add(
            Membership(
                id=f"membership_{suffix}_admin",
                tenant_id=tenant_id,
                organization_id=f"org_{suffix}",
                user_id=f"user_{suffix}_admin",
                role_id=f"role_{suffix}_admin",
                status="active",
            )
        )
        db.session.commit()


def _seed_alert(app, *, alert_id: str, tenant_id: str, source_ip: str):
    from web.database import db
    from web.models import Alert

    with app.app_context():
        db.session.add(
            Alert(
                id=alert_id,
                tenant_id=tenant_id,
                timestamp=datetime.now(timezone.utc),
                source_ip=source_ip,
                threat_type="test",
                level="high",
                status="open",
                summary=f"{tenant_id} alert",
            )
        )
        db.session.commit()


def _allow_legacy_global_query(*_args, **_kwargs):
    """tenant-scan: allow global control-plane query"""
    return None


def test_alert_consumer_uses_tenant_stream_and_rejects_mismatch(monkeypatch):
    monkeypatch.setenv("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
    from flask import Flask
    from flask_socketio import SocketIO
    from src.utils.redis_client import RedisClient, tenant_stream_key
    from web.alert_stream_consumer import GuardianAlertStreamConsumer

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    socketio = SocketIO(app, async_mode="threading")
    rc = RedisClient()
    base = "guardian:alerts:c1"
    group = "guardian:web-c1"
    tenant_a_stream = tenant_stream_key(base, "tenant_a")
    tenant_b_stream = tenant_stream_key(base, "tenant_b")
    assert tenant_a_stream != tenant_b_stream

    rc.stream_ensure_group(tenant_a_stream, group)
    msg_id = rc.stream_add(
        tenant_a_stream,
        {"alert_id": "a1", "tenant_id": "tenant_b", "source_ip": "198.51.100.1"},
    )
    assert msg_id is not None
    consumed = []
    consumer = GuardianAlertStreamConsumer(
        app=app,
        redis_client=rc,
        socketio=socketio,
        stream_key=base,
        group_name=group,
        consumer_name="c1",
        tenant_id="tenant_a",
        per_tenant_stream=True,
        normalizer=lambda fields: dict(fields),
        upsert_alert=lambda row: consumed.append(row) or row,
        alert_to_api_dict=lambda row: dict(row),
    )
    batch = rc.stream_read_group(tenant_a_stream, group, "c1", count=1)
    assert len(batch) == 1
    consumer._process_one(batch[0][0], batch[0][1])

    assert consumed == []
    assert rc.stream_pending(tenant_a_stream, group) == 0


def test_upsert_alert_same_id_cannot_overwrite_other_tenant(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant(app, "tenant_a", "a")
    _seed_tenant(app, "tenant_b", "b")
    _seed_alert(app, alert_id="shared-alert", tenant_id="tenant_a", source_ip="198.51.100.10")

    from web.app import _upsert_alert_to_db
    from web.database import db
    from web.models import Alert

    with app.app_context():
        # tenant-scan: allow legacy cross-tenant conflict probe
        result = _upsert_alert_to_db(
            {
                "id": "shared-alert",
                "tenant_id": "tenant_b",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "203.0.113.99",
                "threat_type": "cross_tenant_probe",
                "level": "critical",
            }
        )
        assert result is None
        # tenant-scan: allow test-only cross-tenant overwrite assertion
        rows = db.session.query(Alert).filter(Alert.id == "shared-alert").all()
        assert len(rows) == 1
        assert rows[0].tenant_id == "tenant_a"
        assert rows[0].source_ip == "198.51.100.10"


def test_response_approval_audit_and_report_export_are_tenant_scoped(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    _seed_tenant(app, "tenant_a", "a")
    _seed_tenant(app, "tenant_b", "b")
    client = app.test_client()
    headers_a = _jwt_headers(app, username="a-admin", tenant_id="tenant_a")
    headers_b = _jwt_headers(app, username="b-admin", tenant_id="tenant_b")

    resp_a = client.post(
        "/api/banned_ips",
        headers=headers_a,
        json={"ip": "198.51.100.21", "reason": "tenant a"},
    )
    resp_b = client.post(
        "/api/banned_ips",
        headers=headers_b,
        json={"ip": "203.0.113.21", "reason": "tenant b"},
    )
    assert resp_a.status_code == 202
    assert resp_b.status_code == 202

    audit_a = client.get("/api/audit/events?event_type=response.ban_ip.pending_approval", headers=headers_a)
    audit_b = client.get("/api/audit/events?event_type=response.ban_ip.pending_approval", headers=headers_b)
    assert {item["resource_id"] for item in audit_a.get_json()["items"]} == {"198.51.100.21"}
    assert {item["resource_id"] for item in audit_b.get_json()["items"]} == {"203.0.113.21"}

    report_a = client.get("/api/reports/export?format=json&period=day", headers=headers_a)
    report_b = client.get("/api/reports/export?format=json&period=day", headers=headers_b)
    targets_a = {item["target"] for item in report_a.get_json()["responses"]}
    targets_b = {item["target"] for item in report_b.get_json()["responses"]}
    assert "198.51.100.21" in targets_a
    assert "203.0.113.21" not in targets_a
    assert "203.0.113.21" in targets_b
    assert "198.51.100.21" not in targets_b


def test_schedule_and_notify_retry_are_tenant_scoped(monkeypatch, tmp_path):
    db_file = tmp_path / "response_tenants.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    import web.models  # noqa: F401
    from src.response.notifier import AlertNotifier
    from src.response.persistence import FlaskSqlalchemyResponsePersistence, build_persistence_app
    from src.response.responder import SecurityResponder
    from web.database import db
    from web.models import Alert, ResponseAction, ResponseScheduleTask

    persistence_app = build_persistence_app(f"sqlite:///{db_file.as_posix()}")
    with persistence_app.app_context():
        db.create_all()
        db.session.add(
            Alert(
                id="alert-a",
                tenant_id="tenant_a",
                timestamp=datetime.now(timezone.utc),
                source_ip="198.51.100.44",
                threat_type="test",
                level="high",
                status="open",
            )
        )
        db.session.commit()

    persist_a = FlaskSqlalchemyResponsePersistence(persistence_app, tenant_id="tenant_a")
    responder_a = SecurityResponder(
        dry_run=True,
        persistence=persist_a,
        notifier=AlertNotifier([]),
        alert_id_from_result=lambda _res: "alert-a",
    )
    responder_a._ban_ip("198.51.100.44", duration=timedelta(seconds=1))
    responder_a.scheduler.schedule_notify_retry(
        run_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        alert_id="alert-a",
        subject="s",
        body="b",
        meta={"tenant_id": "tenant_a"},
    )

    with persistence_app.app_context():
        assert (
            db.session.query(ResponseScheduleTask)
            .filter(ResponseScheduleTask.tenant_id == "tenant_a")
            .count()
            >= 2
        )
        assert (
            db.session.query(ResponseScheduleTask)
            .filter(ResponseScheduleTask.tenant_id == "tenant_b")
            .count()
            == 0
        )

    persist_b = FlaskSqlalchemyResponsePersistence(persistence_app, tenant_id="tenant_b")
    responder_b = SecurityResponder(dry_run=True, persistence=persist_b, notifier=AlertNotifier([]))
    assert responder_b.scheduler.tick(responder_b, now=datetime.now(timezone.utc)) == 0

    with persistence_app.app_context():
        tenant_a_actions = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.tenant_id == "tenant_a")
            .count()
        )
        tenant_b_actions = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.tenant_id == "tenant_b")
            .count()
        )
    assert tenant_a_actions > 0
    assert tenant_b_actions == 0


def test_tenant_static_scan_finds_missing_tenant_predicate(tmp_path):
    scanner_path = Path(__file__).resolve().parents[1] / "scripts" / "tenant_query_scan.py"
    spec = importlib.util.spec_from_file_location("tenant_query_scan", scanner_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    sample = tmp_path / "bad_query.py"
    sample.write_text(
        "from web.database import db\n"
        "from web.models import Alert\n"
        "def f():\n"
        "    return db.session.query(Alert).all()\n",
        encoding="utf-8",
    )
    findings = module.scan_file(sample, root=tmp_path)
    assert findings
    assert findings[0].model == "Alert"
    assert findings[0].line == 4
    assert findings[0].category == "production"
    assert "tenant_query" in findings[0].suggestion

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    allowed = tests_dir / "test_allowed_query.py"
    allowed.write_text(
        "from web.database import db\n"
        "from web.models import Alert\n"
        "def f():\n"
        "    # tenant-scan: allow test-only cross-tenant fixture probe\n"
        "    return db.session.query(Alert).all()\n",
        encoding="utf-8",
    )
    result = module.scan_file_report(allowed, root=tmp_path)
    assert result.findings == []
    assert len(result.exemptions) == 1
    assert result.exemptions[0].category == "test-only"
    assert result.exemptions[0].model == "Alert"
    assert "test-only cross-tenant fixture probe" in result.exemptions[0].exemption_reason
