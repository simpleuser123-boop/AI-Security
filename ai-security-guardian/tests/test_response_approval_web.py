from __future__ import annotations


def _build_test_app(monkeypatch, tmp_path):
    db_file = tmp_path / "approval_web.db"
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    return app


def _auth_headers(client):
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_banned_ips_post_creates_approval_not_ban(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    resp = client.post(
        "/api/banned_ips",
        headers=headers,
        json={"ip": "192.0.2.201", "reason": "manual"},
    )

    assert resp.status_code == 202
    assert resp.get_json()["status"] == "pending_approval"

    with app.app_context():
        from web.database import db
        from web.models import BannedIp, ResponseAction

        assert db.session.get(BannedIp, "192.0.2.201") is None
        action = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.target == "192.0.2.201")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        assert action is not None
        assert action.status == "pending_approval"


def test_command_block_creates_approval_not_ban(monkeypatch, tmp_path):
    app = _build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    headers = _auth_headers(client)

    resp = client.post(
        "/api/command",
        headers=headers,
        json={"command": "block 192.0.2.202"},
    )

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "pending_approval"

    with app.app_context():
        from web.database import db
        from web.models import BannedIp, ResponseAction

        assert db.session.get(BannedIp, "192.0.2.202") is None
        action = (
            db.session.query(ResponseAction)
            .filter(ResponseAction.target == "192.0.2.202")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        assert action is not None
        assert action.status == "pending_approval"
