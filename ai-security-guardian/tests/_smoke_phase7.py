"""Phase 7 最小冒烟脚本：验证 Flask app 与核心 /api/* 路由。

仅开发时本地手动运行，不纳入 pytest 正式套件。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SMOKE_DIR = Path(tempfile.mkdtemp(prefix="guardian-phase7-smoke-"))

# Keep this script isolated from the developer database and real audit logs.
os.chdir(SMOKE_DIR)
os.environ.update(
    {
        "SECRET_KEY": "phase7-smoke-secret-key-which-is-at-least-32b",
        "FLASK_ENV": "testing",
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": "changeme",
        "DATABASE_URL": f"sqlite:///{(SMOKE_DIR / 'phase7_smoke.db').as_posix()}",
        "AUDIT_INTEGRITY_PATROL": "false",
        "ALERT_STREAM_CONSUMER_AUTOSTART": "false",
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "63999",
    }
)
os.environ.pop("ADMIN_PASSWORD_HASH", None)

sys.path.insert(0, str(ROOT))

from web.app import create_app  # noqa: E402


def show(tag: str, resp) -> None:
    body = resp.get_data(as_text=True)
    try:
        body = json.dumps(json.loads(body), ensure_ascii=False)
    except Exception:
        pass
    print(f"[{tag}] {resp.status_code} {body[:220]}")


def main() -> None:
    app, _ = create_app()
    client = app.test_client()

    show("health", client.get("/api/health"))
    show("stats-no-jwt", client.get("/api/stats"))
    show(
        "login-bad",
        client.post("/api/auth/login", json={"username": "x", "password": "y"}),
    )

    resp = client.post(
        "/api/auth/login", json={"username": "admin", "password": "changeme"}
    )
    show("login-ok", resp)
    token = resp.get_json().get("access_token")
    hdr = {"Authorization": f"Bearer {token}"}

    show("stats-jwt", client.get("/api/stats", headers=hdr))
    show("me", client.get("/api/auth/me", headers=hdr))
    show(
        "ban-bad",
        client.post(
            "/api/banned_ips", headers=hdr, json={"ip": "1.2.3.4; rm -rf /"}
        ),
    )
    show(
        "ban-ok",
        client.post(
            "/api/banned_ips",
            headers=hdr,
            json={"ip": "1.2.3.4", "reason": "test"},
        ),
    )
    show("ban-list", client.get("/api/banned_ips", headers=hdr))
    show(
        "cmd-status",
        client.post("/api/command", headers=hdr, json={"command": "status"}),
    )
    show(
        "cmd-block",
        client.post("/api/command", headers=hdr, json={"command": "block 8.8.8.8"}),
    )
    show(
        "cmd-bad",
        client.post(
            "/api/command", headers=hdr, json={"command": "cat /etc/passwd"}
        ),
    )
    show("dashboard-html", client.get("/dashboard"))
    show("login-html", client.get("/login"))
    show("css-theme", client.get("/static/css/theme.css"))
    show("js-utils", client.get("/static/js/utils.js"))


if __name__ == "__main__":
    main()
