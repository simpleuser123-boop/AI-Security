from __future__ import annotations

from werkzeug.security import generate_password_hash


TEST_ADMIN_USERNAME = "admin"
TEST_ADMIN_PASSWORD = "N0nDegraded-Test-Admin-Password!2026"


def test_admin_env(*, role: str = "admin") -> dict[str, str]:
    return {
        "ADMIN_USERNAME": TEST_ADMIN_USERNAME,
        "ADMIN_PASSWORD_HASH": generate_password_hash(TEST_ADMIN_PASSWORD),
        "ADMIN_ROLE": role,
    }


def configure_test_admin(monkeypatch, *, role: str = "admin") -> None:
    for key, value in test_admin_env(role=role).items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)


def login_json() -> dict[str, str]:
    return {
        "username": TEST_ADMIN_USERNAME,
        "password": TEST_ADMIN_PASSWORD,
    }


def auth_headers(client) -> tuple[dict[str, str], dict]:
    resp = client.post("/api/auth/login", json=login_json())
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    return {"Authorization": f"Bearer {body['access_token']}"}, body
