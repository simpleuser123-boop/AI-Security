"""生产安全硬化：密钥、管理员、JWT、CORS、Webhook SSRF、Redis 密码。"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def _run_fresh_config_snippet(code: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    full = os.environ.copy()
    full.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        env=full,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_production_startup_fails_without_secret_key():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "if 'SECRET_KEY' in os.environ: del os.environ['SECRET_KEY']\n"
        "try:\n"
        "    import importlib\n"
        "    import config.config as cc\n"
        "    importlib.reload(cc)\n"
        "except RuntimeError as e:\n"
        "    print('EXPECTED', e)\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_production_get_config_rejects_default_secret():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "os.environ['SECRET_KEY']='dev-only-insecure-key-never-use-in-production'\n"
        "os.environ['ADMIN_PASSWORD_HASH']='pbkdf2:sha256:1$test$somethinginvalid'\n"
        "os.environ['REDIS_PASSWORD']='x'\n"
        "os.environ['ALLOWED_ORIGINS']='https://example.com'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'SECRET_KEY' in str(e) or '禁止' in str(e):\n"
        "        print('ok')\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_production_get_config_requires_admin_password_hash():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "os.environ['SECRET_KEY']='a' * 40\n"
        "os.environ.pop('ADMIN_PASSWORD_HASH', None)\n"
        "os.environ['REDIS_PASSWORD']='redis-secret'\n"
        "os.environ['ALLOWED_ORIGINS']='https://app.example.com'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'ADMIN_PASSWORD_HASH' in str(e):\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_production_get_config_requires_redis_password():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "os.environ['SECRET_KEY']='a' * 40\n"
        "os.environ['ADMIN_PASSWORD_HASH']='pbkdf2:sha256:1$test$somethinginvalid'\n"
        "os.environ.pop('REDIS_PASSWORD', None)\n"
        "os.environ['ALLOWED_ORIGINS']='https://app.example.com'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'REDIS_PASSWORD' in str(e):\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_production_get_config_rejects_cors_wildcard():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "os.environ['SECRET_KEY']='a' * 40\n"
        "os.environ['ADMIN_PASSWORD_HASH']='pbkdf2:sha256:1$test$somethinginvalid'\n"
        "os.environ['REDIS_PASSWORD']='redis-secret'\n"
        "os.environ['ALLOWED_ORIGINS']='https://a.com,*'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'CORS' in str(e) or '通配符' in str(e):\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_verify_admin_rejects_production_without_hash(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    from src.utils.auth import verify_admin_credentials

    assert verify_admin_credentials("admin", "changeme") is False


def test_protected_api_returns_401_without_jwt(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_INTEGRITY_PATROL", "false")
    db_file = tmp_path / "harden.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.get("/api/stats")
    assert r.status_code == 401


def test_cors_rejects_disallowed_origin(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("AUDIT_INTEGRITY_PATROL", "false")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://trusted.example")
    db_file = tmp_path / "cors.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-which-is-at-least-32b")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "changeme")

    from web.app import create_app

    app, _ = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    r = client.options(
        "/api/health",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    aco = r.headers.get("Access-Control-Allow-Origin")
    assert aco != "https://evil.example"


def test_webhook_metadata_hostname_rejected():
    from src.response.webhook_url import check_webhook_url_safe

    r = check_webhook_url_safe("https://metadata.google.internal/computeMetadata/v1/")
    assert r.ok is False


def test_redis_password_used_by_client_constructor():
    from src.utils.redis_client import RedisClient

    c = RedisClient(host="127.0.0.1", port=63999, password="secret-redis-pass")
    assert c.password == "secret-redis-pass"
