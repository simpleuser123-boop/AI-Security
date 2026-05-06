"""生产安全硬化：密钥、管理员、JWT、CORS、Webhook SSRF、Redis 密码。"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest
from werkzeug.security import generate_password_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
PRODUCTION_DB_URL = "postgresql+psycopg2://guardian:secret@db.prod.internal:5432/guardian_prod"


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
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
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
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
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
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
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
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
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
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
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


def test_production_get_config_rejects_localhost_origin():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        f"os.environ['DATABASE_URL']='{PRODUCTION_DB_URL}'\n"
        "os.environ['SECRET_KEY']='a' * 40\n"
        "os.environ['ADMIN_PASSWORD_HASH']='pbkdf2:sha256:1$test$somethinginvalid'\n"
        "os.environ['REDIS_PASSWORD']='redis-secret'\n"
        "os.environ['ALLOWED_ORIGINS']='http://localhost:5000'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'Origin' in str(e) or 'https' in str(e) or '本地' in str(e):\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_production_get_config_rejects_sqlite_database_url():
    code = (
        "import os, sys\n"
        "os.environ['FLASK_ENV']='production'\n"
        "os.environ['DATABASE_URL']='sqlite:///:memory:'\n"
        "os.environ['SECRET_KEY']='a' * 40\n"
        "os.environ['ADMIN_PASSWORD_HASH']='pbkdf2:sha256:1$test$somethinginvalid'\n"
        "os.environ['REDIS_PASSWORD']='redis-secret'\n"
        "os.environ['ALLOWED_ORIGINS']='https://app.example.com'\n"
        "import importlib\n"
        "import config.config as cc\n"
        "importlib.reload(cc)\n"
        "try:\n"
        "    cc.get_config()\n"
        "except RuntimeError as e:\n"
        "    if 'SQLite' in str(e) or 'PostgreSQL' in str(e):\n"
        "        sys.exit(0)\n"
        "    raise\n"
        "sys.exit(1)\n"
    )
    p = _run_fresh_config_snippet(code, {})
    assert p.returncode == 0, p.stderr + p.stdout


def test_readiness_check_requires_postgresql(monkeypatch):
    from scripts.check_production_readiness import check_database_url

    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://guardian:secret@db/guardian_prod")
    mysql_result = check_database_url()
    assert mysql_result.ok is False
    assert "PostgreSQL" in mysql_result.reason

    monkeypatch.setenv("DATABASE_URL", PRODUCTION_DB_URL)
    pg_result = check_database_url()
    assert pg_result.ok is True


def test_readiness_check_rejects_localhost_origin(monkeypatch):
    from scripts.check_production_readiness import check_allowed_origins

    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:5000")
    local_result = check_allowed_origins()
    assert local_result.ok is False
    assert "https" in local_result.reason or "forbidden" in local_result.reason

    monkeypatch.setenv("ALLOWED_ORIGINS", "https://console.example.com")
    prod_result = check_allowed_origins()
    assert prod_result.ok is True


def test_readiness_runtime_guard_false_is_warning(monkeypatch):
    from scripts.check_production_readiness import check_required_runtime_guards

    monkeypatch.setenv("REQUIRE_REDIS_AVAILABLE", "false")
    monkeypatch.setenv("REQUIRE_MODELS_READY", "true")

    result = check_required_runtime_guards()
    assert result.ok is True
    assert result.status == "WARN"
    assert "REQUIRE_REDIS_AVAILABLE" in result.reason


def test_readiness_model_files_require_known_artifacts(monkeypatch, tmp_path):
    from scripts.check_production_readiness import REQUIRED_MODEL_FILES, check_model_files

    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    (tmp_path / REQUIRED_MODEL_FILES[0]).write_text("model", encoding="utf-8")

    missing_result = check_model_files()
    assert missing_result.ok is False
    assert "missing required artifact" in missing_result.reason

    for name in REQUIRED_MODEL_FILES:
        (tmp_path / name).write_text("model", encoding="utf-8")

    ready_result = check_model_files()
    assert ready_result.ok is True


def test_readiness_audit_log_dir_write_probe(monkeypatch, tmp_path):
    from scripts.check_production_readiness import check_audit_log_dir

    monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path))
    result = check_audit_log_dir()

    assert result.ok is True
    assert result.status == "PASS"


def test_readiness_connectivity_checks_are_successful_when_services_respond(monkeypatch):
    import redis
    import scripts.check_production_readiness as readiness

    class FakeRedis:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def ping(self):
            return True

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, statement):
            assert str(statement) == "SELECT 1"

    class FakeEngine:
        def connect(self):
            return FakeConnection()

        def dispose(self):
            return None

    def fake_create_engine(url, **kwargs):
        assert "secret" in url
        assert kwargs["connect_args"]["connect_timeout"] == 3
        return FakeEngine()

    monkeypatch.delenv("GUARDIAN_REDIS_DISABLE_CONNECT", raising=False)
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.setenv("REDIS_PORT", "6379")
    monkeypatch.setenv("REDIS_DB", "0")
    monkeypatch.setenv("REDIS_PASSWORD", "secret-redis-password")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://guardian:secret@db.prod.internal:5432/guardian_prod")
    monkeypatch.setattr(redis, "Redis", FakeRedis)
    monkeypatch.setattr(readiness, "create_engine", fake_create_engine)

    assert readiness.check_redis_connectivity().ok is True
    assert readiness.check_database_connectivity().ok is True


def test_readiness_main_reports_warn_fail_and_never_prints_secrets(monkeypatch, tmp_path, capsys):
    import redis
    import scripts.check_production_readiness as readiness

    model_dir = tmp_path / "models"
    audit_dir = tmp_path / "audit"
    model_dir.mkdir()
    audit_dir.mkdir()
    for name in readiness.REQUIRED_MODEL_FILES:
        (model_dir / name).write_text("model", encoding="utf-8")

    class FakeRedis:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def ping(self):
            return True

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, statement):
            return None

    class FakeEngine:
        def connect(self):
            return FakeConnection()

        def dispose(self):
            return None

    secret_key = "0123456789abcdef" * 4
    redis_password = "secret-redis-password"
    admin_password = "admin-strong-password"
    admin_hash = generate_password_hash(admin_password)
    database_url = "postgresql+psycopg2://guardian:secret-db-password@db.prod.internal:5432/guardian_prod"
    env_values = {
        "FLASK_ENV": "production",
        "SECRET_KEY": secret_key,
        "ADMIN_PASSWORD_HASH": admin_hash,
        "DATABASE_URL": database_url,
        "REDIS_HOST": "redis.internal",
        "REDIS_PORT": "6379",
        "REDIS_DB": "0",
        "REDIS_PASSWORD": redis_password,
        "ALLOWED_ORIGINS": "https://console.example.com",
        "DRY_RUN": "false",
        "REQUIRE_REDIS_AVAILABLE": "false",
        "REQUIRE_MODELS_READY": "true",
        "MODEL_DIR": str(model_dir),
        "LOG_INTEGRITY_ENABLED": "true",
        "AUDIT_LOG_DIR": str(audit_dir),
    }
    for key, value in env_values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("GUARDIAN_REDIS_DISABLE_CONNECT", raising=False)
    monkeypatch.setattr(redis, "Redis", FakeRedis)
    monkeypatch.setattr(readiness, "create_engine", lambda *args, **kwargs: FakeEngine())

    rc = readiness.main(["--skip-env-file"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "[WARN] RUNTIME_GUARDS" in out
    assert secret_key not in out
    assert redis_password not in out
    assert admin_password not in out
    assert admin_hash not in out
    assert "secret-db-password" not in out


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
