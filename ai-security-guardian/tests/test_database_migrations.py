from __future__ import annotations

import os
import subprocess
import sys

from sqlalchemy import create_engine, inspect, text


def _migration_env(db_file, repo_root):
    env = os.environ.copy()
    env.update(
        {
            "FLASK_ENV": "testing",
            "DATABASE_URL": f"sqlite:///{db_file.as_posix()}",
            "SECRET_KEY": "test-secret-key-which-is-at-least-32b",
            "ALERT_STREAM_CONSUMER_AUTOSTART": "false",
            "AUDIT_INTEGRITY_PATROL": "false",
            "GUARDIAN_REDIS_DISABLE_CONNECT": "true",
            "PYTHONPATH": str(repo_root),
        }
    )
    return env


def _run_flask_db(args, *, env, repo_root):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "flask",
            "--app",
            "web.migration_app:create_migration_app",
            "db",
            *args,
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def test_flask_migrate_upgrade_creates_schema_and_is_repeatable(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(__file__))
    db_file = tmp_path / "migrated.db"
    env = _migration_env(db_file, repo_root)

    first = _run_flask_db(["upgrade"], env=env, repo_root=repo_root)
    second = _run_flask_db(["upgrade"], env=env, repo_root=repo_root)

    assert "Running upgrade" in (first.stderr + first.stdout)
    assert second.returncode == 0

    from web.database import db
    import web.models  # noqa: F401

    engine = create_engine(f"sqlite:///{db_file.as_posix()}")
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    expected = set(db.metadata.tables.keys())

    assert expected.issubset(existing)
    assert "alembic_version" in existing

    with engine.begin() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        conn.execute(
            text(
                "INSERT INTO settings (key, value, updated_at) "
                "VALUES ('migration_repeatability_probe', '{}', CURRENT_TIMESTAMP)"
            )
        )

    third = _run_flask_db(["upgrade"], env=env, repo_root=repo_root)
    assert third.returncode == 0

    with engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT COUNT(*) FROM settings WHERE key='migration_repeatability_probe'")
            ).scalar_one()
            == 1
        )
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == version
