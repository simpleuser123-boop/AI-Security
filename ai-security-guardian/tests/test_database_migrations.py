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


def test_phase_b1_migration_backfills_legacy_rows_to_default_tenant(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(__file__))
    db_file = tmp_path / "phase_b1_legacy.db"
    env = _migration_env(db_file, repo_root)

    _run_flask_db(["upgrade", "20260506_0001"], env=env, repo_root=repo_root)

    engine = create_engine(f"sqlite:///{db_file.as_posix()}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO alerts "
                "(id, timestamp, source_ip, threat_type, level, status, created_at, updated_at) "
                "VALUES "
                "('legacy-alert-1', CURRENT_TIMESTAMP, '1.2.3.4', 'scan', 'low', "
                "'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO settings (key, value, updated_at) "
                "VALUES ('legacy-setting', '{}', CURRENT_TIMESTAMP)"
            )
        )

    _run_flask_db(["upgrade"], env=env, repo_root=repo_root)

    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    assert {
        "tenants",
        "organizations",
        "users",
        "roles",
        "memberships",
        "api_keys",
    }.issubset(existing)
    assert "tenant_id" in {c["name"] for c in inspector.get_columns("alerts")}
    assert "tenant_id" in {c["name"] for c in inspector.get_columns("settings")}

    with engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT tenant_id FROM alerts WHERE id='legacy-alert-1'")
            ).scalar_one()
            == "tenant_default"
        )
        assert (
            conn.execute(
                text("SELECT tenant_id FROM settings WHERE key='legacy-setting'")
            ).scalar_one()
            == "tenant_default"
        )
        assert (
            conn.execute(
                text("SELECT COUNT(*) FROM tenants WHERE id='tenant_default'")
            ).scalar_one()
            == 1
        )


def test_commercial_metering_migration_creates_defaults_and_downgrades_to_b1(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(__file__))
    db_file = tmp_path / "commercial_metering.db"
    env = _migration_env(db_file, repo_root)

    _run_flask_db(["upgrade"], env=env, repo_root=repo_root)

    engine = create_engine(f"sqlite:///{db_file.as_posix()}")
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    assert {
        "plans",
        "license_keys",
        "subscriptions",
        "quotas",
        "usage_meters",
    }.issubset(existing)

    with engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT COUNT(*) FROM plans WHERE id='plan_default_mvp'")
            ).scalar_one()
            == 1
        )
        assert (
            conn.execute(
                text("SELECT COUNT(*) FROM subscriptions WHERE id='sub_default_mvp'")
            ).scalar_one()
            == 1
        )
        assert (
            conn.execute(
                text("SELECT COUNT(*) FROM quotas WHERE tenant_id='tenant_default'")
            ).scalar_one()
            == 8
        )
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "20260507_0005"
        )

    _run_flask_db(["downgrade", "20260507_0002"], env=env, repo_root=repo_root)

    inspector = inspect(engine)
    existing_after_downgrade = set(inspector.get_table_names())
    assert "tenants" in existing_after_downgrade
    assert "plans" not in existing_after_downgrade
    assert "usage_meters" not in existing_after_downgrade
    with engine.begin() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "20260507_0002"
        )


def test_phase_c6_real_response_control_tables_exist(tmp_path):
    repo_root = os.path.dirname(os.path.dirname(__file__))
    db_file = tmp_path / "phase_c6_real_response.db"
    env = _migration_env(db_file, repo_root)

    _run_flask_db(["upgrade"], env=env, repo_root=repo_root)

    engine = create_engine(f"sqlite:///{db_file.as_posix()}")
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    assert {
        "response_approvals",
        "response_whitelist_entries",
        "response_provider_configs",
        "response_drills",
    }.issubset(existing)

    approval_columns = {c["name"] for c in inspector.get_columns("response_approvals")}
    assert {
        "tenant_id",
        "response_action_id",
        "provider_config_id",
        "action_type",
        "target_type",
        "target",
        "ttl_seconds",
        "status",
        "evidence",
        "rollback_plan",
    }.issubset(approval_columns)

    provider_columns = {c["name"] for c in inspector.get_columns("response_provider_configs")}
    assert "credential_ref" in provider_columns
    assert "secret_fingerprint" in provider_columns
    assert "secret" not in provider_columns
    assert "access_key" not in provider_columns
