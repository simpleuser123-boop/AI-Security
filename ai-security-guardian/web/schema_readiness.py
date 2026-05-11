"""Read-only database schema readiness checks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from web.database import db

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class SchemaReadinessResult:
    ok: bool
    detail: str


def expected_business_schema() -> dict[str, set[str]]:
    """Return ORM-managed business tables and their expected columns."""
    import web.models  # noqa: F401

    return {
        table_name: {column.name for column in table.columns}
        for table_name, table in db.metadata.tables.items()
    }


def migration_heads() -> set[str]:
    """Return Alembic head revision(s) from the local migration directory."""
    config = Config(str(ROOT / "migrations" / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return set(ScriptDirectory.from_config(config).get_heads())


def check_schema_readiness(engine) -> SchemaReadinessResult:
    """Verify PostgreSQL has all ORM tables/columns and is at Alembic head.

    This function is intentionally read-only: it never creates tables and never
    runs migrations.
    """
    dialect_name = getattr(getattr(engine, "dialect", None), "name", "")
    if dialect_name != "postgresql":
        return SchemaReadinessResult(
            True,
            f"schema_readiness_skipped_for_{dialect_name or 'unknown'}",
        )

    expected = expected_business_schema()
    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            existing_tables = set(inspector.get_table_names())
            problems: list[str] = []

            missing_tables = sorted(set(expected) - existing_tables)
            if missing_tables:
                problems.append("missing tables: " + ", ".join(missing_tables))

            if "alembic_version" not in existing_tables:
                problems.append("missing alembic_version table")
            else:
                alembic_columns = {
                    column["name"] for column in inspector.get_columns("alembic_version")
                }
                if "version_num" not in alembic_columns:
                    problems.append("alembic_version.version_num column is missing")

            for table_name, expected_columns in sorted(expected.items()):
                if table_name not in existing_tables:
                    continue
                existing_columns = {
                    column["name"] for column in inspector.get_columns(table_name)
                }
                missing_columns = sorted(expected_columns - existing_columns)
                if missing_columns:
                    problems.append(
                        f"{table_name} missing columns: " + ", ".join(missing_columns)
                    )

            heads = migration_heads()
            if "alembic_version" in existing_tables:
                current_revisions = set(
                    conn.execute(text("SELECT version_num FROM alembic_version"))
                    .scalars()
                    .all()
                )
                if current_revisions != heads:
                    current = ", ".join(sorted(current_revisions)) or "(none)"
                    expected_heads = ", ".join(sorted(heads)) or "(none)"
                    problems.append(
                        f"alembic not at head: current={current}; head={expected_heads}"
                    )

            if problems:
                return SchemaReadinessResult(False, "; ".join(problems))

            return SchemaReadinessResult(
                True,
                f"{len(expected)} business table(s) present; alembic head "
                f"{', '.join(sorted(heads))}",
            )
    except Exception as exc:  # noqa: BLE001
        return SchemaReadinessResult(False, f"schema_check_error: {type(exc).__name__}")
