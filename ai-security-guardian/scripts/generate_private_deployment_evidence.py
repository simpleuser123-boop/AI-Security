#!/usr/bin/env python3
"""Generate a Private Deployment GA backup/restore evidence package.

The package stores hashes, summaries, and customer action templates only. It
never copies ``.env`` contents and it never prints secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.audit.log_paths import normalize_audit_env, resolve_audit_log_dir
from src.audit.security_logger import SecurityLogger

TEMPLATE_FILES = (
    "customer-beta-evidence-index.md",
    "customer-beta-backup-restore-record.md",
)
HEALTH_PATHS = ("/api/health", "/healthz", "/readyz", "/metrics")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load_env_file(path: Path) -> int:
    """Load missing KEY=VALUE pairs from an env file without returning values."""
    if not path.exists():
        return 0
    loaded = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value
        loaded += 1
    return loaded


def _safe_db_url(value: str) -> str:
    if not value:
        return "(missing)"
    try:
        return make_url(value).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001
        return "(invalid DATABASE_URL)"


def _redact_sensitive_text(text_value: str, *, database_url: str = "") -> str:
    """Return command output safe for evidence logs."""
    if not text_value:
        return ""
    redacted = text_value
    replacements: dict[str, str] = {}
    if database_url:
        replacements[database_url] = _safe_db_url(database_url)
        try:
            url = make_url(database_url)
            if url.password:
                replacements[str(url.password)] = "***REDACTED***"
        except Exception:  # noqa: BLE001
            pass

    sensitive_tokens = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "DATABASE_URL")
    for key, value in os.environ.items():
        if not value or len(value) < 4:
            continue
        if any(token in key.upper() for token in sensitive_tokens):
            replacements.setdefault(value, "***REDACTED***")

    for value, replacement in sorted(
        replacements.items(), key=lambda item: len(item[0]), reverse=True
    ):
        redacted = redacted.replace(value, replacement)
    redacted = re.sub(
        r"(?i)\b(password|secret|token|api[_-]?key)(\s*[=:]\s*|\s+)([^\s,;]+)",
        lambda match: f"{match.group(1)}{match.group(2)}***REDACTED***",
        redacted,
    )
    return redacted[:500]


def _latest_migration_revision() -> str:
    versions = ROOT / "migrations" / "versions"
    latest = ""
    for path in sorted(versions.glob("*.py")):
        if path.name.startswith("__"):
            continue
        parts = path.stem.split("_", 2)
        latest = "_".join(parts[:2]) if len(parts) >= 2 else path.stem
    return latest


def _sqlite_alembic_version(db_path: Path) -> str | None:
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT version_num FROM alembic_version LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None


def _query_database_alembic_version(database_url: str) -> dict[str, Any]:
    if not database_url:
        return {"status": "missing_database_url", "revision": None}
    try:
        url = make_url(database_url)
    except Exception:  # noqa: BLE001
        return {"status": "invalid_database_url", "revision": None}

    connect_args: dict[str, Any] = {}
    if url.get_backend_name() == "postgresql":
        try:
            connect_args["connect_timeout"] = int(
                float(os.environ.get("EVIDENCE_DB_CONNECT_TIMEOUT_SEC", "3"))
            )
        except ValueError:
            connect_args["connect_timeout"] = 3

    engine = None
    try:
        engine = create_engine(
            database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).fetchone()
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "unavailable",
            "revision": None,
            "error_type": type(exc).__name__,
        }
    finally:
        if engine is not None:
            engine.dispose()

    revision = str(row[0]) if row else None
    return {
        "status": "collected" if revision else "missing_alembic_version",
        "revision": revision,
    }


def _env_hash_section(out_dir: Path, env_file: Path) -> dict[str, Any]:
    section: dict[str, Any] = {
        "source": str(env_file),
        "status": "missing",
        "sha256": None,
        "evidence_file": "config/env.sha256",
        "note": ".env contents are not copied into the evidence package.",
    }
    target = out_dir / "config" / "env.sha256"
    if env_file.exists() and env_file.is_file():
        digest = _sha256_file(env_file)
        _write_text(target, f"{digest}  {env_file.name}\n")
        section.update(
            {
                "status": "collected",
                "sha256": digest,
                "size_bytes": env_file.stat().st_size,
            }
        )
    else:
        _write_text(
            target,
            "# pending_customer_environment\n"
            "# Run on the customer host without exposing .env contents:\n"
            "sha256sum .env > evidence/config/env.sha256\n",
        )
    return section


def _copy_templates(out_dir: Path) -> list[str]:
    copied: list[str] = []
    for name in TEMPLATE_FILES:
        source = ROOT / "templates" / name
        if not source.exists():
            continue
        dest = out_dir / "templates" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        copied.append(f"templates/{name}")
    return copied


def _model_section(out_dir: Path, model_dir: Path) -> dict[str, Any]:
    sha_file = out_dir / "models" / "model-sha256.txt"
    manifest_file = out_dir / "models" / "model-manifests.json"
    rows: list[tuple[str, str, int]] = []
    manifests: list[dict[str, Any]] = []

    if model_dir.exists() and model_dir.is_dir():
        for path in sorted(p for p in model_dir.rglob("*") if p.is_file()):
            rel = path.relative_to(model_dir).as_posix()
            digest = _sha256_file(path)
            rows.append((digest, rel, path.stat().st_size))
            if path.name.endswith(".model_manifest.json"):
                try:
                    content = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    manifests.append(
                        {"file": rel, "sha256": digest, "parse_error": "invalid JSON"}
                    )
                else:
                    manifests.append(
                        {"file": rel, "sha256": digest, "content": content}
                    )
    if rows:
        _write_text(sha_file, "".join(f"{digest}  {rel}\n" for digest, rel, _ in rows))
        _write_json(manifest_file, manifests)
        return {
            "status": "collected",
            "model_dir": str(model_dir),
            "files_hashed": len(rows),
            "manifests": len(manifests),
            "evidence_files": [
                "models/model-sha256.txt",
                "models/model-manifests.json",
            ],
        }

    _write_text(
        sha_file,
        "# pending_customer_environment\n"
        "# Run where model files are mounted:\n"
        "find models/saved -type f -exec sha256sum {} \\; | sort > evidence/models/model-sha256.txt\n",
    )
    _write_json(manifest_file, [])
    return {
        "status": "pending_customer_environment",
        "model_dir": str(model_dir),
        "files_hashed": 0,
        "evidence_files": [
            "models/model-sha256.txt",
            "models/model-manifests.json",
        ],
    }


def _database_section(
    out_dir: Path,
    *,
    database_url: str,
    db_dump: Path | None,
    allow_pg_dump: bool,
) -> dict[str, Any]:
    db_dir = out_dir / "database"
    dump_sha = db_dir / "db-dump.sha256"
    migration = {
        "local_latest_revision": _latest_migration_revision(),
        "database_current_revision": None,
        "database_current_status": "not_checked",
        "source_database_current_revision": None,
        "source_database_current_status": "not_checked",
        "restore_drill_current_revision": None,
        "restore_drill_current_status": "pending_customer_environment",
        "database_url": _safe_db_url(database_url),
        "note": (
            "database_url is redacted; restore_drill_current_revision must be "
            "filled from the isolated restored database in the customer environment."
        ),
    }
    section: dict[str, Any] = {
        "database_url": _safe_db_url(database_url),
        "dump_status": "pending_customer_environment",
        "dump_sha256": None,
        "dump_file": None,
        "evidence_files": [
            "database/db-dump.sha256",
            "database/migration-version.json",
            "database/postgresql-restore-drill-command.txt",
        ],
    }

    if db_dump:
        if not db_dump.exists() or not db_dump.is_file():
            section["dump_status"] = "missing_provided_dump"
        else:
            digest = _sha256_file(db_dump)
            _write_text(dump_sha, f"{digest}  {db_dump.name}\n")
            section.update(
                {
                    "dump_status": "collected_existing_dump",
                    "dump_sha256": digest,
                    "dump_file": str(db_dump),
                    "dump_size_bytes": db_dump.stat().st_size,
                }
            )
            migration["database_current_status"] = "pending_restore_drill"
            migration["source_database_current_status"] = "not_checked_existing_dump"
            migration["restore_drill_current_status"] = "pending_customer_environment"
        _write_postgresql_restore_drill_command(db_dir)
        section["migration"] = migration
        _write_json(db_dir / "migration-version.json", migration)
        return section

    try:
        url = make_url(database_url) if database_url else None
    except Exception:  # noqa: BLE001
        url = None
        migration["database_current_status"] = "invalid_database_url"
        migration["source_database_current_status"] = "invalid_database_url"

    if not database_url:
        migration["database_current_status"] = "missing_database_url"
        migration["source_database_current_status"] = "missing_database_url"

    if url is not None and url.get_backend_name() == "sqlite":
        db_path = Path(url.database or "")
        if not db_path.is_absolute():
            db_path = ROOT / db_path
        if db_path.exists():
            copied = db_dir / "security.sqlite"
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(db_path, copied)
            digest = _sha256_file(copied)
            _write_text(dump_sha, f"{digest}  security.sqlite\n")
            migration["database_current_revision"] = _sqlite_alembic_version(copied)
            migration["database_current_status"] = (
                "collected"
                if migration["database_current_revision"]
                else "missing_alembic_version"
            )
            migration["source_database_current_revision"] = migration[
                "database_current_revision"
            ]
            migration["source_database_current_status"] = migration[
                "database_current_status"
            ]
            migration["restore_drill_current_revision"] = migration[
                "database_current_revision"
            ]
            migration["restore_drill_current_status"] = "collected_sqlite_copy"
            section.update(
                {
                    "dump_status": "collected_sqlite_copy",
                    "dump_sha256": digest,
                    "dump_file": "database/security.sqlite",
                    "dump_size_bytes": copied.stat().st_size,
                }
            )
        else:
            section["dump_status"] = "sqlite_file_missing"
    elif url is not None and url.get_backend_name() == "postgresql" and allow_pg_dump:
        dump_file = db_dir / "guardian_prod.dump"
        result = _run_pg_dump(url, dump_file)
        section["pg_dump_result"] = result
        version = _query_database_alembic_version(database_url)
        migration["database_current_revision"] = version["revision"]
        migration["database_current_status"] = version["status"]
        migration["source_database_current_revision"] = version["revision"]
        migration["source_database_current_status"] = version["status"]
        if result["status"] == "collected":
            digest = _sha256_file(dump_file)
            _write_text(dump_sha, f"{digest}  guardian_prod.dump\n")
            section.update(
                {
                    "dump_status": "collected_pg_dump",
                    "dump_sha256": digest,
                    "dump_file": "database/guardian_prod.dump",
                    "dump_size_bytes": dump_file.stat().st_size,
                }
            )
        else:
            section["dump_status"] = "pg_dump_failed"
    elif url is not None and url.get_backend_name() == "postgresql":
        migration["database_current_status"] = "pending_customer_environment"
        migration["source_database_current_status"] = "pending_customer_environment"

    if section["dump_sha256"] is None:
        _write_text(
            dump_sha,
            "# pending_customer_environment\n"
            "# Run on a host with real PostgreSQL access. Do not paste the URL into logs:\n"
            "pg_dump \"$DATABASE_URL\" -Fc -f evidence/database/guardian_prod.dump\n"
            "sha256sum evidence/database/guardian_prod.dump > evidence/database/db-dump.sha256\n",
        )

    _write_postgresql_restore_drill_command(db_dir)
    section["migration"] = migration
    _write_json(db_dir / "migration-version.json", migration)
    return section


def _write_postgresql_restore_drill_command(db_dir: Path) -> None:
    _write_text(
        db_dir / "postgresql-restore-drill-command.txt",
        "createdb guardian_restore_drill\n"
        "pg_restore -d guardian_restore_drill evidence/database/guardian_prod.dump\n"
        "psql guardian_restore_drill -c 'SELECT version_num FROM alembic_version;'\n"
        "psql guardian_restore_drill -c '\\dt'\n",
    )


def _run_pg_dump(url: Any, dump_file: Path) -> dict[str, Any]:
    dump_file.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = str(url.password)
    cmd = ["pg_dump", "-Fc", "-f", str(dump_file)]
    if url.host:
        cmd.extend(["-h", str(url.host)])
    if url.port:
        cmd.extend(["-p", str(url.port)])
    if url.username:
        cmd.extend(["-U", str(url.username)])
    if url.database:
        cmd.append(str(url.database))
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            env=env,
            capture_output=True,
            text=True,
            timeout=float(os.environ.get("EVIDENCE_PG_DUMP_TIMEOUT_SEC", "60")),
        )
    except FileNotFoundError:
        return {"status": "pg_dump_missing", "returncode": None}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "returncode": None}
    if completed.returncode != 0:
        return {
            "status": "failed",
            "returncode": completed.returncode,
            "stderr_summary": _redact_sensitive_text(
                (completed.stderr or "").strip(),
                database_url=os.environ.get("DATABASE_URL", ""),
            ),
        }
    return {"status": "collected", "returncode": 0}


def _audit_section(
    out_dir: Path, *, log_dir: str | None, audit_env: str | None
) -> dict[str, Any]:
    resolved_env = normalize_audit_env(audit_env)
    resolved_dir = Path(resolve_audit_log_dir(log_dir, env=resolved_env))
    sl = SecurityLogger(log_dir=str(resolved_dir), enable_integrity=True)
    try:
        result = sl.verify_integrity()
    finally:
        sl.close()
    payload = {
        "status": "collected",
        "audit_env": resolved_env,
        "log_dir": str(resolved_dir),
        "hash_chain": result,
    }
    _write_json(out_dir / "audit" / "hash-chain-verification.json", payload)
    return payload


def _health_section(out_dir: Path, base_url: str) -> dict[str, Any]:
    if not base_url:
        _write_text(
            out_dir / "health" / "health-check-commands.md",
            "# Customer health evidence commands\n\n"
            "Run from the deployment host and store outputs under `evidence/health/`:\n\n"
            "```bash\n"
            "curl -fsS http://127.0.0.1:5000/api/health > evidence/health/api-health.json\n"
            "curl -fsS http://127.0.0.1:5000/healthz > evidence/health/healthz.json\n"
            "curl -fsS http://127.0.0.1:5000/readyz > evidence/health/readyz.json\n"
            "curl -fsS http://127.0.0.1:5000/metrics > evidence/health/metrics.txt\n"
            "```\n",
        )
        return {
            "status": "pending_customer_environment",
            "summary": "base URL not provided; commands generated",
            "evidence_file": "health/health-check-commands.md",
        }

    session = requests.Session()
    results: dict[str, Any] = {}
    for path in HEALTH_PATHS:
        started = datetime.now(timezone.utc)
        try:
            resp = session.get(
                urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
                timeout=10,
            )
            body = resp.text
            content_type = resp.headers.get("content-type", "")
            parsed: Any = None
            if "json" in content_type:
                try:
                    parsed = resp.json()
                except ValueError:
                    parsed = None
            results[path] = {
                "status_code": resp.status_code,
                "ok": 200 <= resp.status_code < 300,
                "content_type": content_type,
                "bytes": len(resp.content),
                "captured_at": started.isoformat(),
                "summary": _summarize_health_body(path, body, parsed),
            }
        except requests.RequestException as exc:
            results[path] = {
                "ok": False,
                "error_type": type(exc).__name__,
                "captured_at": started.isoformat(),
            }
    payload = {
        "status": "collected",
        "base_url": base_url,
        "results": results,
    }
    _write_json(out_dir / "health" / "health-summary.json", payload)
    return payload


def _summarize_health_body(path: str, body: str, parsed: Any) -> Any:
    if path == "/metrics":
        metric_names: list[str] = []
        for line in body.splitlines():
            if not line or line.startswith("#"):
                continue
            metric_names.append(line.split()[0].split("{", 1)[0])
        return {"metric_names": sorted(set(metric_names))[:80], "series_lines": len(metric_names)}
    if isinstance(parsed, dict):
        return {
            key: value
            for key, value in parsed.items()
            if key.lower() not in {"secret", "password", "token", "database_url"}
        }
    return body[:500]


def _customer_actions(sections: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    database = sections["database"]
    migration = database.get("migration") or {}
    if sections["config"]["status"] != "collected":
        actions.append("Generate `.env` SHA256 on the customer host without copying `.env` contents.")
    if database.get("dump_sha256") is None:
        actions.append("Run PostgreSQL `pg_dump -Fc` in the customer environment and store `db-dump.sha256`.")
    if migration.get("restore_drill_current_status") != "collected_sqlite_copy":
        actions.append("Restore the PostgreSQL dump into an isolated drill database and record table list plus migration version.")
    if sections["models"]["status"] != "collected":
        actions.append("Hash the deployed model files from the mounted `models/saved` directory.")
    if sections["health"]["status"] != "collected":
        actions.append("Capture `/api/health`, `/healthz`, `/readyz`, and `/metrics` from the deployed service.")
    return actions


def generate_evidence_package(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_env_file:
        _load_env_file(Path(args.env_file))

    env_file = Path(args.env_file)
    if not env_file.is_absolute():
        env_file = ROOT / env_file
    model_dir = Path(os.environ.get("MODEL_DIR") or args.model_dir)
    if not model_dir.is_absolute():
        model_dir = ROOT / model_dir
    db_dump = Path(args.db_dump) if args.db_dump else None
    if db_dump is not None and not db_dump.is_absolute():
        db_dump = ROOT / db_dump

    sections = {
        "config": _env_hash_section(out_dir, env_file),
        "database": _database_section(
            out_dir,
            database_url=os.environ.get("DATABASE_URL", ""),
            db_dump=db_dump,
            allow_pg_dump=bool(args.allow_pg_dump),
        ),
        "models": _model_section(out_dir, model_dir),
        "audit": _audit_section(out_dir, log_dir=args.audit_log_dir, audit_env=args.audit_env),
        "health": _health_section(out_dir, args.base_url),
    }
    actions = _customer_actions(sections)
    copied_templates = _copy_templates(out_dir)

    manifest = {
        "schema": "ai-security-guardian.private_deployment_evidence.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package_dir": str(out_dir),
        "sections": sections,
        "templates": copied_templates,
        "customer_environment_actions": actions,
        "secret_handling": {
            "env_contents_copied": False,
            "database_url": _safe_db_url(os.environ.get("DATABASE_URL", "")),
        },
    }
    _write_json(out_dir / "manifest.json", manifest)
    _write_text(out_dir / "customer-actions.md", _format_customer_actions(actions))
    _write_text(out_dir / "README.md", _format_readme(manifest))
    return manifest


def _format_customer_actions(actions: list[str]) -> str:
    if not actions:
        return "# Customer Environment Actions\n\nAll required evidence was collected locally.\n"
    lines = ["# Customer Environment Actions", ""]
    lines.extend(f"- {action}" for action in actions)
    lines.append("")
    return "\n".join(lines)


def _format_readme(manifest: dict[str, Any]) -> str:
    sections = manifest["sections"]
    return (
        "# Private Deployment GA Evidence Package\n\n"
        "This package contains hashes, summaries, templates, and customer action records. "
        "It does not contain `.env` contents or plaintext secrets.\n\n"
        "## Structure\n\n"
        "- `config/env.sha256`: `.env` SHA256 only.\n"
        "- `database/db-dump.sha256`: DB dump hash or customer-side command template.\n"
        "- `database/migration-version.json`: local and restored DB migration version evidence.\n"
        "- `models/model-sha256.txt`: model file SHA256 list.\n"
        "- `audit/hash-chain-verification.json`: audit log hash-chain verification result.\n"
        "- `health/health-summary.json` or `health/health-check-commands.md`: health/readyz/metrics evidence.\n"
        "- `templates/`: customer-facing evidence and backup/restore record templates.\n"
        "- `customer-actions.md`: items that still require the customer environment.\n\n"
        "## Current Status\n\n"
        f"- config: {sections['config']['status']}\n"
        f"- database dump: {sections['database']['dump_status']}\n"
        f"- source migration: {sections['database'].get('migration', {}).get('source_database_current_status')}\n"
        f"- restore migration: {sections['database'].get('migration', {}).get('restore_drill_current_status')}\n"
        f"- models: {sections['models']['status']}\n"
        f"- audit hash-chain valid: {sections['audit']['hash_chain'].get('valid')}\n"
        f"- health: {sections['health']['status']}\n"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Private Deployment GA backup/restore evidence package."
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path("reports") / "private-deployment-evidence" / _timestamp()),
    )
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    parser.add_argument("--skip-env-file", action="store_true")
    parser.add_argument("--model-dir", default="models/saved")
    parser.add_argument("--audit-log-dir", default=None)
    parser.add_argument("--audit-env", default=None)
    parser.add_argument("--db-dump", default="", help="existing DB dump file to hash")
    parser.add_argument(
        "--allow-pg-dump",
        action="store_true",
        help="run pg_dump against DATABASE_URL; omitted generates customer-side commands only",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="deployed service URL for /api/health, /healthz, /readyz, /metrics",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    manifest = generate_evidence_package(args)
    print(f"Evidence package: {manifest['package_dir']}")
    print(f"Customer actions: {len(manifest['customer_environment_actions'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
