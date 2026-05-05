"""Archive the current security audit log and create a fresh integrity baseline."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.audit.log_paths import normalize_audit_env, resolve_audit_log_dir
from src.audit.security_logger import SecurityLogger


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count_non_empty_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def archive_security_log(
    log_dir: str | None = None,
    reason: str = "manual",
    *,
    env: str | None = None,
    operator: str | None = None,
    ticket: str | None = None,
    legacy_log: str | None = None,
) -> dict:
    audit_env = normalize_audit_env(env)
    resolved = Path(resolve_audit_log_dir(log_dir, env=audit_env))
    resolved.mkdir(parents=True, exist_ok=True)
    active_log = resolved / "security.log"
    archive_dir = resolved / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    legacy_path = Path(legacy_log) if legacy_log else Path("logs") / "security.log"
    source_log = active_log
    legacy_source = False
    if log_dir is None and (
        not active_log.exists() or active_log.stat().st_size == 0
    ) and legacy_path.exists() and legacy_path.resolve() != active_log.resolve():
        source_log = legacy_path
        legacy_source = True

    stamp = _timestamp()
    archived_file = archive_dir / f"security-{stamp}.log"
    metadata_file = archive_dir / f"security-{stamp}.json"

    result = {
        "audit_env": audit_env,
        "log_dir": str(resolved),
        "active_log": str(active_log),
        "source_log": str(source_log),
        "legacy_source": legacy_source,
        "archived_log": None,
        "metadata_file": None,
        "pre_archive_integrity": None,
        "baseline_log": str(active_log),
        "entries_archived": 0,
        "archive_sha256": None,
        "baseline_valid": True,
    }

    if source_log.exists() and source_log.stat().st_size > 0:
        inspector = SecurityLogger(log_dir=str(resolved), enable_integrity=True)
        result["pre_archive_integrity"] = inspector.verify_integrity(str(source_log))
        shutil.copy2(source_log, archived_file)
        result["archived_log"] = str(archived_file)
        result["metadata_file"] = str(metadata_file)
        result["entries_archived"] = _count_non_empty_lines(source_log)
        result["archive_sha256"] = _sha256_file(archived_file)
        metadata = {
            "schema": "ai-security-guardian.audit_archive.v1",
            "audit_env": audit_env,
            "archived_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "operator": operator,
            "ticket": ticket,
            "source": str(source_log),
            "archive": str(archived_file),
            "legacy_source": legacy_source,
            "entries_archived": result["entries_archived"],
            "source_sha256": _sha256_file(source_log),
            "archive_sha256": result["archive_sha256"],
            "pre_archive_integrity": result["pre_archive_integrity"],
        }
        metadata_file.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # Create a clean baseline chain in the same environment-specific directory.
    active_log.write_text("", encoding="utf-8")
    baseline_logger = SecurityLogger(log_dir=str(resolved), enable_integrity=True)
    baseline_logger.log_system(
        f"audit log baseline rebuilt reason={reason}", level="info"
    )
    baseline_integrity = baseline_logger.verify_integrity(str(active_log))
    result["baseline_valid"] = bool(baseline_integrity.get("valid"))
    result["baseline_integrity"] = baseline_integrity
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Archive security audit log and rebuild integrity baseline"
    )
    parser.add_argument("--log-dir", default=None, help="Target audit log directory")
    parser.add_argument(
        "--env", default=None, help="Audit env: test/dev/staging/production"
    )
    parser.add_argument("--reason", default="manual", help="Archive reason")
    parser.add_argument("--operator", default=None, help="Operator name or account")
    parser.add_argument("--ticket", default=None, help="Change/incident ticket id")
    parser.add_argument(
        "--legacy-log",
        default=None,
        help="Legacy security.log path to migrate when the env log is empty",
    )
    args = parser.parse_args()
    result = archive_security_log(
        args.log_dir,
        args.reason,
        env=args.env,
        operator=args.operator,
        ticket=args.ticket,
        legacy_log=args.legacy_log,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["baseline_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
