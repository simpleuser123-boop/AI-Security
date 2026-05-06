#!/usr/bin/env python3
"""One-shot deployment readiness check.

The script reads environment variables and, by default, also reads a local
``.env`` file without modifying it. Existing process environment variables win.
It exits with status 0 only when every selected readiness gate passes.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from functools import partial
from typing import Callable, Iterable, Literal
from urllib.parse import urlparse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_MODEL_FILES = (
    "intrusion_rf_v1.pkl",
    "ddos_rf_v1.pkl",
    "web_attack_nb_v1.pkl",
    "anomaly_if_v1.pkl",
    "intrusion_feature_cols_v1.pkl",
    "intrusion_label_encoder_v1.pkl",
    "intrusion_scaler_v1.pkl",
    "intrusion_rf_v1.model_manifest.json",
    "ddos_rf_v1.model_manifest.json",
    "web_attack_nb_v1.model_manifest.json",
    "anomaly_if_v1.model_manifest.json",
)

FORBIDDEN_SECRET_KEYS = {
    "",
    "dev-only-insecure-key-never-use-in-production",
    "test-only-secret-key",
    "changeme",
    "secret",
    "REPLACE_ME_WITH_64_HEX_CHARS",
    "your-secret-key",
    "please-change-me",
}

FORBIDDEN_PASSWORD_VALUES = {
    "admin",
    "guardian",
    "changeme",
    "password",
    "password123",
    "secret",
    "123456",
    "admin123",
}

DEFAULT_DATABASE_URLS = {
    "sqlite:///security.db",
    "sqlite:///data/security.db",
    "sqlite:///:memory:",
}

FORBIDDEN_DATABASE_HOSTS = {
    "",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}

FORBIDDEN_DATABASE_TOKENS = {
    "example",
    "replace",
    "replace_me",
    "replace-with",
    "changeme",
    "test",
    "testing",
    "dev",
    "development",
    "demo",
    "sample",
}

FORBIDDEN_ALLOWED_ORIGINS = {
    "http://localhost",
    "http://localhost:5000",
    "http://127.0.0.1",
    "http://127.0.0.1:5000",
    "http://0.0.0.0",
    "http://0.0.0.0:5000",
}

FORBIDDEN_ORIGIN_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}

FORBIDDEN_ORIGIN_TOKENS = {
    "example",
    "replace",
    "replace_with",
    "change_me",
    "changeme",
    "placeholder",
    "localhost",
}

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}
ReadinessGate = Literal["private-beta", "real-enforcement"]


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    reason: str
    level: str = "PASS"

    @property
    def status(self) -> str:
        if not self.ok:
            return "FAIL"
        if self.level == "WARN":
            return "WARN"
        return "PASS"


def _load_env_file(path: Path) -> int:
    """Load missing KEY=VALUE pairs from an env file. Never writes the file."""
    if not path.exists():
        return 0
    if not path.is_file():
        raise RuntimeError(f"{path} exists but is not a file")

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


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key, default) or "").strip()


def _is_bool(value: str) -> bool:
    return value.lower() in TRUTHY or value.lower() in FALSY


def _path_from_env(key: str, default: str) -> Path:
    raw = _env(key, default)
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def _bool_value(value: str) -> bool:
    return value.lower() in TRUTHY


def _shannon_entropy_bits(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    entropy_per_char = -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )
    return entropy_per_char * len(value)


def _safe_exception_type(exc: Exception) -> str:
    return type(exc).__name__


def _contains_forbidden_database_token(value: str) -> bool:
    tokens = {token for token in re.split(r"[^a-z0-9]+", value.lower()) if token}
    return bool(tokens & FORBIDDEN_DATABASE_TOKENS)


def check_flask_env() -> CheckResult:
    value = _env("FLASK_ENV")
    if value != "production":
        return CheckResult(
            "FLASK_ENV",
            False,
            "must be exactly 'production' for this readiness gate",
        )
    return CheckResult("FLASK_ENV", True, "production")


def check_secret_key() -> CheckResult:
    value = _env("SECRET_KEY")
    if not value:
        return CheckResult("SECRET_KEY", False, "missing")
    if value in FORBIDDEN_SECRET_KEYS:
        return CheckResult("SECRET_KEY", False, "uses a default/example value")
    if len(value) < 32:
        return CheckResult("SECRET_KEY", False, "must be at least 32 characters")
    lowered = value.lower()
    weak_secret_tokens = {"secret", "password", "changeme"}
    weak_tokens = [token for token in weak_secret_tokens if token in lowered]
    if weak_tokens:
        return CheckResult("SECRET_KEY", False, "contains an obvious weak token")
    if len(set(value)) < 12:
        return CheckResult("SECRET_KEY", False, "has too little character variety")
    entropy_bits = _shannon_entropy_bits(value)
    if entropy_bits < 160:
        return CheckResult(
            "SECRET_KEY",
            True,
            "set and non-default, but recommended entropy is at least 160 bits",
            "WARN",
        )
    return CheckResult("SECRET_KEY", True, "strong random-looking value configured")


def check_admin_password_hash() -> CheckResult:
    value = _env("ADMIN_PASSWORD_HASH")
    if not value:
        return CheckResult("ADMIN_PASSWORD_HASH", False, "missing")
    if value.lower() in FORBIDDEN_PASSWORD_VALUES:
        return CheckResult(
            "ADMIN_PASSWORD_HASH",
            False,
            "looks like a default/plain password instead of a hash",
        )
    if not (value.startswith("pbkdf2:") or value.startswith("scrypt:")) or "$" not in value:
        return CheckResult(
            "ADMIN_PASSWORD_HASH",
            False,
            "must be a Werkzeug password hash generated by scripts/generate_admin_password_hash.py",
        )
    try:
        from werkzeug.security import check_password_hash
    except ImportError:
        return CheckResult(
            "ADMIN_PASSWORD_HASH",
            False,
            "cannot validate default passwords because Werkzeug is not installed",
        )
    for candidate in FORBIDDEN_PASSWORD_VALUES:
        try:
            if check_password_hash(value, candidate):
                return CheckResult(
                    "ADMIN_PASSWORD_HASH",
                    False,
                    "hash matches a known default password",
                )
        except ValueError:
            return CheckResult("ADMIN_PASSWORD_HASH", False, "hash format is invalid")
    return CheckResult("ADMIN_PASSWORD_HASH", True, "hash configured")


def check_plain_admin_password() -> CheckResult:
    value = _env("ADMIN_PASSWORD")
    if value:
        reason = "production must not define plaintext ADMIN_PASSWORD"
        if value.lower() in FORBIDDEN_PASSWORD_VALUES:
            reason += "; current value is a known default"
        return CheckResult("ADMIN_PASSWORD", False, reason)
    return CheckResult("ADMIN_PASSWORD", True, "not set")


def check_database_url() -> CheckResult:
    value = _env("DATABASE_URL")
    if not value:
        return CheckResult("DATABASE_URL", False, "missing")
    if value in DEFAULT_DATABASE_URLS:
        return CheckResult("DATABASE_URL", False, "uses a local/default SQLite URL")
    try:
        url = make_url(value)
    except Exception:  # noqa: BLE001
        return CheckResult("DATABASE_URL", False, "invalid database URL format")
    backend = url.get_backend_name()
    if backend == "sqlite":
        return CheckResult(
            "DATABASE_URL",
            False,
            "SQLite is only allowed for development/testing; use PostgreSQL in production",
        )
    if backend != "postgresql":
        return CheckResult(
            "DATABASE_URL",
            False,
            f"production database must be PostgreSQL, got backend={backend!r}",
        )
    host = (url.host or "").strip().lower()
    if host in FORBIDDEN_DATABASE_HOSTS:
        return CheckResult(
            "DATABASE_URL",
            False,
            "must point to a reachable production PostgreSQL host, not localhost/default",
        )
    database_name = (url.database or "").strip().lower()
    if not database_name:
        return CheckResult("DATABASE_URL", False, "database name is missing")
    combined = " ".join(
        part
        for part in (
            host,
            database_name,
            (url.username or "").lower(),
        )
        if part
    )
    if _contains_forbidden_database_token(combined):
        return CheckResult(
            "DATABASE_URL",
            False,
            "looks like an example, development, testing, or placeholder database",
        )
    return CheckResult("DATABASE_URL", True, "PostgreSQL production URL configured")


def check_redis_password() -> CheckResult:
    value = _env("REDIS_PASSWORD")
    if not value:
        return CheckResult("REDIS_PASSWORD", False, "missing")
    if value.lower() in FORBIDDEN_PASSWORD_VALUES:
        return CheckResult("REDIS_PASSWORD", False, "uses a default/weak password")
    if len(value) < 12:
        return CheckResult("REDIS_PASSWORD", False, "must be at least 12 characters")
    return CheckResult("REDIS_PASSWORD", True, "set and non-default")


def check_allowed_origins() -> CheckResult:
    value = _env("ALLOWED_ORIGINS")
    if not value:
        return CheckResult("ALLOWED_ORIGINS", False, "missing")
    origins = [part.strip() for part in value.split(",") if part.strip()]
    if not origins:
        return CheckResult("ALLOWED_ORIGINS", False, "contains no usable origins")
    if any(origin == "*" for origin in origins):
        return CheckResult("ALLOWED_ORIGINS", False, "wildcard '*' is forbidden")
    invalid = [origin for origin in origins if not origin.lower().startswith("https://")]
    if invalid:
        return CheckResult(
            "ALLOWED_ORIGINS",
            False,
            f"production origins must use https://, got: {invalid[0]}",
        )
    for origin in origins:
        parsed = urlparse(origin)
        host = (parsed.hostname or "").strip().lower()
        normalized = origin.lower().rstrip("/")
        if not parsed.scheme or not host:
            return CheckResult("ALLOWED_ORIGINS", False, f"invalid origin URL: {origin}")
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            return CheckResult("ALLOWED_ORIGINS", False, f"origin must not include path/query/fragment: {origin}")
        if normalized in FORBIDDEN_ALLOWED_ORIGINS or host in FORBIDDEN_ORIGIN_HOSTS:
            return CheckResult(
                "ALLOWED_ORIGINS",
                False,
                f"local/default origin is forbidden in production: {origin}",
            )
        if "*" in host:
            return CheckResult("ALLOWED_ORIGINS", False, f"wildcard host is forbidden: {origin}")
        if "." not in host:
            return CheckResult("ALLOWED_ORIGINS", False, f"production origin must use a formal domain: {origin}")
        host_tokens = {token for token in re.split(r"[^a-z0-9_]+", host) if token}
        if host_tokens & FORBIDDEN_ORIGIN_TOKENS:
            return CheckResult(
                "ALLOWED_ORIGINS",
                False,
                f"origin looks like an example or placeholder, not a real Beta/production domain: {origin}",
            )
    return CheckResult("ALLOWED_ORIGINS", True, f"{len(origins)} origin(s) configured")


def check_dry_run(gate: ReadinessGate = "private-beta") -> CheckResult:
    value = _env("DRY_RUN")
    if not value:
        return CheckResult("DRY_RUN", False, "missing; readiness requires an explicit true/false value")
    if not _is_bool(value):
        return CheckResult("DRY_RUN", False, "must be true or false")
    is_dry_run = value.lower() in TRUTHY
    if gate == "real-enforcement":
        if is_dry_run:
            return CheckResult(
                "DRY_RUN",
                False,
                "must be false for real-enforcement readiness",
            )
        return CheckResult("DRY_RUN", True, "false; real enforcement explicitly enabled")
    if is_dry_run:
        return CheckResult("DRY_RUN", True, "true; private Beta runs in non-enforcing mode")
    return CheckResult(
        "DRY_RUN",
        True,
        "false; allowed for private Beta only when real enforcement is separately approved",
        "WARN",
    )


def _check_required_true(key: str, reason: str) -> CheckResult:
    value = _env(key)
    if not value:
        return CheckResult(key, False, f"missing; {reason}")
    if not _is_bool(value):
        return CheckResult(key, False, "must be true or false")
    if not _bool_value(value):
        return CheckResult(key, False, reason)
    return CheckResult(key, True, "true")


def check_response_business_whitelist() -> CheckResult:
    whitelist = _env("RESPONSE_BUSINESS_IP_WHITELIST")
    if not whitelist:
        return CheckResult(
            "RESPONSE_BUSINESS_IP_WHITELIST",
            False,
            "must be non-empty before real enforcement to protect business/LB/monitoring IPs",
        )
    return CheckResult("RESPONSE_BUSINESS_IP_WHITELIST", True, "business whitelist configured")


def check_real_enforcement_approval_required() -> CheckResult:
    return _check_required_true(
        "REAL_ENFORCEMENT_APPROVAL_REQUIRED",
        "real enforcement must have an explicit approval gate",
    )


def check_real_enforcement_audit_verified() -> CheckResult:
    return _check_required_true(
        "REAL_ENFORCEMENT_AUDIT_VERIFIED",
        "real enforcement must verify audit logging and hash-chain evidence",
    )


def check_real_enforcement_rollback_ready() -> CheckResult:
    return _check_required_true(
        "REAL_ENFORCEMENT_ROLLBACK_READY",
        "real enforcement must have a tested rollback/stop-the-bleed path",
    )


def check_real_enforcement_unblock_ready() -> CheckResult:
    return _check_required_true(
        "REAL_ENFORCEMENT_UNBLOCK_READY",
        "real enforcement must have tested manual unblock or equivalent recovery",
    )


def check_real_enforcement_review_required() -> CheckResult:
    return _check_required_true(
        "REAL_ENFORCEMENT_REVIEW_REQUIRED",
        "real enforcement must require post-action review/复盘",
    )


def check_required_runtime_guards() -> CheckResult:
    problems: list[str] = []
    warnings: list[str] = []
    umbrella = _env("RUNTIME_GUARDS_ENABLED")
    if not umbrella:
        problems.append("RUNTIME_GUARDS_ENABLED must be explicitly true")
    elif not _is_bool(umbrella):
        problems.append("RUNTIME_GUARDS_ENABLED must be true or false")
    elif not _bool_value(umbrella):
        problems.append("RUNTIME_GUARDS_ENABLED must be true for private Beta/production")
    for key in ("REQUIRE_REDIS_AVAILABLE", "REQUIRE_MODELS_READY"):
        value = _env(key)
        if not value:
            problems.append(f"{key} must be explicitly true")
            continue
        if not _is_bool(value):
            problems.append(f"{key} must be true or false")
            continue
        if not _bool_value(value):
            problems.append(f"{key} must be true for private Beta/production")
    if problems:
        return CheckResult("RUNTIME_GUARDS", False, "; ".join(problems))
    if warnings:
        return CheckResult("RUNTIME_GUARDS", True, "; ".join(warnings), "WARN")
    return CheckResult(
        "RUNTIME_GUARDS",
        True,
        "RUNTIME_GUARDS_ENABLED, REQUIRE_REDIS_AVAILABLE, and REQUIRE_MODELS_READY are true",
    )


def check_model_dir() -> CheckResult:
    model_dir = _path_from_env("MODEL_DIR", "models/saved")
    if not model_dir.exists():
        return CheckResult("MODEL_DIR", False, f"directory does not exist: {model_dir}")
    if not model_dir.is_dir():
        return CheckResult("MODEL_DIR", False, f"not a directory: {model_dir}")
    try:
        has_content = any(model_dir.iterdir())
    except OSError as exc:
        return CheckResult("MODEL_DIR", False, f"cannot read directory: {exc}")
    if not has_content:
        return CheckResult("MODEL_DIR", False, f"directory is empty: {model_dir}")
    return CheckResult("MODEL_DIR", True, f"directory exists: {model_dir}")


def check_model_files() -> CheckResult:
    model_dir = _path_from_env("MODEL_DIR", "models/saved")
    if not model_dir.exists() or not model_dir.is_dir():
        return CheckResult("MODEL_FILES", False, "model directory is not readable")
    missing = [name for name in REQUIRED_MODEL_FILES if not (model_dir / name).is_file()]
    if missing:
        shown = ", ".join(missing[:4])
        suffix = "" if len(missing) <= 4 else f", ... (+{len(missing) - 4} more)"
        return CheckResult("MODEL_FILES", False, f"missing required artifact(s): {shown}{suffix}")
    unreadable = [name for name in REQUIRED_MODEL_FILES if not os.access(model_dir / name, os.R_OK)]
    if unreadable:
        return CheckResult("MODEL_FILES", False, f"required artifact is not readable: {unreadable[0]}")
    return CheckResult("MODEL_FILES", True, f"{len(REQUIRED_MODEL_FILES)} required artifact(s) present")


def check_log_integrity() -> CheckResult:
    value = _env("LOG_INTEGRITY_ENABLED")
    if not value:
        return CheckResult("LOG_INTEGRITY_ENABLED", False, "missing; production must set true")
    if not _is_bool(value):
        return CheckResult("LOG_INTEGRITY_ENABLED", False, "must be true or false")
    if value.lower() not in TRUTHY:
        return CheckResult("LOG_INTEGRITY_ENABLED", False, "must be true in production")
    return CheckResult("LOG_INTEGRITY_ENABLED", True, "true")


def check_audit_log_dir() -> CheckResult:
    try:
        from src.audit.log_paths import resolve_audit_log_dir
    except ImportError:
        raw_dir = _env("AUDIT_LOG_DIR") or _env("GUARDIAN_LOG_DIR") or _env("LOG_DIR", "logs/production")
    else:
        raw_dir = resolve_audit_log_dir()
    log_dir = Path(raw_dir)
    if not log_dir.is_absolute():
        log_dir = ROOT / log_dir
    if not log_dir.exists():
        return CheckResult("AUDIT_LOG_DIR", False, f"directory does not exist: {log_dir}")
    if not log_dir.is_dir():
        return CheckResult("AUDIT_LOG_DIR", False, f"not a directory: {log_dir}")
    if not os.access(log_dir, os.W_OK):
        return CheckResult("AUDIT_LOG_DIR", False, f"directory is not writable: {log_dir}")
    try:
        with tempfile.NamedTemporaryFile(prefix=".readiness-", dir=log_dir, delete=True):
            pass
    except OSError as exc:
        return CheckResult("AUDIT_LOG_DIR", False, f"write probe failed: {_safe_exception_type(exc)}")
    return CheckResult("AUDIT_LOG_DIR", True, f"directory exists and is writable: {log_dir}")


def check_redis_connectivity() -> CheckResult:
    if _env("GUARDIAN_REDIS_DISABLE_CONNECT").lower() == "true":
        return CheckResult(
            "REDIS_CONNECTIVITY",
            False,
            "GUARDIAN_REDIS_DISABLE_CONNECT=true prevents production Redis validation",
        )
    try:
        import redis  # type: ignore
    except ImportError:
        return CheckResult("REDIS_CONNECTIVITY", False, "redis package is not installed")

    host = _env("REDIS_HOST", "localhost")
    try:
        port = int(_env("REDIS_PORT", "6379"))
        db = int(_env("REDIS_DB", "0"))
        connect_timeout = float(_env("REDIS_CONNECT_TIMEOUT_SEC", "0.5"))
        socket_timeout = float(_env("REDIS_SOCKET_TIMEOUT_SEC", "2.0"))
    except ValueError:
        return CheckResult("REDIS_CONNECTIVITY", False, "Redis port/db/timeout must be numeric")

    try:
        client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=_env("REDIS_PASSWORD") or None,
            socket_connect_timeout=connect_timeout,
            socket_timeout=socket_timeout,
            decode_responses=True,
        )
        if client.ping() is True:
            return CheckResult("REDIS_CONNECTIVITY", True, "Redis ping succeeded")
        return CheckResult("REDIS_CONNECTIVITY", False, "Redis ping returned a non-OK response")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "REDIS_CONNECTIVITY",
            False,
            f"Redis ping failed ({_safe_exception_type(exc)}); check host/port/password/network",
        )


def check_database_connectivity() -> CheckResult:
    value = _env("DATABASE_URL")
    if not value:
        return CheckResult("DB_CONNECTIVITY", False, "DATABASE_URL is missing")
    try:
        url = make_url(value)
    except Exception:  # noqa: BLE001
        return CheckResult("DB_CONNECTIVITY", False, "DATABASE_URL format is invalid")

    connect_args: dict[str, object] = {}
    if url.get_backend_name() == "postgresql":
        try:
            connect_args["connect_timeout"] = int(float(_env("DB_CONNECT_TIMEOUT_SEC", "3")))
        except ValueError:
            return CheckResult("DB_CONNECTIVITY", False, "DB_CONNECT_TIMEOUT_SEC must be numeric")
    try:
        engine = create_engine(value, connect_args=connect_args, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "DB_CONNECTIVITY",
            False,
            f"database SELECT 1 failed ({_safe_exception_type(exc)}); check host/port/credentials/network",
        )
    return CheckResult("DB_CONNECTIVITY", True, "database SELECT 1 succeeded")


def _checks(gate: ReadinessGate) -> Iterable[Callable[[], CheckResult]]:
    checks: list[Callable[[], CheckResult]] = [
        check_flask_env,
        check_secret_key,
        check_admin_password_hash,
        check_plain_admin_password,
        check_database_url,
        check_redis_password,
        check_allowed_origins,
        partial(check_dry_run, gate),
        check_required_runtime_guards,
        check_model_dir,
        check_model_files,
        check_log_integrity,
        check_audit_log_dir,
        check_redis_connectivity,
        check_database_connectivity,
    ]
    if gate == "real-enforcement":
        checks.extend(
            [
                check_response_business_whitelist,
                check_real_enforcement_approval_required,
                check_real_enforcement_audit_verified,
                check_real_enforcement_rollback_ready,
                check_real_enforcement_unblock_ready,
                check_real_enforcement_review_required,
            ]
        )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate AI-Security-Guardian readiness gates."
    )
    parser.add_argument(
        "--gate",
        choices=("private-beta", "real-enforcement", "production-enforcement"),
        default="private-beta",
        help=(
            "readiness gate to evaluate: private-beta allows DRY_RUN=true; "
            "real-enforcement requires DRY_RUN=false plus explicit safety controls"
        ),
    )
    parser.add_argument(
        "--env-file",
        default=str(ROOT / ".env"),
        help="optional env file to read without overriding existing variables (default: .env)",
    )
    parser.add_argument(
        "--skip-env-file",
        action="store_true",
        help="use only the current process environment",
    )
    args = parser.parse_args(argv)

    if not args.skip_env_file:
        env_path = Path(args.env_file)
        if not env_path.is_absolute():
            env_path = ROOT / env_path
        try:
            loaded = _load_env_file(env_path)
        except RuntimeError as exc:
            print(f"[FAIL] ENV_FILE: {exc}")
            return 1
        print(f"Env file: {env_path} ({loaded} value(s) loaded, existing env preserved)")
    else:
        print("Env file: skipped")

    gate: ReadinessGate = (
        "real-enforcement" if args.gate == "production-enforcement" else args.gate
    )

    print(f"AI-Security-Guardian readiness check: {gate}")
    print("-" * 56)

    results = [check() for check in _checks(gate)]
    for result in results:
        print(f"[{result.status}] {result.name}: {result.reason}")

    failures = [result for result in results if not result.ok]
    warnings = [result for result in results if result.status == "WARN"]
    print("-" * 56)
    if failures:
        print(f"Result: FAIL ({len(failures)} failure(s), {len(warnings)} warning(s))")
        return 1

    if warnings:
        print(f"Result: PASS with WARN ({len(warnings)} warning(s))")
        return 0

    print("Result: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
