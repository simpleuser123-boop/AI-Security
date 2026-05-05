"""Audit log path helpers.

The project keeps audit logs physically separated by environment so test,
development, staging, and production records cannot be mixed accidentally.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_ENV_ALIASES = {
    "test": "test",
    "testing": "test",
    "dev": "dev",
    "development": "dev",
    "stage": "staging",
    "staging": "staging",
    "prod": "production",
    "production": "production",
}

VALID_AUDIT_ENVS = ("test", "dev", "staging", "production")


def normalize_audit_env(env: Optional[str] = None) -> str:
    """Return the canonical audit environment name."""
    raw = (
        env
        or os.environ.get("AUDIT_ENV")
        or os.environ.get("APP_ENV")
        or os.environ.get("FLASK_ENV")
        or os.environ.get("ENVIRONMENT")
        or "development"
    )
    key = str(raw).strip().lower()
    return _ENV_ALIASES.get(key, "dev")


def resolve_audit_log_dir(
    log_dir: Optional[str] = None,
    *,
    env: Optional[str] = None,
    base_dir: str = "logs",
) -> str:
    """Resolve the environment-specific audit log directory.

    Explicit directories always win. Otherwise, AUDIT_LOG_DIR/GUARDIAN_LOG_DIR
    can override the derived path. The default is ``logs/<env>``.
    """
    explicit = log_dir or os.environ.get("AUDIT_LOG_DIR") or os.environ.get(
        "GUARDIAN_LOG_DIR"
    )
    if explicit:
        return str(Path(explicit))
    return str(Path(base_dir) / normalize_audit_env(env))
