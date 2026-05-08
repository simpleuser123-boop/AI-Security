"""Shared real-enforcement admission checks.

These helpers intentionally validate only gate metadata and operator evidence.
They never call response providers.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Mapping, Optional

REAL_ENFORCEMENT_GATE_ENV = "REAL_ENFORCEMENT_GATE"
REAL_ENFORCEMENT_GATE_VALUE = "real-enforcement"

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}

REQUIRED_REAL_ENFORCEMENT_TRUE_ENV: tuple[tuple[str, str], ...] = (
    (
        "REAL_ENFORCEMENT_APPROVAL_REQUIRED",
        "operator approval workflow evidence is required before real response",
    ),
    (
        "REAL_ENFORCEMENT_AUDIT_VERIFIED",
        "audit log and hash-chain evidence must be verified",
    ),
    (
        "REAL_ENFORCEMENT_ROLLBACK_READY",
        "tested rollback or stop-the-bleed path evidence is required",
    ),
    (
        "REAL_ENFORCEMENT_UNBLOCK_READY",
        "tested manual or scheduled unblock evidence is required",
    ),
    (
        "REAL_ENFORCEMENT_REVIEW_REQUIRED",
        "post-action review requirement evidence is required",
    ),
)


def _get_env(environ: Optional[Mapping[str, str]], key: str) -> str:
    source = environ if environ is not None else os.environ
    return str(source.get(key, "") or "").strip()


def is_boolish(value: str) -> bool:
    return value.lower() in TRUTHY or value.lower() in FALSY


def is_truthy(value: str) -> bool:
    return value.lower() in TRUTHY


def real_enforcement_env_failures(
    *,
    gate_value: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    include_gate: bool = True,
) -> List[Dict[str, Any]]:
    """Return missing/invalid env prerequisites for real enforcement."""

    failures: List[Dict[str, Any]] = []
    if include_gate:
        value = _get_env(environ, REAL_ENFORCEMENT_GATE_ENV) if gate_value is None else gate_value
        if value.strip().lower() != REAL_ENFORCEMENT_GATE_VALUE:
            failures.append(
                {
                    "code": "real_enforcement_gate_required",
                    "name": REAL_ENFORCEMENT_GATE_ENV,
                    "required": f"{REAL_ENFORCEMENT_GATE_ENV}={REAL_ENFORCEMENT_GATE_VALUE}",
                    "current": value,
                    "message": (
                        "missing runtime gate marker; set "
                        f"{REAL_ENFORCEMENT_GATE_ENV}={REAL_ENFORCEMENT_GATE_VALUE}"
                    ),
                }
            )
    for key, evidence in REQUIRED_REAL_ENFORCEMENT_TRUE_ENV:
        value = _get_env(environ, key)
        if not value:
            failures.append(
                {
                    "code": key.lower(),
                    "name": key,
                    "required": f"{key}=true",
                    "current": "",
                    "message": f"missing env {key}=true; {evidence}",
                }
            )
            continue
        if not is_boolish(value):
            failures.append(
                {
                    "code": key.lower(),
                    "name": key,
                    "required": f"{key}=true",
                    "current": value,
                    "message": f"invalid env {key}; must be true or false",
                }
            )
            continue
        if not is_truthy(value):
            failures.append(
                {
                    "code": key.lower(),
                    "name": key,
                    "required": f"{key}=true",
                    "current": value,
                    "message": f"env {key} must be true; {evidence}",
                }
            )
    return failures


def first_failure_code(failures: Iterable[Mapping[str, Any]], default: str) -> str:
    for failure in failures:
        code = str(failure.get("code") or "").strip()
        if code:
            return code
    return default
