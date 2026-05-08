"""Tenant context and scoped query helpers.

Business data must never trust a client supplied tenant_id. API handlers resolve
the tenant from server-owned auth context, then repositories use these helpers to
apply the same filter/write policy everywhere.
"""
from __future__ import annotations

import os
from typing import Any, Optional, TypeVar

from flask import has_request_context, request
from flask_jwt_extended import get_jwt
from sqlalchemy.orm import Query

from web.models import DEFAULT_TENANT_ID

T = TypeVar("T")


def configured_default_tenant_id() -> str:
    return (os.environ.get("GUARDIAN_DEFAULT_TENANT_ID") or DEFAULT_TENANT_ID).strip()


def login_tenant_id(_username: str) -> str:
    """Resolve login tenant from server configuration, not request JSON."""
    return (os.environ.get("ADMIN_TENANT_ID") or configured_default_tenant_id()).strip()


def current_tenant_id() -> str:
    """Resolve tenant from JWT/API key context with legacy single-tenant fallback."""
    try:
        jwt_tenant = str((get_jwt() or {}).get("tenant_id") or "").strip()
    except RuntimeError:
        jwt_tenant = ""
    if jwt_tenant:
        return jwt_tenant

    if has_request_context():
        api_key_tenant = getattr(request, "guardian_tenant_id", "")
        if api_key_tenant:
            return str(api_key_tenant)

    return configured_default_tenant_id()


def tenant_query(query: Query, model: Any, tenant_id: Optional[str] = None) -> Query:
    return query.filter(model.tenant_id == (tenant_id or current_tenant_id()))


def tenant_get(session: Any, model: Any, ident: Any, tenant_id: Optional[str] = None) -> Any:
    row = session.get(model, ident)
    if row is None:
        return None
    if getattr(row, "tenant_id", None) != (tenant_id or current_tenant_id()):
        return None
    return row


def assign_tenant(row: T, tenant_id: Optional[str] = None) -> T:
    setattr(row, "tenant_id", tenant_id or current_tenant_id())
    return row
