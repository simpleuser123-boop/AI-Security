"""
IOC 持久化与多源合并（数据库层）。

与 ``web.models.IOC`` 对齐；不记录 API Key；会话由调用方管理（commit/rollback）。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Set

_CVE_CANON = re.compile(r"^(CVE-\d{4}-\d{4,})$", re.IGNORECASE)

from sqlalchemy.orm import Session


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_value(ioc_type: str, value: str) -> str:
    t = ioc_type.lower().strip()
    v = value.strip()
    if t == "domain":
        return v.lower()
    if t == "file_hash":
        return v.lower()
    if t == "cve":
        m = _CVE_CANON.match(v)
        return m.group(1).upper() if m else v.upper()
    return v


def merge_source_lists(a: Optional[Sequence[str]], b: Optional[Sequence[str]]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for src in list(a or ()) + list(b or ()):
        s = (src or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


class IOCRepository:
    """Flask-SQLAlchemy ``Session`` 上的 IOC CRUD / 合并。"""

    def __init__(self, session: Session, *, tenant_id: Optional[str] = None) -> None:
        self.session = session
        if tenant_id is None:
            try:
                from web.tenant import current_tenant_id

                tenant_id = current_tenant_id()
            except Exception:  # noqa: BLE001
                from web.models import DEFAULT_TENANT_ID

                tenant_id = DEFAULT_TENANT_ID
        self.tenant_id = str(tenant_id)

    def _model(self):  # lazy import：避免无 Flask 时加载失败
        from web.models import IOC

        return IOC

    def find_active_dict(
        self, ioc_type: str, value: str, *, now: Optional[datetime] = None
    ) -> Optional[Dict[str, Any]]:
        IOC = self._model()
        now = now or utc_now()
        canon = _canonical_value(ioc_type, value)
        row = (
            self.session.query(IOC)
            .filter(
                IOC.tenant_id == self.tenant_id,
                IOC.ioc_type == ioc_type,
                IOC.value == canon,
            )
            .one_or_none()
        )
        if row is None:
            return None
        if row.expires_at is not None and row.expires_at <= now:
            return None
        return self._row_to_dict(row)

    def list_active_dicts(self, *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        IOC = self._model()
        now = now or utc_now()
        q = self.session.query(IOC).filter(
            IOC.tenant_id == self.tenant_id,
            (IOC.expires_at.is_(None)) | (IOC.expires_at > now),
        )
        return [self._row_to_dict(r) for r in q.all()]

    @staticmethod
    def _row_to_dict(row: Any) -> Dict[str, Any]:
        return {
            "id": row.id,
            "ioc_type": row.ioc_type,
            "value": row.value,
            "sources": list(row.sources or []),
            "reason": row.reason or "",
            "note": row.note or "",
            "score": row.score,
            "ttl_seconds": row.ttl_seconds,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "expires_at": row.expires_at,
            "metadata": row.ioc_meta,
            "hits": row.hits,
            "added_at": row.added_at,
            "updated_at": row.updated_at,
        }

    def upsert_merge(
        self,
        *,
        ioc_type: str,
        value: str,
        source: str,
        score: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        reason: Optional[str] = None,
        note: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """同 type+value 合并 sources，保留更高 score 与更近的过期时间（更长 TTL）。"""
        IOC = self._model()
        now = now or utc_now()
        canon = _canonical_value(ioc_type, value)
        src = (source or "manual").strip() or "manual"
        row = (
            self.session.query(IOC)
            .filter(
                IOC.tenant_id == self.tenant_id,
                IOC.ioc_type == ioc_type,
                IOC.value == canon,
            )
            .one_or_none()
        )

        def _merge_expires(
            existing_exp: Optional[datetime], new_ttl: Optional[int]
        ) -> Optional[datetime]:
            """合并后保留更晚的 ``expires_at``（更长有效期）。"""
            cand: Optional[datetime] = None
            if new_ttl is not None and new_ttl > 0:
                cand = now + timedelta(seconds=int(new_ttl))
            if existing_exp is None:
                return cand
            if cand is None:
                return existing_exp
            return cand if cand >= existing_exp else existing_exp

        meta_merged: Optional[Dict[str, Any]] = None
        if row is None:
            exp = _merge_expires(None, ttl_seconds)
            meta_merged = dict(metadata) if metadata else None
            row = IOC(
                id=uuid.uuid4().hex,
                tenant_id=self.tenant_id,
                ioc_type=ioc_type,
                value=canon,
                sources=[src],
                reason=reason or "",
                note=note or "",
                score=score,
                ttl_seconds=ttl_seconds,
                first_seen=now,
                last_seen=now,
                expires_at=exp,
                ioc_meta=meta_merged,
                hits=0,
            )
            self.session.add(row)
        else:
            row.sources = merge_source_lists(row.sources, [src])
            if reason:
                row.reason = reason
            if note is not None:
                row.note = note
            if score is not None:
                if row.score is None or score > int(row.score):
                    row.score = int(score)
            if ttl_seconds is not None:
                if row.ttl_seconds is None or ttl_seconds > int(row.ttl_seconds or 0):
                    row.ttl_seconds = int(ttl_seconds)
            row.expires_at = _merge_expires(row.expires_at, ttl_seconds)
            row.last_seen = now
            if row.first_seen is None:
                row.first_seen = now
            if metadata:
                base = row.ioc_meta if isinstance(row.ioc_meta, dict) else {}
                merged = {**base, **metadata}
                row.ioc_meta = merged
                meta_merged = merged

        self.session.flush()
        return self._row_to_dict(row)

    def delete(self, ioc_type: str, value: str) -> bool:
        IOC = self._model()
        canon = _canonical_value(ioc_type, value)
        row = (
            self.session.query(IOC)
            .filter(
                IOC.tenant_id == self.tenant_id,
                IOC.ioc_type == ioc_type,
                IOC.value == canon,
            )
            .one_or_none()
        )
        if row is None:
            return False
        self.session.delete(row)
        return True
