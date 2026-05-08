"""
响应动作与调度任务的数据库持久化（Flask-SQLAlchemy，独立于 Web 请求上下文）。
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from flask import Flask

from web.database import db


def _require_ttl_for_real_ban(
    *,
    action_type: str,
    status: str,
    dry_run: bool,
    scheduled_unblock_at: Optional[datetime],
) -> None:
    if (
        action_type == "ban_ip"
        and status == "executed"
        and not dry_run
        and scheduled_unblock_at is None
    ):
        raise ValueError("real ban_ip executed action requires scheduled_unblock_at")
    if (
        action_type == "ban_ip"
        and status == "executed"
        and not dry_run
        and scheduled_unblock_at is not None
    ):
        now = datetime.now(timezone.utc)
        compare_at = scheduled_unblock_at
        if compare_at.tzinfo is None:
            compare_at = compare_at.replace(tzinfo=timezone.utc)
        if compare_at <= now:
            raise ValueError("real ban_ip executed action requires future scheduled_unblock_at")


@dataclass
class ScheduleTaskRow:
    id: int
    tenant_id: str
    task_type: str
    alert_id: Optional[str]
    payload: Dict[str, Any]
    run_at: datetime
    status: str
    attempt_count: int
    max_attempts: int
    related_response_action_id: Optional[int]
    last_error: Optional[str] = None


class ResponsePersistence:
    """最小持久化接口。"""

    def save_response_action(
        self,
        *,
        alert_id: Optional[str],
        action_type: str,
        target: Optional[str],
        status: str,
        dry_run: bool,
        error: Optional[str] = None,
        scheduled_unblock_at: Optional[datetime] = None,
        meta: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        operator: Optional[str] = None,
        trigger_source: Optional[str] = None,
    ) -> int:
        raise NotImplementedError

    def enqueue_schedule_task(
        self,
        *,
        task_type: str,
        run_at: datetime,
        alert_id: Optional[str],
        payload: Dict[str, Any],
        related_response_action_id: Optional[int] = None,
        max_attempts: int = 5,
    ) -> int:
        raise NotImplementedError

    def fetch_due_tasks(self, *, before: datetime, limit: int = 50) -> List[ScheduleTaskRow]:
        raise NotImplementedError

    def update_schedule_task(
        self,
        task_id: int,
        *,
        status: str,
        attempt_count: Optional[int] = None,
        last_error: Optional[str] = None,
        run_at: Optional[datetime] = None,
    ) -> None:
        raise NotImplementedError

    def append_audit_db_event(
        self,
        *,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        resource_id: Optional[str] = None,
        actor: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """可选写入 audit_events 表。"""
        raise NotImplementedError

    @property
    def tenant_id(self) -> str:
        raise NotImplementedError


class NullResponsePersistence(ResponsePersistence):
    @property
    def tenant_id(self) -> str:
        from web.tenant import configured_default_tenant_id

        return configured_default_tenant_id()

    def save_response_action(
        self,
        *,
        alert_id: Optional[str],
        action_type: str,
        target: Optional[str],
        status: str,
        dry_run: bool,
        error: Optional[str] = None,
        scheduled_unblock_at: Optional[datetime] = None,
        meta: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        operator: Optional[str] = None,
        trigger_source: Optional[str] = None,
    ) -> int:
        _require_ttl_for_real_ban(
            action_type=action_type,
            status=status,
            dry_run=dry_run,
            scheduled_unblock_at=scheduled_unblock_at,
        )
        return 0

    def enqueue_schedule_task(
        self,
        *,
        task_type: str,
        run_at: datetime,
        alert_id: Optional[str],
        payload: Dict[str, Any],
        related_response_action_id: Optional[int] = None,
        max_attempts: int = 5,
    ) -> int:
        return 0

    def fetch_due_tasks(self, *, before: datetime, limit: int = 50) -> List[ScheduleTaskRow]:
        return []

    def update_schedule_task(
        self,
        task_id: int,
        *,
        status: str,
        attempt_count: Optional[int] = None,
        last_error: Optional[str] = None,
        run_at: Optional[datetime] = None,
    ) -> None:
        return

    def append_audit_db_event(
        self,
        *,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        resource_id: Optional[str] = None,
        actor: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        return


class FlaskSqlalchemyResponsePersistence(ResponsePersistence):
    """使用独立 Flask app 上下文绑定 SQLAlchemy。"""

    def __init__(self, app: Flask, tenant_id: Optional[str] = None) -> None:
        self._app = app
        from web.tenant import configured_default_tenant_id

        self._tenant_id = str(tenant_id or configured_default_tenant_id()).strip()
        if not self._tenant_id:
            raise ValueError("tenant_id is required")

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @contextmanager
    def _write(self) -> Iterator[None]:
        with self._app.app_context():
            try:
                yield
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise

    @contextmanager
    def _read(self) -> Iterator[None]:
        with self._app.app_context():
            try:
                yield
            finally:
                db.session.rollback()

    def save_response_action(
        self,
        *,
        alert_id: Optional[str],
        action_type: str,
        target: Optional[str],
        status: str,
        dry_run: bool,
        error: Optional[str] = None,
        scheduled_unblock_at: Optional[datetime] = None,
        meta: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        operator: Optional[str] = None,
        trigger_source: Optional[str] = None,
    ) -> int:
        from web.models import ResponseAction
        from web.models import Alert
        from web.billing import (
            METRIC_RESPONSE_ACTIONS,
            ensure_quota,
            record_usage,
        )

        _require_ttl_for_real_ban(
            action_type=action_type,
            status=status,
            dry_run=dry_run,
            scheduled_unblock_at=scheduled_unblock_at,
        )

        action_meta = dict(meta or {})
        action_meta.setdefault("reason", reason or "")
        action_meta.setdefault("operator", operator or "")
        action_meta.setdefault("trigger_source", trigger_source or "")
        with self._write():
            if alert_id:
                # tenant-scan: allow tenant checked immediately after load.
                alert = db.session.get(Alert, alert_id)
                if alert is None or alert.tenant_id != self._tenant_id:
                    raise ValueError("alert tenant mismatch for response action")
            ensure_quota(db.session, self._tenant_id, METRIC_RESPONSE_ACTIONS, requested=1)
            row = ResponseAction(
                tenant_id=self._tenant_id,
                alert_id=alert_id,
                action_type=action_type,
                target=target,
                status=status,
                dry_run=dry_run,
                error=error,
                scheduled_unblock_at=scheduled_unblock_at,
                meta=action_meta,
            )
            db.session.add(row)
            db.session.flush()
            rid = int(row.id)
            record_usage(
                db.session,
                self._tenant_id,
                METRIC_RESPONSE_ACTIONS,
                actor=operator or "response_persistence",
                resource_type="response_action",
                resource_id=str(rid),
            )
        return rid

    def enqueue_schedule_task(
        self,
        *,
        task_type: str,
        run_at: datetime,
        alert_id: Optional[str],
        payload: Dict[str, Any],
        related_response_action_id: Optional[int] = None,
        max_attempts: int = 5,
    ) -> int:
        from web.models import ResponseScheduleTask
        from web.models import Alert

        with self._write():
            if alert_id:
                # tenant-scan: allow tenant checked immediately after load.
                alert = db.session.get(Alert, alert_id)
                if alert is None or alert.tenant_id != self._tenant_id:
                    raise ValueError("alert tenant mismatch for schedule task")
            task_payload = dict(payload or {})
            task_tenant = str(task_payload.get("tenant_id") or self._tenant_id).strip()
            if task_tenant != self._tenant_id:
                raise ValueError("payload tenant_id does not match scheduler tenant")
            task_payload["tenant_id"] = self._tenant_id
            row = ResponseScheduleTask(
                tenant_id=self._tenant_id,
                task_type=task_type,
                alert_id=alert_id,
                payload=task_payload,
                run_at=run_at,
                status="pending",
                max_attempts=max_attempts,
                related_response_action_id=related_response_action_id,
            )
            db.session.add(row)
            db.session.flush()
            tid = int(row.id)
        return tid

    def fetch_due_tasks(self, *, before: datetime, limit: int = 50) -> List[ScheduleTaskRow]:
        from web.models import ResponseScheduleTask

        with self._read():
            q = (
                db.session.query(ResponseScheduleTask)
                .filter(
                    ResponseScheduleTask.status == "pending",
                    ResponseScheduleTask.tenant_id == self._tenant_id,
                    ResponseScheduleTask.run_at <= before,
                )
                .order_by(ResponseScheduleTask.run_at.asc())
                .limit(limit)
            )
            rows = list(q)
            out = [
                ScheduleTaskRow(
                    id=int(r.id),
                    tenant_id=r.tenant_id,
                    task_type=r.task_type,
                    alert_id=r.alert_id,
                    payload=dict(r.payload or {}),
                    run_at=r.run_at,
                    status=r.status,
                    attempt_count=int(r.attempt_count or 0),
                    max_attempts=int(r.max_attempts or 5),
                    related_response_action_id=r.related_response_action_id,
                    last_error=r.last_error,
                )
                for r in rows
            ]
        return out

    def update_schedule_task(
        self,
        task_id: int,
        *,
        status: str,
        attempt_count: Optional[int] = None,
        last_error: Optional[str] = None,
        run_at: Optional[datetime] = None,
    ) -> None:
        from web.models import ResponseScheduleTask

        with self._write():
            # tenant-scan: allow tenant checked immediately after load.
            row = db.session.get(ResponseScheduleTask, task_id)
            if row is None or row.tenant_id != self._tenant_id:
                return
            row.status = status
            if attempt_count is not None:
                row.attempt_count = attempt_count
            if last_error is not None:
                row.last_error = last_error
            if run_at is not None:
                row.run_at = run_at

    def append_audit_db_event(
        self,
        *,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        resource_id: Optional[str] = None,
        actor: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        from web.models import AuditEvent

        with self._write():
            db.session.add(
                AuditEvent(
                    tenant_id=self._tenant_id,
                    event_type=event_type,
                    actor=actor,
                    resource_type="response",
                    resource_id=resource_id,
                    payload=payload or {},
                    ip_address=ip_address,
                )
            )


def build_persistence_app(database_url: str) -> Flask:
    """创建仅用于响应持久化的 Flask 应用（注册 ORM）。"""
    import web.models  # noqa: F401 - register ORM mappers

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "response-persistence-key")
    db.init_app(app)
    return app


def create_response_persistence_from_env() -> ResponsePersistence:
    uri = os.environ.get("DATABASE_URL", "").strip()
    if not uri:
        return NullResponsePersistence()
    app = build_persistence_app(uri)
    return FlaskSqlalchemyResponsePersistence(
        app,
        tenant_id=os.environ.get("RESPONSE_WORKER_TENANT_ID") or None,
    )
