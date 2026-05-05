"""
响应动作与调度任务的数据库持久化（Flask-SQLAlchemy，独立于 Web 请求上下文）。
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from flask import Flask

from web.database import db


@dataclass
class ScheduleTaskRow:
    id: int
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


class NullResponsePersistence(ResponsePersistence):
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

    def __init__(self, app: Flask) -> None:
        self._app = app

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

        action_meta = dict(meta or {})
        action_meta.setdefault("reason", reason or "")
        action_meta.setdefault("operator", operator or "")
        action_meta.setdefault("trigger_source", trigger_source or "")
        with self._write():
            row = ResponseAction(
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

        with self._write():
            row = ResponseScheduleTask(
                task_type=task_type,
                alert_id=alert_id,
                payload=payload,
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
                    ResponseScheduleTask.run_at <= before,
                )
                .order_by(ResponseScheduleTask.run_at.asc())
                .limit(limit)
            )
            rows = list(q)
            out = [
                ScheduleTaskRow(
                    id=int(r.id),
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
            row = db.session.get(ResponseScheduleTask, task_id)
            if row is None:
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
    return FlaskSqlalchemyResponsePersistence(app)
