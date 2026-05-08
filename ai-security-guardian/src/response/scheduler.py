"""
ResponseScheduler：定时解封、通知失败重试、任务持久化/内存降级。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from src.response.persistence import (
    NullResponsePersistence,
    ResponsePersistence,
    ScheduleTaskRow,
)

if TYPE_CHECKING:
    from src.response.responder import SecurityResponder

logger = logging.getLogger(__name__)

TASK_SCHEDULED_UNBLOCK = "scheduled_unblock"
TASK_NOTIFY_RETRY = "notify_retry"


class ResponseScheduler:
    """当持久化为 Null 时使用进程内队列；否则读写 response_schedule_tasks 表。"""

    def __init__(self, persistence: ResponsePersistence) -> None:
        self._persist = persistence
        self._mem_tasks: List[ScheduleTaskRow] = []
        self._mem_seq = 1

    def _use_memory(self) -> bool:
        return isinstance(self._persist, NullResponsePersistence)

    @property
    def tenant_id(self) -> str:
        return self._persist.tenant_id

    def _payload_with_tenant(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(payload)
        tid = str(out.get("tenant_id") or self.tenant_id).strip()
        if tid != self.tenant_id:
            raise ValueError("task payload tenant_id does not match scheduler tenant")
        out["tenant_id"] = self.tenant_id
        return out

    def schedule_unblock(
        self,
        *,
        ip: str,
        run_at: datetime,
        dry_run: bool,
        alert_id: Optional[str],
        related_response_action_id: Optional[int],
    ) -> int:
        payload: Dict[str, Any] = self._payload_with_tenant({"ip": ip, "dry_run": dry_run})
        if self._use_memory():
            tid = self._mem_seq
            self._mem_seq += 1
            self._mem_tasks.append(
                ScheduleTaskRow(
                    id=tid,
                    tenant_id=self.tenant_id,
                    task_type=TASK_SCHEDULED_UNBLOCK,
                    alert_id=alert_id,
                    payload=payload,
                    run_at=run_at,
                    status="pending",
                    attempt_count=0,
                    max_attempts=5,
                    related_response_action_id=related_response_action_id,
                    last_error=None,
                )
            )
            return tid
        return self._persist.enqueue_schedule_task(
            task_type=TASK_SCHEDULED_UNBLOCK,
            run_at=run_at,
            alert_id=alert_id,
            payload=payload,
            related_response_action_id=related_response_action_id,
        )

    def schedule_notify_retry(
        self,
        *,
        run_at: datetime,
        alert_id: Optional[str],
        subject: str,
        body: str,
        meta: Dict[str, Any],
        max_attempts: int = 5,
    ) -> int:
        payload = self._payload_with_tenant({"subject": subject, "body": body, "meta": meta})
        if self._use_memory():
            tid = self._mem_seq
            self._mem_seq += 1
            self._mem_tasks.append(
                ScheduleTaskRow(
                    id=tid,
                    tenant_id=self.tenant_id,
                    task_type=TASK_NOTIFY_RETRY,
                    alert_id=alert_id,
                    payload=payload,
                    run_at=run_at,
                    status="pending",
                    attempt_count=0,
                    max_attempts=max_attempts,
                    related_response_action_id=None,
                    last_error=None,
                )
            )
            return tid
        return self._persist.enqueue_schedule_task(
            task_type=TASK_NOTIFY_RETRY,
            run_at=run_at,
            alert_id=alert_id,
            payload=payload,
            max_attempts=max_attempts,
        )

    def fetch_due(self, *, before: datetime, limit: int = 50) -> List[ScheduleTaskRow]:
        if self._use_memory():
            due = [t for t in self._mem_tasks if t.status == "pending" and t.run_at <= before]
            due.sort(key=lambda x: x.run_at)
            return due[:limit]
        return self._persist.fetch_due_tasks(before=before, limit=limit)

    def mark_running_memory(self, task_id: int) -> None:
        if not self._use_memory():
            return
        for i, t in enumerate(self._mem_tasks):
            if t.id == task_id:
                self._mem_tasks[i] = ScheduleTaskRow(
                    id=t.id,
                    tenant_id=t.tenant_id,
                    task_type=t.task_type,
                    alert_id=t.alert_id,
                    payload=t.payload,
                    run_at=t.run_at,
                    status="running",
                    attempt_count=t.attempt_count + 1,
                    max_attempts=t.max_attempts,
                    related_response_action_id=t.related_response_action_id,
                    last_error=t.last_error,
                )
                break

    def complete_memory(self, task_id: int, *, status: str, last_error: Optional[str]) -> None:
        if not self._use_memory():
            return
        for i, t in enumerate(self._mem_tasks):
            if t.id == task_id:
                self._mem_tasks[i] = ScheduleTaskRow(
                    id=t.id,
                    tenant_id=t.tenant_id,
                    task_type=t.task_type,
                    alert_id=t.alert_id,
                    payload=t.payload,
                    run_at=t.run_at,
                    status=status,
                    attempt_count=t.attempt_count,
                    max_attempts=t.max_attempts,
                    related_response_action_id=t.related_response_action_id,
                    last_error=last_error,
                )
                break

    def tick(self, responder: "SecurityResponder", *, now: Optional[datetime] = None) -> int:
        """执行到期任务。返回本 tick 处理条数。"""
        ts = now or datetime.now(timezone.utc)
        due = self.fetch_due(before=ts, limit=30)
        processed = 0
        for task in due:
            if task.tenant_id != self.tenant_id:
                logger.error(
                    "[scheduler] skip cross-tenant task id=%s expected=%s got=%s",
                    task.id,
                    self.tenant_id,
                    task.tenant_id,
                )
                continue
            executed_attempts = task.attempt_count + 1
            if self._use_memory():
                self.mark_running_memory(task.id)
            else:
                self._persist.update_schedule_task(
                    task.id,
                    status="running",
                    attempt_count=executed_attempts,
                )
            try:
                if task.task_type == TASK_SCHEDULED_UNBLOCK:
                    unblock_error = responder.execute_scheduled_unblock(
                        task.payload.get("ip", ""),
                        dry_run=bool(task.payload.get("dry_run")),
                        alert_id=task.alert_id,
                        schedule_task_id=task.id,
                        related_response_action_id=task.related_response_action_id,
                    )
                    if unblock_error is None:
                        self._finish_task(task, success=True, error=None)
                    else:
                        self._fail_or_reschedule(
                            task,
                            unblock_error,
                            now=ts,
                            executed_attempts=executed_attempts,
                        )
                elif task.task_type == TASK_NOTIFY_RETRY:
                    ok = responder.execute_notify_retry(
                        subject=str(task.payload.get("subject", "")),
                        body=str(task.payload.get("body", "")),
                        meta=dict(task.payload.get("meta") or {}),
                        alert_id=task.alert_id,
                        schedule_task_id=task.id,
                        attempt=executed_attempts,
                        max_attempts=task.max_attempts,
                    )
                    if ok:
                        self._finish_task(task, success=True, error=None)
                    else:
                        self._fail_or_reschedule(
                            task,
                            "notify_retry_all_failed",
                            now=ts,
                            executed_attempts=executed_attempts,
                        )
                else:
                    self._finish_task(task, success=False, error="unknown_task_type")
            except Exception as exc:  # noqa: BLE001
                logger.exception("[scheduler] task %s failed: %s", task.id, exc)
                self._fail_or_reschedule(
                    task, str(exc), now=ts, executed_attempts=executed_attempts
                )
            processed += 1
        return processed

    def _finish_task(self, task: ScheduleTaskRow, *, success: bool, error: Optional[str]) -> None:
        if self._use_memory():
            self.complete_memory(task.id, status="completed" if success else "failed", last_error=error)
            return
        self._persist.update_schedule_task(
            task.id,
            status="completed" if success else "failed",
            last_error=error,
        )

    def _fail_or_reschedule(
        self,
        task: ScheduleTaskRow,
        err: str,
        *,
        now: datetime,
        executed_attempts: int,
    ) -> None:
        attempts = executed_attempts
        if attempts >= task.max_attempts:
            if self._use_memory():
                self.complete_memory(task.id, status="failed", last_error=err)
            else:
                self._persist.update_schedule_task(
                    task.id, status="failed", attempt_count=attempts, last_error=err
                )
            return
        # 退避重调度
        from datetime import timedelta

        delay = timedelta(seconds=min(3600, 30 * (2 ** (attempts - 1))))
        new_run = now + delay
        if self._use_memory():
            for i, t in enumerate(self._mem_tasks):
                if t.id == task.id:
                    self._mem_tasks[i] = ScheduleTaskRow(
                        id=t.id,
                        tenant_id=t.tenant_id,
                        task_type=t.task_type,
                        alert_id=t.alert_id,
                        payload=t.payload,
                        run_at=new_run,
                        status="pending",
                        attempt_count=attempts,
                        max_attempts=t.max_attempts,
                        related_response_action_id=t.related_response_action_id,
                        last_error=err,
                    )
                    break
        else:
            self._persist.update_schedule_task(
                task.id,
                status="pending",
                attempt_count=attempts,
                last_error=err,
                run_at=new_run,
            )
