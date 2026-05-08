"""消费 ``guardian:alerts`` Redis Stream：规范化 → 入库 → ack → Socket.IO / 内存缓存同步。"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask
from flask_socketio import SocketIO

from src.utils.redis_client import RedisClient, tenant_stream_key
from web.database import db
from web.tenant import configured_default_tenant_id

logger = logging.getLogger(__name__)


class GuardianAlertStreamConsumer:
    """后台线程：consumer group 读流、失败留在 PEL 可重试、``XAUTOCLAIM`` 回收滞留。"""

    def __init__(
        self,
        *,
        app: Flask,
        redis_client: RedisClient,
        socketio: SocketIO,
        stream_key: str,
        group_name: str,
        consumer_name: Optional[str] = None,
        read_count: int = 20,
        idle_block_ms: int = 1500,
        autoclaim_idle_ms: int = 120_000,
        autoclaim_interval_sec: float = 30.0,
        normalizer: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
        upsert_alert: Optional[Callable[[Dict[str, Any]], Any]] = None,
        alert_to_api_dict: Optional[Callable[[Any], Dict[str, Any]]] = None,
        tenant_id: Optional[str] = None,
        per_tenant_stream: bool = False,
    ) -> None:
        if normalizer is None or upsert_alert is None or alert_to_api_dict is None:
            from web.app import (  # Local import avoids a startup circular import.
                _alert_to_api_dict,
                _upsert_alert_to_db,
                normalize_guardian_stream_fields,
            )

            normalizer = normalizer or normalize_guardian_stream_fields
            upsert_alert = upsert_alert or _upsert_alert_to_db
            alert_to_api_dict = alert_to_api_dict or _alert_to_api_dict

        self._app = app
        self._redis = redis_client.fork_for_stream_consumer()
        self._socketio = socketio
        self._normalizer = normalizer
        self._upsert_alert = upsert_alert
        self._alert_to_api_dict = alert_to_api_dict
        self._tenant_id = str(tenant_id or configured_default_tenant_id()).strip()
        if not self._tenant_id:
            raise ValueError("tenant_id is required for alert stream consumer")
        self._stream = (
            tenant_stream_key(stream_key, self._tenant_id)
            if per_tenant_stream
            else stream_key
        )
        self._group = group_name
        self._consumer = consumer_name or f"web-{os.getpid()}"
        self._read_count = read_count
        self._idle_block_ms = idle_block_ms
        self._autoclaim_idle_ms = autoclaim_idle_ms
        self._autoclaim_interval = autoclaim_interval_sec
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_autoclaim = 0.0
        self._stats_lock = threading.Lock()
        self._stats: Dict[str, float] = {
            "consumed_total": 0.0,
            "failed_total": 0.0,
            "latency_sum_ms": 0.0,
            "latency_count": 0.0,
            "latency_max_ms": 0.0,
            "last_consumed_ts": 0.0,
        }
        self._app.extensions["guardian_alert_consumer_stats"] = self._stats

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="GuardianAlertStreamConsumer",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "[AlertConsumer] started stream=%s group=%s consumer=%s redis_mode=%s",
            self._stream,
            self._group,
            self._consumer,
            self._redis.mode,
        )

    def stop(self, timeout: float = 8.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("[AlertConsumer] stopped")

    def _publish_stats(self) -> None:
        with self._stats_lock:
            self._app.extensions["guardian_alert_consumer_stats"] = dict(self._stats)

    def _record_success(self, fields: Dict[str, Any]) -> None:
        now = time.time()
        latency_ms = _message_age_ms(fields, now)
        with self._stats_lock:
            self._stats["consumed_total"] += 1
            self._stats["last_consumed_ts"] = now
            if latency_ms is not None:
                self._stats["latency_sum_ms"] += latency_ms
                self._stats["latency_count"] += 1
                self._stats["latency_max_ms"] = max(
                    self._stats["latency_max_ms"], latency_ms
                )
        self._publish_stats()

    def _record_failure(self) -> None:
        with self._stats_lock:
            self._stats["failed_total"] += 1
        self._publish_stats()

    def _run_loop(self) -> None:
        try:
            self._redis.stream_ensure_group(self._stream, self._group)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[AlertConsumer] ensure_group failed: %s", exc)

        while not self._stop.is_set():
            try:
                batch: List[Tuple[str, Dict[str, Any]]] = []
                batch.extend(
                    self._redis.stream_read_own_pending(
                        self._stream,
                        self._group,
                        self._consumer,
                        self._read_count,
                    )
                )
                now = time.monotonic()
                if now - self._last_autoclaim >= self._autoclaim_interval:
                    batch.extend(
                        self._redis.stream_autoclaim(
                            self._stream,
                            self._group,
                            self._consumer,
                            min_idle_ms=self._autoclaim_idle_ms,
                            start="0-0",
                            count=self._read_count,
                        )
                    )
                    self._last_autoclaim = now

                if not batch:
                    block = max(100, min(self._idle_block_ms, 3000))
                    batch = self._redis.stream_read_group(
                        self._stream,
                        self._group,
                        self._consumer,
                        count=self._read_count,
                        block_ms=block if self._redis.is_available else 50,
                    )

                if not batch:
                    if not self._redis.is_available:
                        time.sleep(0.25)
                    continue

                for msg_id, fields in batch:
                    if self._stop.is_set():
                        break
                    self._process_one(msg_id, fields)
            except Exception:  # noqa: BLE001
                logger.exception("[AlertConsumer] loop error")
                time.sleep(1.0)

    def _process_one(self, msg_id: str, fields: Dict[str, Any]) -> None:
        norm = self._normalizer(fields)
        if norm is None:
            logger.warning(
                "[AlertConsumer] skip malformed entry (no alert_id), acking %s", msg_id
            )
            self._redis.stream_ack(self._stream, self._group, [msg_id])
            return
        msg_tenant = str(norm.get("tenant_id") or self._tenant_id).strip()
        if msg_tenant != self._tenant_id:
            logger.error(
                "[AlertConsumer] tenant mismatch stream=%s msg_id=%s expected=%s got=%s; acking",
                self._stream,
                msg_id,
                self._tenant_id,
                msg_tenant,
            )
            self._redis.stream_ack(self._stream, self._group, [msg_id])
            return
        norm["tenant_id"] = self._tenant_id

        ack = False
        try:
            with self._app.app_context():
                row = self._upsert_alert(norm)
                if row is None:
                    logger.error("[AlertConsumer] upsert returned None for %s", msg_id)
                else:
                    api_dict = self._alert_to_api_dict(row)
                    try:
                        self._socketio.emit("alert", api_dict)
                    except Exception:  # noqa: BLE001
                        logger.debug("[AlertConsumer] socket emit failed", exc_info=True)
                    state = self._app.extensions.get("guardian_state")
                    if state is not None:
                        try:
                            state.add_alert(api_dict)
                        except Exception:  # noqa: BLE001
                            logger.debug(
                                "[AlertConsumer] memory cache sync failed", exc_info=True
                            )
                    ack = True
        except Exception:  # noqa: BLE001
            logger.exception(
                "[AlertConsumer] persist failed msg_id=%s (not ack; will retry)", msg_id
            )
            self._record_failure()
            try:
                db.session.rollback()
            except Exception:  # noqa: BLE001
                pass

        if ack:
            self._redis.stream_ack(self._stream, self._group, [msg_id])
            self._record_success(fields)


def _message_age_ms(fields: Dict[str, Any], now_ts: float) -> Optional[float]:
    for key in ("created_ts", "created_at_ts", "emitted_ts", "timestamp_ms", "ts_ms"):
        raw = fields.get(key)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if value <= 0:
            continue
        seconds = value / 1000.0 if value > 10_000_000_000 else value
        return max(0.0, (now_ts - seconds) * 1000.0)
    return None
