"""Guardian 运行时指标：线程安全采集、可选写入 Redis（采集失败不影响主链路）。"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict

logger = logging.getLogger(__name__)

GUARDIAN_METRICS_REDIS_KEY: str = "guardian:metrics:snapshot"


@dataclass
class _AggCounterSnapshot:
    malformed: int = 0
    single_discarded: int = 0
    partial_discarded: int = 0


class GuardianMetricsCollector:
    """进程内计数 + 周期性刷入 Redis HASH，供 Web /metrics 聚合。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets_total: int = 0
        self._packets_dropped: int = 0
        self._latency_sum_ms: float = 0.0
        self._latency_count: int = 0
        self._alerts_total: int = 0
        self._model_ready_gauge: int = 0
        self._model_expected_count: int = 0
        self._model_loaded_count: int = 0
        self._model_missing_count: int = 0
        self._model_status_updated_ts: float = 0.0
        self._last_detection_ts: float = 0.0
        self._collection_packet: bool = False
        self._collection_web: bool = False
        self._redis_stream_writes_ok: int = 0
        self._redis_stream_writes_fail: int = 0
        self._last_flush_ts: float = 0.0
        self._prev_agg = _AggCounterSnapshot()

    def record_packets_seen(self, n: int) -> None:
        if n <= 0:
            return
        with self._lock:
            self._packets_total += n

    def record_threat_intel_drops(self, n: int) -> None:
        if n <= 0:
            return
        with self._lock:
            self._packets_dropped += n

    def record_queue_read_error(self) -> None:
        with self._lock:
            self._packets_dropped += 1

    def record_aggregator_deltas(self, malformed: int, single: int, partial: int) -> None:
        """传入本 tick 相对上次的增量（非累计）。"""
        d = max(0, malformed) + max(0, single) + max(0, partial)
        if d <= 0:
            return
        with self._lock:
            self._packets_dropped += d

    def record_detection_latency_ms(self, ms: float) -> None:
        if ms < 0:
            return
        with self._lock:
            self._latency_sum_ms += ms
            self._latency_count += 1

    def record_alert(self) -> None:
        with self._lock:
            self._alerts_total += 1
            self._last_detection_ts = time.time()

    def set_model_ready_gauge(self, value: int) -> None:
        with self._lock:
            self._model_ready_gauge = 1 if int(value) > 0 else 0
            self._model_status_updated_ts = time.time()

    def set_model_load_state(self, *, expected: int, loaded: int) -> None:
        """Set binary readiness plus counts for the critical model set."""
        expected_count = max(0, int(expected))
        loaded_count = max(0, min(expected_count, int(loaded)))
        missing_count = max(0, expected_count - loaded_count)
        with self._lock:
            self._model_expected_count = expected_count
            self._model_loaded_count = loaded_count
            self._model_missing_count = missing_count
            self._model_ready_gauge = (
                1 if expected_count > 0 and loaded_count == expected_count else 0
            )
            self._model_status_updated_ts = time.time()

    def set_collection_flags(self, packet: bool, web: bool) -> None:
        with self._lock:
            self._collection_packet = packet
            self._collection_web = web

    def record_redis_stream_write(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self._redis_stream_writes_ok += 1
            else:
                self._redis_stream_writes_fail += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "packets_total": self._packets_total,
                "packets_dropped_total": self._packets_dropped,
                "detection_latency_sum_ms": self._latency_sum_ms,
                "detection_latency_count": self._latency_count,
                "alerts_total": self._alerts_total,
                "model_ready": self._model_ready_gauge,
                "model_expected_count": self._model_expected_count,
                "model_loaded_count": self._model_loaded_count,
                "model_missing_count": self._model_missing_count,
                "model_status_updated_ts": self._model_status_updated_ts,
                "last_detection_ts": self._last_detection_ts,
                "collection_packet": int(self._collection_packet),
                "collection_web": int(self._collection_web),
                "redis_stream_writes_ok": self._redis_stream_writes_ok,
                "redis_stream_writes_fail": self._redis_stream_writes_fail,
                "updated_ts": time.time(),
            }

    def flush_to_redis(self, redis_client: Any, min_interval_sec: float = 2.0) -> None:
        """写入 Redis；失败仅打 debug，不抛异常。"""
        now = time.time()
        with self._lock:
            if now - self._last_flush_ts < min_interval_sec:
                return
            self._last_flush_ts = now
            snap = {
                "packets_total": str(self._packets_total),
                "packets_dropped_total": str(self._packets_dropped),
                "detection_latency_sum_ms": str(self._latency_sum_ms),
                "detection_latency_count": str(self._latency_count),
                "alerts_total": str(self._alerts_total),
                "model_ready": str(self._model_ready_gauge),
                "model_expected_count": str(self._model_expected_count),
                "model_loaded_count": str(self._model_loaded_count),
                "model_missing_count": str(self._model_missing_count),
                "model_status_updated_ts": str(self._model_status_updated_ts),
                "last_detection_ts": str(self._last_detection_ts),
                "collection_packet": str(int(self._collection_packet)),
                "collection_web": str(int(self._collection_web)),
                "redis_stream_writes_ok": str(self._redis_stream_writes_ok),
                "redis_stream_writes_fail": str(self._redis_stream_writes_fail),
                "updated_ts": str(now),
            }
        if not getattr(redis_client, "is_available", False):
            return
        try:
            rc = redis_client._client  # noqa: SLF001 - 适配层内部；仅运维指标
            if rc is None:
                return
            rc.hset(GUARDIAN_METRICS_REDIS_KEY, mapping=snap)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[GuardianMetrics] flush_to_redis 失败: %s", exc)

    def write_status_file(self, path: str) -> None:
        """人读 JSON 状态（不含密钥）。"""
        try:
            body = {"guardian": self.snapshot(), "schema": "guardian_status_v1"}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(body, f, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.debug("[GuardianMetrics] status 文件写入失败: %s", exc)


def read_guardian_redis_snapshot(redis_client: Any) -> Dict[str, float]:
    """Web 侧读取 Guardian 刷入的指标；缺失字段视为 0。"""
    out: Dict[str, float] = {}
    if not getattr(redis_client, "is_available", False):
        return out
    try:
        rc = redis_client._client  # noqa: SLF001
        if rc is None:
            return out
        raw = rc.hgetall(GUARDIAN_METRICS_REDIS_KEY)
        for k, v in (raw or {}).items():
            key = k.decode() if isinstance(k, bytes) else str(k)
            val = v.decode() if isinstance(v, bytes) else str(v)
            try:
                out[key] = float(val)
            except ValueError:
                out[key] = 0.0
    except Exception as exc:  # noqa: BLE001
        logger.debug("[GuardianMetrics] read_guardian_redis_snapshot 失败: %s", exc)
    return out
