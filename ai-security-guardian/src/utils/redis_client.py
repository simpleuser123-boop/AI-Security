"""
Redis 轻量客户端 + 内存降级适配层（Phase 8 集成与降级）
对应架构文档 §11 部署架构 & Phase 8 D 节 / E 节

设计目标：
    1. 在 Redis 可用时，作为缓存 / 轻量消息队列使用
    2. Redis 不可用时自动回退到 **进程内内存实现**，保证主流程不被阻断
    3. 提供统一的对外接口，调用方无需关心底层实现
    4. 初始化失败（依赖缺失、连接超时、鉴权失败）不抛异常，记录日志并降级

对外接口：
    - get(key) / set(key, value, ttl=None)       缓存
    - delete(key)                                 缓存
    - push(queue, message) / pop(queue)           轻量队列（FIFO List）
    - ping()                                      健康检查
    - is_available                                当前是否真正连上 Redis
    - mode                                        'redis' | 'memory'
    - Streams（Phase 8+）：
        stream_add(stream, fields, maxlen=None)
        stream_ensure_group(stream, group)
        stream_read_group(stream, group, consumer, count, block_ms)
        stream_read_own_pending(stream, group, consumer, count)
        stream_autoclaim(stream, group, consumer, min_idle_ms, start, count)
        stream_ack(stream, group, ids)
        stream_pending(stream, group)
        stream_len(stream)
      Streams 在内存模式下用 (str id, dict fields) + 已投递 / 已 ack 集合模拟，
      行为对 consumer group 语义足够近似，可作为开发 / 单元测试兜底。
"""
from __future__ import annotations

import itertools
import json
import logging
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =====================================================================
# 内存模式 Streams 实现（极简版）
# =====================================================================
class _InMemoryStream:
    """Redis Streams 的最简内存模拟。

    - 每条消息是 (stream_id, fields_dict)
    - stream_id 使用单调递增整数（格式 `0-N`）以模拟 Redis 的 `ms-seq`
    - 每个 group 维护 `pending`（已发送但未 ack）与 `delivered_ids`
    - maxlen 软上限：超过即从头丢弃
    """

    def __init__(self) -> None:
        self.entries: List[Tuple[str, Dict[str, Any]]] = []
        self._id_counter = itertools.count(1)
        # group -> {"consumers": {"c1": [ids]}, "pending": {id: consumer}, "last_id": str}
        self.groups: Dict[str, Dict[str, Any]] = {}

    def next_id(self) -> str:
        return f"0-{next(self._id_counter)}"

    def trim(self, maxlen: Optional[int]) -> None:
        if maxlen is None or maxlen <= 0:
            return
        if len(self.entries) > maxlen:
            self.entries = self.entries[-maxlen:]


class RedisClient:
    """Redis 适配客户端，Redis 不可用时自动降级到内存实现。

    调用方只需实例化一次，通过 :pyattr:`is_available` / :pyattr:`mode`
    判断当前运行模式，其余调用方法对两种模式完全透明。
    """

    _CONNECT_TIMEOUT: float = 2.0
    _SOCKET_TIMEOUT: float = 2.0

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str = "",
    ) -> None:
        self.host = host
        self.port = int(port)
        self.db = int(db)
        self.password = password or None

        self._client = None
        self._mode: str = "memory"

        # 内存降级态
        self._mem_lock = threading.Lock()
        self._mem_cache: Dict[str, Tuple[Any, Optional[float]]] = {}  # key -> (value, expire_at_ts)
        self._mem_queues: Dict[str, Deque[str]] = {}
        self._mem_streams: Dict[str, _InMemoryStream] = {}

        self._try_connect()

    # ------------------------------------------------------------------
    # 初始化 / 重连
    # ------------------------------------------------------------------
    def _try_connect(self) -> None:
        """尝试初始化 Redis 连接；失败时静默降级到内存模式。"""
        import os

        if os.environ.get("GUARDIAN_REDIS_DISABLE_CONNECT", "").lower() == "true":
            self._client = None
            self._mode = "memory"
            return
        try:
            import redis  # type: ignore

            client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_connect_timeout=self._CONNECT_TIMEOUT,
                socket_timeout=self._SOCKET_TIMEOUT,
                decode_responses=True,
                health_check_interval=30,
            )
            client.ping()
            self._client = client
            self._mode = "redis"
            logger.info(
                "[RedisClient] Redis 连接成功 host=%s port=%s db=%s",
                self.host,
                self.port,
                self.db,
            )
        except ImportError:
            logger.warning("[RedisClient] redis 依赖未安装，降级到内存模式")
            self._client = None
            self._mode = "memory"
        except Exception as exc:
            logger.warning(
                "[RedisClient] Redis 连接失败，自动降级到内存模式: %s", exc
            )
            self._client = None
            self._mode = "memory"

    def reconnect(self) -> bool:
        """显式重连 Redis；成功则切回 redis 模式。"""
        self._try_connect()
        return self.is_available

    # ------------------------------------------------------------------
    # 属性
    # ------------------------------------------------------------------
    @property
    def is_available(self) -> bool:
        """当前是否真正连接到 Redis。"""
        return self._client is not None and self._mode == "redis"

    @property
    def mode(self) -> str:
        """当前运行模式: 'redis' | 'memory'。"""
        return self._mode

    # ------------------------------------------------------------------
    # 健康检查
    # ------------------------------------------------------------------
    def ping(self) -> bool:
        """健康检查。Redis 断开时自动降级。"""
        if self._client is None:
            return False
        try:
            return bool(self._client.ping())
        except Exception as exc:
            logger.warning("[RedisClient] ping 失败，降级到内存模式: %s", exc)
            self._degrade()
            return False

    # ------------------------------------------------------------------
    # 缓存 API
    # ------------------------------------------------------------------
    def get(self, key: str) -> Optional[Any]:
        """读取缓存。"""
        if self.is_available:
            try:
                raw = self._client.get(key)  # type: ignore[union-attr]
                if raw is None:
                    return None
                return self._deserialize(raw)
            except Exception as exc:
                logger.warning("[RedisClient] get 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            item = self._mem_cache.get(key)
            if not item:
                return None
            value, expire_at = item
            if expire_at is not None and time.time() > expire_at:
                self._mem_cache.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """写入缓存。ttl 单位秒；None 表示不过期。"""
        if self.is_available:
            try:
                serialized = self._serialize(value)
                if ttl is not None:
                    self._client.setex(key, int(ttl), serialized)  # type: ignore[union-attr]
                else:
                    self._client.set(key, serialized)  # type: ignore[union-attr]
                return True
            except Exception as exc:
                logger.warning("[RedisClient] set 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            expire_at = time.time() + ttl if ttl is not None else None
            self._mem_cache[key] = (value, expire_at)
        return True

    def delete(self, key: str) -> bool:
        """删除缓存键。"""
        if self.is_available:
            try:
                return bool(self._client.delete(key))  # type: ignore[union-attr]
            except Exception as exc:
                logger.warning("[RedisClient] delete 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            return self._mem_cache.pop(key, None) is not None

    # ------------------------------------------------------------------
    # 轻量队列 API（FIFO；基于 Redis List 或内存 deque）
    # ------------------------------------------------------------------
    def push(self, queue: str, message: Any) -> bool:
        """将一条消息追加到队列尾部。"""
        if self.is_available:
            try:
                self._client.rpush(queue, self._serialize(message))  # type: ignore[union-attr]
                return True
            except Exception as exc:
                logger.warning("[RedisClient] push 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            q = self._mem_queues.setdefault(queue, deque())
            q.append(self._serialize(message))
        return True

    def pop(self, queue: str) -> Optional[Any]:
        """从队列头部弹出一条消息；空队列返回 None。"""
        if self.is_available:
            try:
                raw = self._client.lpop(queue)  # type: ignore[union-attr]
                if raw is None:
                    return None
                return self._deserialize(raw)
            except Exception as exc:
                logger.warning("[RedisClient] pop 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            q = self._mem_queues.get(queue)
            if not q:
                return None
            try:
                return self._deserialize(q.popleft())
            except IndexError:
                return None

    def queue_len(self, queue: str) -> int:
        """返回队列长度（不可用或异常时返回 0）。"""
        if self.is_available:
            try:
                return int(self._client.llen(queue))  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("[RedisClient] llen 失败: %s", exc)
                return 0
        with self._mem_lock:
            return len(self._mem_queues.get(queue, ()))

    # ------------------------------------------------------------------
    # Redis Streams API（消息队列升级版 — consumer group + ack）
    # ------------------------------------------------------------------
    def stream_add(
        self,
        stream: str,
        fields: Dict[str, Any],
        maxlen: Optional[int] = None,
        approximate: bool = True,
    ) -> Optional[str]:
        """向流追加一条消息。

        Args:
            stream: 流名称。
            fields: 消息字段字典；value 非字符串会自动 JSON 序列化。
            maxlen: 软上限（`XADD MAXLEN ~`），保护 Redis 内存。
            approximate: 是否允许近似修剪（Redis 推荐 True，性能更好）。

        Returns:
            成功时返回新增消息的 id（形如 ``1700000000000-0``）；失败返回 None。
        """
        encoded = {k: self._serialize(v) for k, v in fields.items()}

        if self.is_available:
            try:
                kwargs: Dict[str, Any] = {}
                if maxlen is not None:
                    kwargs["maxlen"] = int(maxlen)
                    kwargs["approximate"] = bool(approximate)
                return self._client.xadd(stream, encoded, **kwargs)  # type: ignore[union-attr]
            except Exception as exc:
                logger.warning("[RedisClient] xadd 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            st = self._mem_streams.setdefault(stream, _InMemoryStream())
            msg_id = st.next_id()
            st.entries.append((msg_id, encoded))
            st.trim(maxlen)
            return msg_id

    def stream_ensure_group(
        self,
        stream: str,
        group: str,
        mkstream: bool = True,
        start_id: str = "0",
    ) -> bool:
        """确保 consumer group 存在；已存在视为成功。"""
        if self.is_available:
            try:
                self._client.xgroup_create(  # type: ignore[union-attr]
                    name=stream, groupname=group, id=start_id, mkstream=mkstream
                )
                return True
            except Exception as exc:
                # redis.exceptions.ResponseError: BUSYGROUP 表示已存在
                if "BUSYGROUP" in str(exc):
                    return True
                logger.warning("[RedisClient] xgroup_create 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            st = self._mem_streams.setdefault(stream, _InMemoryStream())
            if group not in st.groups:
                st.groups[group] = {
                    "consumers": {},  # consumer -> set(id)
                    "pending": {},    # id -> consumer
                    "last_id": start_id,
                }
            return True

    def stream_read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block_ms: Optional[int] = None,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """以 consumer group 方式读取消息（只读未投递给本 group 的新消息）。

        Returns:
            [(msg_id, fields_dict), ...]；空结果返回 []。
        """
        if self.is_available:
            try:
                block = int(block_ms) if block_ms is not None else None
                raw = self._client.xreadgroup(  # type: ignore[union-attr]
                    groupname=group,
                    consumername=consumer,
                    streams={stream: ">"},
                    count=int(count),
                    block=block,
                )
                out: List[Tuple[str, Dict[str, Any]]] = []
                for _stream_name, entries in raw or []:
                    for msg_id, fields in entries:
                        decoded = {k: self._deserialize(v) for k, v in fields.items()}
                        out.append((msg_id, decoded))
                return out
            except Exception as exc:
                logger.warning("[RedisClient] xreadgroup 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            st = self._mem_streams.get(stream)
            if st is None or group not in st.groups:
                return []
            grp = st.groups[group]
            consumers: Dict[str, Set[str]] = grp["consumers"]
            pending: Dict[str, str] = grp["pending"]

            # 仅读取 last_id 之后的消息
            last_id = grp["last_id"]
            collected: List[Tuple[str, Dict[str, Any]]] = []
            last_seen = last_id
            for msg_id, fields in st.entries:
                if _compare_stream_id(msg_id, last_id) <= 0:
                    continue
                collected.append(
                    (msg_id, {k: self._deserialize(v) for k, v in fields.items()})
                )
                last_seen = msg_id
                if len(collected) >= count:
                    break

            # 登记 pending
            consumer_set = consumers.setdefault(consumer, set())
            for msg_id, _ in collected:
                pending[msg_id] = consumer
                consumer_set.add(msg_id)

            grp["last_id"] = last_seen
            return collected

    def stream_read_own_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """读取已投递给当前 consumer 但未 ack 的消息（PEL），用于失败重试。

        对应 Redis ``XREADGROUP ... STREAMS <key> 0``（非 ``>``）。
        """
        if self.is_available:
            try:
                raw = self._client.xreadgroup(  # type: ignore[union-attr]
                    groupname=group,
                    consumername=consumer,
                    streams={stream: "0"},
                    count=int(count),
                    block=0,
                )
                out: List[Tuple[str, Dict[str, Any]]] = []
                for _stream_name, entries in raw or []:
                    for msg_id, fields in entries:
                        decoded = {k: self._deserialize(v) for k, v in fields.items()}
                        out.append((msg_id, decoded))
                return out
            except Exception as exc:
                logger.warning("[RedisClient] xreadgroup(pending) 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            st = self._mem_streams.get(stream)
            if st is None or group not in st.groups:
                return []
            grp = st.groups[group]
            pending: Dict[str, str] = grp["pending"]
            id_to_fields: Dict[str, Dict[str, Any]] = {
                mid: {k: self._deserialize(v) for k, v in fd.items()}
                for mid, fd in st.entries
            }
            out: List[Tuple[str, Dict[str, Any]]] = []
            for msg_id, owner in list(pending.items()):
                if owner != consumer:
                    continue
                fields = id_to_fields.get(msg_id)
                if fields is None:
                    continue
                out.append((msg_id, dict(fields)))
                if len(out) >= int(count):
                    break
            return out

    def stream_autoclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_ms: int,
        start: str = "0-0",
        count: int = 10,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """认领空闲时间超过 ``min_idle_ms`` 的 pending 消息（``XAUTOCLAIM``）。

        用于崩溃后其它 consumer 实例回收滞留消息；内存模式下返回空列表。
        """
        if self.is_available:
            try:
                # redis-py: xautoclaim returns [next_start, messages, deleted_ids]
                raw = self._client.xautoclaim(  # type: ignore[union-attr]
                    name=stream,
                    groupname=group,
                    consumername=consumer,
                    min_idle_time=int(min_idle_ms),
                    start_id=start,
                    count=int(count),
                    justid=False,
                )
                if not raw or not isinstance(raw, (list, tuple)):
                    return []
                messages = raw[1] if len(raw) > 1 else []
                out: List[Tuple[str, Dict[str, Any]]] = []
                for item in messages or []:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        msg_id, fields = item[0], item[1]
                    else:
                        continue
                    if not isinstance(fields, dict):
                        continue
                    decoded = {k: self._deserialize(v) for k, v in fields.items()}
                    out.append((str(msg_id), decoded))
                return out
            except Exception as exc:
                logger.debug("[RedisClient] xautoclaim 失败: %s", exc)
                return []

        return []

    def stream_ack(self, stream: str, group: str, ids: List[str]) -> int:
        """确认消费 ids；返回成功 ack 的数量。"""
        if not ids:
            return 0
        if self.is_available:
            try:
                return int(self._client.xack(stream, group, *ids))  # type: ignore[union-attr]
            except Exception as exc:
                logger.warning("[RedisClient] xack 失败降级: %s", exc)
                self._degrade()

        with self._mem_lock:
            st = self._mem_streams.get(stream)
            if st is None or group not in st.groups:
                return 0
            grp = st.groups[group]
            pending: Dict[str, str] = grp["pending"]
            consumers: Dict[str, Set[str]] = grp["consumers"]
            acked = 0
            for msg_id in ids:
                consumer = pending.pop(msg_id, None)
                if consumer is None:
                    continue
                consumers.get(consumer, set()).discard(msg_id)
                acked += 1
            return acked

    def stream_pending(self, stream: str, group: str) -> int:
        """返回当前 group 中 pending（未 ack）消息的数量。"""
        if self.is_available:
            try:
                info = self._client.xpending(stream, group)  # type: ignore[union-attr]
                if isinstance(info, dict):
                    return int(info.get("pending", 0))
                if isinstance(info, (list, tuple)) and info:
                    # 旧 API：[count, min, max, consumers]
                    return int(info[0] or 0)
                return 0
            except Exception as exc:
                logger.debug("[RedisClient] xpending 失败: %s", exc)
                return 0

        with self._mem_lock:
            st = self._mem_streams.get(stream)
            if st is None or group not in st.groups:
                return 0
            return len(st.groups[group]["pending"])

    def stream_len(self, stream: str) -> int:
        """返回流的总消息数。"""
        if self.is_available:
            try:
                return int(self._client.xlen(stream))  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("[RedisClient] xlen 失败: %s", exc)
                return 0
        with self._mem_lock:
            st = self._mem_streams.get(stream)
            return len(st.entries) if st else 0

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize(value: Any) -> str:
        """对外统一以 JSON 字符串存储，保证跨模式一致。"""
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except TypeError:
            return str(value)

    @staticmethod
    def _deserialize(raw: Any) -> Any:
        """若为合法 JSON 则还原，否则原样返回字符串。"""
        if not isinstance(raw, str):
            return raw
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw

    def _degrade(self) -> None:
        """Redis 运行期出现异常时主动切换到内存模式。"""
        self._client = None
        self._mode = "memory"
        logger.warning("[RedisClient] 已切换到内存降级模式")


# ---------------------------------------------------------------------
# 辅助：按 Redis 风格比较 stream id（形如 "ms-seq"）
# ---------------------------------------------------------------------
def _compare_stream_id(a: str, b: str) -> int:
    """返回 -1 / 0 / 1；"0" 视为最小 id。"""
    def _parse(x: str) -> Tuple[int, int]:
        if x in ("0", "$", ""):
            return (-1 if x == "0" else 10**18, 0)
        if "-" in x:
            lhs, rhs = x.split("-", 1)
            try:
                return (int(lhs), int(rhs))
            except ValueError:
                return (-1, 0)
        try:
            return (int(x), 0)
        except ValueError:
            return (-1, 0)

    ta, tb = _parse(a), _parse(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0
