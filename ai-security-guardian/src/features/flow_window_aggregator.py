"""
跨 tick 的流窗口聚合器（network_flow_v1）

将实时抓包从「单包 extract 后清空」改为「按五元组累积，空闲超时后一次性输出」，
满足 P0 实时检测链路：批量/滑动窗口聚合后再进入检测器。

与 :class:`FlowFeatureExtractor` 解耦：后者仍用于无状态批处理与单元测试；
本类在发射时对包数 >= 2 的流委托 ``FlowFeatureExtractor.extract`` 计算 TCP 统计等字段，
并补充 ``packet_count`` / ``byte_count`` / 速率 / 源 IP 窗口内唯一目的等 schema 字段。
"""
from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, DefaultDict, Deque, Dict, List, Optional, Tuple

from src.schema.feature_schemas import attach_network_flow_v1_block

from .flow_features import FlowFeatureExtractor

logger = logging.getLogger(__name__)


def _packet_timestamp_seconds(packet: Dict[str, Any], fallback: float) -> float:
    """将包内 timestamp 规范为秒（float）。支持 Unix 秒与 ISO8601 字符串。"""
    ts = packet.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            # fromisoformat 兼容 '2026-04-28T12:00:00.123456'
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            pass
    return float(fallback)


def _make_flow_key(packet: Dict[str, Any]) -> str:
    return (
        f"{packet.get('src_ip', '')}:{packet.get('src_port', 0)}-"
        f"{packet.get('dst_ip', '')}:{packet.get('dst_port', 0)}-"
        f"{packet.get('protocol', 'OTHER')}"
    )


@dataclass
class FlowWindowAggregatorConfig:
    """聚合器配置（可由环境变量 / RuntimeConfig 注入）。"""

    min_flow_packets: int = 2
    flow_idle_timeout_sec: float = 5.0
    aggregation_window_sec: float = 10.0
    # 单包流在空闲超时后：discard = 不输出；emit_low_confidence = 输出带低置信标记的特征
    single_packet_idle_policy: str = "discard"  # discard | emit_low_confidence


@dataclass
class FlowWindowAggregatorCounters:
    """可观测计数（主循环不依赖其成功）。"""

    malformed_packet_skips: int = 0
    single_packet_discarded: int = 0
    partial_flow_discarded: int = 0
    flows_emitted: int = 0
    low_confidence_emissions: int = 0


@dataclass
class _FlowBuffer:
    packets: List[Dict[str, Any]] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0


class FlowWindowAggregator:
    """
    按五元组维护流状态；在「流空闲超时」时输出一条聚合特征（tumbling）。

    同一流在超时前持续累积包；超时且包数 >= min_flow_packets 时输出 1 条；
    单包流在超时后按 ``single_packet_idle_policy`` 丢弃或低置信输出。

    源 IP 滑动窗口（aggregation_window_sec）用于
    ``window_unique_dst_ip`` / ``window_unique_dst_port`` / ``window_protocol_dist``。
    """

    SCHEMA_VERSION = "network_flow_v1"

    def __init__(
        self,
        cfg: Optional[FlowWindowAggregatorConfig] = None,
        extractor: Optional[FlowFeatureExtractor] = None,
    ) -> None:
        self.cfg = cfg or FlowWindowAggregatorConfig()
        self._extractor = extractor or FlowFeatureExtractor()
        self._flows: Dict[str, _FlowBuffer] = {}
        self._src_activity: DefaultDict[str, Deque[Tuple[float, str, int, str]]] = (
            defaultdict(deque)
        )
        self.counters = FlowWindowAggregatorCounters()

    def reset(self) -> None:
        self._flows.clear()
        self._src_activity.clear()
        self.counters = FlowWindowAggregatorCounters()

    def _prune_src_window(self, src_ip: str, now: float) -> None:
        dq = self._src_activity.get(src_ip)
        if not dq:
            return
        cutoff = now - self.cfg.aggregation_window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            del self._src_activity[src_ip]

    def _record_src_window(self, pkt: Dict[str, Any], ts: float) -> None:
        src = str(pkt.get("src_ip", ""))
        if not src:
            return
        dst_ip = str(pkt.get("dst_ip", ""))
        dst_port = int(pkt.get("dst_port", 0) or 0)
        proto = str(pkt.get("protocol", "OTHER"))
        self._src_activity[src].append((ts, dst_ip, dst_port, proto))
        self._prune_src_window(src, ts)

    def _window_stats_for_src(self, src_ip: str, now: float) -> Tuple[int, int, Dict[str, int]]:
        self._prune_src_window(src_ip, now)
        dq = self._src_activity.get(src_ip)
        if not dq:
            return 0, 0, {}
        uniq_dst = {item[1] for item in dq if item[1]}
        uniq_dport = {item[2] for item in dq}
        protos = [item[3] for item in dq]
        dist = dict(Counter(protos))
        return len(uniq_dst), len(uniq_dport), dist

    def _build_low_confidence_feature(
        self, pkt: Dict[str, Any], now: float
    ) -> Dict[str, Any]:
        plen = int(pkt.get("packet_len", 0) or 0)
        flags = str(pkt.get("tcp_flags", ""))
        syn_count = 1 if "S" in flags else 0
        ack_count = 1 if "A" in flags else 0
        fin_count = 1 if "F" in flags else 0
        rst_count = 1 if "R" in flags else 0
        src_ip = str(pkt.get("src_ip", ""))
        w_dst, w_port, w_proto = self._window_stats_for_src(src_ip, now)
        feat: Dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "src_ip": pkt.get("src_ip", ""),
            "dst_ip": pkt.get("dst_ip", ""),
            "src_port": int(pkt.get("src_port", 0) or 0),
            "dst_port": int(pkt.get("dst_port", 0) or 0),
            "protocol": str(pkt.get("protocol", "OTHER")),
            "packet_count": 1,
            "byte_count": plen,
            "flow_pkt_count": 1,
            "flow_byte_count": plen,
            "flow_duration": 0.0,
            "flow_pkt_rate": 0.0,
            "flow_byte_rate": 0.0,
            "window_unique_dst_ip": w_dst,
            "window_unique_dst_port": w_port,
            "window_protocol_dist": w_proto,
            "pkt_len_mean": float(plen),
            "pkt_len_std": 0.0,
            "pkt_len_max": float(plen),
            "pkt_len_min": float(plen),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "flow_low_confidence": True,
        }
        attach_network_flow_v1_block(feat)
        return feat

    def _enrich_network_flow_v1(
        self,
        base: Dict[str, Any],
        packets: List[Dict[str, Any]],
        now: float,
    ) -> Dict[str, Any]:
        if not packets:
            return base
        times = [_packet_timestamp_seconds(p, now) for p in packets]
        t0, t1 = min(times), max(times)
        span = max(t1 - t0, 1e-9)
        pkt_count = len(packets)
        byte_sum = int(
            sum(int(p.get("packet_len", 0) or 0) for p in packets)
        )
        src_ip = str(base.get("src_ip", packets[0].get("src_ip", "")))
        w_dst, w_port, w_proto = self._window_stats_for_src(src_ip, now)

        base["schema_version"] = self.SCHEMA_VERSION
        base["packet_count"] = int(base.get("flow_pkt_count", pkt_count))
        base["byte_count"] = int(base.get("flow_byte_count", byte_sum))
        base["flow_duration"] = float(t1 - t0)
        base["flow_pkt_rate"] = float(pkt_count) / span
        base["flow_byte_rate"] = float(byte_sum) / span
        base["window_unique_dst_ip"] = w_dst
        base["window_unique_dst_port"] = w_port
        base["window_protocol_dist"] = w_proto
        base["flow_low_confidence"] = False
        attach_network_flow_v1_block(base)
        return base

    def tick(
        self,
        packets: List[Dict[str, Any]],
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        摄入本 tick 的数据包，根据空闲超时发射 ``network_flow_v1`` 特征列表。
        """
        wall = float(now if now is not None else time.time())
        emitted: List[Dict[str, Any]] = []

        for pkt in packets:
            try:
                key = _make_flow_key(pkt)
            except Exception as exc:  # noqa: BLE001
                logger.debug("[FlowWindowAggregator] 跳过无效包 key: %s", exc)
                self.counters.malformed_packet_skips += 1
                continue

            ts = _packet_timestamp_seconds(pkt, wall)
            buf = self._flows.get(key)
            if buf is None:
                buf = _FlowBuffer()
                buf.first_ts = ts
                buf.last_ts = ts
                buf.packets = [pkt]
                self._flows[key] = buf
            else:
                buf.packets.append(pkt)
                buf.last_ts = max(buf.last_ts, ts)
                buf.first_ts = min(buf.first_ts, ts)

            try:
                self._record_src_window(pkt, ts)
            except Exception as exc:  # noqa: BLE001
                logger.debug("[FlowWindowAggregator] 源窗口记录失败: %s", exc)

        # 空闲超时：发射并移除
        idle_keys: List[str] = []
        for key, buf in list(self._flows.items()):
            if wall - buf.last_ts < self.cfg.flow_idle_timeout_sec:
                continue
            idle_keys.append(key)

        for key in idle_keys:
            buf = self._flows.pop(key, None)
            if buf is None:
                continue
            pkts = buf.packets
            n = len(pkts)
            if n >= self.cfg.min_flow_packets:
                feats = self._extractor.extract(list(pkts))
                for f in feats:
                    enriched = self._enrich_network_flow_v1(f, pkts, wall)
                    emitted.append(enriched)
                    self.counters.flows_emitted += 1
                if not feats:
                    logger.warning(
                        "[FlowWindowAggregator] extractor 未返回特征但包数=%d key=%s",
                        n,
                        key,
                    )
            elif n == 1:
                pol = self.cfg.single_packet_idle_policy.lower()
                if pol == "emit_low_confidence":
                    emitted.append(self._build_low_confidence_feature(pkts[0], wall))
                    self.counters.flows_emitted += 1
                    self.counters.low_confidence_emissions += 1
                else:
                    self.counters.single_packet_discarded += 1
            else:
                # 1 < n < min_flow_packets：空闲到期仍不足最小包数，丢弃
                self.counters.partial_flow_discarded += 1

        return emitted
