"""
R1 / P0：流窗口聚合器与主入口批量网络路径单元测试
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from main import RuntimeConfig, SecurityGuardian  # noqa: E402
from src.collectors.packet_collector import PacketCollector  # noqa: E402
from src.features.flow_window_aggregator import (  # noqa: E402
    FlowWindowAggregator,
    FlowWindowAggregatorConfig,
)


def _pkt(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    proto: str,
    ts: float,
    plen: int = 64,
    flags: str = "",
) -> dict:
    return {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,
        "timestamp": ts,
        "packet_len": plen,
        "tcp_flags": flags,
    }


class TestFlowWindowAggregatorCrossTick:
    """同一五元组多包跨 tick：空闲超时后输出 1 条 network_flow_v1。"""

    def test_three_packets_across_ticks_one_flow_feature(self) -> None:
        cfg = FlowWindowAggregatorConfig(
            min_flow_packets=3,
            flow_idle_timeout_sec=0.05,
            aggregation_window_sec=60.0,
            single_packet_idle_policy="discard",
        )
        agg = FlowWindowAggregator(cfg)
        t0 = 1_700_000_000.0
        flow = ("10.0.0.1", "10.0.0.2", 1000, 80, "TCP")

        assert agg.tick([_pkt(*flow, t0, 60, "S")], now=t0) == []
        assert agg.tick([_pkt(*flow, t0 + 0.001, 60, "SA")], now=t0 + 0.001) == []
        assert agg.tick([_pkt(*flow, t0 + 0.002, 100, "PA")], now=t0 + 0.002) == []

        outs = agg.tick([], now=t0 + 1.0)
        assert len(outs) == 1
        f = outs[0]
        assert f["schema_version"] == "network_flow_v1"
        assert f["packet_count"] == 3
        assert f["byte_count"] == 60 + 60 + 100
        assert f["flow_pkt_count"] == 3
        assert f["flow_byte_count"] == 60 + 60 + 100
        assert f["src_ip"] == "10.0.0.1"
        assert f["dst_ip"] == "10.0.0.2"
        assert f["src_port"] == 1000
        assert f["dst_port"] == 80
        assert f["protocol"] == "TCP"
        assert f["flow_duration"] >= 0.0
        assert f["flow_pkt_rate"] > 0
        assert f["flow_byte_rate"] > 0
        assert "window_unique_dst_ip" in f
        assert "window_unique_dst_port" in f
        assert isinstance(f["window_protocol_dist"], dict)
        assert f.get("flow_low_confidence") is False


class TestFlowWindowAggregatorSinglePacketPolicy:
    def test_single_packet_no_output_before_idle(self) -> None:
        cfg = FlowWindowAggregatorConfig(
            min_flow_packets=2,
            flow_idle_timeout_sec=10.0,
            single_packet_idle_policy="discard",
        )
        agg = FlowWindowAggregator(cfg)
        t0 = 100.0
        p = _pkt("1.1.1.1", "2.2.2.2", 1, 2, "TCP", t0, 100, "S")
        assert agg.tick([p], now=t0) == []
        assert agg.tick([], now=t0 + 1.0) == []

    def test_single_packet_discard_after_idle(self) -> None:
        cfg = FlowWindowAggregatorConfig(
            min_flow_packets=2,
            flow_idle_timeout_sec=0.01,
            single_packet_idle_policy="discard",
        )
        agg = FlowWindowAggregator(cfg)
        t0 = 200.0
        agg.tick([_pkt("1.1.1.1", "2.2.2.2", 1, 2, "TCP", t0, 100, "S")], now=t0)
        outs = agg.tick([], now=t0 + 1.0)
        assert outs == []
        assert agg.counters.single_packet_discarded == 1

    def test_single_packet_emit_low_confidence_after_idle(self) -> None:
        cfg = FlowWindowAggregatorConfig(
            min_flow_packets=2,
            flow_idle_timeout_sec=0.01,
            single_packet_idle_policy="emit_low_confidence",
        )
        agg = FlowWindowAggregator(cfg)
        t0 = 300.0
        agg.tick([_pkt("1.1.1.1", "2.2.2.2", 1, 2, "TCP", t0, 100, "S")], now=t0)
        outs = agg.tick([], now=t0 + 1.0)
        assert len(outs) == 1
        assert outs[0]["flow_low_confidence"] is True
        assert outs[0]["packet_count"] == 1
        assert agg.counters.low_confidence_emissions == 1


class TestPacketCollectorQueueFull:
    """队列满时丢包计数递增（不抛异常）。"""

    def test_drop_count_on_full_queue(self) -> None:
        from scapy.all import IP, TCP

        collector = PacketCollector(queue_size=1)
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2)
        for _ in range(4):
            collector._packet_callback(pkt)
        assert collector.packet_queue.qsize() == 1
        assert collector.drop_count == 3


class TestSecurityGuardianNetworkDrain:
    """批量读取异常时记录错误计数且可继续调用。"""

    def test_drain_increments_error_counter_on_get_packets_failure(self) -> None:
        os.environ.setdefault("ENABLE_PACKET_CAPTURE", "false")
        os.environ.setdefault("ENABLE_WEB_LOG", "false")
        cfg = RuntimeConfig.from_env()
        cfg.enable_packet_capture = True
        cfg.enable_web_log = False

        g = SecurityGuardian(cfg=cfg)
        _n = 0

        def _get_packets(*_a, **_k):
            nonlocal _n
            _n += 1
            if _n == 1:
                raise RuntimeError("simulated queue read")
            return []

        g.packet_collector = SimpleNamespace(get_packets=_get_packets)

        assert g._packet_queue_read_errors == 0
        g._drain_network_packets_this_tick()
        assert g._packet_queue_read_errors == 1

        g._drain_network_packets_this_tick()
        assert g._packet_queue_read_errors == 1
        assert _n == 2
