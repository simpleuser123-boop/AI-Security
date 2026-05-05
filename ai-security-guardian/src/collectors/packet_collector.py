"""
网络流量采集器 - 基于 Scapy 的实时数据包采集模块
对应架构文档 §3.3 流量采集架构

职责：
    - 使用 Scapy sniff 接口在后台线程中实时抓取网络流量
    - 解析 IP / TCP / UDP / ICMP 层的关键字段
    - 将解析后的数据包放入线程安全队列，供下游模块消费
    - 当队列满时丢弃最新包并记录告警（保证系统不被 OOM 打爆）
"""
from __future__ import annotations

import logging
import queue
import threading
from datetime import datetime
from typing import List, Optional

from scapy.all import ICMP, IP, TCP, UDP, sniff
from scapy.packet import Packet

logger = logging.getLogger(__name__)


class PacketCollector:
    """实时网络流量采集器"""

    def __init__(self, interface: Optional[str] = None, queue_size: int = 10000):
        """
        Args:
            interface: 网卡名称，None 表示由 Scapy 自动选择默认网卡
            queue_size: 数据包缓冲队列大小，超出后新包会被丢弃
        """
        self.interface = interface
        self.packet_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._drop_count: int = 0

    def _packet_callback(self, packet: Packet) -> None:
        """Scapy 回调函数，解析每个数据包并投递到队列"""
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        parsed = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': 'OTHER',
            'src_port': 0,
            'dst_port': 0,
            'packet_len': len(packet),
            'ttl': ip_layer.ttl,
            'tcp_flags': '',
        }

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            parsed['protocol'] = 'TCP'
            parsed['src_port'] = int(tcp_layer.sport)
            parsed['dst_port'] = int(tcp_layer.dport)
            parsed['tcp_flags'] = str(tcp_layer.flags)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            parsed['protocol'] = 'UDP'
            parsed['src_port'] = int(udp_layer.sport)
            parsed['dst_port'] = int(udp_layer.dport)
        elif packet.haslayer(ICMP):
            parsed['protocol'] = 'ICMP'

        try:
            self.packet_queue.put_nowait(parsed)
        except queue.Full:
            self._drop_count += 1
            if self._drop_count % 1000 == 0:
                logger.warning(
                    f"[PacketCollector] 队列已满，已丢弃 {self._drop_count} 个数据包"
                )

    def start(self) -> None:
        """启动抓包（在后台守护线程中运行）"""
        if self._running:
            logger.warning("[PacketCollector] 已处于运行状态，忽略重复 start 调用")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run, name='PacketCollector', daemon=True
        )
        self._thread.start()
        logger.info(
            f"[PacketCollector] 已启动，接口: {self.interface or '自动'}"
        )

    def _run(self) -> None:
        """Scapy sniff 阻塞循环，stop_filter 判断退出"""
        try:
            sniff(
                prn=self._packet_callback,
                iface=self.interface,
                store=False,
                stop_filter=lambda _pkt: not self._running,
            )
        except PermissionError:
            logger.error(
                "[PacketCollector] 抓包权限不足，请以管理员/root 身份运行"
            )
            self._running = False
        except Exception as exc:  # pragma: no cover - 防御性日志
            logger.error(f"[PacketCollector] sniff 异常退出: {exc}")
            self._running = False

    def stop(self) -> None:
        """停止抓包（标记退出并等待后台线程结束）"""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("[PacketCollector] 已停止")

    def get_packets(self, max_count: int = 100) -> List[dict]:
        """
        从队列中取出最多 max_count 个数据包
        队列为空时立即返回已取出的部分
        """
        packets: List[dict] = []
        for _ in range(max_count):
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    @property
    def drop_count(self) -> int:
        """累计丢弃的数据包数（用于监控）"""
        return self._drop_count
