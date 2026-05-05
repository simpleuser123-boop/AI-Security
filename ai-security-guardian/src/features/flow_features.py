"""
网络流量特征提取器
对应架构文档 §4.2.1 网络流量特征

基于五元组 (src_ip, src_port, dst_ip, dst_port, protocol) 对数据包进行流聚合，
计算每条流的统计特征（包数、字节数、包长均值/方差、TCP 标志位分布等），
供下游检测引擎（DDoS / 入侵检测 / 异常检测）使用。
"""
from __future__ import annotations

import logging
from typing import Dict, List

import numpy as np

from src.schema.feature_schemas import attach_network_flow_v1_block

logger = logging.getLogger(__name__)


class FlowFeatureExtractor:
    """
    基于五元组的流统计特征提取器。

    工作机制：
        1. ``extract()`` 被调用时，按五元组 key 对输入数据包分组；
        2. 对于包数 >= 2 的流，计算统计特征（包数、字节数、包长均值/方差等）；
        3. 统计 TCP 标志位（SYN/ACK/FIN/RST）数量；
        4. 处理完成后清空内部流状态（无状态化批处理）。

    Attributes:
        timeout:     流超时时间（秒），超过此时间视为新流（预留字段，当前批处理模式未启用）。
        _flows:      五元组 key 到流状态的映射。
    """

    def __init__(self, timeout: float = 120.0) -> None:
        """
        Args:
            timeout: 流超时时间（秒），默认 120s。
        """
        self.timeout: float = timeout
        self._flows: Dict[str, dict] = {}

    def _make_flow_key(self, packet: dict) -> str:
        """
        生成五元组 key。

        格式: ``{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}``
        """
        return (
            f"{packet.get('src_ip', '')}:{packet.get('src_port', 0)}-"
            f"{packet.get('dst_ip', '')}:{packet.get('dst_port', 0)}-"
            f"{packet.get('protocol', 'OTHER')}"
        )

    def extract(self, packets: List[dict]) -> List[dict]:
        """
        从数据包列表中提取流特征。

        Args:
            packets: 数据包字典列表，每个元素至少包含:
                     src_ip / src_port / dst_ip / dst_port / protocol /
                     timestamp / packet_len / tcp_flags。

        Returns:
            特征字典列表，每条流一条记录。仅返回包数 >= 2 的流。
        """
        if not packets:
            return []

        # 1. 按五元组分组
        for pkt in packets:
            try:
                key = self._make_flow_key(pkt)
            except Exception as exc:
                logger.warning("[FlowFeatureExtractor] 跳过无效数据包: %s", exc)
                continue

            if key not in self._flows:
                self._flows[key] = {
                    'start_time': pkt.get('timestamp', 0.0),
                    'packets': [],
                    'src_ip': pkt.get('src_ip', ''),
                    'dst_ip': pkt.get('dst_ip', ''),
                    'protocol': pkt.get('protocol', 'OTHER'),
                }
            self._flows[key]['packets'].append(pkt)

        # 2. 计算每个流的统计特征
        features_list: List[dict] = []
        for key, flow in self._flows.items():
            pkts: List[dict] = flow['packets']
            if len(pkts) < 2:
                continue

            pkt_lens = np.asarray(
                [int(p.get('packet_len', 0)) for p in pkts], dtype=np.float64
            )

            features: dict = {
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'protocol': flow['protocol'],
                'src_port': int(pkts[0].get('src_port', 0)),
                'dst_port': int(pkts[0].get('dst_port', 0)),
                'flow_pkt_count': int(len(pkts)),
                'flow_byte_count': int(pkt_lens.sum()),
                'pkt_len_mean': float(np.mean(pkt_lens)),
                'pkt_len_std': float(np.std(pkt_lens)),
                'pkt_len_max': float(np.max(pkt_lens)),
                'pkt_len_min': float(np.min(pkt_lens)),
            }

            # 3. TCP 标志位统计
            syn_count = sum(1 for p in pkts if 'S' in str(p.get('tcp_flags', '')))
            ack_count = sum(1 for p in pkts if 'A' in str(p.get('tcp_flags', '')))
            fin_count = sum(1 for p in pkts if 'F' in str(p.get('tcp_flags', '')))
            rst_count = sum(1 for p in pkts if 'R' in str(p.get('tcp_flags', '')))

            features.update({
                'syn_count': int(syn_count),
                'ack_count': int(ack_count),
                'fin_count': int(fin_count),
                'rst_count': int(rst_count),
            })
            attach_network_flow_v1_block(features)
            features_list.append(features)

        logger.debug(
            "[FlowFeatureExtractor] 本次处理 %d 个数据包，生成 %d 条流特征",
            len(packets), len(features_list),
        )

        # 4. 清空流状态
        self._flows.clear()
        return features_list
