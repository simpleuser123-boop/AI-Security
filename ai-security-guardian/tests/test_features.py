"""
Phase 2 特征工程层 - 验证脚本
对应架构文档 §4 / Phase 2 提示词验收标准

运行方式:
    cd ai-security-guardian
    python -m pytest tests/test_features.py -v
"""
from __future__ import annotations

import os
import sys
import tempfile

import numpy as np
import pytest

# 确保 src 能被导入
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features import (  # noqa: E402
    FeaturePipeline,
    FlowFeatureExtractor,
    WebFeatureExtractor,
)


# =====================================================================
# 测试 1: FlowFeatureExtractor
# =====================================================================
class TestFlowFeatureExtractor:
    """验证网络流量特征提取器。"""

    @staticmethod
    def _build_sample_packets():
        """构造 8 个数据包,组成 2 条流(TCP + UDP)。"""
        base_ts = 1_700_000_000.0
        tcp_flow = [
            # TCP 三次握手 + 数据传输 + FIN
            {'src_ip': '192.168.1.100', 'src_port': 54321,
             'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
             'timestamp': base_ts + 0.0, 'packet_len': 60, 'tcp_flags': 'S'},
            {'src_ip': '192.168.1.100', 'src_port': 54321,
             'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
             'timestamp': base_ts + 0.1, 'packet_len': 60, 'tcp_flags': 'SA'},
            {'src_ip': '192.168.1.100', 'src_port': 54321,
             'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
             'timestamp': base_ts + 0.2, 'packet_len': 52, 'tcp_flags': 'A'},
            {'src_ip': '192.168.1.100', 'src_port': 54321,
             'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
             'timestamp': base_ts + 0.3, 'packet_len': 1500, 'tcp_flags': 'PA'},
            {'src_ip': '192.168.1.100', 'src_port': 54321,
             'dst_ip': '10.0.0.1', 'dst_port': 80, 'protocol': 'TCP',
             'timestamp': base_ts + 0.4, 'packet_len': 120, 'tcp_flags': 'FA'},
        ]
        udp_flow = [
            {'src_ip': '192.168.1.200', 'src_port': 5000,
             'dst_ip': '8.8.8.8', 'dst_port': 53, 'protocol': 'UDP',
             'timestamp': base_ts + 1.0, 'packet_len': 80, 'tcp_flags': ''},
            {'src_ip': '192.168.1.200', 'src_port': 5000,
             'dst_ip': '8.8.8.8', 'dst_port': 53, 'protocol': 'UDP',
             'timestamp': base_ts + 1.1, 'packet_len': 120, 'tcp_flags': ''},
            {'src_ip': '192.168.1.200', 'src_port': 5000,
             'dst_ip': '8.8.8.8', 'dst_port': 53, 'protocol': 'UDP',
             'timestamp': base_ts + 1.2, 'packet_len': 200, 'tcp_flags': ''},
        ]
        return tcp_flow + udp_flow

    def test_extract_returns_two_flows(self):
        """应聚合成 2 条流。"""
        extractor = FlowFeatureExtractor()
        features = extractor.extract(self._build_sample_packets())
        assert len(features) == 2

    def test_tcp_flow_feature_values(self):
        extractor = FlowFeatureExtractor()
        features = extractor.extract(self._build_sample_packets())

        tcp_flow = next(f for f in features if f['protocol'] == 'TCP')
        assert tcp_flow['flow_pkt_count'] == 5
        assert tcp_flow['flow_byte_count'] == 60 + 60 + 52 + 1500 + 120
        assert tcp_flow['pkt_len_max'] == 1500
        assert tcp_flow['pkt_len_min'] == 52
        # numpy 均值
        expected_mean = np.mean([60, 60, 52, 1500, 120])
        assert abs(tcp_flow['pkt_len_mean'] - expected_mean) < 1e-6
        # TCP 标志位计数(S 出现在 'S' 和 'SA' 中)
        assert tcp_flow['syn_count'] == 2
        assert tcp_flow['ack_count'] == 4  # 'SA','A','PA','FA'
        assert tcp_flow['fin_count'] == 1
        assert tcp_flow['rst_count'] == 0
        # 五元组
        assert tcp_flow['src_ip'] == '192.168.1.100'
        assert tcp_flow['dst_ip'] == '10.0.0.1'
        assert tcp_flow['src_port'] == 54321
        assert tcp_flow['dst_port'] == 80

    def test_single_packet_flow_dropped(self):
        """只有 1 个包的流不应输出特征(要求 >= 2)。"""
        extractor = FlowFeatureExtractor()
        single = [{
            'src_ip': '1.1.1.1', 'src_port': 1, 'dst_ip': '2.2.2.2',
            'dst_port': 2, 'protocol': 'TCP', 'timestamp': 0,
            'packet_len': 100, 'tcp_flags': 'S',
        }]
        assert extractor.extract(single) == []

    def test_state_cleared_between_batches(self):
        """extract 调用完毕后内部状态应清空。"""
        extractor = FlowFeatureExtractor()
        extractor.extract(self._build_sample_packets())
        assert extractor._flows == {}


# =====================================================================
# 测试 2: WebFeatureExtractor
# =====================================================================
class TestWebFeatureExtractor:
    """验证 Web 请求特征提取器(重点:编码绕过防御)。"""

    def test_normal_request_no_keywords(self):
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': '/api/users?page=1&limit=10',
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 1024,
        })
        assert feat['sql_keyword_count'] == 0
        assert feat['xss_keyword_count'] == 0
        assert feat['cmd_keyword_count'] == 0
        assert feat['http_method'] == 'GET'
        assert feat['status_code'] == 200
        # param_count 至少 >= 1(有 ?)
        assert feat['param_count'] >= 1

    def test_sql_injection_detected(self):
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': "/login?user=admin'%20OR%201=1--",
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 500,
        })
        assert feat['sql_keyword_count'] > 0
        assert 'OR 1=1' in feat['url_decoded'].upper() or \
               "'" in feat['url_decoded']

    def test_xss_detected(self):
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': "/search?q=<script>alert(1)</script>",
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 300,
        })
        assert feat['xss_keyword_count'] > 0

    def test_command_injection_detected(self):
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': "/ping?host=127.0.0.1;cat /etc/passwd",
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 100,
        })
        assert feat['cmd_keyword_count'] > 0

    def test_single_layer_url_encoding_bypass(self):
        """单层 URL 编码: %27 OR 1%3D1-- 应被解码后检测到。"""
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': '/q=%27%20OR%201%3D1--',
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 0,
        })
        assert feat['sql_keyword_count'] > 0, \
            f"单层编码 SQL 注入未被识别: {feat['url_decoded']}"
        # 解码后长度应不同于原始长度
        assert feat['decoded_url_length'] < feat['url_length']

    def test_double_layer_url_encoding_bypass(self):
        """
        【安全修复关键】双层 URL 编码:
        %253Cscript%253E -> %3Cscript%3E -> <script>
        必须在多层解码后被检测。
        """
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': '/page?x=%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 0,
        })
        assert feat['xss_keyword_count'] > 0, \
            f"双层编码 XSS 未被识别: {feat['url_decoded']}"
        assert '<script' in feat['url_decoded'].lower()

    def test_decode_idempotent(self):
        """不含编码的 URL 解码后应与原值基本一致。"""
        extractor = WebFeatureExtractor()
        plain = '/simple/path'
        assert extractor._decode_url(plain) == plain

    def test_decode_handles_non_string(self):
        """非字符串输入应安全返回空串,不抛异常。"""
        assert WebFeatureExtractor._decode_url(None) == ''  # type: ignore[arg-type]

    def test_src_ip_preserved_in_features_and_web_request_v1(self):
        """src_ip 必须在顶层特征与 web_request_v1 中同时保留。"""
        extractor = WebFeatureExtractor()
        feat = extractor.extract({
            'url': '/api/ping',
            'http_method': 'GET',
            'status_code': 200,
            'response_size': 10,
            'src_ip': '198.51.100.10',
            'user_agent': 'curl/8.0',
            'timestamp': '28/Apr/2026:12:00:00 +0000',
        })
        assert feat['src_ip'] == '198.51.100.10'
        wr = feat['web_request_v1']
        assert wr['schema'] == 'web_request_v1'
        assert wr['src_ip'] == '198.51.100.10'
        assert wr['url'] == '/api/ping'
        assert wr['method'] == 'GET'
        assert wr['status_code'] == 200
        assert wr['response_size'] == 10
        assert wr['user_agent'] == 'curl/8.0'
        assert wr['timestamp'] == '28/Apr/2026:12:00:00 +0000'


# =====================================================================
# 测试 3: FeaturePipeline
# =====================================================================
class TestFeaturePipeline:
    """验证特征标准化流水线。"""

    @staticmethod
    def _build_train_samples():
        return [
            {'pkt_count': 10, 'byte_count': 1500, 'protocol': 'TCP', 'src_ip': '1.1.1.1'},
            {'pkt_count': 20, 'byte_count': 3000, 'protocol': 'UDP', 'src_ip': '2.2.2.2'},
            {'pkt_count': 5,  'byte_count': 500,  'protocol': 'TCP', 'src_ip': '3.3.3.3'},
            {'pkt_count': 50, 'byte_count': 8000, 'protocol': 'ICMP','src_ip': '4.4.4.4'},
            {'pkt_count': 30, 'byte_count': 4500, 'protocol': 'TCP', 'src_ip': '5.5.5.5'},
        ]

    def test_fit_identifies_column_types(self):
        pipe = FeaturePipeline()
        pipe.fit(self._build_train_samples())
        assert set(pipe.numeric_columns) == {'pkt_count', 'byte_count'}
        assert set(pipe.categorical_columns) == {'protocol', 'src_ip'}

    def test_transform_returns_2d_array(self):
        pipe = FeaturePipeline()
        samples = self._build_train_samples()
        pipe.fit(samples)
        X = pipe.transform(samples)
        assert isinstance(X, np.ndarray)
        assert X.ndim == 2
        assert X.shape[0] == len(samples)
        assert X.shape[1] == len(pipe.numeric_columns) + len(pipe.categorical_columns)

    def test_numeric_columns_are_standardized(self):
        """标准化后数值列均值 ~0。"""
        pipe = FeaturePipeline()
        samples = self._build_train_samples()
        pipe.fit(samples)
        X = pipe.transform(samples)
        n_numeric = len(pipe.numeric_columns)
        numeric_part = X[:, :n_numeric]
        # 每列均值应接近 0
        means = numeric_part.mean(axis=0)
        assert np.allclose(means, 0, atol=1e-6), f"数值列均值未归零: {means}"

    def test_unknown_category_encoded_as_minus_one(self):
        """未见过的类别应被编码为 -1 而非抛异常。"""
        pipe = FeaturePipeline()
        pipe.fit(self._build_train_samples())

        new_sample = [{
            'pkt_count': 15, 'byte_count': 2000,
            'protocol': 'SCTP',   # 训练时未见过
            'src_ip': '9.9.9.9',  # 训练时未见过
        }]
        X = pipe.transform(new_sample)
        n_numeric = len(pipe.numeric_columns)
        cat_part = X[:, n_numeric:]
        # 两个类别列均应为 -1
        assert (cat_part == FeaturePipeline.UNKNOWN_CATEGORY_CODE).all(), \
            f"未知类别应编码为 -1,实际: {cat_part}"

    def test_save_load_round_trip(self):
        """save/load 往返后 transform 结果应一致。"""
        pipe = FeaturePipeline()
        samples = self._build_train_samples()
        pipe.fit(samples)
        X_before = pipe.transform(samples)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'pipeline.pkl')
            pipe.save(path)
            assert os.path.exists(path)

            loaded = FeaturePipeline.load(path)
            X_after = loaded.transform(samples)

        assert np.allclose(X_before, X_after), "save/load 往返结果不一致"

    def test_transform_before_fit_raises(self):
        pipe = FeaturePipeline()
        with pytest.raises(RuntimeError):
            pipe.transform([{'a': 1}])

    def test_empty_input_transform(self):
        pipe = FeaturePipeline()
        pipe.fit(self._build_train_samples())
        X = pipe.transform([])
        assert X.shape == (
            0,
            len(pipe.numeric_columns) + len(pipe.categorical_columns),
        )


# =====================================================================
# 测试 4: 端到端集成
# =====================================================================
class TestEndToEndIntegration:
    """验证三个模块能端到端协同工作。"""

    def test_flow_and_web_features_through_pipeline(self):
        # 1) 构造数据包 -> FlowFeatureExtractor
        packets = [
            {'src_ip': '10.0.0.1', 'src_port': 1000, 'dst_ip': '10.0.0.2',
             'dst_port': 80, 'protocol': 'TCP',
             'timestamp': 0, 'packet_len': 100, 'tcp_flags': 'S'},
            {'src_ip': '10.0.0.1', 'src_port': 1000, 'dst_ip': '10.0.0.2',
             'dst_port': 80, 'protocol': 'TCP',
             'timestamp': 0.1, 'packet_len': 500, 'tcp_flags': 'A'},
            {'src_ip': '10.0.0.1', 'src_port': 1000, 'dst_ip': '10.0.0.2',
             'dst_port': 80, 'protocol': 'TCP',
             'timestamp': 0.2, 'packet_len': 800, 'tcp_flags': 'PA'},
        ]
        flow_features = FlowFeatureExtractor().extract(packets)
        assert len(flow_features) == 1

        # 2) 构造 Web 日志 -> WebFeatureExtractor
        web_logs = [
            {'url': '/api/items?id=1', 'http_method': 'GET',
             'status_code': 200, 'response_size': 500},
            {'url': "/login?u=admin'%20OR%201=1--", 'http_method': 'POST',
             'status_code': 401, 'response_size': 100},
            {'url': '/q=%253Cscript%253Ealert(1)%253C%252Fscript%253E',
             'http_method': 'GET', 'status_code': 200, 'response_size': 0},
        ]
        web_extractor = WebFeatureExtractor()
        web_features = [web_extractor.extract(log) for log in web_logs]
        assert len(web_features) == 3

        # 3) 合并特征(去除不参与 ML 的冗余字段)
        for wf in web_features:
            wf.pop('url_raw', None)
            wf.pop('url_decoded', None)

        combined = flow_features + web_features
        assert len(combined) == 4

        # 4) FeaturePipeline.fit + transform
        pipe = FeaturePipeline()
        pipe.fit(combined)
        X = pipe.transform(combined)

        assert X.shape[0] == 4
        assert X.shape[1] > 0
        assert not np.isnan(X).any(), "transform 结果含 NaN"

        # 5) 验证 save/load 后整条流水线仍可运行
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'e2e_pipeline.pkl')
            pipe.save(path)
            reloaded = FeaturePipeline.load(path)
            X2 = reloaded.transform(combined)
        assert np.allclose(X, X2)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
