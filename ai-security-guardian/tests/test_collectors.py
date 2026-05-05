"""
Phase 1 数据采集层单元测试
覆盖：PacketCollector / LogCollector / ThreatIntelCollector

运行：
    pytest tests/test_collectors.py -v
"""
from __future__ import annotations

import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# 将项目根目录加入 sys.path，便于直接运行 pytest
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.collectors.log_collector import LogCollector
from src.collectors.packet_collector import PacketCollector
from src.collectors.threat_intel import ThreatIntelCollector


# ======================================================================
# PacketCollector 测试
# ======================================================================
class TestPacketCollector:
    """网络流量采集器测试"""

    def test_packet_collector_init(self):
        """默认参数初始化正确"""
        collector = PacketCollector()
        assert collector.interface is None
        assert collector.packet_queue.maxsize == 10000
        assert collector._running is False
        assert collector._thread is None
        assert collector.drop_count == 0

    def test_packet_collector_custom_params(self):
        """自定义参数初始化正确"""
        collector = PacketCollector(interface='eth0', queue_size=100)
        assert collector.interface == 'eth0'
        assert collector.packet_queue.maxsize == 100

    def test_packet_callback_ip_tcp(self):
        """含 IP+TCP 的数据包能被正确解析"""
        from scapy.all import IP, TCP

        collector = PacketCollector(queue_size=10)
        packet = IP(src='1.2.3.4', dst='5.6.7.8', ttl=64) / TCP(
            sport=1234, dport=80, flags='S'
        )
        collector._packet_callback(packet)

        assert collector.packet_queue.qsize() == 1
        parsed = collector.packet_queue.get_nowait()
        assert parsed['src_ip'] == '1.2.3.4'
        assert parsed['dst_ip'] == '5.6.7.8'
        assert parsed['protocol'] == 'TCP'
        assert parsed['src_port'] == 1234
        assert parsed['dst_port'] == 80
        assert 'S' in parsed['tcp_flags']
        assert parsed['ttl'] == 64
        assert parsed['packet_len'] > 0
        assert 'timestamp' in parsed

    def test_packet_callback_ip_udp(self):
        """含 IP+UDP 的数据包能被正确解析"""
        from scapy.all import IP, UDP

        collector = PacketCollector(queue_size=10)
        packet = IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=53, dport=5353)
        collector._packet_callback(packet)

        parsed = collector.packet_queue.get_nowait()
        assert parsed['protocol'] == 'UDP'
        assert parsed['src_port'] == 53
        assert parsed['dst_port'] == 5353
        assert parsed['tcp_flags'] == ''

    def test_packet_callback_ip_icmp(self):
        """含 IP+ICMP 的数据包能被正确解析"""
        from scapy.all import ICMP, IP

        collector = PacketCollector(queue_size=10)
        packet = IP(src='1.1.1.1', dst='2.2.2.2') / ICMP()
        collector._packet_callback(packet)

        parsed = collector.packet_queue.get_nowait()
        assert parsed['protocol'] == 'ICMP'
        assert parsed['src_port'] == 0
        assert parsed['dst_port'] == 0

    def test_packet_callback_non_ip(self):
        """非 IP 数据包应被直接忽略"""
        from scapy.all import Ether

        collector = PacketCollector(queue_size=10)
        packet = Ether()  # 无 IP 层
        collector._packet_callback(packet)

        assert collector.packet_queue.qsize() == 0

    def test_packet_callback_queue_full(self):
        """队列已满时，丢弃计数应递增"""
        from scapy.all import IP, TCP

        collector = PacketCollector(queue_size=2)
        packet = IP(src='1.2.3.4', dst='5.6.7.8') / TCP(sport=1, dport=2)

        for _ in range(5):
            collector._packet_callback(packet)

        assert collector.packet_queue.qsize() == 2
        assert collector.drop_count == 3

    def test_get_packets_empty(self):
        """空队列返回空列表"""
        collector = PacketCollector()
        assert collector.get_packets() == []

    def test_get_packets_with_max_count(self):
        """max_count 正确限制取出数量"""
        from scapy.all import IP, TCP

        collector = PacketCollector(queue_size=100)
        packet = IP(src='1.2.3.4', dst='5.6.7.8') / TCP(sport=1, dport=2)
        for _ in range(10):
            collector._packet_callback(packet)

        packets = collector.get_packets(max_count=3)
        assert len(packets) == 3
        assert collector.packet_queue.qsize() == 7

    def test_start_stop_no_exception(self):
        """start/stop 流程不抛异常（抓包被 mock）"""
        collector = PacketCollector(queue_size=10)
        with patch('src.collectors.packet_collector.sniff') as mock_sniff:
            mock_sniff.return_value = None
            collector.start()
            assert collector._running is True
            time.sleep(0.05)
            collector.stop()
            assert collector._running is False
            assert collector._thread is None


# ======================================================================
# LogCollector 测试
# ======================================================================
class TestLogCollector:
    """日志采集器测试"""

    def test_log_collector_init(self):
        """默认参数初始化"""
        collector = LogCollector(log_path='/tmp/fake.log')
        assert collector.log_path == '/tmp/fake.log'
        assert collector.log_type == 'web'
        assert collector.last_position == 0

    def test_parse_web_log_valid(self):
        """标准 Apache 格式日志解析正确"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='web')
        line = (
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326'
        )
        result = collector._parse_web_log(line)

        assert result is not None
        assert result['src_ip'] == '192.168.1.1'
        assert result['http_method'] == 'GET'
        assert result['method'] == 'GET'
        assert result['url'] == '/apache_pb.gif'
        assert result['status_code'] == 200
        assert result['response_size'] == 2326
        assert result['user_agent'] == ''
        assert result['timestamp'] == '10/Oct/2000:13:55:36 -0700'
        assert result['log_type'] == 'web'

    def test_parse_web_log_combined_with_user_agent(self):
        """Combined Log Format：应解析 referer 与 user-agent。"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='web')
        line = (
            '203.0.113.9 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /search?q=1 HTTP/1.0" 200 2326 '
            '"http://example.com/ref" "Mozilla/5.0 (TestAgent)"'
        )
        result = collector._parse_web_log(line)
        assert result is not None
        assert result['src_ip'] == '203.0.113.9'
        assert result['user_agent'] == 'Mozilla/5.0 (TestAgent)'
        assert result['method'] == 'GET'
        assert result['response_size'] == 2326

    def test_parse_web_log_dash_response_size(self):
        """Nginx 以 ``-`` 表示缺失字节数时应映射为 0。"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='web')
        line = (
            '192.168.1.5 - - [10/Oct/2000:13:55:36 -0700] '
            '"HEAD /health HTTP/1.0" 204 -'
        )
        result = collector._parse_web_log(line)
        assert result is not None
        assert result['response_size'] == 0

    def test_parse_web_log_invalid(self):
        """非法格式返回 None"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='web')
        assert collector._parse_web_log('not a valid log line') is None
        assert collector._parse_web_log('') is None

    def test_parse_system_log_valid(self):
        """系统日志解析正确"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='system')
        line = 'Oct 10 13:55:36 sshd[1234]: Failed password for user'
        result = collector._parse_system_log(line)

        assert result is not None
        assert result['timestamp'] == 'Oct 10 13:55:36'
        assert result['process'] == 'sshd[1234]'
        assert result['log_type'] == 'system'

    def test_parse_system_log_short_line(self):
        """不足 4 段的行返回 None"""
        collector = LogCollector(log_path='/tmp/fake.log', log_type='system')
        assert collector._parse_system_log('Oct 10') is None

    def test_read_new_lines_nonexistent(self):
        """文件不存在时返回空列表"""
        collector = LogCollector(log_path='/nonexistent/path/xxx.log')
        assert collector.read_new_lines() == []

    def test_incremental_read(self, tmp_path):
        """增量读取：第二次只读取新增内容"""
        log_file = tmp_path / 'access.log'
        line1 = (
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /a HTTP/1.0" 200 100\n'
        )
        line2 = (
            '192.168.1.2 - - [10/Oct/2000:13:55:37 -0700] '
            '"POST /b HTTP/1.0" 404 50\n'
        )

        log_file.write_text(line1, encoding='utf-8')
        collector = LogCollector(str(log_file), log_type='web')

        first = collector.read_new_lines()
        assert len(first) == 1
        assert first[0]['src_ip'] == '192.168.1.1'

        # 再次读取应为空
        assert collector.read_new_lines() == []

        # 追加一行后，只应读出新行
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(line2)

        second = collector.read_new_lines()
        assert len(second) == 1
        assert second[0]['src_ip'] == '192.168.1.2'
        assert second[0]['http_method'] == 'POST'

    def test_reset_position(self, tmp_path):
        """reset_position 后可重新全量读取"""
        log_file = tmp_path / 'a.log'
        log_file.write_text(
            '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /a HTTP/1.0" 200 100\n',
            encoding='utf-8',
        )
        collector = LogCollector(str(log_file), log_type='web')
        assert len(collector.read_new_lines()) == 1
        assert len(collector.read_new_lines()) == 0
        collector.reset_position()
        assert len(collector.read_new_lines()) == 1


# ======================================================================
# ThreatIntelCollector 测试
# ======================================================================
class TestThreatIntelCollector:
    """威胁情报采集器测试"""

    @pytest.mark.parametrize('ip', [
        '192.168.1.1',
        '8.8.8.8',
        '0.0.0.0',
        '255.255.255.255',
        '10.0.0.1',
    ])
    def test_validate_ip_valid(self, ip):
        """合法 IP 地址应通过验证"""
        assert ThreatIntelCollector._validate_ip(ip) is True

    @pytest.mark.parametrize('ip', [
        '999.999.999.999',
        '1.2.3',
        'abc',
        '',
        '1.2.3.4.5',
        '256.1.1.1',
        '1.2.3.4; rm -rf /',
        '01.02.03.04',   # 拒绝前导 0
        '1.2.3.-1',
    ])
    def test_validate_ip_invalid(self, ip):
        """非法 IP 地址必须被拒绝（防止注入）"""
        assert ThreatIntelCollector._validate_ip(ip) is False

    def test_validate_ip_non_string(self):
        """非字符串输入安全返回 False"""
        assert ThreatIntelCollector._validate_ip(None) is False
        assert ThreatIntelCollector._validate_ip(123) is False

    def test_check_ip_invalid_format(self):
        """无效 IP 格式返回安全默认值"""
        collector = ThreatIntelCollector()
        result = collector.check_ip('not-an-ip')
        assert result['is_malicious'] is False
        assert result['reason'] == 'invalid_ip_format'

    def test_check_ip_cache_hit(self):
        """本地缓存命中时直接返回"""
        collector = ThreatIntelCollector()
        collector.add_ip_to_blacklist('1.2.3.4')
        result = collector.check_ip('1.2.3.4')
        assert result['is_malicious'] is True
        assert result['source'] == 'local'
        assert result['ioc_value'] == '1.2.3.4'

    def test_check_ip_no_api_key(self):
        """无 API Key 且不在缓存时返回非恶意"""
        collector = ThreatIntelCollector()
        result = collector.check_ip('8.8.8.8')
        assert result['is_malicious'] is False
        assert result['source'] == 'none'
        assert result.get('ioc_value') == '8.8.8.8'

    @patch('src.collectors.ioc_providers.requests.get')
    def test_query_abuseipdb_malicious(self, mock_get):
        """AbuseIPDB 返回高分时应标记为恶意"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {'data': {'abuseConfidenceScore': 90}}
        mock_get.return_value = mock_resp

        collector = ThreatIntelCollector(abuseipdb_key='fake-key', external_wait_sec=5.0)
        result = collector.check_ip('1.2.3.4')

        assert result['is_malicious'] is True
        assert result['source'] == 'abuseipdb'
        assert result['score'] == 90
        mock_get.assert_called_once()
        _args, kwargs = mock_get.call_args
        assert kwargs.get('timeout') == collector.external_http_timeout

    @patch('src.collectors.ioc_providers.requests.get')
    def test_query_abuseipdb_benign(self, mock_get):
        """AbuseIPDB 返回低分时不标记为恶意"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {'data': {'abuseConfidenceScore': 10}}
        mock_get.return_value = mock_resp

        collector = ThreatIntelCollector(abuseipdb_key='fake-key', external_wait_sec=5.0)
        result = collector.check_ip('1.2.3.4')
        assert result['is_malicious'] is False
        assert result['source'] == 'none'

    @patch('src.collectors.ioc_providers.requests.get')
    def test_query_abuseipdb_timeout(self, mock_get):
        """AbuseIPDB 请求超时时应安全降级"""
        import requests as req_mod

        mock_get.side_effect = req_mod.exceptions.Timeout('timeout')
        collector = ThreatIntelCollector(abuseipdb_key='fake-key', external_wait_sec=5.0)
        result = collector.check_ip('1.2.3.4')
        assert result['is_malicious'] is False
        assert result['source'] == 'none'

    @patch('src.collectors.ioc_providers.requests.get')
    def test_query_abuseipdb_network_error(self, mock_get):
        """网络异常时安全降级"""
        import requests as req_mod

        mock_get.side_effect = req_mod.exceptions.ConnectionError('conn err')
        collector = ThreatIntelCollector(abuseipdb_key='fake-key', external_wait_sec=5.0)
        result = collector.check_ip('1.2.3.4')
        assert result['is_malicious'] is False
        assert result['source'] == 'none'

    def test_check_domain_empty(self):
        """空域名安全处理"""
        collector = ThreatIntelCollector()
        assert collector.check_domain('') == {
            'is_malicious': False, 'source': 'none'
        }
        assert collector.check_domain(None) == {
            'is_malicious': False, 'source': 'none'
        }

    def test_check_domain_cached(self):
        """域名缓存命中（大小写不敏感）"""
        collector = ThreatIntelCollector()
        collector.add_domain_to_blacklist('Evil.COM')
        result = collector.check_domain('evil.com')
        assert result['is_malicious'] is True
        assert result['source'] == 'local'
        assert result['ioc_value'] == 'evil.com'

    def test_check_domain_unknown(self):
        """未知域名返回非恶意"""
        collector = ThreatIntelCollector()
        r = collector.check_domain('benign.example.com')
        assert r['is_malicious'] is False
        assert r['source'] == 'none'

    def test_get_blacklist_stats_structure(self):
        """统计结构包含必需字段"""
        collector = ThreatIntelCollector()
        stats = collector.get_blacklist_stats()
        assert 'ip_count' in stats
        assert 'domain_count' in stats
        assert 'last_update' in stats
        assert stats['ip_count'] == 0
        assert stats['last_update'] is None

    def test_update_blacklist_updates_timestamp(self):
        """update_blacklist 后 last_update 不再为 None"""
        collector = ThreatIntelCollector()
        collector.update_blacklist()
        stats = collector.get_blacklist_stats()
        assert stats['last_update'] is not None

    def test_add_ip_to_blacklist_rejects_invalid(self):
        """拒绝把非法 IP 加入黑名单"""
        collector = ThreatIntelCollector()
        assert collector.add_ip_to_blacklist('1.2.3.4; rm -rf /') is False
        assert collector.get_blacklist_stats()['ip_count'] == 0

    def test_thread_safety_check_ip(self):
        """多线程并发 check_ip 不会崩溃或数据竞争"""
        import threading as th

        collector = ThreatIntelCollector()
        collector.add_ip_to_blacklist('1.2.3.4')

        results = []
        errors = []

        def worker():
            try:
                for _ in range(50):
                    r = collector.check_ip('1.2.3.4')
                    results.append(r['is_malicious'])
            except Exception as exc:
                errors.append(exc)

        threads = [th.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(results)
        assert len(results) == 8 * 50


if __name__ == '__main__':  # pragma: no cover
    sys.exit(pytest.main([__file__, '-v']))
