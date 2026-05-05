"""
Web 请求特征提取器
对应架构文档 §4.2.2 Web 请求特征

【安全修复】必须多层 URL 解码 + 所有正则匹配都在解码后的 URL 上执行，
           防止攻击者通过 ``%253C -> %3C -> <`` 多层编码链绕过检测。
"""
from __future__ import annotations

import logging
import re
from typing import Pattern
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class WebFeatureExtractor:
    """
    HTTP 请求特征提取器。

    输出用于下游:
        - Web 攻击规则/ML 引擎(SQL 注入 / XSS / 命令注入);
        - 异常检测(基于长度、参数数量、特殊字符比例);
        - 安全审计日志。

    所有正则均预编译且使用 ``re.IGNORECASE``,以加速批量处理。
    """

    # ===== 预编译正则:SQL 注入关键字 =====
    SQL_KEYWORDS: Pattern[str] = re.compile(
        r"(union\s+select|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|"
        r"delete\s+from|drop\s+(table|database)|alter\s+table|exec(ute)?\s*\(|"
        r"xp_cmdshell|information_schema|0x[0-9a-f]+|char\s*\(|concat\s*\(|"
        r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay|load_file\s*\(|"
        r"\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|'\s*or\s*')",
        re.IGNORECASE,
    )

    # ===== 预编译正则:XSS 关键字 =====
    XSS_KEYWORDS: Pattern[str] = re.compile(
        r"(<\s*script\b|</\s*script\s*>|javascript\s*:|vbscript\s*:|"
        r"on(error|load|click|mouseover|focus|submit|toggle|start)\s*=|"
        r"alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|"
        r"document\.(cookie|domain|write|location)|window\.(location|open)|"
        r"<\s*iframe\b|<\s*svg\b|<\s*img\b[^>]*onerror)",
        re.IGNORECASE,
    )

    # ===== 预编译正则:命令注入关键字 =====
    CMD_KEYWORDS: Pattern[str] = re.compile(
        r"(;\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ping)\b|"
        r"\|\s*(cat|ls|id|whoami|nc|wget|curl|bash|sh)\b|"
        r"&&\s*(cat|ls|id|whoami|wget|curl)\b|"
        r"\$\([^)]+\)|`[^`]+`|"
        r"/etc/(passwd|shadow|hosts)|/proc/self|/bin/(bash|sh)|"
        r"\bbash\s+-i\b|\bnc\s+-e\b|reverse.*shell)",
        re.IGNORECASE,
    )

    # ===== 预编译正则:特殊字符 =====
    SPECIAL_CHARS: Pattern[str] = re.compile(r"[?'\"<>;|&`$\\{}\[\]()]")

    # 【安全修复】URL 最大解码层数,防止无限循环
    MAX_DECODE_LAYERS: int = 5

    @staticmethod
    def _decode_url(url: str) -> str:
        """
        【安全修复】多层 URL 解码(最多 5 层)。

        攻击者可能使用多层编码绕过检测:
            ``%25253C -> %253C -> %3C -> <``

        本方法循环调用 ``urllib.parse.unquote`` 直到:
            1. 连续两次解码结果相同(已完全解码);或
            2. 达到最大层数(防止构造超长编码链耗尽资源)。

        所有解码异常被静默吞掉,返回当前已解码的内容,
        避免单个畸形 URL 导致整个检测流水线崩溃。

        Args:
            url: 原始 URL 字符串,可能经过 0-N 层 URL 编码。

        Returns:
            完全解码后的 URL 字符串。
        """
        if not isinstance(url, str):
            return ''

        decoded: str = url
        for _ in range(WebFeatureExtractor.MAX_DECODE_LAYERS):
            try:
                new_decoded = unquote(decoded)
            except Exception as exc:  # pragma: no cover - unquote 基本不抛异常
                logger.debug("[WebFeatureExtractor] URL 解码异常: %s", exc)
                break
            if new_decoded == decoded:
                break
            decoded = new_decoded
        return decoded

    def extract(self, log_entry: dict) -> dict:
        """
        从 HTTP 日志条目中提取安全相关特征。

        Args:
            log_entry: 日志字典,通常包含:
                url、http_method 或 method、status_code、response_size、
                src_ip、user_agent、timestamp。

        Returns:
            特征字典；含 ``web_request_v1`` 契约块(含 src_ip 等)与顶层 ``src_ip``,
            供检测器/融合/响应/审计链路直接使用。
        """
        url: str = str(log_entry.get('url', '') or '')
        method_raw = log_entry.get('http_method', log_entry.get('method', 'GET'))
        method: str = str(method_raw or 'GET').upper()
        src_ip: str = str(log_entry.get('src_ip', '') or '').strip()
        user_agent: str = str(log_entry.get('user_agent', '') or '')
        ts_val = log_entry.get('timestamp')
        log_timestamp: str = '' if ts_val is None else str(ts_val)

        # 【安全修复】所有关键字匹配必须基于解码后的 URL,防止编码绕过
        decoded_url: str = self._decode_url(url)

        # 参数数量: & 或 ; 分隔 +1(至少 1 个)
        param_count: int = url.count('&') + url.count(';') + (1 if '?' in url else 0)

        status_code = int(log_entry.get('status_code', 200) or 0)
        response_size = int(log_entry.get('response_size', 0) or 0)

        web_request_v1: dict = {
            'schema': 'web_request_v1',
            'src_ip': src_ip,
            'url': url,
            'method': method,
            'status_code': status_code,
            'response_size': response_size,
            'user_agent': user_agent,
            'timestamp': log_timestamp,
        }

        features: dict = {
            'url_length': len(url),
            'decoded_url_length': len(decoded_url),
            'http_method': method,
            'param_count': int(param_count),
            'status_code': status_code,
            'response_size': response_size,
            'src_ip': src_ip,
            'user_agent': user_agent,
            'log_timestamp': log_timestamp,
            'web_request_v1': web_request_v1,
            # 【安全修复】以下统计必须作用在 decoded_url 上
            'special_char_count': len(self.SPECIAL_CHARS.findall(decoded_url)),
            'sql_keyword_count': len(self.SQL_KEYWORDS.findall(decoded_url)),
            'xss_keyword_count': len(self.XSS_KEYWORDS.findall(decoded_url)),
            'cmd_keyword_count': len(self.CMD_KEYWORDS.findall(decoded_url)),
            # 原始与解码后 URL,供下游规则引擎/ML 模型二次使用
            'url_raw': url,
            'url_decoded': decoded_url,
        }
        return features
