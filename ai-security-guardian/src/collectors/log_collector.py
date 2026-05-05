"""
日志采集器 - 支持增量读取系统日志与 Web access.log
对应架构文档 §3.2 数据源

职责：
    - 按文件增量（tell/seek）方式读取日志，避免重复扫描全文件
    - 将 Apache/Nginx access.log 解析成结构化字典
    - 将 /var/log/auth.log 等 syslog 风格行解析成结构化字典
"""
from __future__ import annotations

import logging
import os
import re
from typing import List, Optional

logger = logging.getLogger(__name__)


class LogCollector:
    """日志文件采集器（支持增量读取）"""

    # Apache / Nginx access.log：核心行 + 可选 Combined Log 尾部 referer / user-agent
    ACCESS_LOG_CORE = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" '
        r'(?P<status>\d+) (?P<size>-|\d+)'
    )
    # Combined: ... size "referer" "user-agent"
    ACCESS_LOG_COMBINED_TAIL = re.compile(
        r'^\s*"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<user_agent>(?:[^"\\]|\\.)*)"\s*$'
    )

    def __init__(self, log_path: str, log_type: str = 'web'):
        """
        Args:
            log_path: 日志文件绝对路径
            log_type: 日志类型，支持 'web' | 'system' | 'app'
        """
        self.log_path = log_path
        self.log_type = log_type
        self._last_position: int = 0

    def read_new_lines(self) -> List[dict]:
        """读取自上次调用以来的新增行，已解析为结构化字典"""
        if not os.path.exists(self.log_path):
            return []

        results: List[dict] = []
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self._last_position)
                for line in f:
                    parsed = self._parse_line(line.strip())
                    if parsed:
                        results.append(parsed)
                self._last_position = f.tell()
        except IOError as exc:
            logger.error(f"[LogCollector] 读取日志失败: {exc}")
        return results

    def _parse_line(self, line: str) -> Optional[dict]:
        """根据 log_type 分派到具体解析方法"""
        if not line:
            return None
        if self.log_type == 'web':
            return self._parse_web_log(line)
        if self.log_type == 'system':
            return self._parse_system_log(line)
        return None

    def _parse_web_log(self, line: str) -> Optional[dict]:
        """解析 Apache/Nginx access.log 格式（含可选 referer / user-agent）。"""
        match = self.ACCESS_LOG_CORE.match(line)
        if not match:
            return None
        try:
            size_raw = match.group('size')
            response_size = 0 if size_raw == '-' else int(size_raw)
            method = match.group('method')
            tail = line[match.end() :]
            user_agent = ''
            if tail.strip():
                tail_m = self.ACCESS_LOG_COMBINED_TAIL.match(tail)
                if tail_m:
                    user_agent = tail_m.group('user_agent')
            return {
                'timestamp': match.group('time'),
                'src_ip': match.group('ip'),
                'url': match.group('url'),
                'method': method,
                'http_method': method,
                'status_code': int(match.group('status')),
                'response_size': response_size,
                'user_agent': user_agent,
                'log_type': 'web',
            }
        except (ValueError, TypeError) as exc:
            logger.error(f"[LogCollector] Web 日志字段转换失败: {exc}")
            return None

    def _parse_system_log(self, line: str) -> Optional[dict]:
        """解析 /var/log/auth.log 等 syslog 风格日志"""
        parts = line.split(maxsplit=3)
        if len(parts) < 4:
            return None
        process_field = parts[3]
        process_name = (
            process_field.split(':')[0] if ':' in process_field else process_field
        )
        return {
            'timestamp': f"{parts[0]} {parts[1]} {parts[2]}",
            'process': process_name,
            'message': process_field,
            'log_type': 'system',
        }

    @property
    def last_position(self) -> int:
        """当前读取位置（用于监控与断点续传）"""
        return self._last_position

    def reset_position(self) -> None:
        """重置读取位置为 0（调试或重新全量扫描时使用）"""
        self._last_position = 0
