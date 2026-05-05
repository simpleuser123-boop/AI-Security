"""
AlertNotifier：SMTP、Webhook（防 SSRF）、企业通道占位。
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Any, Callable, Dict, List, Optional

from src.response.webhook_url import WebhookUrlCheck, check_webhook_url_safe

logger = logging.getLogger(__name__)


@dataclass
class NotifyAttempt:
    channel: str
    ok: bool
    detail: str


class NotificationChannel(ABC):
    name: str = "base"

    @abstractmethod
    def send(self, subject: str, body: str, *, meta: Optional[Dict[str, Any]] = None) -> NotifyAttempt:
        ...


class SmtpNotificationChannel(NotificationChannel):
    name = "smtp"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        password: str,
        mail_from: str,
        mail_to: str,
        use_tls: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._from = mail_from
        self._to = mail_to.split(",") if mail_to else []
        self._use_tls = use_tls

    def send(self, subject: str, body: str, *, meta: Optional[Dict[str, Any]] = None) -> NotifyAttempt:
        if not self._host or not self._to:
            return NotifyAttempt(self.name, False, "smtp_not_configured")
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)
        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                if self._use_tls:
                    server.starttls()
                if self._user:
                    server.login(self._user, self._password)
                server.sendmail(self._from, self._to, msg.as_string())
            return NotifyAttempt(self.name, True, "sent")
        except Exception as exc:  # noqa: BLE001
            # 不向日志/返回值泄露认证细节（密码等可能出现在异常文本中）
            return NotifyAttempt(self.name, False, f"smtp_error:{type(exc).__name__}")


class WebhookNotificationChannel(NotificationChannel):
    name = "webhook"

    def __init__(self, url: str, timeout_sec: float = 10.0) -> None:
        self._url = url.strip()
        self._timeout_sec = timeout_sec

    def send(self, subject: str, body: str, *, meta: Optional[Dict[str, Any]] = None) -> NotifyAttempt:
        chk = check_webhook_url_safe(self._url)
        if not chk.ok:
            return NotifyAttempt(self.name, False, f"ssrf_blocked:{chk.reason}")
        payload = {
            "subject": subject,
            "body": body,
            "meta": meta or {},
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_sec) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                if code and int(code) >= 400:
                    return NotifyAttempt(self.name, False, f"http_{code}")
            return NotifyAttempt(self.name, True, "ok")
        except urllib.error.HTTPError as exc:
            return NotifyAttempt(self.name, False, f"http_error:{exc.code}")
        except urllib.error.URLError as exc:
            return NotifyAttempt(self.name, False, f"url_error:{type(exc).__name__}")
        except Exception as exc:  # noqa: BLE001
            return NotifyAttempt(self.name, False, f"webhook_error:{type(exc).__name__}")


class EnterprisePlaceholderChannel(NotificationChannel):
    """企业微信/钉钉/飞书等统一占位，不落真实签名请求。"""

    name = "enterprise_placeholder"

    def send(self, subject: str, body: str, *, meta: Optional[Dict[str, Any]] = None) -> NotifyAttempt:
        logger.warning(
            "[企业通知占位] subject=%s len(body)=%d meta_keys=%s",
            subject[:120],
            len(body),
            list((meta or {}).keys()),
        )
        return NotifyAttempt(self.name, True, "placeholder_no_external_io")


class AlertNotifier:
    """聚合多通道；支持失败重试（同步）。"""

    def __init__(
        self,
        channels: List[NotificationChannel],
        *,
        max_retries: int = 3,
        retry_backoff_sec: float = 0.2,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self._channels = list(channels)
        self._max_retries = max(1, max_retries)
        self._retry_backoff_sec = retry_backoff_sec
        self._sleep_fn = sleep_fn

    @classmethod
    def from_env(cls) -> "AlertNotifier":
        channels: List[NotificationChannel] = []

        smtp_host = os.environ.get("ALERT_SMTP_HOST", "").strip()
        smtp_port = int(os.environ.get("ALERT_SMTP_PORT", "587"))
        smtp_user = os.environ.get("ALERT_SMTP_USER", "").strip()
        smtp_pass = os.environ.get("ALERT_SMTP_PASSWORD", "").strip()
        mail_from = os.environ.get("ALERT_SMTP_FROM", "").strip()
        mail_to = os.environ.get("ALERT_EMAIL", "").strip()
        if smtp_host and mail_from and mail_to:
            use_tls = os.environ.get("ALERT_SMTP_USE_TLS", "true").lower() == "true"
            channels.append(
                SmtpNotificationChannel(
                    host=smtp_host,
                    port=smtp_port,
                    user=smtp_user,
                    password=smtp_pass,
                    mail_from=mail_from,
                    mail_to=mail_to,
                    use_tls=use_tls,
                )
            )

        wh = os.environ.get("ALERT_WEBHOOK", "").strip()
        if wh:
            channels.append(WebhookNotificationChannel(wh))

        if os.environ.get("ALERT_ENTERPRISE_CHANNEL_ENABLED", "").lower() == "true":
            channels.append(EnterprisePlaceholderChannel())

        max_retries = int(os.environ.get("ALERT_NOTIFY_MAX_RETRIES", "3"))
        return cls(channels, max_retries=max_retries)

    def notify_all(
        self,
        subject: str,
        body: str,
        *,
        meta: Optional[Dict[str, Any]] = None,
    ) -> List[NotifyAttempt]:
        """逐通道发送；单通道失败会重试。返回每次尝试的汇总（最后一次为主）。"""
        if not self._channels:
            return [NotifyAttempt("none", True, "no_channels_configured")]
        results: List[NotifyAttempt] = []
        for ch in self._channels:
            last: Optional[NotifyAttempt] = None
            for attempt in range(self._max_retries):
                last = ch.send(subject, body, meta=meta)
                results.append(last)
                if last.ok:
                    break
                if attempt + 1 < self._max_retries:
                    self._sleep_fn(self._retry_backoff_sec * (2**attempt))
            # last 非 None
        return results
