from __future__ import annotations

import os


def pytest_configure(config):
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("ALERT_STREAM_CONSUMER_AUTOSTART", "false")
    os.environ.setdefault("AUDIT_INTEGRITY_PATROL", "false")
    os.environ.setdefault("REDIS_HOST", "127.0.0.1")
    os.environ.setdefault("REDIS_PORT", "63999")
    os.environ.setdefault("GUARDIAN_REDIS_DISABLE_CONNECT", "true")
