#!/usr/bin/env python3
"""v1.0 端到端验收脚本（不含需 Flask DB 的场景 10）。

用法（在项目根目录 ai-security-guardian）::

    python scripts/verify_v1.py
    echo ExitCode: %ERRORLEVEL%

场景 10 请运行::

    python -m pytest tests/e2e/test_v1_acceptance.py::test_10_web_restart_alerts -q
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.e2e.verify_scenarios import main as run_verify_main


if __name__ == "__main__":
    raise SystemExit(run_verify_main())
