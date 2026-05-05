"""
IOC 同步任务入口（cron / APScheduler / 手工执行）。

用法::

    python -m src.collectors.ioc_sync

在 Flask 应用上下文中：将数据库中未过期 IOC 刷新到 ``ThreatIntelCollector`` 内存缓存。
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any, Dict, Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def run_ioc_sync(
    app: Any,
    *,
    purge_expired: bool = False,
) -> Dict[str, Any]:
    """供调度器调用：刷新威胁情报内存缓存；可选清理过期行。

    Args:
        app: ``create_app()`` 返回的 Flask 应用。
        purge_expired: 为 True 时从数据库删除已过期 IOC（慎用，默认仅停止命中）。
    """
    from web.database import db
    from web.models import IOC

    ti = app.extensions.get("guardian_threat_intel")
    if ti is None:
        return {"ok": False, "reason": "threat_intel_missing"}

    removed = 0
    with app.app_context():
        if purge_expired:
            from src.collectors.ioc_repository import utc_now

            now = utc_now()
            stale = (
                db.session.query(IOC)
                .filter(
                    IOC.expires_at.isnot(None),
                    IOC.expires_at <= now,
                )
                .all()
            )
            removed = len(stale)
            for row in stale:
                db.session.delete(row)
            db.session.commit()

        loaded = ti.refresh_local_from_db()

    return {"ok": True, "loaded": loaded, "removed_expired": removed}


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    )
    parser = argparse.ArgumentParser(description="IOC 同步：DB → ThreatIntelCollector 内存")
    parser.add_argument(
        "--purge-expired",
        action="store_true",
        help="同时从数据库删除已过期 IOC（默认只刷新缓存，不删行）",
    )
    args = parser.parse_args(argv)

    from web.app import create_app

    app, _ = create_app()
    result = run_ioc_sync(app, purge_expired=args.purge_expired)
    print(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
