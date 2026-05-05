"""Flask-SQLAlchemy 扩展与表初始化工具（R2 持久化基础）。"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

db = SQLAlchemy()


def ensure_sqlite_parent_dir(app: Flask) -> None:
    """若使用基于文件的 SQLite，确保数据库文件所在目录存在。"""
    uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if not uri.startswith("sqlite:"):
        return
    try:
        from sqlalchemy.engine import make_url

        url = make_url(uri)
    except Exception:  # noqa: BLE001
        return
    if url.database in (None, "", ":memory:"):
        return
    # Flask-SQLAlchemy resolves relative sqlite:/// paths from app.instance_path.
    # Create the same parent directory the engine will actually use.
    db_path = Path(url.database)
    if not db_path.is_absolute():
        db_path = Path(app.instance_path) / db_path
    parent = db_path.parent
    if parent and str(parent) not in (".", ""):
        parent.mkdir(parents=True, exist_ok=True)


def ensure_ioc_schema_compat(engine) -> None:
    """为已有 SQLite 库补齐 IOC 生产化字段（create_all 不会 ALTER 旧表）。"""
    if engine.dialect.name != "sqlite":
        return
    try:
        insp = inspect(engine)
        if "iocs" not in insp.get_table_names():
            return
        cols = {c["name"] for c in insp.get_columns("iocs")}
    except Exception:  # noqa: BLE001
        return
    # (column, ddl_type) — SQLite 无原生 JSON 类型，用 TEXT 存 JSON
    wanted: list[tuple[str, str]] = [
        ("ttl_seconds", "INTEGER"),
        ("first_seen", "TEXT"),
        ("last_seen", "TEXT"),
        ("expires_at", "TEXT"),
        ("ioc_meta", "TEXT"),
    ]
    with engine.begin() as conn:
        for name, ddl in wanted:
            if name in cols:
                continue
            try:
                conn.execute(text(f"ALTER TABLE iocs ADD COLUMN {name} {ddl}"))
                logger.info("[DB] iocs 表已添加列: %s", name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[DB] iocs 添加列 %s 失败: %s", name, exc)


def init_db_tables(app: Flask, *, force: bool = False) -> None:
    """创建 ORM 定义的全部表。

    - development / testing：启动时自动调用（一键开发）。
    - production：默认不在启动时建表，请使用 ``python -m web.init_db``；
      若设置环境变量 ``AUTO_CREATE_DB_TABLES=true`` 则也会在启动时建表（应急/演示）。
    """
    env = os.environ.get("FLASK_ENV", "development")
    auto_prod = os.environ.get("AUTO_CREATE_DB_TABLES", "").lower() == "true"
    if env == "production" and not force and not auto_prod:
        logger.info(
            "[DB] 生产环境跳过自动建表；首次请执行: python -m web.init_db "
            "（或设置 AUTO_CREATE_DB_TABLES=true 仅限应急）"
        )
        return

    ensure_sqlite_parent_dir(app)
    with app.app_context():
        db.create_all()
        ensure_ioc_schema_compat(db.engine)
    logger.info("[DB] SQLAlchemy create_all 已完成 (env=%s)", env)


def init_db_command(app: Flask) -> None:
    """CLI / 模块入口：无条件建表（任意 FLASK_ENV）。"""
    ensure_sqlite_parent_dir(app)
    with app.app_context():
        db.create_all()
        ensure_ioc_schema_compat(db.engine)
