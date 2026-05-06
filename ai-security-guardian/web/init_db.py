"""数据库初始化入口（R2）。

用法：
    python -m web.init_db
    python -m web.init_db --check
"""
from __future__ import annotations

import argparse
import logging

from flask import Flask
from sqlalchemy import inspect

from config.config import get_config
from web.database import db, init_db_command


def create_init_app() -> Flask:
    """创建仅用于数据库初始化的轻量 app，避免完整 Web 启动依赖已存在表。"""
    cfg = get_config()
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = cfg.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = cfg.SQLALCHEMY_TRACK_MODIFICATIONS
    db.init_app(app)
    import web.models  # noqa: F401

    return app


def _schema_status(app: Flask) -> tuple[list[str], list[str]]:
    with app.app_context():
        expected = sorted(db.metadata.tables.keys())
        existing = sorted(inspect(db.engine).get_table_names())
    missing = sorted(set(expected) - set(existing))
    return existing, missing


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize or check database tables.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="only verify that ORM tables exist; do not create missing tables",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    )
    app = create_init_app()
    existing_before, missing_before = _schema_status(app)

    if args.check:
        print(f"Existing tables: {', '.join(existing_before) if existing_before else '(none)'}")
        if missing_before:
            raise SystemExit(f"Missing tables: {', '.join(missing_before)}")
        print("Database schema check passed.")
        return

    init_db_command(app)
    existing_after, missing_after = _schema_status(app)
    print(f"Existing tables: {', '.join(existing_after) if existing_after else '(none)'}")
    if missing_after:
        raise SystemExit(f"Database initialization incomplete; missing: {', '.join(missing_after)}")
    print("Database tables initialized successfully.")


if __name__ == "__main__":
    main()
