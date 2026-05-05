"""数据库初始化入口（R2）。

用法：
    python -m web.init_db
"""
from __future__ import annotations

import logging

from web.app import create_app
from web.database import init_db_command


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    )
    app, _ = create_app()
    init_db_command(app)
    print("Database tables created successfully.")


if __name__ == "__main__":
    main()
