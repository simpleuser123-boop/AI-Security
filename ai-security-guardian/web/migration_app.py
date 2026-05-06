"""Lightweight Flask app used by Flask-Migrate/Alembic CLI commands.

Use this module for schema migrations so ``flask db`` does not start the full
Web/API stack, Socket.IO, Redis stream consumers, or audit patrol workers.
"""
from __future__ import annotations

from flask import Flask

from config.config import get_config
from web.database import db, ensure_sqlite_parent_dir, init_migration_extension


def create_migration_app() -> Flask:
    """Create a minimal app with DB metadata registered for Alembic."""
    cfg = get_config()
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = cfg.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = cfg.SQLALCHEMY_TRACK_MODIFICATIONS

    ensure_sqlite_parent_dir(app)
    db.init_app(app)
    import web.models  # noqa: F401

    init_migration_extension(app)
    return app
