"""Flask-SQLAlchemy 扩展与表初始化工具（R2 持久化基础）。"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

db = SQLAlchemy()
migrate = Migrate(compare_type=True, render_as_batch=True)


def init_migration_extension(app: Flask) -> None:
    """Register Flask-Migrate/Alembic commands for a configured app."""
    migrate.init_app(app, db)


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


def ensure_api_key_schema_compat(engine) -> None:
    """为已有 SQLite 库补齐 API Key RBAC 字段。"""
    if engine.dialect.name != "sqlite":
        return
    try:
        insp = inspect(engine)
        if "api_keys" not in insp.get_table_names():
            return
        cols = {c["name"] for c in insp.get_columns("api_keys")}
    except Exception:  # noqa: BLE001
        return
    if "role" in cols:
        return
    with engine.begin() as conn:
        try:
            conn.execute(
                text("ALTER TABLE api_keys ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'viewer'")
            )
            logger.info("[DB] api_keys 表已添加列: role")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[DB] api_keys 添加 role 失败: %s", exc)


def ensure_billing_schema_compat(engine) -> None:
    """为已有 SQLite 库补齐 Phase C3 商业计量字段。"""
    if engine.dialect.name != "sqlite":
        return
    try:
        insp = inspect(engine)
        table_names = set(insp.get_table_names())
    except Exception:  # noqa: BLE001
        return
    wanted: dict[str, list[tuple[str, str]]] = {
        "quotas": [
            ("warning_thresholds", "TEXT"),
            ("overage_policy", "VARCHAR(32) NOT NULL DEFAULT 'reject'"),
        ],
        "usage_meters": [
            ("period_start", "TEXT"),
            ("period_end", "TEXT"),
        ],
    }
    with engine.begin() as conn:
        for table, columns in wanted.items():
            if table not in table_names:
                continue
            try:
                existing = {c["name"] for c in insp.get_columns(table)}
            except Exception:  # noqa: BLE001
                continue
            for name, ddl in columns:
                if name in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    logger.info("[DB] %s 表已添加列: %s", table, name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("[DB] %s 添加列 %s 失败: %s", table, name, exc)


def ensure_billing_seed() -> None:
    """为商业计量 MVP 建立默认套餐和默认租户订阅。"""
    from web.billing import DEFAULT_PLAN_CODE, DEFAULT_PLAN_LIMITS, sync_quota_rows
    from web.models import DEFAULT_TENANT_ID, Plan, Subscription, Tenant

    now_tenant = db.session.get(Tenant, DEFAULT_TENANT_ID)
    if now_tenant is not None and not now_tenant.plan:
        now_tenant.plan = DEFAULT_PLAN_CODE

    plan = db.session.query(Plan).filter(Plan.code == DEFAULT_PLAN_CODE).one_or_none()
    if plan is None:
        plan = Plan(
            id="plan_default_mvp",
            code=DEFAULT_PLAN_CODE,
            name="Default MVP",
            status="active",
            limits=dict(DEFAULT_PLAN_LIMITS),
        )
        db.session.add(plan)
        db.session.flush()
    else:
        plan.limits = {**dict(DEFAULT_PLAN_LIMITS), **dict(plan.limits or {})}

    sub = (
        db.session.query(Subscription)
        .filter(
            Subscription.tenant_id == DEFAULT_TENANT_ID,
            Subscription.status == "active",
        )
        .one_or_none()
    )
    if sub is None:
        sub = Subscription(
            id="sub_default_mvp",
            tenant_id=DEFAULT_TENANT_ID,
            plan_id=plan.id,
            status="active",
        )
        db.session.add(sub)
    elif sub.plan_id is None and sub.license_key_id is None:
        sub.plan_id = plan.id
    sync_quota_rows(db.session, DEFAULT_TENANT_ID)


def ensure_default_tenant_seed() -> None:
    """为开发/testing 的 create_all 路径补齐单企业兼容租户种子。"""
    from web.models import (
        DEFAULT_ORGANIZATION_ID,
        DEFAULT_ROLE_ID,
        DEFAULT_SYSTEM_USER_ID,
        DEFAULT_TENANT_ID,
        Membership,
        Organization,
        Role,
        Tenant,
        User,
    )

    if db.session.get(Tenant, DEFAULT_TENANT_ID) is None:
        db.session.add(
            Tenant(
                id=DEFAULT_TENANT_ID,
                name="Default Tenant",
                slug="default",
                status="active",
                plan="legacy-single-tenant",
            )
        )
    # tenant-scan: allow bootstrap of the legacy default tenant organization.
    if db.session.get(Organization, DEFAULT_ORGANIZATION_ID) is None:
        db.session.add(
            Organization(
                id=DEFAULT_ORGANIZATION_ID,
                tenant_id=DEFAULT_TENANT_ID,
                name="Default Organization",
                slug="default",
                status="active",
            )
        )
    if db.session.get(User, DEFAULT_SYSTEM_USER_ID) is None:
        db.session.add(
            User(
                id=DEFAULT_SYSTEM_USER_ID,
                email="system@local.guardian",
                username="system",
                display_name="System",
                status="active",
            )
        )
    if db.session.get(Role, DEFAULT_ROLE_ID) is None:
        db.session.add(
            Role(
                id=DEFAULT_ROLE_ID,
                tenant_id=DEFAULT_TENANT_ID,
                name="owner",
                description="Legacy single-enterprise owner role",
                scope="tenant",
                permissions=["*"],
            )
        )
    if db.session.get(Membership, "membership_default_owner") is None:
        db.session.add(
            Membership(
                id="membership_default_owner",
                tenant_id=DEFAULT_TENANT_ID,
                organization_id=DEFAULT_ORGANIZATION_ID,
                user_id=DEFAULT_SYSTEM_USER_ID,
                role_id=DEFAULT_ROLE_ID,
                status="active",
            )
        )
    db.session.flush()
    ensure_billing_seed()
    db.session.commit()


def init_db_tables(app: Flask, *, force: bool = False) -> None:
    """创建 ORM 定义的全部表。

    - development / testing：启动时自动调用（一键开发）。
    - production：默认不在启动时建表，请使用 ``flask db upgrade``；
      若设置环境变量 ``AUTO_CREATE_DB_TABLES=true`` 则也会在启动时建表（应急/演示）。
    """
    env = os.environ.get("FLASK_ENV", "development")
    auto_prod = os.environ.get("AUTO_CREATE_DB_TABLES", "").lower() == "true"
    if env == "production" and not force and not auto_prod:
        logger.info(
            "[DB] 生产环境跳过自动建表；请执行: "
            "flask --app web.migration_app:create_migration_app db upgrade "
            "（或设置 AUTO_CREATE_DB_TABLES=true 仅限应急）"
        )
        return

    ensure_sqlite_parent_dir(app)
    with app.app_context():
        db.create_all()
        ensure_ioc_schema_compat(db.engine)
        ensure_api_key_schema_compat(db.engine)
        ensure_billing_schema_compat(db.engine)
        ensure_default_tenant_seed()
    logger.info("[DB] SQLAlchemy create_all 已完成 (env=%s)", env)


def init_db_command(app: Flask) -> None:
    """CLI / 模块入口：无条件建表（任意 FLASK_ENV）。"""
    ensure_sqlite_parent_dir(app)
    with app.app_context():
        db.create_all()
        ensure_ioc_schema_compat(db.engine)
        ensure_api_key_schema_compat(db.engine)
        ensure_billing_schema_compat(db.engine)
        ensure_default_tenant_seed()
