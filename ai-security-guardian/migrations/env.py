from __future__ import annotations

import logging
from logging.config import fileConfig

from flask import current_app

from alembic import context

config = context.config

fileConfig(config.config_file_name)
logger = logging.getLogger("alembic.env")

target_db = current_app.extensions["migrate"].db
target_metadata = target_db.metadata


def get_engine():
    try:
        return target_db.engine
    except (TypeError, AttributeError):
        return target_db.get_engine()


def get_engine_url() -> str:
    try:
        return str(get_engine().url).replace("%", "%%")
    except AttributeError:
        return str(get_engine().url).replace("%", "%%")


config.set_main_option("sqlalchemy.url", get_engine_url())


def get_metadata():
    if hasattr(target_db, "metadatas"):
        return target_db.metadatas[None]
    return target_metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    conf_args = current_app.extensions["migrate"].configure_args
    if conf_args.get("process_revision_directives") is None:

        def process_revision_directives(context, revision, directives):
            if getattr(config.cmd_opts, "autogenerate", False):
                script = directives[0]
                if script.upgrade_ops.is_empty():
                    directives[:] = []
                    logger.info("No changes in schema detected.")

        conf_args["process_revision_directives"] = process_revision_directives

    connectable = get_engine()
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=get_metadata(), **conf_args)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
