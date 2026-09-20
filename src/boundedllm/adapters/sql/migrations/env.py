"""Alembic environment for the bundled SQL adapter.

The database URL comes from ``GUARD_DATABASE_URL`` through ``Settings`` so a
migration run cannot be pointed somewhere the application itself would refuse,
and so the URL never has to be written into a config file in the repository.

Importing the support schema registers the reference domain's tables on the same
MetaData. A deployment that does not use that domain can remove the import; its
tables are then absent from autogenerate and from the migration history.
"""

from alembic import context
from sqlalchemy import engine_from_config, pool

import boundedllm.support.schema  # noqa: F401  registers the reference domain tables
from boundedllm.adapters.sql.schema import metadata
from boundedllm.config import Settings

config = context.config
target_metadata = metadata


def _url() -> str:
    return Settings().database_url.get_secret_value()


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # SQLite cannot ALTER most columns in place; batch mode rewrites the
            # table instead so the same revision runs on the demo and on Postgres.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
