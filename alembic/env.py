from __future__ import annotations

from logging.config import fileConfig
import copy
import os

from alembic import context
from sqlalchemy import MetaData, engine_from_config, pool

# The first historical migration uses core.storage.Base.metadata.create_all()
# as its 12-table baseline. Snapshot that baseline before loading the complete
# ORM registry so later models cannot accidentally make migration 0001 create
# tables owned by later revisions.
from core.storage import Base

_LEGACY_BASELINE_TABLES = frozenset(Base.metadata.tables)

from core.orm import Base as ORMBase

assert ORMBase is Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

url = os.getenv("THREATFADE_DATABASE_URL")
if url:
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))

# Alembic/autogenerate receives an independent complete metadata snapshot.
# deepcopy preserves explicit historical index names and the distinction
# between UniqueConstraint objects and ordinary indexes; Table.to_metadata()
# can regenerate names from Column(index=True) during the copy.
target_metadata: MetaData = copy.deepcopy(Base.metadata)


def _prepare_historical_migration_base() -> None:
    """Restore the metadata shape expected by migration 20260822_0001."""
    for table_name in list(Base.metadata.tables):
        if table_name not in _LEGACY_BASELINE_TABLES:
            Base.metadata.remove(Base.metadata.tables[table_name])


def run_migrations_offline() -> None:
    _prepare_historical_migration_base()
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    _prepare_historical_migration_base()
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
