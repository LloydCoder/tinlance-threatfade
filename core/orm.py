"""Canonical ORM model registry.

Import this module wherever complete application/Alembic metadata is required.
Import order is deliberate: the shared Base is created first, all mapped model
modules are then registered, and historical index/constraint names are finally
reconciled in metadata without issuing database DDL.
"""
from __future__ import annotations

from core import storage as storage
from core import analyst as analyst
from core import identity as identity
from core import environment_profile_storage as environment_profile_storage
from core import schema_contract as schema_contract

Base = storage.Base
ENGINE = storage.ENGINE

__all__ = ["Base", "ENGINE", "storage", "analyst", "identity", "environment_profile_storage"]
