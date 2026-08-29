"""Normalize ORM metadata to the established Alembic/database contract.

Historical migrations are authoritative. This module changes SQLAlchemy metadata
only; it performs no database DDL and must be imported after all ORM model modules.
"""
from __future__ import annotations

from sqlalchemy import Index, UniqueConstraint

from core.storage import Base


_SINGLE_INDEXES: dict[str, dict[str, str]] = {
    "detections": {
        "tenant_id": "ix_detections_tenant_id",
        "correlation_id": "ix_detections_correlation_id",
        "input_sha256": "ix_detections_input_sha256",
        "rule_pack_sha256": "ix_detections_rule_pack_sha256",
        "engine_version": "ix_detections_engine_version",
        "model_sha256": "ix_detections_model_sha256",
        "config_sha256": "ix_detections_config_sha256",
    },
    "cases": {"tenant_id": "ix_cases_tenant_id"},
    "detection_feedback": {
        "tenant_id": "ix_detection_feedback_tenant_id",
        "detection_id": "ix_detection_feedback_detection_id",
    },
    "case_comments": {
        "tenant_id": "ix_case_comments_tenant_id",
        "case_id": "ix_case_comments_case_id",
    },
    "case_events": {
        "tenant_id": "ix_case_events_tenant_id",
        "case_id": "ix_case_events_case_id",
        "correlation_id": "ix_case_events_correlation_id",
    },
    "tenant_config": {"tenant_id": "ix_tenant_config_tenant_id"},
    "audit_events": {
        "tenant_id": "ix_audit_events_tenant_id",
        "request_id": "ix_audit_events_request_id",
        "correlation_id": "ix_audit_events_correlation_id",
    },
    "evidence": {
        "tenant_id": "ix_evidence_tenant_id",
        "correlation_id": "ix_evidence_correlation_id",
        "case_id": "ix_evidence_case_id",
        "content_sha256": "ix_evidence_content_sha256",
    },
    "provenance": {
        "tenant_id": "ix_provenance_tenant_id",
        "correlation_id": "ix_provenance_correlation_id",
        "detection_id": "ix_provenance_detection_id",
    },
    "investigation_timeline": {
        "tenant_id": "ix_investigation_timeline_tenant_id",
        "case_id": "ix_investigation_timeline_case_id",
        "correlation_id": "ix_investigation_timeline_correlation_id",
    },
    "legal_holds": {"tenant_id": "ix_legal_holds_tenant_id"},
    "detection_workflow": {
        "tenant_id": "ix_detection_workflow_tenant",
        "detection_id": "ix_detection_workflow_detection",
    },
    "case_detection_links": {
        "tenant_id": "ix_case_detection_links_tenant",
        "case_id": "ix_case_detection_links_case",
        "detection_id": "ix_case_detection_links_detection",
    },
    "analyst_dispositions": {
        "tenant_id": "ix_analyst_dispositions_tenant",
        "detection_id": "ix_analyst_dispositions_detection",
        "case_id": "ix_analyst_dispositions_case",
    },
    "investigation_entities": {
        "tenant_id": "ix_investigation_entities_tenant",
        "correlation_id": "ix_investigation_entities_correlation",
    },
    "investigation_sessions": {
        "tenant_id": "ix_investigation_sessions_tenant",
        "session_key": "ix_investigation_sessions_key",
        "correlation_id": "ix_investigation_sessions_correlation",
    },
    "identity_users": {
        "subject": "ix_identity_users_subject",
        "email": "ix_identity_users_email",
    },
    "identity_organizations": {"slug": "ix_identity_organizations_slug"},
    "identity_memberships": {
        "organization_id": "ix_identity_memberships_org",
        "subject": "ix_identity_memberships_subject",
    },
    "identity_invitations": {
        "organization_id": "ix_identity_invitations_org",
        "email": "ix_identity_invitations_email",
        "token_hash": "ix_identity_invitations_token_hash",
    },
    "identity_sessions": {
        "token_hash": "ix_identity_sessions_token_hash",
        "subject": "ix_identity_sessions_subject",
    },
}

_COMPOSITE_INDEXES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("audit_events", "ix_audit_events_tenant_sequence", ("tenant_id", "sequence_no")),
    ("evidence", "ix_evidence_tenant_correlation", ("tenant_id", "correlation_id")),
    ("provenance", "ix_provenance_tenant_correlation", ("tenant_id", "correlation_id")),
    ("investigation_timeline", "ix_timeline_tenant_case", ("tenant_id", "case_id", "created_at")),
)

_UNIQUE_CONSTRAINTS: dict[tuple[str, tuple[str, ...]], str] = {
    ("audit_events", ("sequence_no",)): "audit_events_sequence_no_key",
    ("audit_events", ("event_hash",)): "audit_events_event_hash_key",
    ("evidence", ("custody_hash",)): "evidence_custody_hash_key",
    ("provenance", ("provenance_sha256",)): "provenance_provenance_sha256_key",
    ("retention_policies", ("tenant_id",)): "retention_policies_tenant_id_key",
    ("legal_holds", ("hold_id",)): "legal_holds_hold_id_key",
    ("detection_workflow", ("detection_id",)): "detection_workflow_detection_id_key",
    ("identity_users", ("subject",)): "identity_users_subject_key",
    ("identity_organizations", ("slug",)): "identity_organizations_slug_key",
    ("identity_invitations", ("token_hash",)): "identity_invitations_token_hash_key",
    ("identity_sessions", ("token_hash",)): "identity_sessions_token_hash_key",
}

_UNIQUE_CONSTRAINT_WITH_INDEX: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("detection_workflow", ("detection_id",)),
    ("identity_users", ("subject",)),
    ("identity_organizations", ("slug",)),
    ("identity_invitations", ("token_hash",)),
    ("identity_sessions", ("token_hash",)),
)


def _columns_key(index: Index) -> tuple[str, ...]:
    return tuple(column.name for column in index.columns)


def _ensure_index(table, columns: tuple[str, ...], canonical_name: str) -> None:
    for index in table.indexes:
        if _columns_key(index) == columns:
            index.name = canonical_name
            return
    Index(canonical_name, *(table.c[column] for column in columns))


def _reconcile_unique_constraint(table, columns: tuple[str, ...], canonical_name: str) -> None:
    for constraint in table.constraints:
        if isinstance(constraint, UniqueConstraint) and tuple(column.name for column in constraint.columns) == columns:
            constraint.name = canonical_name
            return

    unique_index = next(
        (index for index in table.indexes if index.unique and _columns_key(index) == columns),
        None,
    )
    if unique_index is not None:
        table.indexes.remove(unique_index)
        table.append_constraint(UniqueConstraint(*(table.c[column] for column in columns), name=canonical_name))
        return

    table.append_constraint(UniqueConstraint(*(table.c[column] for column in columns), name=canonical_name))


def reconcile_metadata() -> None:
    # Restore established names for mapped-column indexes. If an historical
    # index was not declared by the current model, represent that known index
    # explicitly in metadata so Alembic can compare it to the database.
    for table_name, names in _SINGLE_INDEXES.items():
        table = Base.metadata.tables[table_name]
        for column_name, canonical_name in names.items():
            _ensure_index(table, (column_name,), canonical_name)

    for table_name, canonical_name, columns in _COMPOSITE_INDEXES:
        _ensure_index(Base.metadata.tables[table_name], columns, canonical_name)

    for (table_name, columns), canonical_name in _UNIQUE_CONSTRAINTS.items():
        table = Base.metadata.tables[table_name]
        _reconcile_unique_constraint(table, columns, canonical_name)

    for table_name, columns in _UNIQUE_CONSTRAINT_WITH_INDEX:
        table = Base.metadata.tables[table_name]
        _ensure_index(table, columns, _SINGLE_INDEXES[table_name][columns[0]])


reconcile_metadata()
