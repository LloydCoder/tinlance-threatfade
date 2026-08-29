from sqlalchemy import UniqueConstraint

from core.orm import Base


EXPECTED_TABLES = {
    "detections",
    "cases",
    "detection_feedback",
    "case_comments",
    "case_events",
    "tenant_config",
    "audit_events",
    "evidence",
    "provenance",
    "investigation_timeline",
    "retention_policies",
    "legal_holds",
    "detection_workflow",
    "case_detection_links",
    "analyst_dispositions",
    "investigation_entities",
    "investigation_sessions",
    "identity_users",
    "identity_organizations",
    "identity_memberships",
    "identity_invitations",
    "identity_sessions",
    "environment_profiles",
    "environment_profile_audit",
}


def test_complete_metadata_contains_expected_24_tables():
    assert set(Base.metadata.tables) == EXPECTED_TABLES
    assert len(Base.metadata.tables) == 24


def test_environment_profile_schema_contract():
    profiles = Base.metadata.tables["environment_profiles"]
    audit = Base.metadata.tables["environment_profile_audit"]

    assert [column.name for column in profiles.columns] == [
        "id",
        "tenant_id",
        "profile_id",
        "version",
        "schema_version",
        "name",
        "status",
        "profile_json",
        "digest",
        "created_by",
        "created_at",
    ]
    assert [column.name for column in audit.columns] == [
        "id",
        "tenant_id",
        "profile_id",
        "version",
        "action",
        "previous_version",
        "digest",
        "actor",
        "created_at",
    ]
    assert {index.name for index in profiles.indexes} == {
        "ix_environment_profiles_tenant",
        "ix_environment_profiles_active",
    }
    assert {index.name for index in audit.indexes} == {"ix_environment_profile_audit_tenant"}
    assert any(
        isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_environment_profiles_version"
        and tuple(column.name for column in constraint.columns) == ("tenant_id", "profile_id", "version")
        for constraint in profiles.constraints
    )


def test_historical_composite_indexes_are_present():
    expected = {
        "ix_audit_events_tenant_sequence",
        "ix_evidence_tenant_correlation",
        "ix_provenance_tenant_correlation",
        "ix_timeline_tenant_case",
        "ix_detections_input_sha256",
        "ix_detections_rule_pack_sha256",
        "ix_detections_engine_version",
        "ix_detections_model_sha256",
        "ix_detections_config_sha256",
    }
    actual = {index.name for table in Base.metadata.tables.values() for index in table.indexes}
    assert expected <= actual


def test_historical_unique_constraints_are_named():
    expected = {
        "audit_events_sequence_no_key",
        "audit_events_event_hash_key",
        "evidence_custody_hash_key",
        "provenance_provenance_sha256_key",
        "retention_policies_tenant_id_key",
        "legal_holds_hold_id_key",
        "detection_workflow_detection_id_key",
        "identity_users_subject_key",
        "identity_organizations_slug_key",
        "identity_invitations_token_hash_key",
        "identity_sessions_token_hash_key",
    }
    actual = {
        constraint.name
        for table in Base.metadata.tables.values()
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert expected <= actual


def test_historical_unique_columns_are_constraints_not_unique_indexes():
    expected = {
        ("detection_workflow", ("detection_id",)),
        ("identity_users", ("subject",)),
        ("identity_organizations", ("slug",)),
        ("identity_invitations", ("token_hash",)),
        ("identity_sessions", ("token_hash",)),
    }
    for table_name, columns in expected:
        table = Base.metadata.tables[table_name]
        assert any(
            isinstance(constraint, UniqueConstraint)
            and tuple(column.name for column in constraint.columns) == columns
            for constraint in table.constraints
        )
        assert any(
            index.unique is False
            and tuple(column.name for column in index.columns) == columns
            for index in table.indexes
        )
        assert not any(
            index.unique is True and tuple(column.name for column in index.columns) == columns
            for index in table.indexes
        )
