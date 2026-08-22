# ThreatFade Disaster Recovery & Operational Continuity

## Objectives

| Objective | Target | Measurement |
|---|---:|---|
| RPO for production PostgreSQL | ≤ 15 minutes | Last successfully archived WAL / provider PITR checkpoint |
| RTO for database service | ≤ 60 minutes | Restore drill: incident declaration → verified ready database |
| Logical backup portability | Daily | Verified `pg_dump -Fc` artifact + SHA-256 manifest |
| Restore verification | Every backup | `pg_restore --list` plus scheduled isolated restore drill |

RPO/RTO values are engineering targets, not contractual guarantees.

## Backup tiers

1. **Primary continuity:** provider-native PostgreSQL PITR/WAL archiving. PostgreSQL documents continuous archiving as the mechanism for point-in-time recovery; the continuous WAL sequence must cover the base backup. urlPostgreSQL continuous archiving and PITR documentationhttps://www.postgresql.org/docs/current/continuous-archiving.html
2. **Portable recovery:** daily custom-format logical dump produced by `scripts/backup.py`. PostgreSQL documents the custom format as a flexible archive designed for `pg_restore`. urlPostgreSQL pg_dump documentationhttps://www.postgresql.org/docs/current/app-pgdump.html
3. **Integrity verification:** SHA-256 manifest plus `pg_restore --list` before an artifact is accepted as recoverable.
4. **Restore drill:** restore into an isolated database, verify Alembic migration state, enterprise tables and forced RLS, and only then mark the backup usable.

## Backup handling requirements

- Backups must be encrypted at rest by the storage/provider layer.
- Backup storage must be separate from the production database failure domain.
- Backup/restore credentials must be scoped to the minimum required database privileges.
- Backup artifacts must not be committed to Git or included in container images.
- Production restore must never be performed directly against the live database during a drill.
- A restore from an untrusted archive must be treated as code execution against the restore environment; PostgreSQL explicitly warns that restores can execute arbitrary code from the source archive. urlPostgreSQL pg_dump documentationhttps://www.postgresql.org/docs/current/app-pgdump.html

## Restore procedure

1. Declare the incident and record the recovery target timestamp.
2. Select the latest backup whose integrity manifest verifies.
3. Provision an isolated PostgreSQL target with the approved major version.
4. Restore the logical archive using `pg_restore` with a least-privileged restore workflow.
5. If PITR is required, restore the physical base backup and replay archived WAL to the recovery target; `pg_dump` is not a WAL replay base. urlPostgreSQL PITR documentationhttps://www.postgresql.org/docs/current/continuous-archiving.html
6. Apply or verify the Alembic migration head.
7. Run database integrity, tenant-isolation and evidence-chain verification.
8. Run application readiness and smoke tests against the isolated target.
9. Capture actual RTO/RPO and deviations in the incident record.
10. Promote the recovered service only after security and data-integrity checks pass.

## Recovery drill acceptance criteria

- Backup checksum matches manifest.
- Archive has a non-empty restore catalog.
- Restore completes without ignored errors.
- Required tables and Alembic revision exist.
- Tenant RLS remains enabled and forced.
- Audit hash chain verifies.
- Evidence custody chain verifies.
- Application `/ready` returns ready against the restored database.
- Measured RTO is within the target.

## Scope boundary

The repository automates backup creation, artifact verification and isolated logical restore checks. Provider-specific PITR/WAL configuration, cross-region replication, object-storage encryption/KMS, DNS failover and production promotion remain deployment-environment responsibilities.
