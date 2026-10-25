# Threat model

## Scope and assets

This release processes synthetic or manually submitted endpoint metadata in one local service and includes a Windows Event Log agent source that has not yet been runtime-tested on Windows 11. It has no automated endpoint enrollment, certificate revocation, user accounts, or production network deployment. With mTLS enabled, event ingestion checks that the verified client certificate URI SAN names the submitted host ID. Assets are event/alert/incident/audit records, bearer tokens, client certificate keys, local SQLite spool, database credentials when PostgreSQL is enabled, and event provenance.

| Boundary | Threat | Current control | Remaining risk |
|---|---|---|---|
| Client to service | Oversized or malformed event | 1 MiB request cap, JSON decoding, required-field and length checks | No broad schema fuzzing yet |
| Write route | Unauthorized submissions | Random startup bearer token; configured analyst/admin split | Shared tokens, no account lifecycle or rate limiting |
| Browser to service | Script injection, framing | Escaped dynamic text, CSP, nosniff, frame denial | Basic local app; token lifecycle is limited |
| Service to local file | Data disclosure or corruption | Mode 0600, temp-file rename, loopback binding | No encryption, backup rotation, corruption recovery, or multi-process locking |
| Service to PostgreSQL | Unauthorized DB access or data loss | Parameterized queries, loopback-only Compose port, transaction boundaries, indexed relational schema | Local Compose credentials are shared development values; least-privilege roles, backups, TLS policy, retention, and recovery are not configured |
| Simulation and live workflow | Simulated activity presented as real | Per-run provenance; live overview excludes replay data | No live action endpoints exist; future actions need backend enforcement |
| Host telemetry collection | Unsafe/invasive collection | Read-only Windows Event Log subscriptions; bounded SQLite outbox; no response actions | Windows service privileges, channel ACLs, install/recovery and retention behavior need Windows 11 integration review |
| Agent transport | Impersonation or interception | HTTPS-only for remote endpoints; system TLS trust; optional mTLS CA verification; URI SAN to host ID check on ingest | Certificate identities are provisioned out of band; bearer token is shared; no per-endpoint revocation |

## Checklist

- [x] Loopback-only default bind.
- [x] Random bearer token if none configured; write APIs require it.
- [x] Event body and selected field lengths bounded.
- [x] Browser output escaped; security headers and server timeouts set.
- [x] Simulation provenance is persisted and separated from live overview counts.
- [x] Optional HTTPS when both certificate paths are configured.
- [x] TLS 1.3 server configuration; optional mTLS client-chain verification.
- [x] With mTLS enabled, certificate URI SAN must match the event host ID on ingest.
- [ ] Automated endpoint enrollment, certificate rotation, and endpoint identity revocation.
- [ ] User accounts, RBAC, session lifecycle, CSRF strategy for cookie auth.
- [ ] Rate limits, replay-resistant ingestion, comprehensive schema validation, audit tamper evidence.
- [ ] Production database least privilege, retention, encrypted storage, backup and recovery.
- [ ] Windows least-privilege sensor review and Windows integration tests.

A hash chain alone would require a trusted external checkpoint to detect an attacker who can rewrite the full local chain. This implementation's audit log is a logical activity trail only.
