# Threat model

## Scope and assets

This release processes synthetic or manually submitted endpoint metadata in one local service and includes a Windows Event Log agent source that has not yet been runtime-tested on Windows 11. It has no automated endpoint enrollment, certificate revocation, user accounts, or production network deployment. With mTLS enabled, event ingestion checks that the verified client certificate URI SAN names the submitted host ID. Assets are event/alert/incident/audit records, bearer tokens, client certificate keys, local SQLite spool, database credentials when PostgreSQL is enabled, and event provenance.

| Boundary | Threat | Current control | Remaining risk |
|---|---|---|---|
| Client to service | Oversized or malformed event | 1 MiB request cap, JSON decoding, required-field and length checks | No broad schema fuzzing yet |
| Telemetry content | Credentials accidentally present in command lines or custom fields | Agent redacts common credential-named arguments before spooling; Go service redacts those arguments and credential-named custom fields before detection/storage; covered by Rust and Go unit/integration tests | Narrow key-based filter only; unknown encodings, arbitrary free text, and unrecognized secret names can pass through |
| Write route | Unauthorized submissions or request floods | Bearer-token role split, per-client-IP token buckets for telemetry and write routes, payload caps | Shared tokens; in-process limits do not coordinate across replicas or distinguish clients behind the same NAT |
| Browser to service | Script injection, framing | Escaped dynamic text, CSP, nosniff, frame denial | Basic local app; token lifecycle is limited |
| Service to local file | Data disclosure or corruption | Mode 0600, temp-file rename, loopback binding | No encryption, backup rotation, corruption recovery, or multi-process locking |
| Service to PostgreSQL | Unauthorized DB access or data loss | Parameterized queries, loopback-only Compose port, transaction boundaries, indexed relational schema, optional transactional retention | Local Compose credentials are shared development values; least-privilege roles, backups, TLS policy, and recovery are not configured |
| Simulation and live workflow | Simulated activity presented as real | Per-run provenance; API overview exposes separate live/replay counts; live posture metrics and recent-detection panel exclude replay records; reset is scoped by run ID | Other analyst lists can include both namespaces; operators must inspect provenance before export or case work |
| Host telemetry collection | Unsafe/invasive collection | Read-only Windows Event Log subscriptions; bounded SQLite outbox; no response actions | Windows service privileges, channel ACLs, install/recovery and retention behavior need Windows 11 integration review |
| Agent transport | Impersonation or interception | HTTPS-only for remote endpoints; system TLS trust; optional mTLS CA verification; URI SAN to host ID check on ingest | Certificate identities are provisioned out of band; bearer token is shared; no per-endpoint revocation |

## Checklist

- [x] Loopback-only default bind.
- [x] Random bearer token if none configured; write APIs require it.
- [x] Event body and selected field lengths bounded.
- [x] Common credential-named command-line arguments are redacted before agent spooling and backend persistence; Rust/Go tests cover representative forms.
- [x] Browser output escaped; security headers and server timeouts set.
- [x] Simulation provenance is persisted, overview counts are separated by namespace, live posture metrics exclude replay alerts/cases, and run reset preserves live records (Go integration and browser tests).
- [x] Optional HTTPS when both certificate paths are configured.
- [x] TLS 1.3 server configuration; optional mTLS client-chain verification.
- [x] With mTLS enabled, certificate URI SAN must match the event host ID on ingest.
- [ ] Automated endpoint enrollment, certificate rotation, and endpoint identity revocation.
- [ ] User accounts, RBAC, session lifecycle, CSRF strategy for cookie auth.
- [x] Per-process write-route rate limits with bounded per-client state and `Retry-After` responses.
- [ ] Replay-resistant ingestion, comprehensive schema validation, audit tamper evidence.
- [x] Optional data-retention policy that removes old records and preserves alert evidence relationships.
- [ ] Production database least privilege, encrypted storage, backup and recovery.
- [ ] Windows least-privilege sensor review and Windows integration tests.

A hash chain alone would require a trusted external checkpoint to detect an attacker who can rewrite the full local chain. This implementation's audit log is a logical activity trail only.

## Rate limits

Write routes use per-IP, in-process token buckets: event ingestion allows 240 requests initially and refills at 120/second; heartbeats allow 10 initially and refill at 0.5/second; simulation and reset routes allow 6 initially and refill at 0.1/second; analyst updates allow 20 initially and refill at 2/second. At most 4096 client/class buckets are retained, with idle buckets evicted after 10 minutes. The limiter trusts only the TCP peer address and does not consume `X-Forwarded-For`. Deployments behind a proxy therefore share the proxy's bucket, and multiple service replicas have independent limits. These starting values have not been tuned with production load testing.
