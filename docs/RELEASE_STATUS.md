# Release status

## Verified in this repository

- Go service event ingestion, bounded rule evaluation, evidence-linked alerts, incident grouping, analyst updates, local JSON persistence, and run-scoped simulation cleanup.
- Six deterministic synthetic scenarios through the Go HTTP ingestion/detection path. Go tests cover every declared expected rule; a local service smoke run exercised S06 and returned all three required alerts.
- PostgreSQL migration and repository integration tests passed against PostgreSQL 17 in GitHub Actions. Local PostgreSQL runtime testing was unavailable because Docker was not running.
- Static GitHub Pages preview with six exported scenarios, browser-side rule evaluation, replay playback controls, timeline scrubbing, labeled ground truth/detected techniques, downloadable reports, and browser-profile persistence.
- Rust event XML parsing, normalization, bounded event validation, SQLite WAL spool, duplicate suppression, payload cap, bookmarks, and remote transport policy in portable tests.
- HTTPS server configuration with TLS 1.3 and optional CA-verified client certificates. When mTLS is enabled, ingest requires a certificate and binds its verified URI SAN to the event host ID; a handler regression test covers matching, mismatched, and missing identities.
- Authenticated endpoint heartbeats persisted in JSON and PostgreSQL, with a 90-second freshness threshold, endpoint version and declared collection source/capability inventory, and optional mTLS host binding. Go handler and storage tests cover update, expiry, and identity checks. Rust agent heartbeat delivery is implemented but Windows runtime behavior is not verified here.
- In-process write-route rate limiting with per-IP token buckets, bounded bucket storage, idle cleanup, and `Retry-After` responses. Unit coverage verifies client isolation, denial, and refill. Limits are fixed starting values, not load-tuned, and do not coordinate service replicas.
- Optional service-store retention configured by `SENTINEL_RETENTION_DAYS`; expired event evidence, dependent alerts/incidents, audit rows, and stale endpoint records are pruned transactionally in PostgreSQL or atomically saved in JSON mode. Retention is disabled by default, and purge counts are audit logged.
- Authenticated `/api/events` uses stable keyset pagination, defaults to 100 records, caps requests at 500, and reports a continuation cursor. The PostgreSQL path uses an ingestion-time index; JSON mode sorts a snapshot. The dashboard exposes older records in process and network investigations and labels overview counts as the loaded page.
- The process investigator now groups the loaded records by host and process ID, makes observed parent links selectable, and labels parent IDs absent from the loaded evidence as unresolved. PID reuse remains ambiguous without a process GUID.
- Reproducible Go detection microbenchmarks cover single-event and threshold-correlation evaluation. A five-run local baseline is recorded in `benchmarks/README.md`; it is not an end-to-end ingestion or capacity benchmark.

## Requires Windows validation

The Rust Windows service subscribes to selected Security and Sysmon channels using the native Event Log API. It uses future-only delivery on first launch and resumes from saved bookmarks. The `x86_64-pc-windows-msvc` cross-target compile, including the heartbeat sender, passed in GitHub Actions on commit `e8c302e`; this local machine does not have the Windows Rust standard-library target. No Windows 11 service installation, channel ACL, Sysmon, reconnection, or event-loss test has been run. Do not treat cross-compilation as runtime proof.

## Not implemented

- Automated endpoint enrollment, certificate revocation/rotation, endpoint configuration management, or automatic provisioning. mTLS host binding depends on out-of-band per-host certificate provisioning and still requires the shared bearer token. Heartbeat source/capability values are self-reported; no Windows runtime check verifies that configured channels are collecting successfully.
- User accounts, web sessions, a full RBAC/analyst identity service, or a live push channel.
- Full Sigma parsing, YARA-X scanning, rule authoring/version history, advanced correlation language, containment, remote commands, or auto-update.
- A Next.js frontend, end-to-end performance/load suite, signed release pipeline, production deployment profile, formal audit-log tamper evidence, or external security assessment.

The sensor is read-only and has no response action. The event model is versioned and OCSF-inspired, not OCSF-compliant.

## Demo data boundary

GitHub Pages has no Go backend. It stores simulated events, alerts, incidents, analyst changes, audit entries, and completed replay reports in `localStorage` for the current browser profile. It does not upload that data to GitHub or sync it to another device. The local Go deployment stores service records in PostgreSQL or a development JSON file. Use **Export run data** or **Export JSON report** before clearing browser site data if a portable copy is needed.
