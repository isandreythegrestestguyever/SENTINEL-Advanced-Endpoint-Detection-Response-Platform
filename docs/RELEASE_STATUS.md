# Release status

## Verified in this repository

- Go service event ingestion, bounded rule evaluation, evidence-linked alerts, incident grouping, analyst updates, local JSON persistence, and run-scoped simulation cleanup.
- Six deterministic synthetic scenarios through the Go HTTP ingestion/detection path. Go tests cover every declared expected rule; a local service smoke run exercised S06 and returned all three required alerts.
- PostgreSQL migration and repository integration tests passed against PostgreSQL 17 in GitHub Actions. Local PostgreSQL runtime testing was unavailable because Docker was not running.
- Static GitHub Pages preview with six exported scenarios, browser-side rule evaluation, replay playback controls, timeline scrubbing, labeled ground truth/detected techniques, downloadable reports, and browser-profile persistence.
- Rust event XML parsing, normalization, bounded event validation, SQLite WAL spool, duplicate suppression, payload cap, bookmarks, and remote transport policy in portable tests.
- HTTPS server configuration with TLS 1.3 and optional CA-verified client certificates. When mTLS is enabled, ingest requires a certificate and binds its verified URI SAN to the event host ID; a handler regression test covers matching, mismatched, and missing identities.

## Requires Windows validation

The Rust Windows service subscribes to selected Security and Sysmon channels using the native Event Log API. It uses future-only delivery on first launch and resumes from saved bookmarks. The `x86_64-pc-windows-msvc` cross-target compile passed in GitHub Actions on commit `b9730fe`; this local machine does not have the Windows Rust standard-library target. No Windows 11 service installation, channel ACL, Sysmon, reconnection, or event-loss test has been run. Do not treat cross-compilation as runtime proof.

## Not implemented

- Automated endpoint enrollment, certificate revocation/rotation, heartbeat, endpoint configuration management, or automatic provisioning. mTLS host binding currently depends on out-of-band per-host certificate provisioning and still requires the shared bearer token.
- User accounts, web sessions, a full RBAC/analyst identity service, rate limiting, data retention, event pagination, or a live push channel.
- Full Sigma parsing, YARA-X scanning, rule authoring/version history, advanced correlation language, containment, remote commands, or auto-update.
- A Next.js frontend, performance benchmark suite, signed release pipeline, production deployment profile, formal audit-log tamper evidence, or external security assessment.

The sensor is read-only and has no response action. The event model is versioned and OCSF-inspired, not OCSF-compliant.

## Demo data boundary

GitHub Pages has no Go backend. It stores simulated events, alerts, incidents, analyst changes, audit entries, and completed replay reports in `localStorage` for the current browser profile. It does not upload that data to GitHub or sync it to another device. The local Go deployment stores service records in PostgreSQL or a development JSON file. Use **Export run data** or **Export JSON report** before clearing browser site data if a portable copy is needed.
