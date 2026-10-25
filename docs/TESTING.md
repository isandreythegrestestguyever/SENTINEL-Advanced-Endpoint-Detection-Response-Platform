# Testing and verification

## Automated checks

Run from the repository root:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
go build ./cmd/sentinel
node --check web/app.js
node --test web/app.test.mjs
cargo fmt --manifest-path agent/Cargo.toml -- --check
cargo test --locked --manifest-path agent/Cargo.toml
```

The Go suite asserts expected detections for all six deterministic scenarios, runs every scenario through authenticated HTTP ingestion, checks the authentication count threshold, tests JSON persistence and cleanup, verifies protected reads and administrator-only simulation reset, exercises duplicate rejection and analyst updates, checks mTLS certificate URI host binding for event ingestion and heartbeat, and verifies heartbeat update/freshness expiry. PostgreSQL repository integration tests run when `SENTINEL_TEST_DATABASE_URL` is provided. GitHub Actions starts PostgreSQL 17 and sets that variable, so that job also verifies migrations, indexed recent-event queries, SQL-backed correlation evidence, and transactional reset. The Rust portable suite covers spool persistence/deduplication/bookmarks, XML normalization, UTF-8-safe command-line bounds, and transport policy; a Windows CI job checks the Windows target compiles, including the heartbeat sender. The Node suite executes the browser evaluator over all six Go-exported scenarios and verifies local replay-state restoration. It does not exercise real browser DOM behavior.

## Manual backend smoke path

1. Run `go run ./cmd/sentinel` with a temporary JSON path and a local analyst token.
2. Confirm `/api/health` reports `ok`.
3. Submit a unique normalized record to `POST /api/ingest`; verify it is accepted and matching alerts include event evidence.
4. Submit the same ID again and expect HTTP 409.
5. Run S01–S06 in Sentinel Range, inspect alert and incident records, update analyst notes, then reset one run. Separately POST a valid `AgentHeartbeat` to `/api/heartbeat` and verify `/api/endpoints` reports it online before the 90-second freshness threshold and stale afterward.
6. Restart with the same `SENTINEL_DB` and confirm non-reset data persists.
7. Verify an unauthenticated write is rejected and malformed/oversized events are rejected.

Browser end-to-end tests are not currently included. PostgreSQL-backed tests are configured for CI but have not run on this machine because the Docker daemon is unavailable. A Windows Rust target could not be compiled locally because the Windows standard-library target is not installed; the Windows CI job is the compile check. Windows service runtime integration, load/latency tests, dependency scanning, and production security review remain outstanding.

## Current run results

On 2026-10-25, the Go test suite and vet passed locally after heartbeat implementation, the Go service built, the Node syntax and three tests passed, Rust formatting passed, and all five portable Rust tests passed. The heartbeat handler regression verifies authenticated endpoint registration, live/stale transitions, and matching/mismatched mTLS identities. GitHub Actions passed the Go suite, PostgreSQL 17 integration tests, native Rust suite, and Windows MSVC cross-target compile on commit `b55e2ad`. A temporary local Go server returned healthy status, and its authenticated S06 simulation endpoint processed five events into all three expected alerts with no misses or unexpected rules. The published browser demo's S06 replay also met all three rule assertions; the pre-existing completed S01 replay remains in the user's original browser profile. No Windows service runtime, local PostgreSQL runtime, performance, or production-readiness claim is made.
