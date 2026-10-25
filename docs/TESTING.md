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
npm ci
npx playwright install chromium
npm run test:e2e
```

The Go suite asserts exact expected detection sets for all seven deterministic scenarios, including a no-alert benign baseline, runs every scenario through authenticated HTTP ingestion, checks the authentication count threshold, tests JSON persistence, cleanup, and retention, verifies protected reads and administrator-only simulation reset, exercises duplicate rejection and analyst updates, checks mTLS certificate URI host binding for event ingestion and heartbeat, verifies heartbeat update/freshness expiry, tests rate-limit denial/client isolation/refill, and verifies event cursor paging in the API and JSON store. PostgreSQL repository integration tests run when `SENTINEL_TEST_DATABASE_URL` is provided. GitHub Actions starts PostgreSQL 17 and sets that variable, so that job also verifies migrations, indexed recent-event queries, keyset event pages, SQL-backed correlation evidence, transactional reset, and retention cleanup. The Rust portable suite covers spool persistence/deduplication/bookmarks, XML normalization, UTF-8-safe command-line bounds, and transport policy; a Windows CI job checks the Windows target compiles, including the heartbeat sender. The Node suite executes the browser evaluator over all seven Go-exported scenarios, verifies that unexpected alerts fail a replay, local replay-state restoration, full static event-history preservation, simulation archive merge/rollback and paused-run restoration, and process tree parent linking and unknown-ancestry handling. The Playwright suite starts the real Go service and browser, verifies a rejected and accepted analyst token, replays all seven scenarios through authenticated ingestion, checks the reports against each scenario's expected rules, and inspects S01 Sigma evidence and its incident. Detection-only benchmarks can be run with the command in `benchmarks/README.md`; they do not measure HTTP, storage, or agent performance.

## Manual backend smoke path

1. Run `go run ./cmd/sentinel` with a temporary JSON path and a local analyst token.
2. Confirm `/api/health` reports `ok`.
3. Submit a unique normalized record to `POST /api/ingest`; verify it is accepted and matching alerts include event evidence.
4. Submit the same ID again and expect HTTP 409.
5. Run S01–S06 in Sentinel Range, inspect alert and incident records, update analyst notes, then reset one run. Separately POST a valid `AgentHeartbeat` to `/api/heartbeat` and verify `/api/endpoints` reports it online before the 90-second freshness threshold and stale afterward.
6. Restart with the same `SENTINEL_DB` and confirm non-reset data persists.
7. Verify an unauthenticated write is rejected and malformed/oversized events are rejected.

PostgreSQL-backed tests are configured for CI but have not run on this machine because the Docker daemon is unavailable. A Windows Rust target could not be compiled locally because the Windows standard-library target is not installed; the Windows CI job is the compile check. Windows service runtime integration, load/latency tests, dependency scanning, and production security review remain outstanding.

## Current run results

On 2026-10-25, the Go test suite and vet passed locally after heartbeat, rate-limit, and retention implementation; the Go service built in CI; the Node syntax and three tests passed; Rust formatting passed; and all five portable Rust tests passed. Go tests cover authenticated heartbeat freshness and identity binding, rate-limiter denial/isolation/refill, and JSON retention consistency. GitHub Actions passed the Go suite, PostgreSQL 17 migration and retention integration tests, native Rust suite, and Windows MSVC cross-target compile on commit `e8c302e`. A temporary local Go server returned healthy status, and its authenticated S06 simulation endpoint processed five events into all three expected alerts with no misses or unexpected rules. The published browser demo's S06 replay also met all three rule assertions; the pre-existing completed S01 replay remains in the user's original browser profile. No Windows service runtime, local PostgreSQL runtime, performance, or production-readiness claim is made.

After event pagination and process graph updates, local Go tests and vet passed; GitHub CI passed Go tests, PostgreSQL 17 migration/page integration, Go build, native Rust tests, Windows MSVC cross-target compilation, browser tests, and Pages deployment for commit `cece833`. On Apple M4 / macOS Darwin 24.6.0 / Go 1.26.4, five `GOMAXPROCS=1` detection benchmark runs had median 606.1 ns/op for a single event and 683.5 ns/op for the threshold fixture; this excludes HTTP, database, and agent costs. The user's S01 browser replay and its two alerts/one incident were visible in the existing Pages browser profile before the new deployment; no code path in these changes clears or rewrites that browser local storage.

The Playwright browser flows passed locally in Google Chrome against an isolated Go service. They rejected an invalid analyst token, accepted the configured test token, replayed all seven scenarios through authenticated ingestion, checked each exported detection set against the scenario ground truth, and inspected S01 Sigma evidence and its simulation incident. Other dashboard pages and responsive browser sizes still need broader E2E coverage.

For the live/replay boundary update, local `go test ./...`, `go vet ./...`, and the Go service build passed; all 16 Node tests passed. The new integration case ingests both a replay and a live event, confirms the overview returns separated counts, and verifies simulation reset keeps the live event, alert, and incident. Browser tests verify replay alerts do not enter live posture metrics or navigation badges, while replay counts remain available in the lab. Rust checks were not rerun because this change does not touch the agent; the subsequent GitHub workflow is the full-repository gate.
