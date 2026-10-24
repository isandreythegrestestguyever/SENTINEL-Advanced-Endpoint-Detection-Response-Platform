# Testing and verification

## Automated checks

Run from the repository root:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
node --check web/app.js
```

The Go suite asserts expected detections for all six deterministic scenarios, tests JSON store persistence and cleanup, and exercises authenticated HTTP routes with `httptest` for ingest, duplicate rejection, alert/incident updates, and simulation reset. PostgreSQL repository integration tests run when `SENTINEL_TEST_DATABASE_URL` is provided. GitHub Actions starts PostgreSQL 17 and sets that variable, so that job also verifies migrations and SQL-backed ingest/update/reset. `go vet` checks the Go packages. `node --check` only parses the browser script; it does not exercise DOM behavior.

## Manual backend smoke path

1. Run `go run ./cmd/sentinel` with a temporary JSON path and a local analyst token.
2. Confirm `/api/health` reports `ok`.
3. Submit a unique normalized record to `POST /api/ingest`; verify it is accepted and matching alerts include event evidence.
4. Submit the same ID again and expect HTTP 409.
5. Run S01–S06 in Sentinel Range, inspect alert and incident records, update analyst notes, then reset one run.
6. Restart with the same `SENTINEL_DB` and confirm non-reset data persists.
7. Verify an unauthenticated write is rejected and malformed/oversized events are rejected.

Browser end-to-end tests are not currently included. A local port bind was unavailable in this restricted environment, so the standalone server smoke path was not run here. The Docker daemon is not running locally, so PostgreSQL-backed tests are configured for CI but have not run on this machine. Windows sensor compilation/integration, load/latency tests, dependency scanning, and production security review remain outstanding.

## Current run results

On 2026-10-25, `go test ./...`, `go vet ./...`, `go build ./cmd/sentinel`, and `node --check web/app.js` passed using Go 1.26.4 and Node 26.7.0. Because `SENTINEL_TEST_DATABASE_URL` was unset, the PostgreSQL integration test skipped locally. The standalone local listener attempt was blocked by the environment's network permission (`bind: operation not permitted`); the same HTTP handlers were exercised in-process through `httptest`. The published browser demo was manually opened and S01 and S06 replayed successfully; reset and alert evidence views were also checked. No Windows, local database runtime, performance, or production-readiness claim is made.
