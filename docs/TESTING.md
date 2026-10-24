# Testing and verification

## Automated checks

Run from the repository root:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
node --check web/app.js
```

The Go suite asserts expected detections for all six deterministic scenarios and tests JSON store persistence, analyst updates, simulation cleanup, and duplicate event rejection. `go vet` checks the Go packages. `node --check` only parses the browser script; it does not exercise DOM behavior.

## Manual backend smoke path

1. Run `go run ./cmd/sentinel` with a temporary JSON path and a local analyst token.
2. Confirm `/api/health` reports `ok`.
3. Submit a unique normalized record to `POST /api/ingest`; verify it is accepted and matching alerts include event evidence.
4. Submit the same ID again and expect HTTP 409.
5. Run S01–S06 in Sentinel Range, inspect alert and incident records, update analyst notes, then reset one run.
6. Restart with the same `SENTINEL_DB` and confirm non-reset data persists.
7. Verify an unauthenticated write is rejected and malformed/oversized events are rejected.

Automated API integration tests and browser end-to-end tests are not currently included. A local port bind was unavailable in this restricted environment, so the server smoke path was not run here. Windows sensor compilation/integration, Postgres migration checks, load/latency tests, dependency scanning, and production security review are unsupported because those components are not implemented.

## Current run results

On 2026-10-25, `go test ./...` passed, `go vet ./...` passed, and `node --check web/app.js` passed using Go 1.26.4 and Node 26.7.0. A local listener attempt was blocked by the environment's network permission (`bind: operation not permitted`); this is not evidence of a server runtime failure. No Windows, database, performance, or production-readiness claim is made.
