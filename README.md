# SENTINEL

**A local-first endpoint telemetry and detection workbench with a safe replay lab.**

When GitHub Pages deployment is enabled, the browser-only demo is published at `https://isandreythegrestestguyever.github.io/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/`.

SENTINEL is an early functional security engineering release. Its Go service accepts normalized event envelopes, evaluates enabled rules, writes evidence and alerts to a local JSON store, groups related alerts into incidents, and serves a compact SOC dashboard. Six deterministic fictional scenarios enter through the same event-processing function as the ingest API. Replay data carries a run ID and remains separated from live metrics.

> **Current limits:** This release has no Windows sensor and monitors no live endpoints. The local JSON store is for development and demonstrations, not multi-user or production use. Authentication is a single bearer token, not a user/RBAC system. HTTPS is available when certificates are supplied; mutual TLS is not implemented. Do not expose the service to an untrusted network.

## Quick start

Requirements: Go 1.22 or newer. No external service or database is required.

```sh
go run ./cmd/sentinel
```

Open <http://127.0.0.1:8080>. The server prints a temporary analyst token at startup. Choose **Set analyst token**, paste it, then run a replay. To use a stable local token, set `SENTINEL_ADMIN_TOKEN`. The token is needed for event ingestion and simulation actions.

| Setting | Default | Purpose |
|---|---|---|
| `SENTINEL_ADDR` | `127.0.0.1:8080` | Listen address; loopback by default |
| `SENTINEL_DB` | `sentinel-data.json` | Local persisted store path |
| `SENTINEL_ADMIN_TOKEN` | Random per start | Token for write endpoints |
| `SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY` | unset | When both are set, serve HTTPS |

## Event-to-alert path

1. `POST /api/ingest` accepts a schema `1.0` event (maximum request body 1 MiB).
2. The service validates fields, evaluates enabled rules, and records matching evidence.
3. Events, alerts, audit entries, and grouped incidents are persisted to the local JSON file.
4. The dashboard reads the API and displays stored values.
5. `POST /api/simulate` sends scenario events through the same event-processing path and checks expected rule IDs.

Example:

```sh
curl -sS http://127.0.0.1:8080/api/ingest \
  -H 'Authorization: Bearer YOUR_LOCAL_TOKEN' -H 'Content-Type: application/json' \
  -d '{"id":"demo-1","schema_version":"1.0","time":"2026-10-25T09:00:00Z","host_id":"host-1","hostname":"WORKSTATION-1","source":"example","category":"endpoint","type":"process_start","image":"C:\\Users\\Public\\Temp\\stage.exe"}'
```

Read-only API routes: `/api/health`, `/api/overview`, `/api/events`, `/api/alerts`, `/api/incidents`, `/api/audit`, `/api/rules`, `/api/scenarios`. Mutating routes require the bearer token. Read routes are unauthenticated in this development build; keep the listener on loopback.

## Architecture

```mermaid
flowchart LR
  UI[Browser dashboard] -->|read API| API[Go HTTP service]
  UI -->|tokened replay request| SIM[Replay scenarios]
  SIM --> PIPE[Shared event processing]
  SENSOR[Future Windows sensor] -. planned .->|tokened ingestion| API
  API --> PIPE
  PIPE --> RULES[Versioned rule set]
  PIPE --> STORE[Local JSON store]
  STORE --> API
```

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and the guides in `docs/`.

## Implemented scope

- Versioned event envelope with timestamps, host, source, type, process metadata, destination, technique, and simulation provenance.
- Six enabled explainable single-event rules, with severity, confidence, ATT&CK technique identifier, evidence text, and false-positive guidance.
- Durable atomic file writes, alert evidence, local incident grouping, and logical audit records.
- Payload size and field validation, loopback default, random startup token, HTTPS option, request timeouts, and browser security headers.
- Six deterministic scenarios with mandatory rule assertions and downloadable JSON result reports.
- Dashboard with overview, alert list, sensor boundary disclosure, rule inventory, scenario selection, replay, and results.

The Pages demo is explicitly browser-only: the workflow exports scenario fixtures and rule definitions from the Go application, and the browser evaluates those same conditions locally for a preview. It has no backend, authentication, or persistent data; replay results last only for the open page session. Local Go mode sends replay events into the backend's event-processing and persistence path.

The event shape borrows concepts from OCSF but is **not OCSF compliant**. Rule matching is a small native subset and has **no Sigma parser**. Correlation groups detections by host and simulation run; it does not detect temporal sequences. Precision/recall are scenario-specific checks against declared rule IDs, not calibrated quality measures.

## Verification status

Automated scenario assertion tests are included. Execution was blocked by this host's Go installation: `go test ./...` reported standard packages as “not in std” under `/opt/homebrew/Cellar/go/1.26.4/libexec/src`, although source directories exist. This does not establish whether the code compiles. Re-run with a working Go installation:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
go run ./cmd/sentinel
```

See [testing notes](docs/TESTING.md). No benchmark, Windows build, browser automation, or runtime result is claimed.

## Safety and license

Replay scenarios create synthetic in-app records only. No malware, credentials, real connections, file changes, persistence modifications, or remote commands are performed. This is a local development utility, not hardened production EDR. See [SECURITY.md](SECURITY.md). Licensed Apache-2.0.
