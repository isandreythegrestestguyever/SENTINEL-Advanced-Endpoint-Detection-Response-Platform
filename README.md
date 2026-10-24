# SENTINEL

**A local-first endpoint telemetry and detection workbench with a safe replay lab.**

[Open the GitHub Pages demo](https://isandreythegrestestguyever.github.io/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/)

SENTINEL is an early, functional security engineering project. The Go service accepts normalized event records, evaluates a small explainable rule set, persists matching evidence, creates host-and-run incident groups, and serves an analyst dashboard. Six deterministic fictional exercises feed events through the same ingest route and detection code used by submitted telemetry.

The hosted Pages build is a **browser-only simulation**: its fixtures and rule definitions are exported from the Go packages, and JavaScript evaluates them in the browser. Run results, alerts, notes, and audit entries are saved in that browser's local storage, so they survive reloads in the same browser profile. They do not sync between devices or to GitHub, and clearing site data removes them. Run the local Go service to exercise the backend event path and server-side persistence.

> **Not production EDR:** There is no Windows sensor, endpoint enrollment, response action, user accounts or sessions, mTLS, or production deployment configuration. PostgreSQL support does not make this a production service. Configured analyst and administrator bearer tokens are a minimal single-process access split, not a full identity system. The local JSON store is development-only. Do not expose the service to an untrusted network or submit sensitive telemetry.

## Run locally

Requirements: Go 1.25 or newer. PostgreSQL 14+ is used when `SENTINEL_DATABASE_URL` is set.

```sh
docker compose up -d postgres
export SENTINEL_DATABASE_URL='postgres://sentinel:sentinel-local-only@127.0.0.1:5432/sentinel?sslmode=disable'
export SENTINEL_ADMIN_TOKEN='local-development-token'
go run ./cmd/sentinel
```

Open <http://127.0.0.1:8080> and choose **Set analyst token** to paste the token configured above. The Compose password is only for local development. If Docker is unavailable, omit `SENTINEL_DATABASE_URL`; the service then uses the local JSON development store.

| Setting | Default | Purpose |
|---|---|---|
| `SENTINEL_ADDR` | `127.0.0.1:8080` | Listen address; loopback by default |
| `SENTINEL_DB` | `sentinel-data.json` | Local JSON persistence path |
| `SENTINEL_DATABASE_URL` | unset | PostgreSQL connection string; enables migrations and SQL storage |
| `SENTINEL_ADMIN_TOKEN` | Random per start | Administrator bearer token; required for simulation reset |
| `SENTINEL_ANALYST_TOKEN` | unset | Optional distinct analyst bearer token; can read data and submit events or analyst updates |
| `SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY` | unset | Serve HTTPS when both paths are set |

## What works

- Versioned Sentinel event envelope (`schema_version: 1.0`) with source, host, timestamp, process metadata, destination, ATT&CK label, and simulation provenance.
- Six enabled, documented single-field detection rules with evidence links, severity, confidence metadata, ATT&CK identifiers, revisions, and false-positive notes.
- Bounded count correlations for repeated authentication failures, file modifications, and same-destination network activity; correlated alerts include every supporting event ID.
- Authenticated ingestion with request and field bounds, duplicate event ID rejection, JSON persistence, automatic alert grouping, and analyst audit entries.
- PostgreSQL persistence with versioned migrations, indexed event/alert/incident tables, alert-to-event links, transactional event and alert writes, and run-scoped cleanup. JSON remains available for lightweight local demos.
- Analyst alert actions: filter/search, inspect evidence, acknowledge/close, assign, and save notes.
- Incident queue, status and notes updates, evidence timeline, and JSON incident export.
- Endpoint inventory derived from received events, process ancestry assembled only from available process IDs, network metadata view, detection catalog, and audit history.
- Six deterministic, safe replay scenarios, with one-event-at-a-time playback, pause/resume, speed control, reset, result evaluation, and JSON report export.
- Browser-only Pages replay state is saved per browser profile; local API mode persists through PostgreSQL or the local JSON development store.
- Responsive dashboard with explicit live-submission versus simulated-data labeling.

## Event-to-alert path

1. `POST /api/ingest` accepts a schema `1.0` event (maximum body 1 MiB).
2. The service validates required fields and bounds, rejects duplicate event IDs, evaluates enabled rules, and stores evidence for matches.
3. Events, alerts, host/run incident groups, and logical audit records are saved transactionally in PostgreSQL, or in the local JSON file when that development mode is selected.
4. The dashboard reads actual local API data and sends analyst changes back to authenticated routes.
5. Sentinel Range replays events individually through `POST /api/ingest`; it evaluates the actual returned alerts against each scenario's declared expected rule IDs.

`/api/health`, `/api/rules`, and `/api/scenarios` are public. Overview, event, endpoint, alert, incident, and audit data require an administrator or analyst bearer token. `POST /api/ingest`, `POST /api/simulate`, `PATCH /api/alerts/{id}`, and `PATCH /api/incidents/{id}` accept either role. `DELETE /api/simulations/{run}` requires the administrator token.

## Repository guide

- `cmd/sentinel`: local Go HTTP service.
- `cmd/export-demo`: exports scenario and rule definitions for Pages.
- `internal/model`: versioned Sentinel event, alert, incident, and endpoint types.
- `internal/detection`: native single-field rule matching.
- `internal/simulator`: six deterministic synthetic scenario fixtures.
- `internal/store`: PostgreSQL persistence and migrations, plus a mutex-protected JSON development store.
- `web`: static dashboard and browser-only Pages preview.
- `docs`: architecture, detection, simulator, testing, and threat-model notes.

See [architecture](docs/ARCHITECTURE.md), [detection engine](docs/DETECTION_ENGINE.md), [simulator guide](docs/SIMULATOR.md), [testing](docs/TESTING.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md).

## Verification

The current source has been checked with `go test ./...`, `go vet ./...`, and `node --check web/app.js`. These checks cover Go unit tests and JavaScript syntax; they do not establish Windows sensor support, production security, multi-user operation, or live endpoint monitoring. See the testing guide for the exact verification boundary.

## Roadmap

The next major engineering slices are a Windows Rust service using documented event providers; authenticated endpoint enrollment and mutual TLS; user accounts and session-based analyst access; broader browser end-to-end tests; and a general-purpose correlation language. The dashboard currently serves the local API directly and is not a Next.js application. The event model is OCSF-inspired, not OCSF-compliant. Sigma parsing and YARA scanning are not implemented.

## License

Apache-2.0. See [LICENSE](LICENSE).
