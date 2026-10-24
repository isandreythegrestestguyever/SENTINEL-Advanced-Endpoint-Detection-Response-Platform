# SENTINEL

**A local-first endpoint telemetry and detection workbench with a safe replay lab.**

[Open the GitHub Pages demo](https://isandreythegrestestguyever.github.io/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/)

SENTINEL is an early, functional security engineering project. The Go service accepts normalized event records, evaluates a small explainable rule set, persists matching evidence, creates host-and-run incident groups, and serves an analyst dashboard. Six deterministic fictional exercises feed events through the same ingest route and detection code used by submitted telemetry.

The hosted Pages build is a **browser-only simulation**: its fixtures and rule definitions are exported from the Go packages, and JavaScript evaluates them in the page session. It has no service, sign-in, or persistent storage. Run the local Go service to exercise the backend event path and persistent analyst workflows.

> **Not production EDR:** There is no Windows sensor, endpoint enrollment, response action, PostgreSQL database, multi-user authentication, RBAC, mTLS, or production deployment configuration. The local JSON store and shared bearer token are development-only. Do not expose the service to an untrusted network or submit sensitive telemetry.

## Run locally

Requirements: Go 1.24 or newer.

```sh
go run ./cmd/sentinel
```

Open <http://127.0.0.1:8080>. Copy the temporary analyst token from the server output and choose **Set analyst token**. To use a stable development token, set `SENTINEL_ADMIN_TOKEN` before starting.

| Setting | Default | Purpose |
|---|---|---|
| `SENTINEL_ADDR` | `127.0.0.1:8080` | Listen address; loopback by default |
| `SENTINEL_DB` | `sentinel-data.json` | Local JSON persistence path |
| `SENTINEL_ADMIN_TOKEN` | Random per start | Bearer token for write routes |
| `SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY` | unset | Serve HTTPS when both paths are set |

## What works

- Versioned Sentinel event envelope (`schema_version: 1.0`) with source, host, timestamp, process metadata, destination, ATT&CK label, and simulation provenance.
- Six enabled, documented single-field detection rules with evidence links, severity, confidence metadata, ATT&CK identifiers, revisions, and false-positive notes.
- Authenticated ingestion with request and field bounds, duplicate event ID rejection, JSON persistence, automatic alert grouping, and analyst audit entries.
- Analyst alert actions: filter/search, inspect evidence, acknowledge/close, assign, and save notes.
- Incident queue, status and notes updates, evidence timeline, and JSON incident export.
- Endpoint inventory derived from received events, process ancestry assembled only from available process IDs, network metadata view, detection catalog, and audit history.
- Six deterministic, safe replay scenarios, with one-event-at-a-time playback, pause/resume, speed control, reset, result evaluation, and JSON report export.
- Responsive dashboard with explicit live-submission versus simulated-data labeling.

## Event-to-alert path

1. `POST /api/ingest` accepts a schema `1.0` event (maximum body 1 MiB).
2. The service validates required fields and bounds, rejects duplicate event IDs, evaluates enabled rules, and stores evidence for matches.
3. Events, alerts, host/run incident groups, and logical audit records are saved in the local JSON file.
4. The dashboard reads actual local API data and sends analyst changes back to authenticated routes.
5. Sentinel Range replays events individually through `POST /api/ingest`; it evaluates the actual returned alerts against each scenario's declared expected rule IDs.

Read routes: `/api/health`, `/api/overview`, `/api/events`, `/api/endpoints`, `/api/alerts`, `/api/incidents`, `/api/audit`, `/api/rules`, and `/api/scenarios`. Write routes require `Authorization: Bearer <token>`: `POST /api/ingest`, `POST /api/simulate`, `PATCH /api/alerts/{id}`, `PATCH /api/incidents/{id}`, and `DELETE /api/simulations/{run}`.

## Repository guide

- `cmd/sentinel`: local Go HTTP service.
- `cmd/export-demo`: exports scenario and rule definitions for Pages.
- `internal/model`: versioned Sentinel event, alert, incident, and endpoint types.
- `internal/detection`: native single-field rule matching.
- `internal/simulator`: six deterministic synthetic scenario fixtures.
- `internal/store`: mutex-protected JSON persistence.
- `web`: static dashboard and browser-only Pages preview.
- `docs`: architecture, detection, simulator, testing, and threat-model notes.

See [architecture](docs/ARCHITECTURE.md), [detection engine](docs/DETECTION_ENGINE.md), [simulator guide](docs/SIMULATOR.md), [testing](docs/TESTING.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md).

## Verification

The current source has been checked with `go test ./...`, `go vet ./...`, and `node --check web/app.js`. These checks cover Go unit tests and JavaScript syntax; they do not establish Windows sensor support, production security, multi-user operation, or live endpoint monitoring. See the testing guide for the exact verification boundary.

## Roadmap

The next major engineering slices are PostgreSQL with migrations and indexed queries; a Windows Rust service using documented event providers; multi-event temporal correlation; authenticated endpoint enrollment and secure transport; and broader API/browser integration tests. The dashboard currently serves the local API directly and is not a Next.js application. The event model is OCSF-inspired, not OCSF-compliant. Sigma parsing and YARA scanning are not implemented.

## License

Apache-2.0. See [LICENSE](LICENSE).
