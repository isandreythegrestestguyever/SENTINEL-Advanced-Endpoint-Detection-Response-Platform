# SENTINEL

**A local-first endpoint telemetry and detection workbench with a safe replay lab.**

[Open the GitHub Pages demo](https://isandreythegrestestguyever.github.io/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/)

SENTINEL is a local-first security engineering workbench. The Go service accepts normalized event records, evaluates explainable rules, persists evidence, groups alerts into incidents, and serves an analyst dashboard. The Rust Windows service collects selected Security and Sysmon Event Log records, normalizes them, durably buffers them in SQLite, and delivers them to the authenticated ingest endpoint. Seven deterministic fictional exercises send events through the Go ingest and detection path in local mode, including a benign baseline that expects no alerts.

The hosted Pages build is a **browser-only simulation**: fixtures and rule definitions are exported from the Go packages, then JavaScript applies those exported definitions to events in the browser. This is a browser implementation of the same documented rule conditions; it does not call the Go detector. Run results, alerts, notes, and audit entries are saved in that browser's local storage, so they survive reloads in the same browser profile. They do not sync between devices or to GitHub, and clearing site data removes them. Sentinel Range includes **Export All Sim Data** and **Import Sim Data** for portable simulation archives. Import adds records to the current browser store, keeps existing records, and can restore a paused replay without starting it. The archive contains simulated events, alerts, cases, audit entries, scenarios, and saved run reports; live records are excluded. Run the local Go service to send each replay event through the actual Go backend and server-side persistence.

> **Not production EDR:** The Windows sensor has portable normalization/spool tests and a Windows CI cross-target build check, but has not been run on a Windows 11 endpoint here. It reports authenticated heartbeats and agent-declared sources/capabilities; no Windows runtime evidence is available. There is no automated endpoint enrollment, certificate rotation or revocation, response action, user accounts or sessions, production deployment, retention policy, or external security review. When mTLS is enabled, heartbeat and ingest require the client certificate URI SAN to match the host ID; operators provision this identity out of band, and the shared bearer token remains required. Configured bearer tokens are a minimal single-process access split, not a full identity system. Do not expose the service to an untrusted network or submit sensitive telemetry.

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
| `SENTINEL_RETENTION_DAYS` | `0` (disabled) | Remove service records older than this many days; cleanup runs at startup and hourly |
| `SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY` | unset | Serve HTTPS when both paths are set |
| `SENTINEL_CLIENT_CA` | unset | Verify presented client certificates; require a host-bound certificate on ingest; requires HTTPS |

## What works

- Versioned Sentinel event envelope (`schema_version: 1.0`) with source, host, timestamp, process metadata, destination, ATT&CK label, and simulation provenance.
- Six enabled, documented native rules plus one bundled, enabled Windows process-creation Sigma rule. Active Sigma is bounded to one mapped field and `contains`; both native and Sigma findings use authenticated ingestion and preserve evidence and rule revision.
- Bounded count correlations for repeated authentication failures, file modifications, and same-destination network activity; correlated alerts include every supporting event ID.
- Authenticated ingestion with request and field bounds, duplicate event ID rejection, JSON persistence, automatic alert grouping, and analyst audit entries.
- Common command-line credential arguments and credential-named custom fields are redacted by the Windows agent before spooling and by the service before detection/storage; this narrow filter is not general-purpose DLP.
- Bounded per-IP rate limits on telemetry and write routes, with `Retry-After` responses and a capped in-process bucket map.
- Optional service-side retention for expired telemetry, dependent alerts/cases, audit entries, and stale heartbeat records; disabled unless configured.
- Authenticated event history with stable cursor pagination, capped page sizes, and older-event controls in process and network investigations.
- PostgreSQL persistence with versioned migrations, indexed event/alert/incident tables, alert-to-event links, transactional event and alert writes, and run-scoped cleanup. JSON remains available for lightweight local demos.
- Analyst alert actions: filter/search, inspect evidence, acknowledge/close, assign, and save notes.
- Authenticated local-only Sigma rule test workspace: parses a bounded YAML rule with sigma-go and evaluates one normalized event without persisting it or changing the ingest detector.
- Incident queue, status and notes updates, evidence timeline, and JSON incident export.
- Endpoint inventory derived from received events, a selectable process tree that links only observed parent IDs, process event details, network metadata view, detection catalog, and audit history.
- Provenance-separated live and replay counts in the authenticated overview API. Live posture metrics and recent-detection panels exclude replay alerts/incidents; the Range lab retains separate simulation counts and records.
- Seven deterministic, safe replay scenarios, with one-event-at-a-time playback, pause/resume, speed control, timeline scrubbing, results compared with declared ground truth, saved run history, and evidence-linked JSON/Markdown report export. Runs fail on either missed expected rules or unexpected alert rules; the benign baseline checks that ordinary activity stays clear.
- Simulation-only JSON archive export that keeps browser and service replay evidence portable without mixing live event records into the archive.
- A fictional topology view labeled as synthetic metadata, event-level ATT&CK ground truth versus detector mappings, and visible evidence links in the replay stream.
- Browser-only Pages replay state is saved per browser profile; local API mode persists through PostgreSQL or the local JSON development store.
- Read-only Windows Event Log service source with bounded SQLite outbox, persistent channel bookmarks, stable event IDs, HTTPS client identity support, common credential-argument redaction before spooling, and structured rotating JSONL logs.
- Reproducible detection-package microbenchmarks with environment and observed baseline recorded separately from end-to-end capacity claims.
- Responsive dashboard with explicit live-submission versus simulated-data labeling.

## Event-to-alert path

1. `POST /api/ingest` accepts a schema `1.0` event (maximum body 1 MiB). `POST /api/heartbeat` stores agent version, configured source/capability reports, and server receipt time; connected status expires after 90 seconds.
2. The service validates required fields and bounds, rejects duplicate event IDs, evaluates enabled rules, and stores evidence for matches.
3. Events, alerts, host/run incident groups, and logical audit records are saved transactionally in PostgreSQL, or in the local JSON file when that development mode is selected.
4. The dashboard reads actual local API data and sends analyst changes back to authenticated routes.
5. Sentinel Range replays events individually through `POST /api/ingest`; it evaluates the actual returned alerts against each scenario's declared expected rule IDs.

`/api/health`, `/api/rules`, and `/api/scenarios` are public. Overview, event, endpoint, alert, incident, and audit data require an administrator or analyst bearer token. `POST /api/ingest`, `POST /api/simulate`, `PATCH /api/alerts/{id}`, and `PATCH /api/incidents/{id}` accept either role. `DELETE /api/simulations/{run}` requires the administrator token.

## Repository guide

- `cmd/sentinel`: local Go HTTP service.
- `agent`: Rust Windows Event Log service and portable spool/normalization components.
- `cmd/export-demo`: exports scenario and rule definitions for Pages.
- `internal/model`: versioned Sentinel event, alert, incident, and endpoint types.
- `internal/detection`: native single-field rule matching.
- `internal/simulator`: seven deterministic synthetic scenario fixtures; S01 now exercises the bundled Sigma rule through both local ingestion and browser replay.
- `internal/store`: PostgreSQL persistence and migrations, plus a mutex-protected JSON development store.
- `web`: static dashboard and browser-only Pages preview.
- `docs`: architecture, detection, simulator, testing, and threat-model notes.

See [architecture](docs/ARCHITECTURE.md), [detection engine](docs/DETECTION_ENGINE.md), [simulator guide](docs/SIMULATOR.md), [agent guide](docs/AGENT.md), [release status](docs/RELEASE_STATUS.md), [testing](docs/TESTING.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md).

## Verification

Local checks: `go test ./...`, `go vet ./...`, `go build ./cmd/sentinel`, `node --check web/app.js`, `node --test web/app.test.mjs`, and Rust format/tests. Real browser flows use `npm ci`, `npx playwright install chromium`, and `npm run test:e2e`; Playwright starts an isolated Go service, verifies analyst-token validation, replays all seven scenarios through authenticated ingestion, checks S01 Sigma evidence and incident display, and validates every downloaded report against ground truth. These checks do not establish Windows service runtime support, production security, multi-user operation, or live endpoint monitoring. See the testing guide for the exact verification boundary.

The screenshot below is captured by the passing Playwright run. Every event shown is a deterministic synthetic fixture; the screenshot does not show a live endpoint.

![SENTINEL simulated S01 replay after a passing browser run](screenshots/sentinel-range.png)

## Roadmap

Next engineering priorities are Windows 11 service integration tests, automated endpoint enrollment and certificate rotation/revocation, user accounts and sessions, additional browser end-to-end workflows, and a general-purpose correlation language. The active Sigma subset is bundled and read-only; dynamic authoring, persistence, broader modifier/logsource support, and multi-event aggregation are not implemented. The one-event test workspace does not change active rules. sigma-go v0.6.5 documents itself as draft-spec; no universal Sigma compatibility is claimed. YARA scanning is not implemented. The dashboard currently serves the local API directly and is not a Next.js application. The event model is OCSF-inspired, not OCSF-compliant.

## License

Apache-2.0. See [LICENSE](LICENSE).
