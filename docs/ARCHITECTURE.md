# Architecture

SENTINEL currently ships as a single Go process with a static browser UI and a local JSON file store. The static architecture makes the ingest-to-detection path easy to run locally, but it is a development foundation rather than the target multi-component EDR system.

```mermaid
flowchart LR
  UI[Browser analyst UI] -->|read and analyst actions| API[Go HTTP service]
  UI -->|one event at a time| API
  SENSOR[Future Rust Windows sensor] -. planned .->|authenticated telemetry| API
  API --> VALIDATE[Event validation]
  VALIDATE --> ENGINE[Six native rules]
  ENGINE --> STORE[Local JSON store]
  STORE --> UI
  EXPORT[Go scenario and rule exporter] --> PAGES[GitHub Pages preview]
  PAGES -->|browser session only| JS[Local fixture evaluator]
```

## Current components

- `internal/model`: Sentinel schema `1.0` events, alerts, incidents, and derived endpoint records. The schema borrows concepts from OCSF but is not conformant.
- `internal/detection`: six enabled, revisioned rules, each matching a single field with a case-insensitive substring condition.
- `internal/simulator`: six fictional fixtures with declared expected rule IDs. It performs no host activity.
- `internal/store`: mutex-protected in-memory slices persisted by atomic JSON-file replacement. It rejects duplicate event IDs within the store and records analyst actions in a logical audit list.
- `cmd/sentinel`: validation, bearer-token checks on writes, API routes, response headers, request limits, local listener, and optional HTTPS.
- `web`: static responsive dashboard for local API operation and the browser-only Pages preview.

Local `/api/ingest` and paced scenario replay both call the same event-processing path. A matching event produces an alert linked to the original event. Alerts are grouped into an incident by host and simulation run. Analyst status, assignment, and note changes are persisted and audit-logged. Reset removes records for one simulation run while retaining an audit record of the reset.

GitHub Pages cannot run the Go service. The workflow exports scenario and rule fixtures from the Go source; `web/app.js` uses those definitions in browser memory. It is explicitly labeled static demo mode and has no authentication or persistence.

## Deliberate limitations

There is no PostgreSQL adapter or migration set, Rust sensor, endpoint enrollment, heartbeat, event pagination, live push channel, multi-user account model, RBAC, mTLS, rate limiting, temporal correlation engine, Sigma parser, YARA scanning, or response action. Read API routes are unauthenticated. The JSON store is unsuitable for concurrent service replicas, large datasets, or production retention needs. Keep the listener on loopback. HTTPS only encrypts the connection when configured; it does not provide endpoint identity.
