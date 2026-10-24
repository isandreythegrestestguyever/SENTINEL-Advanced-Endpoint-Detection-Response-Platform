# Architecture

SENTINEL currently ships as a single Go service with a static browser UI. PostgreSQL is the persistent service path when `SENTINEL_DATABASE_URL` is configured; a local JSON store remains available for dependency-free development. GitHub Pages runs only a browser-side preview.

```mermaid
flowchart LR
  UI[Browser analyst UI] -->|read and analyst actions| API[Go HTTP service]
  UI -->|one event at a time| API
  SENSOR[Future Rust Windows sensor] -. planned .->|authenticated telemetry| API
  API --> VALIDATE[Event validation]
  VALIDATE --> ENGINE[Six native rules]
  ENGINE --> STORE[Repository interface]
  STORE --> PG[(PostgreSQL)]
  STORE -. local mode .-> JSON[JSON file store]
  PG --> UI
  EXPORT[Go scenario and rule exporter] --> PAGES[GitHub Pages preview]
  PAGES -->|browser session only| JS[Local fixture evaluator]
```

## Current components

- `internal/model`: Sentinel schema `1.0` events, alerts, incidents, and derived endpoint records. The schema borrows concepts from OCSF but is not conformant.
- `internal/detection`: six enabled, revisioned rules using case-insensitive field conditions; three also correlate bounded event counts by host/run and, for network activity, destination.
- `internal/simulator`: six fictional fixtures with declared expected rule IDs. It performs no host activity.
- `internal/store`: repository interface; mutex-protected JSON development store; PostgreSQL implementation using pgx, embedded versioned SQL migrations, indexes, transactional event/alert/case/audit writes, and normalized evidence links.
- `cmd/sentinel`: validation, bearer-token checks on writes, API routes, response headers, request limits, local listener, optional HTTPS, and backend selection.
- `web`: static responsive dashboard for local API operation and the browser-only Pages preview.

Local `/api/ingest` and paced scenario replay both call the same event-processing path. A matching event produces an alert linked to the original event. Alerts are grouped into an incident by host and simulation run. Analyst status, assignment, and note changes are persisted and audit-logged. Reset removes records for one simulation run while retaining a reset audit entry.

GitHub Pages cannot run the Go service. The workflow exports scenario and rule fixtures from the Go source; `web/app.js` uses those definitions in browser memory. It is explicitly labeled static demo mode and has no authentication or persistence.

## Deliberate limitations

There is no Rust sensor, endpoint enrollment, heartbeat, event pagination, live push channel, multi-user account model, RBAC, mTLS, rate limiting, general-purpose correlation language, Sigma parser, YARA scanning, or response action. Read API routes are unauthenticated. PostgreSQL support is exercised in CI against a PostgreSQL service but not against a local daemon here. JSON mode is unsuitable for concurrent service replicas, large datasets, or production retention needs. Keep the listener on loopback. HTTPS only encrypts the connection when configured; it does not provide endpoint identity.
