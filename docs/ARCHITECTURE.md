# Architecture

The first release is a single-process Go service with a static browser UI. This keeps replay and ingestion on one shared processing path and removes external service dependencies from the demo.

- `internal/model`: JSON event, alert, incident, and endpoint types. Schema `1.0` is Sentinel-specific and OCSF-inspired, not conformant.
- `internal/detection`: six enabled single-event substring rules. Each alert points to one event and includes a matching explanation.
- `internal/simulator`: six deterministic synthetic scenario definitions. It performs no host activity.
- `internal/store`: mutex-protected state with atomic JSON snapshot writes. Suitable only for one local process and small demos.
- `cmd/sentinel`: API, validation, token check, listener, headers, and route wiring.
- `web`: static responsive dashboard using JSON APIs.

Ingested and replayed events both reach `processEvent`. It timestamps ingestion, evaluates rules, creates alerts, updates an incident group, appends a logical audit entry, and persists state. Each replay event receives a run ID; live overview counts exclude simulation records.

There is no SQL database, Windows Event Log sensor, enrollment service, mTLS, RBAC, Sigma import, YARA scanning, streaming transport, or production deployment setup. Read routes are public to the listener. Keep it on loopback. OCSF class-specific conformance is not claimed; see the [OCSF event model overview](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md).
