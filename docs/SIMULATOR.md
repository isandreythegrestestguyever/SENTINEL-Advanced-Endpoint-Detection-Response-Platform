# Sentinel Range

The six built-in exercises are deterministic, fictional event fixtures. They create records only: they do not launch processes, connect to destinations, modify files or registry settings, collect credentials, or establish persistence.

## Run locally

1. Start `go run ./cmd/sentinel` and open `http://127.0.0.1:8080`.
2. Set the analyst token printed in the server output, or provide `SENTINEL_ADMIN_TOKEN` before startup.
3. Open **Sentinel Range**, choose S01–S06, and click **Start replay**.
4. Events are submitted individually to the local `POST /api/ingest` endpoint. Pause/resume and 1×/2×/4× controls change playback; the timeline scrubber changes the visible event window without undoing submitted records. Reset deletes only that run's event, alert, and incident records and leaves a reset audit entry.
5. The results compare actual run alerts to declared expected rule IDs. Export JSON or Markdown reports, then inspect the same evidence in Detections and Incidents. Completed reports remain in the browser's saved replay history.

The current dataset has a fixed time seed and no random number generation. Replay evaluation reports fixture conformance. Precision/recall do not estimate real-world detector quality, and latency benchmarking is not implemented.

## Scenario index

| ID | Exercise | Expected rules |
|---|---|---|
| S01 | Suspicious process chain | `SEN-EXEC-001`, `SEN-PROC-002` |
| S02 | Credential access investigation | `SEN-AUTH-003` |
| S03 | Ransomware activity investigation | `SEN-FILE-004` |
| S04 | Persistence investigation | `SEN-PERSIST-005` |
| S05 | Suspicious network beaconing | `SEN-NET-006` |
| S06 | Multi-stage intrusion | `SEN-EXEC-001`, `SEN-PERSIST-005`, `SEN-NET-006` |

These exercise labels describe synthetic telemetry only. Authentication, file-change, and network fixtures reach configured count thresholds inside their event-time windows; the resulting alerts include the contributing event IDs. The remaining current rules match individual events. Fixture success verifies these declared cases only.

## GitHub Pages preview

The Pages workflow exports rules and scenarios from the Go packages. The page evaluates those definitions in the browser and saves generated events, alerts, notes, reports, and audit entries in this browser profile's `localStorage`. Reloading the page preserves those run results; clearing browser data or using another browser profile does not. **Export All Sim Data** downloads a JSON archive containing simulated events, alerts, incidents, audit records linked to the simulation, fixture definitions, and saved run reports. It excludes records without simulation provenance. **Import Sim Data** merges archive records by ID and leaves existing browser records in place; a paused run can be restored without starting playback. If browser storage cannot save the merged archive, the import rolls back in memory and leaves the stored bytes unchanged. If an archive is unreadable, the app leaves it available for recovery instead of deleting it. In local Go mode, the export follows all event pages before collecting the simulation records. This preview has no backend or authentication. Local Go mode is the server-side event-to-alert path. The topology diagram shows fictional fixture metadata and does not imply that a connection occurred.
