# Sentinel Range

The six built-in exercises are deterministic, fictional event fixtures. They create records only: they do not launch processes, connect to destinations, modify files or registry settings, collect credentials, or establish persistence.

## Run locally

1. Start `go run ./cmd/sentinel` and open `http://127.0.0.1:8080`.
2. Set the analyst token printed in the server output, or provide `SENTINEL_ADMIN_TOKEN` before startup.
3. Open **Sentinel Range**, choose S01–S06, and click **Start replay**.
4. Events are submitted individually to the local `POST /api/ingest` endpoint. Pause/resume and 1×/2×/4× controls change playback; reset deletes only that run's event, alert, and incident records and leaves a reset audit entry.
5. The results compare actual run alerts to declared expected rule IDs. Export the JSON report, then inspect the same evidence in Detections and Incidents.

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

These exercise labels describe synthetic telemetry only. Current rule matches are independent single-event conditions. For example, repeated authentication rows each match the same rule; they do not prove a temporal sequence detector exists.

## GitHub Pages preview

The Pages workflow exports rules and scenarios from the Go packages. The page evaluates those definitions locally in browser memory. This preview has no backend, authentication, or persistent state. Local Go mode is the end-to-end event-to-alert path.
