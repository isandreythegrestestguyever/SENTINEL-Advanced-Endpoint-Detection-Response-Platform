# Sentinel Range

The six built-in scenarios are fictional definitions. They create no processes, network connections, registry edits, file reads/writes, credentials, or persistence. Every event has a unique simulation run ID and is persisted through the same processing function as `/api/ingest`.

## Run a scenario

1. Start the server and open the dashboard.
2. Copy the temporary analyst token from server output, or set `SENTINEL_ADMIN_TOKEN` before starting.
3. Choose **Set analyst token** and paste it into this browser.
4. Choose S01 through S06 and click **Run replay**.
5. Review actual alerts and assertions; export the JSON report.

All scenarios currently run to completion immediately. Pause/resume, speed, scrubbing, topology, and rule revision comparison are not implemented. The fixtures cover synthetic script and temporary-path execution, authentication failures, file modification bursts, startup change, repeated connection metadata, and combined activity. Corresponding detections are single-event matches; the engine does not yet correlate temporal sequences.

## GitHub Pages preview

The Pages workflow exports scenarios and rules directly from the Go packages. The browser-only page then evaluates the exported conditions locally. This preview has no backend, authentication, or persistence and is clearly labeled **STATIC BROWSER DEMO**. Local Go mode remains the event-to-alert backend path.
