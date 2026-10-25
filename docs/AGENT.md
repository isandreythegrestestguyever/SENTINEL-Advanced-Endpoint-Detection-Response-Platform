# Windows agent

The `agent/` Rust crate implements a Windows service that subscribes to the native Windows Event Log API (`EvtSubscribe`), converts selected events into Sentinel schema `1.0`, durably queues them in SQLite, then delivers them to `POST /api/ingest`. It performs read-only collection and has no response or remote command capability.

## Collected records

By default the service subscribes to these channels and event IDs:

| Channel | IDs | Normalized events |
|---|---:|---|
| `Security` | 4625, 4688 | Authentication failures; process starts |
| `Microsoft-Windows-Sysmon/Operational` | 1, 3, 11–14 | Process starts, connection metadata, file creation, registry changes |

Security process-creation event 4688 depends on the Windows audit policy being enabled. Command-line values depend on the corresponding policy. Sysmon is optional; its channel must exist and be readable by the service identity. Registry telemetry is labeled `startup_change` only when the target path matches a known startup location. Ordinary registry changes remain generic.

These are event-log records, not complete host visibility. The agent does not inspect packets, read file contents, collect credentials, or claim to detect every process, file, registry, or authentication action. Sysmon collection is metadata-only. Windows Security channel permissions vary by policy; grant only the required channel access to the service identity.

## Build and install

The portable spool and normalizer tests run on macOS/Linux:

```sh
cargo test --locked --manifest-path agent/Cargo.toml
```

Build the Windows service on Windows with the MSVC toolchain:

```powershell
cargo build --release --locked --manifest-path agent/Cargo.toml
```

The Windows CI job cross-target checks this crate. That checks compilation only; it does not substitute for running the service on a Windows 11 host.

Create the service using an account with access to the configured event channels. For example, after placing the binary at a protected path:

```powershell
sc.exe create SENTINEL binPath= "C:\Program Files\SENTINEL\sentinel-agent.exe" start= auto obj= "NT AUTHORITY\LocalService"
```

Configure the service environment before starting it. Required values are `SENTINEL_SERVER_URL`, `SENTINEL_AGENT_TOKEN`, and `COMPUTERNAME` (normally set by Windows). Optional values are `SENTINEL_HOST_ID`, `SENTINEL_SPOOL_PATH`, `SENTINEL_SPOOL_LIMIT_MB`, `SENTINEL_EVENT_CHANNELS`, `SENTINEL_LOG_PATH`, `SENTINEL_CLIENT_CERT`, and `SENTINEL_CLIENT_KEY`. The default JSONL log path shares the spool basename with a `.log` extension and rotates one file at 5 MiB. Keep the spool directory and private key readable only by the service identity and administrators. The agent currently reads configuration from the process environment; it does not yet provide DPAPI-backed secret storage or an enrollment flow.

`SENTINEL_EVENT_CHANNELS` uses `ChannelName:id,id;OtherChannel:id,id`. For example:

```text
Security:4625,4688;Microsoft-Windows-Sysmon/Operational:1,3,11,12,13,14
```

On first start, the subscription begins with future events. It persists Windows Event Log bookmarks after an event and its normalized record have been committed to the SQLite outbox. On restart, it resumes after that bookmark. Unsupported event records advance the bookmark after being parsed; malformed supported records stop collection rather than silently advancing it. Test retention and channel-reset behavior on the target Windows configuration before relying on recovery guarantees.

## Delivery and recovery

- Each event is bounded to 1 MiB; SQLite WAL and `synchronous=FULL` persist the outbox.
- The default payload queue limit is 256 MiB and can be changed with `SENTINEL_SPOOL_LIMIT_MB` (minimum 1 MiB).
- Upload uses HTTPS with the system trust store. The agent requires a client certificate and key for HTTPS and refuses non-loopback plain HTTP.
- A `409 Conflict` is treated as an already-accepted event; successful or duplicate acknowledgments remove the queued row.
- Network and server errors retry with bounded exponential backoff. Authentication and other client errors stop the service so a misconfigured agent does not silently spin.
- When the SQLite payload limit is reached, the event-log callback applies backpressure until the uploader creates space. Windows log retention can still overwrite records during a long outage; this is not a no-loss guarantee.

Configure the Go service with `SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY`, and `SENTINEL_CLIENT_CA` to require and verify client certificates (mTLS). Provision a distinct client certificate per endpoint and a restricted analyst token for ingestion. The current server authenticates the certificate chain and bearer role separately; it does not enroll endpoint identities, bind certificate subject to `host_id`, rotate certificates, or revoke individual endpoints.

## Normalization

The agent emits stable event IDs derived from host, channel, provider, record number, and event time. It maps process IDs, parent process IDs, image, command line, user, destination/port/protocol, SHA-256 values when supplied by the Windows provider, channel, provider, event ID, and record number when observable. Missing values remain missing. The schema is OCSF-inspired and is not OCSF-compliant.
