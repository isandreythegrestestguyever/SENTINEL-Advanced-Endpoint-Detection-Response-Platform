# Detection engine

The Go engine evaluates six enabled native rules in `internal/detection/engine.go` plus one bundled Sigma rule in `internal/detection/sigma_rules/`. Each native rule checks one field for a case-insensitive substring; three rules also require a bounded count correlation. The Sigma rule is parsed and compiled at service startup, logsource-filtered, and evaluated during the same authenticated ingest flow. Findings produce alerts with rule ID/revision metadata, severity, ATT&CK identifier, evidence references, and a condition explanation. Sigma confidence remains unscored rather than represented by an invented probability.

| Field | Match type | Example condition |
|---|---|---|
| `command_line` | case-insensitive contains | `encodedcommand` |
| `image` | case-insensitive contains | `\\temp\\` |
| `type` | case-insensitive contains | `authentication_failure`, `file_`, `startup_change`, `network_connection` |

## Correlation rules

| Rule | Threshold | Window | Grouping |
|---|---:|---:|---|
| `SEN-AUTH-003` | 3 authentication failures | 5 minutes | Host and simulation run |
| `SEN-FILE-004` | 3 file creation or modification events | 10 seconds | Host and simulation run |
| `SEN-NET-006` | 3 network connection events | 5 minutes | Host, simulation run, and destination |

Correlation uses the event timestamp and includes only same-host, same-run prior events in the configured window. The finding links all events that meet the threshold. The current rule set emits when a sequence reaches its threshold; duplicate suppression across concurrent event submissions is not yet implemented, so concurrent deliveries at the threshold can produce duplicate alerts.

These conditions are engineering fixtures, not validated behavioral detections. The confidence value is rule metadata and is not a probability. Scenario evaluation compares unique expected rule IDs to the actual alerts produced by that run; it reports missed/unexpected IDs and precision/recall when denominators are defined. A zero denominator returns `null`. These measurements represent fixture conformance only.

There is no general-purpose correlation language, arbitrary rule authoring, or broad log-source compatibility. Correlation behavior in the ingest detector is limited to the three hard-coded threshold rules above. No universal Sigma compatibility claim is made; see the [Sigma specification](https://sigmahq.io/sigma-specification/).

## Active Sigma subset

Bundled rules require a Sigma UUID and unique `sentinel_id`, Windows `process_creation` logsource, one selection, one mapped field, one scalar string, and the `contains` modifier. Sentinel maps that logsource only to normalized `category=process` and `type=process_start`. Levels critical/high/medium/low/informational are accepted; informational maps to low. Matching is one event at a time. sigma-go v0.6.5 documents itself as a draft-spec implementation.

| Capability | Active bundled rules | Boundary |
|---|---|---|
| Product/category | `windows` / `process_creation` | Category is enforced against normalized process-start events; service selectors and other products/categories are rejected. |
| Conditions | One named selection, one event matcher | Multiple selections, boolean condition expressions, and aggregation are rejected. |
| Fields | `Image`, `CommandLine`, `ProcessId`, `ParentProcessId`, `User`, `Computer`, `Hostname`, `HostId`, `EventType`, `EventCategory`, `Source`, `DestinationIp`, `Destination`, `Technique` | Values map to the normalized event envelope or its custom `fields` map. Unmapped fields are rejected. |
| Modifiers and values | One `contains` modifier and one non-empty scalar string (maximum 512 bytes) | Other modifiers, multiple values, and lists are rejected. |
| Levels and metadata | Critical, high, medium, low, informational; ATT&CK tags; false-positive text | Informational maps to low. Confidence is left unscored. |
| Evaluation | One normalized event per rule | The active Sigma subset does not aggregate events or use time windows. Existing native correlation rules remain separate. |

The current bundled rule is `SEN-SIGMA-PUBLIC-001`, matching a process image under `\\users\\public\\`. Bundled rules are compiled when the service starts; an invalid or duplicate rule ID prevents startup. Rule revision is recorded on generated alerts.

## Sigma test workspace

The local Go service exposes an authenticated, non-persisting `POST /api/rules/test` operation used by the rulebook workspace. It parses one YAML rule with [`sigma-go` v0.6.5](https://github.com/bradleyjkemp/sigma-go) and evaluates it against one normalized event. This test path exposes the same field mappings but does not enforce the narrower active-rule shape, and it does not filter by logsource category or service.

Submitted YAML in the test workspace is not saved or added to `/api/rules`; only bundled and startup-validated rules run during ingestion. Rule acceptance is not a claim of general Sigma 2.1 compliance. The published Pages build exports rule definitions for its deterministic browser-side simulation but does not provide the Go parser, authenticated ingest, or live service.
