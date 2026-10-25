# Detection engine

The Go engine currently evaluates six enabled rules in `internal/detection/engine.go`. Each rule checks one field for a case-insensitive substring; three rules also require a bounded count correlation. A finding produces an alert with rule ID/revision metadata, severity, confidence metadata, ATT&CK identifier, all supporting event references, and a textual explanation of the condition.

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

There is no general-purpose correlation language, arbitrary rule authoring, Sigma field mapping for ingestion, or broad log-source compatibility. Correlation behavior in the ingest detector is limited to the three hard-coded threshold rules above. No universal Sigma compatibility claim is made; see the [Sigma specification](https://sigmahq.io/sigma-specification/).

## Sigma test workspace

The local Go service exposes an authenticated, non-persisting `POST /api/rules/test` operation used by the rulebook workspace. It parses one YAML rule with [`sigma-go` v0.6.5](https://github.com/bradleyjkemp/sigma-go) and evaluates it against one normalized event. The event mapper exposes `Image`, `CommandLine`, `ProcessId`, `ParentProcessId`, `User`, `Computer`, `Hostname`, `HostId`, `EventType`, `EventCategory`, `Source`, `DestinationIp`, `Destination`, and `Technique`, plus the event's custom `fields` map. Non-Windows `logsource.product` values are rejected. The logsource category/service do not filter the event because Sentinel's current source/category values do not implement the Sigma taxonomy.

This is a rule test path only: submitted YAML is not saved, added to `/api/rules`, or applied to subsequent ingestion. Single-event conditions are the supported operational scope; aggregation and temporal Sigma correlation are not configured. The library describes v0.6.5 as a draft-spec implementation, so rule acceptance is not a claim of general Sigma 2.1 compliance. The published Pages build does not provide the Go parser and labels the workspace unavailable there.
