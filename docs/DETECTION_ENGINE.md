# Detection engine

The Go engine currently evaluates six enabled rules independently for each event in `internal/detection/engine.go`. Each rule checks one field for a case-insensitive substring. A match produces an alert with rule ID/revision metadata, severity, confidence metadata, ATT&CK identifier, event reference, and a textual explanation of the condition.

| Field | Match type | Example condition |
|---|---|---|
| `command_line` | case-insensitive contains | `encodedcommand` |
| `image` | case-insensitive contains | `\\temp\\` |
| `type` | case-insensitive contains | `authentication_failure`, `file_modified`, `startup_change`, `network_connection` |

The current six conditions are engineering fixtures, not validated behavioral detections. The confidence value is rule metadata and is not a probability. Scenario evaluation compares unique expected rule IDs to the actual alerts produced by that run; it reports missed/unexpected IDs and precision/recall when denominators are defined. A zero denominator returns `null`. These measurements represent fixture conformance only.

There is no temporal correlation, Sigma parser, arbitrary rule authoring, field mapping, or broad log-source compatibility. Repeated events match independently. No universal Sigma compatibility claim is made; see the [Sigma specification](https://sigmahq.io/sigma-specification/).
