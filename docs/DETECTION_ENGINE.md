# Detection engine

The engine evaluates six enabled rules in `internal/detection/engine.go`. Each checks one field for a case-insensitive substring. A match produces an alert with rule ID, severity, confidence, ATT&CK technique ID, event reference, and matching condition. Rules are illustrative and need tuning against real environments.

| Field | Match type | Example |
|---|---|---|
| `command_line` | case-insensitive contains | `encodedcommand` |
| `image` | case-insensitive contains | `\\temp\\` |
| `type` | case-insensitive contains | `authentication_failure`, `file_modified`, `startup_change`, `network_connection` |

Rules have an ID, revision, title, description, severity, confidence, technique, false-positive note, enabled state, and condition. Editing and Sigma parsing are not implemented. There is no temporal sequence detection; repeated synthetic records independently match single-event rules. No general Sigma modifier, field mapping, or log-source support is claimed. See the [Sigma specification](https://sigmahq.io/sigma-specification/).

Scenario evaluation checks expected rule IDs against alerts produced for that run. It reports missed and unexpected IDs plus recall and precision when denominators are defined. A zero denominator returns `null`. These are fixture conformance measures, not real-world quality estimates. The seed label documents deterministic fixture data; no random generator is used.
