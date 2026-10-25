package model

import "testing"

func TestRedactSensitiveRemovesCommonCommandLineCredentials(t *testing.T) {
	event := Event{
		CommandLine: `tool.exe --profile "approved deployment" --password="very secret value" --access_token abc123 --api-key:xyz`,
		Fields:      map[string]string{"client_secret": "field-secret", "safe_label": "workstation"},
	}
	RedactSensitive(&event)
	for _, secret := range []string{"very secret value", "abc123", "xyz", "field-secret"} {
		if contains(event.CommandLine, secret) || contains(event.Fields["client_secret"], secret) {
			t.Fatalf("sensitive value %q survived redaction: %#v", secret, event)
		}
	}
	if event.CommandLine != `tool.exe --profile "approved deployment" --password=[REDACTED] --access_token [REDACTED] --api-key:[REDACTED]` {
		t.Fatalf("unexpected redacted command line: %q", event.CommandLine)
	}
	if event.Fields["client_secret"] != redactedValue || event.Fields["safe_label"] != "workstation" {
		t.Fatalf("unexpected field redaction: %#v", event.Fields)
	}
}

func contains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
