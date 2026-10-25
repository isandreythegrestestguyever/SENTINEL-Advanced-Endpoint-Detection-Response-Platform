package detection

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
)

func TestEveryScenarioExpectedRulesMatch(t *testing.T) {
	for _, scenario := range simulator.All() {
		t.Run(scenario.ID, func(t *testing.T) {
			got := map[string]bool{}
			var previous []model.Event
			for _, event := range scenario.Events {
				for _, finding := range Evaluate(event, previous) {
					got[finding.Rule.ID] = true
				}
				previous = append(previous, event)
			}
			for _, want := range scenario.ExpectedRuleIDs {
				if !got[want] {
					t.Errorf("%s did not match expected %s", scenario.ID, want)
				}
			}
			for actual := range got {
				if !slices.Contains(scenario.ExpectedRuleIDs, actual) {
					t.Errorf("%s produced unexpected rule %s", scenario.ID, actual)
				}
			}
		})
	}
}

func TestSigmaSingleEventTestUsesNormalizedFieldMappings(t *testing.T) {
	rule := `title: Encoded PowerShell
id: 7ad5e09c-34f5-4e22-8c22-355a4fb27810
description: Detect an encoded command line
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: encodedcommand
  condition: selection
level: high
`
	event := model.Event{ID: "sigma-1", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "sigma-host", Hostname: "SIGMA-HOST", Source: "test", Type: "process_start", CommandLine: "powershell.exe -EncodedCommand SAMPLE"}
	result, err := TestSigmaRule(rule, event)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched || result.RuleID != "7ad5e09c-34f5-4e22-8c22-355a4fb27810" || !result.SearchResults["selection"] {
		t.Fatalf("Sigma rule did not match normalized command_line: %#v", result)
	}
	event.CommandLine = "powershell.exe -NoProfile"
	result, err = TestSigmaRule(rule, event)
	if err != nil || result.Matched {
		t.Fatalf("Sigma rule unexpectedly matched unrelated event: result=%#v err=%v", result, err)
	}
}

func TestSigmaTestRejectsUnsupportedProductAndOversizedRule(t *testing.T) {
	event := model.Event{ID: "sigma-2", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "sigma-host", Hostname: "SIGMA-HOST", Source: "test", Type: "process_start"}
	rule := `title: Other Platform
detection:
  selection:
    CommandLine: test
  condition: selection
logsource:
  product: linux
`
	if _, err := TestSigmaRule(rule, event); err == nil {
		t.Fatal("unsupported logsource product was accepted")
	}
	if _, err := TestSigmaRule(string(make([]byte, MaxSigmaRuleBytes+1)), event); err == nil {
		t.Fatal("oversized Sigma input was accepted")
	}
}

func TestAuthenticationCorrelationThresholdAndProvenance(t *testing.T) {
	base := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	var previous []model.Event
	for i := 0; i < 2; i++ {
		event := authEvent(i, "host-a", "run-a", base.Add(time.Duration(i)*time.Minute))
		if findings := Evaluate(event, previous); len(findings) != 0 {
			t.Fatalf("event %d triggered before threshold: %#v", i+1, findings)
		}
		previous = append(previous, event)
	}
	third := authEvent(2, "host-a", "run-a", base.Add(2*time.Minute))
	findings := Evaluate(third, previous)
	if len(findings) != 1 || findings[0].Rule.ID != "SEN-AUTH-003" {
		t.Fatalf("third event findings = %#v", findings)
	}
	if len(findings[0].EventIDs) != 3 || findings[0].Evidence == "" {
		t.Fatalf("correlation evidence missing event references: %#v", findings[0])
	}
	previous = append(previous, third)
	fourth := authEvent(3, "host-a", "run-a", base.Add(3*time.Minute))
	if findings := Evaluate(fourth, previous); len(findings) != 0 {
		t.Fatalf("continued sequence generated a duplicate threshold alert: %#v", findings)
	}

	otherHost := authEvent(4, "host-b", "run-a", base.Add(4*time.Minute))
	if findings := Evaluate(otherHost, previous); len(findings) != 0 {
		t.Fatalf("events from another host were correlated: %#v", findings)
	}
	otherRun := authEvent(5, "host-a", "run-b", base.Add(4*time.Minute))
	if findings := Evaluate(otherRun, previous); len(findings) != 0 {
		t.Fatalf("events from another simulation run were correlated: %#v", findings)
	}
}

func TestNetworkCorrelationSeparatesDestinations(t *testing.T) {
	base := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	previous := []model.Event{
		networkEvent("n1", "198.51.100.10:443", base),
		networkEvent("n2", "198.51.100.10:443", base.Add(time.Second)),
	}
	if findings := Evaluate(networkEvent("n3", "203.0.113.20:443", base.Add(2*time.Second)), previous); len(findings) != 0 {
		t.Fatalf("mixed destinations triggered a beacon correlation: %#v", findings)
	}
	findings := Evaluate(networkEvent("n4", "198.51.100.10:443", base.Add(2*time.Second)), previous)
	if len(findings) != 1 || findings[0].Rule.ID != "SEN-NET-006" || len(findings[0].EventIDs) != 3 {
		t.Fatalf("same-destination sequence findings = %#v", findings)
	}
}

func TestFileCreationAndModificationShareSafeRateRule(t *testing.T) {
	base := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	previous := []model.Event{
		{ID: "f1", HostID: "file-host", SimulationRunID: "file-run", Time: base, Type: "file_created"},
		{ID: "f2", HostID: "file-host", SimulationRunID: "file-run", Time: base.Add(time.Second), Type: "file_modified"},
	}
	findings := Evaluate(model.Event{ID: "f3", HostID: "file-host", SimulationRunID: "file-run", Time: base.Add(2 * time.Second), Type: "file_created"}, previous)
	if len(findings) != 1 || findings[0].Rule.ID != "SEN-FILE-004" || len(findings[0].EventIDs) != 3 {
		t.Fatalf("mixed file create/modify sequence findings = %#v", findings)
	}
}

func authEvent(index int, host, run string, timestamp time.Time) model.Event {
	return model.Event{ID: fmt.Sprintf("auth-%d", index), HostID: host, SimulationRunID: run, Time: timestamp, Type: "authentication_failure"}
}

func networkEvent(id, destination string, timestamp time.Time) model.Event {
	return model.Event{ID: id, HostID: "network-host", SimulationRunID: "network-run", Time: timestamp, Type: "network_connection", Destination: destination}
}
