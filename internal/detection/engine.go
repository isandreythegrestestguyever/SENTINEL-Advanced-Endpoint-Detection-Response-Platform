package detection

import (
	"fmt"
	"strings"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

type Rule struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	Confidence    int    `json:"confidence"`
	Technique     string `json:"technique"`
	Field         string `json:"field"`
	Contains      string `json:"contains"`
	FalsePositive string `json:"false_positive"`
	Revision      int    `json:"revision"`
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold,omitempty"`
	WindowSeconds int    `json:"window_seconds,omitempty"`
	GroupBy       string `json:"group_by,omitempty"`
}

type Finding struct {
	Rule     Rule
	EventIDs []string
	Evidence string
}

var Rules = []Rule{
	{ID: "SEN-EXEC-001", Title: "Suspicious scripting execution", Description: "Script interpreter launched with encoded or download-related arguments.", Severity: "high", Confidence: 82, Technique: "T1059", Field: "command_line", Contains: "encodedcommand", FalsePositive: "Approved software deployment scripts.", Revision: 1, Enabled: true},
	{ID: "SEN-PROC-002", Title: "Execution from a temporary directory", Description: "A process image was observed under a temporary path.", Severity: "medium", Confidence: 70, Technique: "T1204", Field: "image", Contains: "\\temp\\", FalsePositive: "Installers and temporary unpacking workflows.", Revision: 1, Enabled: true},
	{ID: "SEN-AUTH-003", Title: "Repeated authentication failures", Description: "Three failed logon records for one host within five minutes.", Severity: "high", Confidence: 75, Technique: "T1110", Field: "type", Contains: "authentication_failure", FalsePositive: "User error or expired credentials.", Revision: 1, Enabled: true, Threshold: 3, WindowSeconds: 300, GroupBy: "host"},
	{ID: "SEN-FILE-004", Title: "High-rate file change activity", Description: "Three file modification records for one host within ten seconds.", Severity: "critical", Confidence: 85, Technique: "T1486", Field: "type", Contains: "file_modified", FalsePositive: "Bulk updates and backup tools.", Revision: 1, Enabled: true, Threshold: 3, WindowSeconds: 10, GroupBy: "host"},
	{ID: "SEN-PERSIST-005", Title: "Startup configuration change", Description: "A startup configuration change was observed.", Severity: "high", Confidence: 78, Technique: "T1547", Field: "type", Contains: "startup_change", FalsePositive: "Authorized software installation.", Revision: 1, Enabled: true},
	{ID: "SEN-NET-006", Title: "Repeated outbound connection pattern", Description: "Three connections to one destination from one host within five minutes.", Severity: "medium", Confidence: 68, Technique: "T1071", Field: "type", Contains: "network_connection", FalsePositive: "Expected health checks or update traffic.", Revision: 1, Enabled: true, Threshold: 3, WindowSeconds: 300, GroupBy: "host,destination"},
}

func Match(e model.Event) []Rule {
	var out []Rule
	for _, rule := range Rules {
		if rule.Enabled && matchesField(rule, e) {
			out = append(out, rule)
		}
	}
	return out
}

// Evaluate matches single-event rules and bounded correlations against earlier events.
// Callers supply only events for the same host and simulation namespace.
func Evaluate(event model.Event, previous []model.Event) []Finding {
	var findings []Finding
	for _, rule := range Rules {
		if !rule.Enabled || !matchesField(rule, event) {
			continue
		}
		if rule.Threshold == 0 {
			findings = append(findings, Finding{Rule: rule, EventIDs: []string{event.ID}, Evidence: fmt.Sprintf("%s matched %s containing %q", rule.Field, rule.ID, rule.Contains)})
			continue
		}
		windowStart := event.Time.Add(-time.Duration(rule.WindowSeconds) * time.Second)
		priorMatches := make([]model.Event, 0, rule.Threshold)
		for _, candidate := range previous {
			if candidate.HostID != event.HostID || candidate.SimulationRunID != event.SimulationRunID || candidate.Time.Before(windowStart) || candidate.Time.After(event.Time) || !matchesField(rule, candidate) || !sameCorrelationKey(rule, event, candidate) {
				continue
			}
			priorMatches = append(priorMatches, candidate)
		}
		if len(priorMatches)+1 != rule.Threshold {
			continue
		}
		eventIDs := make([]string, 0, len(priorMatches)+1)
		for _, candidate := range priorMatches {
			eventIDs = append(eventIDs, candidate.ID)
		}
		eventIDs = append(eventIDs, event.ID)
		evidence := fmt.Sprintf("%d matching events within %s for %s containing %q", len(eventIDs), time.Duration(rule.WindowSeconds)*time.Second, rule.Field, rule.Contains)
		findings = append(findings, Finding{Rule: rule, EventIDs: eventIDs, Evidence: evidence})
	}
	return findings
}

func matchesField(rule Rule, event model.Event) bool {
	var value string
	switch rule.Field {
	case "command_line":
		value = event.CommandLine
	case "image":
		value = event.Image
	case "type":
		value = event.Type
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(rule.Contains))
}

func sameCorrelationKey(rule Rule, current, candidate model.Event) bool {
	if strings.Contains(rule.GroupBy, "destination") {
		return current.Destination != "" && current.Destination == candidate.Destination
	}
	return true
}
