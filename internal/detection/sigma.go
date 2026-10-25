package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	sigma "github.com/bradleyjkemp/sigma-go"
	sigmaeval "github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

const MaxSigmaRuleBytes = 64 * 1024

type SigmaTestResult struct {
	RuleID          string          `json:"rule_id"`
	Title           string          `json:"title"`
	Level           string          `json:"level"`
	Matched         bool            `json:"matched"`
	SearchResults   map[string]bool `json:"search_results"`
	ConditionResult []bool          `json:"condition_results"`
	Limitations     []string        `json:"limitations"`
}

// TestSigmaRule parses and evaluates one rule against one already-normalized event.
// This is an analyst test path; it does not persist the rule or alter detection state.
func TestSigmaRule(ruleYAML string, event model.Event) (SigmaTestResult, error) {
	if len(ruleYAML) == 0 || len(ruleYAML) > MaxSigmaRuleBytes {
		return SigmaTestResult{}, fmt.Errorf("Sigma YAML must contain 1 to %d bytes", MaxSigmaRuleBytes)
	}
	if event.ID == "" || event.HostID == "" || event.Hostname == "" || event.Type == "" || event.Source == "" || event.Time.IsZero() {
		return SigmaTestResult{}, errors.New("event requires id, host_id, hostname, source, type, and time")
	}
	rule, err := sigma.ParseRule([]byte(ruleYAML))
	if err != nil {
		return SigmaTestResult{}, fmt.Errorf("parse Sigma rule: %w", err)
	}
	if rule.Title == "" {
		return SigmaTestResult{}, errors.New("Sigma rule title is required")
	}
	if rule.ID == "" {
		digest := sha256.Sum256([]byte(ruleYAML))
		rule.ID = "SEN-SIGMA-" + hex.EncodeToString(digest[:8])
	}
	if rule.Logsource.Product != "" && rule.Logsource.Product != "windows" {
		return SigmaTestResult{}, fmt.Errorf("Sigma logsource product %q is not supported by this Windows-first event mapper", rule.Logsource.Product)
	}
	configured := sigmaeval.ForRule(rule, sigmaeval.WithConfig(sigma.Config{FieldMappings: sigmaEventFieldMappings()}))
	result, err := configured.Matches(context.Background(), sigmaEvent(event))
	if err != nil {
		return SigmaTestResult{}, fmt.Errorf("evaluate Sigma rule: %w", err)
	}
	conditions := append([]bool{}, result.ConditionResults...)
	return SigmaTestResult{
		RuleID: rule.ID, Title: rule.Title, Level: rule.Level,
		Matched: result.Match, SearchResults: result.SearchResults,
		ConditionResult: conditions,
		Limitations: []string{
			"This test uses sigma-go v0.6.5, which documents itself as an implementation of a draft Sigma specification.",
			"Only one normalized event is evaluated; aggregation, time windows, and multi-event Sigma correlation are not evaluated here.",
			"The rule is not saved or added to the ingest detector. Logsource category and service are not used as event filters.",
		},
	}, nil
}

func sigmaEventFieldMappings() map[string]sigma.FieldMapping {
	return map[string]sigma.FieldMapping{
		"Image":           {TargetNames: []string{"image"}},
		"CommandLine":     {TargetNames: []string{"command_line"}},
		"ProcessId":       {TargetNames: []string{"process_id"}},
		"ParentProcessId": {TargetNames: []string{"parent_process_id"}},
		"User":            {TargetNames: []string{"user"}},
		"Computer":        {TargetNames: []string{"hostname"}},
		"Hostname":        {TargetNames: []string{"hostname"}},
		"HostId":          {TargetNames: []string{"host_id"}},
		"EventType":       {TargetNames: []string{"type"}},
		"EventCategory":   {TargetNames: []string{"category"}},
		"Source":          {TargetNames: []string{"source"}},
		"DestinationIp":   {TargetNames: []string{"destination"}},
		"Destination":     {TargetNames: []string{"destination"}},
		"Technique":       {TargetNames: []string{"technique"}},
	}
}

func sigmaEvent(event model.Event) map[string]interface{} {
	data := map[string]interface{}{}
	for key, value := range event.Fields {
		data[key] = value
	}
	encoded, _ := json.Marshal(event)
	_ = json.Unmarshal(encoded, &data)
	// Sigma's established Windows field names are mapped to the normalized
	// Sentinel envelope; custom normalized fields remain directly queryable.
	return data
}
