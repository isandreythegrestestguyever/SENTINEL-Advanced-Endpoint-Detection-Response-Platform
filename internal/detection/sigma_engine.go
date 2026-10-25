package detection

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	sigmaeval "github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

//go:embed sigma_rules/*.yml
var sigmaRuleFiles embed.FS

var sentinelSigmaID = regexp.MustCompile(`^SEN-SIGMA-[A-Z0-9-]{1,64}$`)

type compiledSigmaRule struct {
	rule      Rule
	evaluator *sigmaeval.RuleEvaluator
	category  string
}

// SigmaEngine evaluates the intentionally small activation subset supported by
// Sentinel. Compiled rules are immutable after construction.
type SigmaEngine struct {
	rules []compiledSigmaRule
}

// DefaultSigmaEngine loads the versioned Sigma rules shipped with Sentinel.
func DefaultSigmaEngine() (*SigmaEngine, error) {
	files, err := fs.Glob(sigmaRuleFiles, "sigma_rules/*.yml")
	if err != nil {
		return nil, fmt.Errorf("list bundled Sigma rules: %w", err)
	}
	sources := make([][]byte, 0, len(files))
	for _, name := range files {
		contents, err := sigmaRuleFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read bundled Sigma rule %s: %w", name, err)
		}
		sources = append(sources, contents)
	}
	return NewSigmaEngine(sources)
}

// NewSigmaEngine compiles rules that use one search, one scalar field, and the
// contains modifier. It rejects aggregation and unmapped log sources at load.
func NewSigmaEngine(sources [][]byte) (*SigmaEngine, error) {
	engine := &SigmaEngine{rules: make([]compiledSigmaRule, 0, len(sources))}
	seen := make(map[string]bool, len(sources))
	for index, source := range sources {
		if len(source) == 0 || len(source) > MaxSigmaRuleBytes {
			return nil, fmt.Errorf("Sigma rule %d must contain 1 to %d bytes", index+1, MaxSigmaRuleBytes)
		}
		parsed, err := sigma.ParseRule(source)
		if err != nil {
			return nil, fmt.Errorf("parse Sigma rule %d: %w", index+1, err)
		}
		compiled, err := compileSigmaRule(parsed)
		if err != nil {
			return nil, fmt.Errorf("validate Sigma rule %d: %w", index+1, err)
		}
		if seen[compiled.rule.ID] {
			return nil, fmt.Errorf("duplicate Sentinel Sigma rule ID %q", compiled.rule.ID)
		}
		seen[compiled.rule.ID] = true
		engine.rules = append(engine.rules, compiled)
	}
	sort.Slice(engine.rules, func(i, j int) bool { return engine.rules[i].rule.ID < engine.rules[j].rule.ID })
	return engine, nil
}

func compileSigmaRule(parsed sigma.Rule) (compiledSigmaRule, error) {
	if parsed.ID == "" || parsed.Title == "" {
		return compiledSigmaRule{}, errors.New("Sigma id and title are required")
	}
	if parsed.Logsource.Product != "windows" || parsed.Logsource.Service != "" {
		return compiledSigmaRule{}, errors.New("only Windows product rules without a service selector are supported")
	}
	category := parsed.Logsource.Category
	if category != "process_creation" {
		return compiledSigmaRule{}, fmt.Errorf("logsource category %q is not supported; use process_creation", category)
	}
	if len(parsed.Detection.Conditions) != 1 || parsed.Detection.Conditions[0].Aggregation != nil {
		return compiledSigmaRule{}, errors.New("only one non-aggregating condition is supported")
	}
	identifier, ok := parsed.Detection.Conditions[0].Search.(sigma.SearchIdentifier)
	if !ok || len(parsed.Detection.Searches) != 1 || identifier.Name == "" {
		return compiledSigmaRule{}, errors.New("detection must reference one named selection")
	}
	search, ok := parsed.Detection.Searches[identifier.Name]
	if !ok || len(search.EventMatchers) != 1 || len(search.EventMatchers[0]) != 1 {
		return compiledSigmaRule{}, errors.New("selection must contain exactly one field matcher")
	}
	matcher := search.EventMatchers[0][0]
	field, ok := sigmaFieldToSentinel[matcher.Field]
	if !ok {
		return compiledSigmaRule{}, fmt.Errorf("Sigma field %q is not mapped", matcher.Field)
	}
	if len(matcher.Modifiers) != 1 || matcher.Modifiers[0] != "contains" || len(matcher.Values) != 1 {
		return compiledSigmaRule{}, errors.New("field matcher must use one scalar value and the contains modifier")
	}
	contains, ok := matcher.Values[0].(string)
	if !ok || strings.TrimSpace(contains) == "" || len(contains) > 512 {
		return compiledSigmaRule{}, errors.New("contains value must be a non-empty string of at most 512 bytes")
	}
	sentinelID, ok := parsed.AdditionalFields["sentinel_id"].(string)
	if !ok || !sentinelSigmaID.MatchString(sentinelID) {
		return compiledSigmaRule{}, errors.New("sentinel_id must match SEN-SIGMA- followed by 1 to 64 uppercase letters, digits, or hyphens")
	}
	severity, ok := sigmaSeverity(parsed.Level)
	if !ok {
		return compiledSigmaRule{}, fmt.Errorf("Sigma level %q is not supported", parsed.Level)
	}
	technique := ""
	for _, tag := range parsed.Tags {
		if strings.HasPrefix(strings.ToLower(tag), "attack.t") {
			technique = strings.ToUpper(strings.TrimPrefix(strings.ToLower(tag), "attack."))
			break
		}
	}
	description := parsed.Description
	if description == "" {
		description = parsed.Title
	}
	return compiledSigmaRule{
		rule:      Rule{ID: sentinelID, SigmaID: parsed.ID, Kind: "sigma", Title: parsed.Title, Description: description, Severity: severity, Confidence: 0, Technique: technique, Field: field, Contains: contains, FalsePositive: sigmaFalsePositives(parsed), Revision: 1, Enabled: true},
		evaluator: sigmaeval.ForRule(parsed, sigmaeval.WithConfig(sigma.Config{FieldMappings: sigmaEventFieldMappings()})),
		category:  category,
	}, nil
}

func sigmaSeverity(level string) (string, bool) {
	switch strings.ToLower(level) {
	case "critical":
		return "critical", true
	case "high":
		return "high", true
	case "medium":
		return "medium", true
	case "low":
		return "low", true
	case "informational":
		return "low", true
	default:
		return "", false
	}
}

func sigmaFalsePositives(rule sigma.Rule) string {
	value, ok := rule.AdditionalFields["falsepositives"]
	if !ok {
		return "Review expected administration and deployment activity."
	}
	switch values := value.(type) {
	case []interface{}:
		parts := make([]string, 0, len(values))
		for _, item := range values {
			if text, ok := item.(string); ok {
				parts = append(parts, text)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	case string:
		return values
	}
	return "Review expected administration and deployment activity."
}

var sigmaFieldToSentinel = map[string]string{
	"Image": "image", "CommandLine": "command_line", "ProcessId": "process_id",
	"ParentProcessId": "parent_process_id", "User": "user", "Computer": "hostname",
	"Hostname": "hostname", "HostId": "host_id", "EventType": "type",
	"EventCategory": "category", "Source": "source", "DestinationIp": "destination",
	"Destination": "destination", "Technique": "technique",
}

// Evaluate applies only logsource-compatible compiled rules and produces
// one-event findings. Sigma aggregation remains rejected at compile time.
func (engine *SigmaEngine) Evaluate(event model.Event) ([]Finding, error) {
	if engine == nil {
		return nil, nil
	}
	if event.Category != "process" || event.Type != "process_start" {
		return nil, nil
	}
	findings := make([]Finding, 0)
	for _, compiled := range engine.rules {
		if !compiled.rule.Enabled || (compiled.category == "process_creation" && (event.Category != "process" || event.Type != "process_start")) {
			continue
		}
		result, err := compiled.evaluator.Matches(context.Background(), sigmaEvent(event))
		if err != nil {
			return nil, fmt.Errorf("evaluate Sigma rule %s: %w", compiled.rule.ID, err)
		}
		if result.Match {
			findings = append(findings, Finding{Rule: compiled.rule, EventIDs: []string{event.ID}, Evidence: fmt.Sprintf("Sigma %s matched %s containing %q", compiled.rule.SigmaID, compiled.rule.Field, compiled.rule.Contains)})
		}
	}
	return findings, nil
}

func (engine *SigmaEngine) Rules() []Rule {
	if engine == nil {
		return []Rule{}
	}
	rules := make([]Rule, 0, len(engine.rules))
	for _, compiled := range engine.rules {
		rules = append(rules, compiled.rule)
	}
	return rules
}

func AllRules(engine *SigmaEngine) []Rule {
	rules := append([]Rule(nil), Rules...)
	rules = append(rules, engine.Rules()...)
	return rules
}
