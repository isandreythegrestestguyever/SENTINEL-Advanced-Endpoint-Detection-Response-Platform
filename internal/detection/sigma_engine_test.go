package detection

import (
	"strings"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

func TestBundledSigmaRuleRunsAgainstNormalizedEvents(t *testing.T) {
	engine, err := DefaultSigmaEngine()
	if err != nil {
		t.Fatal(err)
	}
	rules := engine.Rules()
	if len(rules) != 1 || rules[0].ID != "SEN-SIGMA-PUBLIC-001" || rules[0].SigmaID == "" || rules[0].Kind != "sigma" || rules[0].Confidence != 0 {
		t.Fatalf("unexpected bundled Sigma catalog: %#v", rules)
	}
	event := model.Event{
		ID: "sigma-public-1", SchemaVersion: "1.0", Time: time.Now().UTC(),
		HostID: "host-1", Hostname: "HOST-1", Source: "windows-eventlog",
		Category: "process", Type: "process_start", Image: `C:\Users\Public\Tools\update.exe`,
	}
	findings, err := engine.Evaluate(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Rule.ID != rules[0].ID || findings[0].Rule.Severity != "medium" || len(findings[0].EventIDs) != 1 || findings[0].Evidence == "" {
		t.Fatalf("public-directory execution did not produce an evidence-linked Sigma finding: %#v", findings)
	}
	if !strings.Contains(findings[0].Evidence, rules[0].SigmaID) {
		t.Fatalf("Sigma UUID missing from finding evidence: %#v", findings[0])
	}
	event.Category, event.Type = "network", "network_connection"
	if findings, err := engine.Evaluate(event); err != nil || len(findings) != 0 {
		t.Fatalf("process_creation rule matched an unrelated log source: findings=%#v err=%v", findings, err)
	}
}

func TestSigmaEngineRejectsUnsupportedRuleCapabilities(t *testing.T) {
	base := `title: Limited rule
id: 7b0cbd19-cc70-4a9b-b6d1-87c51756a422
sentinel_id: SEN-SIGMA-TEST-001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: '\\users\\public\\'
  condition: selection
level: medium
`
	for name, rule := range map[string]string{
		"unsupported product":  strings.Replace(base, "product: windows", "product: linux", 1),
		"unsupported category": strings.Replace(base, "category: process_creation", "category: driver_load", 1),
		"unsupported modifier": strings.Replace(base, "Image|contains", "Image|endswith", 1),
		"unsupported field":    strings.Replace(base, "Image|contains", "TargetFilename|contains", 1),
		"aggregation":          strings.Replace(base, "condition: selection", "condition: selection | count() > 1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigmaEngine([][]byte{[]byte(rule)}); err == nil {
				t.Fatal("unsupported Sigma capability was accepted")
			}
		})
	}
}
