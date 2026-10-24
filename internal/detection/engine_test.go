package detection

import (
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
	"testing"
)

func TestEveryScenarioExpectedRulesMatch(t *testing.T) {
	for _, scenario := range simulator.All() {
		got := map[string]bool{}
		for _, event := range scenario.Events {
			for _, rule := range Match(event) {
				got[rule.ID] = true
			}
		}
		for _, want := range scenario.ExpectedRuleIDs {
			if !got[want] {
				t.Errorf("%s did not match expected %s", scenario.ID, want)
			}
		}
	}
}
