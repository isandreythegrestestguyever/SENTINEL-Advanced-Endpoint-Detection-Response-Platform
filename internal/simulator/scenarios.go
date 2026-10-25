package simulator

import (
	"fmt"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"time"
)

type Scenario struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Summary         string        `json:"summary"`
	ExpectedRuleIDs []string      `json:"expected_rule_ids"`
	Events          []model.Event `json:"events"`
}

func All() []Scenario {
	base := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	makeScenario := func(id, name, summary string, specs []struct{ typ, img, cmd, dst, tech string }, rules []string) Scenario {
		if rules == nil {
			rules = []string{}
		}
		s := Scenario{ID: id, Name: name, Summary: summary, ExpectedRuleIDs: rules}
		for i, x := range specs {
			s.Events = append(s.Events, model.Event{ID: fmt.Sprintf("%s-E%02d", id, i+1), SchemaVersion: "1.0", Time: base.Add(time.Duration(i) * time.Second), HostID: "lab-" + id, Hostname: "LAB-" + id, Source: "sentinel-replay", Category: "endpoint", Type: x.typ, ProcessID: 100 + i, ParentProcessID: 20, Image: x.img, CommandLine: x.cmd, Destination: x.dst, Technique: x.tech})
		}
		return s
	}
	return []Scenario{
		makeScenario("S01", "Suspicious Process Chain", "Synthetic script interpreter activity and unusual process ancestry.", []struct{ typ, img, cmd, dst, tech string }{{"process_start", `C:\\Windows\\System32\\wscript.exe`, `powershell.exe -EncodedCommand TEST`, "", "T1059"}, {"process_start", `C:\\Users\\Analyst\\AppData\\Local\\Temp\\stage.exe`, "stage.exe", "", "T1204"}}, []string{"SEN-EXEC-001", "SEN-PROC-002"}),
		makeScenario("S02", "Credential Access Investigation", "Synthetic authentication failure records; no credentials are collected.", []struct{ typ, img, cmd, dst, tech string }{{"authentication_failure", "", "", "", "T1110"}, {"authentication_failure", "", "", "", "T1110"}, {"authentication_failure", "", "", "", "T1110"}}, []string{"SEN-AUTH-003"}),
		makeScenario("S03", "Ransomware Activity Investigation", "Harmless synthetic file activity records; no files are touched.", []struct{ typ, img, cmd, dst, tech string }{{"file_modified", "", "", "", "T1486"}, {"file_modified", "", "", "", "T1486"}, {"file_modified", "", "", "", "T1486"}}, []string{"SEN-FILE-004"}),
		makeScenario("S04", "Persistence Investigation", "Synthetic startup change and follow-on process event.", []struct{ typ, img, cmd, dst, tech string }{{"startup_change", "", "", "", "T1547"}, {"process_start", `C:\\Program Files\\Updater\\updater.exe`, "updater.exe", "", "T1547"}}, []string{"SEN-PERSIST-005"}),
		makeScenario("S05", "Suspicious Network Beaconing", "Repeated synthetic connection metadata; no connections are made.", []struct{ typ, img, cmd, dst, tech string }{{"network_connection", "agent.exe", "", "203.0.113.40:443", "T1071"}, {"network_connection", "agent.exe", "", "203.0.113.40:443", "T1071"}, {"network_connection", "agent.exe", "", "203.0.113.40:443", "T1071"}}, []string{"SEN-NET-006"}),
		makeScenario("S06", "Multi-Stage Intrusion", "Combined synthetic execution, configuration, and repeated network evidence.", []struct{ typ, img, cmd, dst, tech string }{{"process_start", `C:\\Windows\\System32\\powershell.exe`, "powershell.exe -EncodedCommand TEST", "", "T1059"}, {"startup_change", "", "", "", "T1547"}, {"network_connection", "powershell.exe", "", "203.0.113.40:443", "T1071"}, {"network_connection", "powershell.exe", "", "203.0.113.40:443", "T1071"}, {"network_connection", "powershell.exe", "", "203.0.113.40:443", "T1071"}}, []string{"SEN-EXEC-001", "SEN-PERSIST-005", "SEN-NET-006"}),
		makeScenario("S07", "Benign System Administration", "Routine updater, successful sign-in, and a single expected service check; this replay should produce no alerts.", []struct{ typ, img, cmd, dst, tech string }{{"process_start", `C:\\Program Files\\Company\\Updater\\updater.exe`, "updater.exe --check", "", ""}, {"authentication_success", "", "", "", ""}, {"network_connection", "updater.exe", "", "updates.example.com:443", ""}}, nil),
	}
}
