package detection

import (
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"strings"
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
}

var Rules = []Rule{
	{ID: "SEN-EXEC-001", Title: "Suspicious scripting execution", Description: "Script interpreter launched with encoded or download-related arguments.", Severity: "high", Confidence: 82, Technique: "T1059", Field: "command_line", Contains: "encodedcommand", FalsePositive: "Approved software deployment scripts.", Revision: 1, Enabled: true},
	{ID: "SEN-PROC-002", Title: "Execution from a temporary directory", Description: "A process image was observed under a temporary path.", Severity: "medium", Confidence: 70, Technique: "T1204", Field: "image", Contains: "\\temp\\", FalsePositive: "Installers and temporary unpacking workflows.", Revision: 1, Enabled: true},
	{ID: "SEN-AUTH-003", Title: "Repeated authentication failures", Description: "Multiple failed logon records were replayed for a single host.", Severity: "high", Confidence: 75, Technique: "T1110", Field: "type", Contains: "authentication_failure", FalsePositive: "User error or expired credentials.", Revision: 1, Enabled: true},
	{ID: "SEN-FILE-004", Title: "High-rate file change activity", Description: "A burst of synthetic file modifications was observed.", Severity: "critical", Confidence: 85, Technique: "T1486", Field: "type", Contains: "file_modified", FalsePositive: "Bulk updates and backup tools.", Revision: 1, Enabled: true},
	{ID: "SEN-PERSIST-005", Title: "Startup configuration change", Description: "A startup configuration change was observed.", Severity: "high", Confidence: 78, Technique: "T1547", Field: "type", Contains: "startup_change", FalsePositive: "Authorized software installation.", Revision: 1, Enabled: true},
	{ID: "SEN-NET-006", Title: "Repeated outbound connection pattern", Description: "Repeated synthetic connections share a destination host.", Severity: "medium", Confidence: 68, Technique: "T1071", Field: "type", Contains: "network_connection", FalsePositive: "Expected health checks or update traffic.", Revision: 1, Enabled: true},
}

func Match(e model.Event) []Rule {
	var out []Rule
	for _, r := range Rules {
		if !r.Enabled {
			continue
		}
		var v string
		switch r.Field {
		case "command_line":
			v = e.CommandLine
		case "image":
			v = e.Image
		case "type":
			v = e.Type
		}
		if strings.Contains(strings.ToLower(v), strings.ToLower(r.Contains)) {
			out = append(out, r)
		}
	}
	return out
}
