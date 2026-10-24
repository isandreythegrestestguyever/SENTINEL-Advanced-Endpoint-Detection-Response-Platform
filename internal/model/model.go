package model

import "time"

// Event is Sentinel's versioned, normalized telemetry envelope. It is OCSF-inspired, not OCSF compliant.
type Event struct {
	ID              string            `json:"id"`
	SchemaVersion   string            `json:"schema_version"`
	Time            time.Time         `json:"time"`
	IngestedAt      time.Time         `json:"ingested_at,omitempty"`
	HostID          string            `json:"host_id"`
	Hostname        string            `json:"hostname"`
	Source          string            `json:"source"`
	Category        string            `json:"category"`
	Type            string            `json:"type"`
	ProcessID       int               `json:"process_id,omitempty"`
	ParentProcessID int               `json:"parent_process_id,omitempty"`
	Image           string            `json:"image,omitempty"`
	CommandLine     string            `json:"command_line,omitempty"`
	User            string            `json:"user,omitempty"`
	Destination     string            `json:"destination,omitempty"`
	Technique       string            `json:"technique,omitempty"`
	SimulationRunID string            `json:"simulation_run_id,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"`
}

type Alert struct {
	ID              string    `json:"id"`
	RuleID          string    `json:"rule_id"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	Confidence      int       `json:"confidence"`
	Technique       string    `json:"technique,omitempty"`
	HostID          string    `json:"host_id"`
	Hostname        string    `json:"hostname"`
	EventIDs        []string  `json:"event_ids"`
	Evidence        string    `json:"evidence"`
	CreatedAt       time.Time `json:"created_at"`
	SimulationRunID string    `json:"simulation_run_id,omitempty"`
	Status          string    `json:"status"`
	AnalystNotes    string    `json:"analyst_notes,omitempty"`
	Assignee        string    `json:"assignee,omitempty"`
}

type Incident struct {
	ID              string    `json:"id"`
	HostID          string    `json:"host_id"`
	Hostname        string    `json:"hostname"`
	Severity        string    `json:"severity"`
	Status          string    `json:"status"`
	AlertIDs        []string  `json:"alert_ids"`
	SimulationRunID string    `json:"simulation_run_id,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	AnalystNotes    string    `json:"analyst_notes,omitempty"`
}

type Endpoint struct {
	HostID    string    `json:"host_id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	Simulated bool      `json:"simulated"`
}
