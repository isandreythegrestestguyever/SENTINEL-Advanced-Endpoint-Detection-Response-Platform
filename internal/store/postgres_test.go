package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/detection"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

func TestPostgresRepositoryIntegration(t *testing.T) {
	connectionString := os.Getenv("SENTINEL_TEST_DATABASE_URL")
	if connectionString == "" {
		t.Skip("set SENTINEL_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := OpenPostgres(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	runID := "test-run-" + suffix
	eventID := "test-event-" + suffix
	now := time.Now().UTC()
	event := model.Event{ID: eventID, SchemaVersion: "1.0", Time: now, IngestedAt: now, HostID: "test-host", Hostname: "TEST-HOST", Source: "integration-test", Type: "process_start", SimulationRunID: runID}
	alert := model.Alert{ID: "test-alert-" + suffix, RuleID: "TEST-RULE", Title: "Integration test alert", Severity: "high", Confidence: 80, HostID: event.HostID, Hostname: event.Hostname, EventIDs: []string{eventID}, CreatedAt: now, SimulationRunID: runID, Status: "open"}
	if err := db.AddEvent(event, []model.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddEvent(event, nil); err != ErrDuplicateEvent {
		t.Fatalf("duplicate event error = %v, want %v", err, ErrDuplicateEvent)
	}

	data := db.Snapshot()
	if !containsEvent(data.Events, eventID) || !containsAlert(data.Alerts, alert.ID) || len(data.Incidents) == 0 {
		t.Fatalf("PostgreSQL snapshot missing inserted records: events=%d alerts=%d incidents=%d", len(data.Events), len(data.Alerts), len(data.Incidents))
	}
	status, note, assignee := "acknowledged", "triaged", "test-analyst"
	updatedAlert, found, err := db.UpdateAlert(alert.ID, &status, &note, &assignee)
	if err != nil || !found || updatedAlert.Status != status || updatedAlert.AnalystNotes != note || updatedAlert.Assignee != assignee {
		t.Fatalf("PostgreSQL alert update = %#v, found=%v, err=%v", updatedAlert, found, err)
	}
	var incident model.Incident
	for _, candidate := range data.Incidents {
		if candidate.SimulationRunID == runID {
			incident = candidate
			break
		}
	}
	if incident.ID == "" {
		t.Fatal("PostgreSQL incident snapshot missing the current run")
	}
	incidentStatus, incidentNote := "investigating", "under review"
	updatedIncident, found, err := db.UpdateIncident(incident.ID, &incidentStatus, &incidentNote)
	if err != nil || !found || updatedIncident.Status != incidentStatus || updatedIncident.AnalystNotes != incidentNote {
		t.Fatalf("PostgreSQL incident update = %#v, found=%v, err=%v", updatedIncident, found, err)
	}
	for index := 0; index < 3; index++ {
		correlationEvent := model.Event{ID: fmt.Sprintf("%s-auth-%d", suffix, index), SchemaVersion: "1.0", Time: now.Add(time.Duration(index+1) * time.Minute), HostID: event.HostID, Hostname: event.Hostname, Source: "integration-test", Type: "authentication_failure", SimulationRunID: runID}
		previous, err := db.RecentEvents(correlationEvent, 5*time.Minute, 500)
		if err != nil {
			t.Fatal(err)
		}
		findings := detection.Evaluate(correlationEvent, previous)
		var alerts []model.Alert
		if index < 2 && len(findings) != 0 {
			t.Fatalf("PostgreSQL correlation fired before threshold at event %d: %#v", index+1, findings)
		}
		if index == 2 {
			if len(findings) != 1 || findings[0].Rule.ID != "SEN-AUTH-003" || len(findings[0].EventIDs) != 3 {
				t.Fatalf("PostgreSQL correlation finding = %#v", findings)
			}
			finding := findings[0]
			alerts = append(alerts, model.Alert{ID: "correlation-alert-" + suffix, RuleID: finding.Rule.ID, Title: finding.Rule.Title, Severity: finding.Rule.Severity, Confidence: finding.Rule.Confidence, Technique: finding.Rule.Technique, HostID: event.HostID, Hostname: event.Hostname, EventIDs: finding.EventIDs, Evidence: finding.Evidence, CreatedAt: correlationEvent.Time, SimulationRunID: runID, Status: "open"})
		}
		if err := db.AddEvent(correlationEvent, alerts); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RemoveSimulation(runID); err != nil {
		t.Fatal(err)
	}
	after := db.Snapshot()
	if containsEvent(after.Events, eventID) || containsAlert(after.Alerts, alert.ID) {
		t.Fatalf("simulation reset did not remove run %q", runID)
	}
}

func containsEvent(items []model.Event, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func containsAlert(items []model.Alert, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}
