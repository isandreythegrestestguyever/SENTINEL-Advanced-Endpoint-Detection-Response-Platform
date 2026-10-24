package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

func TestStorePersistsAnalystUpdatesAndSimulationReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	event := model.Event{ID: "sim-event", HostID: "lab-1", Hostname: "LAB-1", SimulationRunID: "run-1", Time: now}
	alert := model.Alert{ID: "sim-alert", HostID: event.HostID, Hostname: event.Hostname, SimulationRunID: event.SimulationRunID, Status: "open", CreatedAt: now}
	if err := s.AddEvent(event, []model.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEvent(event, []model.Alert{alert}); !errors.Is(err, ErrDuplicateEvent) {
		t.Fatalf("duplicate event error = %v, want %v", err, ErrDuplicateEvent)
	}

	alertStatus, analystNote, assignee := "acknowledged", "reviewed", "analyst-1"
	updatedAlert, found, err := s.UpdateAlert(alert.ID, &alertStatus, &analystNote, &assignee)
	if err != nil || !found {
		t.Fatalf("UpdateAlert() found=%v err=%v", found, err)
	}
	if updatedAlert.Status != "acknowledged" || updatedAlert.AnalystNotes != "reviewed" || updatedAlert.Assignee != "analyst-1" {
		t.Fatalf("unexpected alert update: %#v", updatedAlert)
	}
	clearText := ""
	updatedAlert, found, err = s.UpdateAlert(alert.ID, nil, &clearText, &clearText)
	if err != nil || !found || updatedAlert.Status != "acknowledged" || updatedAlert.AnalystNotes != "" || updatedAlert.Assignee != "" {
		t.Fatalf("empty analyst fields should clear without changing status: %#v, found=%v, err=%v", updatedAlert, found, err)
	}

	incident := s.Snapshot().Incidents[0]
	incidentStatus, incidentNote := "investigating", "triaged"
	updatedIncident, found, err := s.UpdateIncident(incident.ID, &incidentStatus, &incidentNote)
	if err != nil || !found {
		t.Fatalf("UpdateIncident() found=%v err=%v", found, err)
	}
	if updatedIncident.Status != "investigating" || updatedIncident.AnalystNotes != "triaged" {
		t.Fatalf("unexpected incident update: %#v", updatedIncident)
	}

	live := model.Event{ID: "live-event", HostID: "host-2", Hostname: "HOST-2", Time: now}
	if err := s.AddEvent(live, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSimulation("run-1"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data := reloaded.Snapshot()
	if len(data.Events) != 1 || data.Events[0].ID != "live-event" {
		t.Fatalf("simulation reset left unexpected events: %#v", data.Events)
	}
	if len(data.Alerts) != 0 || len(data.Incidents) != 0 {
		t.Fatalf("simulation reset left alerts/incidents: %#v / %#v", data.Alerts, data.Incidents)
	}
	if len(data.Audit) < 4 {
		t.Fatalf("expected persisted audit actions, got %d entries", len(data.Audit))
	}
}
