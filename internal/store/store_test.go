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

func TestStoreUpsertsAndPersistsEndpointHeartbeats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	endpoint := model.Endpoint{HostID: "endpoint-1", Hostname: "HOST-1", OS: "Windows", AgentVersion: "0.1.0", TelemetrySources: []string{"Security"}, CollectionCapabilities: []string{"process"}, Status: "online", LastSeen: now, LastHeartbeat: now}
	if err := s.UpsertEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint.AgentVersion = "0.2.0"
	endpoint.LastSeen = now.Add(time.Second)
	endpoint.LastHeartbeat = endpoint.LastSeen
	if err := s.UpsertEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data := reloaded.Snapshot()
	if len(data.Endpoints) != 1 || data.Endpoints[0].AgentVersion != "0.2.0" || !data.Endpoints[0].LastHeartbeat.Equal(endpoint.LastHeartbeat) {
		t.Fatalf("endpoint heartbeat was not updated and persisted: %#v", data.Endpoints)
	}
	if len(data.Audit) != 2 {
		t.Fatalf("expected one audit record per heartbeat, got %d", len(data.Audit))
	}
}

func TestStorePrunesExpiredEvidenceAndKeepsRecentRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	oldEvent := model.Event{ID: "old-event", HostID: "old-host", Hostname: "OLD-HOST", Time: cutoff.Add(-time.Hour), IngestedAt: cutoff.Add(-time.Hour), SimulationRunID: "old-run"}
	oldAlert := model.Alert{ID: "old-alert", HostID: oldEvent.HostID, Hostname: oldEvent.Hostname, EventIDs: []string{oldEvent.ID}, CreatedAt: now, SimulationRunID: oldEvent.SimulationRunID, Status: "open"}
	if err := s.AddEvent(oldEvent, []model.Alert{oldAlert}); err != nil {
		t.Fatal(err)
	}
	freshEvent := model.Event{ID: "fresh-event", HostID: "fresh-host", Hostname: "FRESH-HOST", Time: now, IngestedAt: now, SimulationRunID: "fresh-run"}
	freshAlert := model.Alert{ID: "fresh-alert", HostID: freshEvent.HostID, Hostname: freshEvent.Hostname, EventIDs: []string{freshEvent.ID}, CreatedAt: now, SimulationRunID: freshEvent.SimulationRunID, Status: "open"}
	if err := s.AddEvent(freshEvent, []model.Alert{freshAlert}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{HostID: "old-host", LastHeartbeat: cutoff.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{HostID: "fresh-host", LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.Audit = append(s.Audit, map[string]any{"action": "old.audit", "time": cutoff.Add(-time.Hour)})
	if err := s.save(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	stats, err := s.PruneBefore(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats != (PruneStats{Events: 1, Alerts: 1, Incidents: 1, Audit: 2, Endpoints: 1}) {
		t.Fatalf("unexpected retention counts: %#v", stats)
	}
	data, err := s.ReadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Events) != 1 || data.Events[0].ID != freshEvent.ID || len(data.Alerts) != 1 || data.Alerts[0].ID != freshAlert.ID || len(data.Incidents) != 1 || data.Incidents[0].AlertIDs[0] != freshAlert.ID || len(data.Endpoints) != 1 || data.Endpoints[0].HostID != "fresh-host" {
		t.Fatalf("retention left inconsistent or expired records: %#v", data)
	}
	for _, entry := range data.Audit {
		if entry["action"] == "old.audit" {
			t.Fatal("expired audit record was retained")
		}
	}
	if data.Audit[len(data.Audit)-1]["action"] != "retention.pruned" {
		t.Fatalf("retention action was not audit logged: %#v", data.Audit)
	}
}

func TestStoreReadEventsPageUsesStableDescendingCursor(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "pages.json"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"evt-a", "evt-b", "evt-c", "evt-d", "evt-e"} {
		if err := s.AddEvent(model.Event{ID: id, HostID: "host", Hostname: "HOST", Time: at, IngestedAt: at}, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, cursor, err := s.ReadEventsPage(2, "")
	if err != nil || len(first) != 2 || first[0].ID != "evt-e" || first[1].ID != "evt-d" || cursor == "" {
		t.Fatalf("first page = %#v, cursor=%q, err=%v", first, cursor, err)
	}
	second, next, err := s.ReadEventsPage(2, cursor)
	if err != nil || len(second) != 2 || second[0].ID != "evt-c" || second[1].ID != "evt-b" || next == "" {
		t.Fatalf("second page = %#v, cursor=%q, err=%v", second, next, err)
	}
	third, next, err := s.ReadEventsPage(2, next)
	if err != nil || len(third) != 1 || third[0].ID != "evt-a" || next != "" {
		t.Fatalf("third page = %#v, cursor=%q, err=%v", third, next, err)
	}
	if _, _, err := s.ReadEventsPage(2, "invalid cursor"); !errors.Is(err, ErrInvalidEventCursor) {
		t.Fatalf("invalid cursor error = %v", err)
	}
	if _, _, err := s.ReadEventsPage(MaxEventPageSize+1, ""); !errors.Is(err, ErrInvalidEventPageSize) {
		t.Fatalf("invalid page size error = %v", err)
	}
}
