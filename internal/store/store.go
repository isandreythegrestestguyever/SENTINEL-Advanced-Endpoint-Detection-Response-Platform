package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"os"
	"sync"
	"time"
)

var ErrDuplicateEvent = errors.New("event ID already exists")

type Repository interface {
	ReadSnapshot() (Data, error)
	UpdateAlert(id string, status, note, assignee *string) (model.Alert, bool, error)
	UpdateIncident(id string, status, note *string) (model.Incident, bool, error)
	RemoveSimulation(runID string) error
	AddEvent(event model.Event, alerts []model.Alert) error
	Ping(context.Context) error
	Close()
}

type Data struct {
	Events    []model.Event    `json:"events"`
	Alerts    []model.Alert    `json:"alerts"`
	Incidents []model.Incident `json:"incidents"`
	Audit     []map[string]any `json:"audit"`
}
type Store struct {
	mu   sync.RWMutex
	path string
	Data
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, e := os.ReadFile(path)
	if e == nil {
		e = json.Unmarshal(b, &s.Data)
	}
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}
func (s *Store) Snapshot() Data              { s.mu.RLock(); defer s.mu.RUnlock(); return s.Data }
func (s *Store) ReadSnapshot() (Data, error) { return s.Snapshot(), nil }
func (s *Store) Ping(context.Context) error  { return nil }
func (s *Store) Close()                      {}

func (s *Store) UpdateAlert(id string, status, note, assignee *string) (model.Alert, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Alerts {
		if s.Alerts[i].ID != id {
			continue
		}
		if status != nil {
			s.Alerts[i].Status = *status
		}
		if note != nil {
			s.Alerts[i].AnalystNotes = *note
		}
		if assignee != nil {
			s.Alerts[i].Assignee = *assignee
		}
		s.Audit = append(s.Audit, map[string]any{"action": "alert.updated", "alert_id": id, "status": s.Alerts[i].Status, "time": time.Now().UTC()})
		if err := s.save(); err != nil {
			return model.Alert{}, false, err
		}
		return s.Alerts[i], true, nil
	}
	return model.Alert{}, false, nil
}

func (s *Store) UpdateIncident(id string, status, note *string) (model.Incident, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Incidents {
		if s.Incidents[i].ID != id {
			continue
		}
		if status != nil {
			s.Incidents[i].Status = *status
		}
		if note != nil {
			s.Incidents[i].AnalystNotes = *note
		}
		s.Incidents[i].UpdatedAt = time.Now().UTC()
		s.Audit = append(s.Audit, map[string]any{"action": "incident.updated", "incident_id": id, "status": s.Incidents[i].Status, "time": time.Now().UTC()})
		if err := s.save(); err != nil {
			return model.Incident{}, false, err
		}
		return s.Incidents[i], true, nil
	}
	return model.Incident{}, false, nil
}

func (s *Store) RemoveSimulation(runID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keptEvents := s.Events[:0]
	for _, event := range s.Events {
		if event.SimulationRunID != runID {
			keptEvents = append(keptEvents, event)
		}
	}
	s.Events = keptEvents
	keptAlerts := s.Alerts[:0]
	for _, alert := range s.Alerts {
		if alert.SimulationRunID != runID {
			keptAlerts = append(keptAlerts, alert)
		}
	}
	s.Alerts = keptAlerts
	keptIncidents := s.Incidents[:0]
	for _, incident := range s.Incidents {
		if incident.SimulationRunID != runID {
			keptIncidents = append(keptIncidents, incident)
		}
	}
	s.Incidents = keptIncidents
	s.Audit = append(s.Audit, map[string]any{"action": "simulation.reset", "run_id": runID, "time": time.Now().UTC()})
	return s.save()
}
func (s *Store) AddEvent(e model.Event, alerts []model.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.Events {
		if existing.ID == e.ID {
			return ErrDuplicateEvent
		}
	}
	s.Events = append(s.Events, e)
	s.Alerts = append(s.Alerts, alerts...)
	for _, a := range alerts {
		found := -1
		for i := range s.Incidents {
			if s.Incidents[i].HostID == a.HostID && s.Incidents[i].SimulationRunID == a.SimulationRunID && time.Since(s.Incidents[i].UpdatedAt) < 30*time.Minute {
				found = i
				break
			}
		}
		if found < 0 {
			s.Incidents = append(s.Incidents, model.Incident{ID: "INC-" + a.ID, HostID: a.HostID, Hostname: a.Hostname, Severity: a.Severity, Status: "open", SimulationRunID: a.SimulationRunID, UpdatedAt: a.CreatedAt})
			found = len(s.Incidents) - 1
		}
		s.Incidents[found].AlertIDs = append(s.Incidents[found].AlertIDs, a.ID)
		s.Incidents[found].UpdatedAt = a.CreatedAt
	}
	s.Audit = append(s.Audit, map[string]any{"action": "event.ingested", "event_id": e.ID, "time": time.Now().UTC()})
	return s.save()
}
func (s *Store) save() error {
	b, e := json.MarshalIndent(s.Data, "", "  ")
	if e != nil {
		return e
	}
	tmp := s.path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, s.path)
}
