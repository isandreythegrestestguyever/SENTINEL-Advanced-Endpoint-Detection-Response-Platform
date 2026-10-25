package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"os"
	"sort"
	"sync"
	"time"
)

var ErrDuplicateEvent = errors.New("event ID already exists")

type Repository interface {
	ReadSnapshot() (Data, error)
	RecentEvents(event model.Event, window time.Duration, limit int) ([]model.Event, error)
	UpdateAlert(id string, status, note, assignee *string) (model.Alert, bool, error)
	UpdateIncident(id string, status, note *string) (model.Incident, bool, error)
	RemoveSimulation(runID string) error
	AddEvent(event model.Event, alerts []model.Alert) error
	UpsertEndpoint(endpoint model.Endpoint) error
	PruneBefore(cutoff time.Time) (PruneStats, error)
	Ping(context.Context) error
	Close()
}

type PruneStats struct {
	Events    int `json:"events"`
	Alerts    int `json:"alerts"`
	Incidents int `json:"incidents"`
	Audit     int `json:"audit"`
	Endpoints int `json:"endpoints"`
}

type Data struct {
	Events    []model.Event    `json:"events"`
	Alerts    []model.Alert    `json:"alerts"`
	Incidents []model.Incident `json:"incidents"`
	Endpoints []model.Endpoint `json:"endpoints,omitempty"`
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

func (s *Store) RecentEvents(event model.Event, window time.Duration, limit int) ([]model.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	start := event.Time.Add(-window)
	var matches []model.Event
	for _, candidate := range s.Events {
		if candidate.HostID == event.HostID && candidate.SimulationRunID == event.SimulationRunID && !candidate.Time.Before(start) && !candidate.Time.After(event.Time) {
			matches = append(matches, candidate)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Time.Before(matches[j].Time) })
	if limit > 0 && len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}
	return matches, nil
}

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

func (s *Store) UpsertEndpoint(endpoint model.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.Endpoints {
		if s.Endpoints[index].HostID == endpoint.HostID {
			s.Endpoints[index] = endpoint
			s.Audit = append(s.Audit, map[string]any{"action": "endpoint.heartbeat", "host_id": endpoint.HostID, "time": endpoint.LastHeartbeat})
			return s.save()
		}
	}
	s.Endpoints = append(s.Endpoints, endpoint)
	s.Audit = append(s.Audit, map[string]any{"action": "endpoint.heartbeat", "host_id": endpoint.HostID, "time": endpoint.LastHeartbeat})
	return s.save()
}

func (s *Store) PruneBefore(cutoff time.Time) (PruneStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var stats PruneStats
	expiredEvents := make(map[string]bool)
	events := s.Events[:0]
	for _, event := range s.Events {
		seen := event.IngestedAt
		if seen.IsZero() {
			seen = event.Time
		}
		if seen.Before(cutoff) {
			stats.Events++
			expiredEvents[event.ID] = true
			continue
		}
		events = append(events, event)
	}
	s.Events = events
	keptAlerts := s.Alerts[:0]
	keptAlertIDs := make(map[string]bool, len(s.Alerts))
	for _, alert := range s.Alerts {
		expired := alert.CreatedAt.Before(cutoff)
		for _, eventID := range alert.EventIDs {
			expired = expired || expiredEvents[eventID]
		}
		if expired {
			stats.Alerts++
			continue
		}
		keptAlerts = append(keptAlerts, alert)
		keptAlertIDs[alert.ID] = true
	}
	s.Alerts = keptAlerts
	keptIncidents := s.Incidents[:0]
	for _, incident := range s.Incidents {
		if incident.UpdatedAt.Before(cutoff) {
			stats.Incidents++
			continue
		}
		alertIDs := incident.AlertIDs[:0]
		for _, alertID := range incident.AlertIDs {
			if keptAlertIDs[alertID] {
				alertIDs = append(alertIDs, alertID)
			}
		}
		incident.AlertIDs = alertIDs
		if len(incident.AlertIDs) == 0 {
			stats.Incidents++
			continue
		}
		keptIncidents = append(keptIncidents, incident)
	}
	s.Incidents = keptIncidents
	keptAudit := s.Audit[:0]
	for _, entry := range s.Audit {
		if timestamp, ok := auditTimestamp(entry["time"]); ok && timestamp.Before(cutoff) {
			stats.Audit++
			continue
		}
		keptAudit = append(keptAudit, entry)
	}
	s.Audit = keptAudit
	keptEndpoints := s.Endpoints[:0]
	for _, endpoint := range s.Endpoints {
		if endpoint.LastHeartbeat.Before(cutoff) {
			stats.Endpoints++
			continue
		}
		keptEndpoints = append(keptEndpoints, endpoint)
	}
	s.Endpoints = keptEndpoints
	if stats.Events+stats.Alerts+stats.Incidents+stats.Audit+stats.Endpoints > 0 {
		s.Audit = append(s.Audit, map[string]any{"action": "retention.pruned", "cutoff": cutoff.UTC(), "counts": stats, "time": time.Now().UTC()})
	}
	return stats, s.save()
}

func auditTimestamp(value any) (time.Time, bool) {
	switch value := value.(type) {
	case time.Time:
		return value, true
	case string:
		timestamp, err := time.Parse(time.RFC3339Nano, value)
		return timestamp, err == nil
	default:
		return time.Time{}, false
	}
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
