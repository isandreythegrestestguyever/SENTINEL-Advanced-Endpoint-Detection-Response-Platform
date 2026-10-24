package store

import (
	"encoding/json"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"os"
	"sync"
	"time"
)

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
func (s *Store) Snapshot() Data { s.mu.RLock(); defer s.mu.RUnlock(); return s.Data }
func (s *Store) AddEvent(e model.Event, alerts []model.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
