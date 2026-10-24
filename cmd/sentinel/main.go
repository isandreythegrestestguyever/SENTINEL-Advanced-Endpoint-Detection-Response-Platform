package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/detection"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/store"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var db store.Repository
	if databaseURL := os.Getenv("SENTINEL_DATABASE_URL"); databaseURL != "" {
		postgres, err := store.OpenPostgres(context.Background(), databaseURL)
		if err != nil {
			log.Fatal(err)
		}
		db = postgres
		log.Printf("SENTINEL storage: PostgreSQL")
	} else {
		path := env("SENTINEL_DB", "sentinel-data.json")
		local, err := store.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		db = local
		log.Printf("SENTINEL storage: local JSON development mode")
	}
	defer db.Close()
	token := os.Getenv("SENTINEL_ADMIN_TOKEN")
	if token == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		token = hex.EncodeToString(b)
		log.Printf("Temporary analyst token (set SENTINEL_ADMIN_TOKEN to persist): %s", token)
	}
	mux := routes(db, token)
	addr := env("SENTINEL_ADDR", "127.0.0.1:8080")
	server := &http.Server{Addr: addr, Handler: headers(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("SENTINEL listening on http://%s", addr)
	if cert, key := os.Getenv("SENTINEL_TLS_CERT"), os.Getenv("SENTINEL_TLS_KEY"); cert != "" && key != "" {
		log.Fatal(server.ListenAndServeTLS(cert, key))
	}
	log.Fatal(server.ListenAndServe())
}
func routes(db store.Repository, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		jsonOut(w, map[string]any{"status": "ok", "mode": "local-development", "schema_version": "1.0"})
	})
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if !ok {
			return
		}
		by := map[string]int{}
		hosts := map[string]bool{}
		for _, a := range d.Alerts {
			if a.SimulationRunID == "" {
				by[a.Severity]++
			}
		}
		for _, ev := range d.Events {
			if ev.SimulationRunID == "" {
				hosts[ev.HostID] = true
			}
		}
		jsonOut(w, map[string]any{"monitored_endpoints": len(hosts), "connected_sensors": 0, "open_incidents": countLive(d.Incidents), "alerts_by_severity": by, "events": len(d.Events), "alerts": len(d.Alerts), "mode": "LOCAL DEVELOPMENT · NO LIVE SENSORS"})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			jsonOut(w, d.Events)
		}
	})
	mux.HandleFunc("/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		latest := map[string]model.Endpoint{}
		d, ok := readData(w, db)
		if !ok {
			return
		}
		for _, event := range d.Events {
			seenAt := event.IngestedAt
			if seenAt.IsZero() {
				seenAt = event.Time
			}
			endpoint := latest[event.HostID]
			if endpoint.HostID == "" || seenAt.After(endpoint.LastSeen) {
				endpoint = model.Endpoint{HostID: event.HostID, Hostname: event.Hostname, OS: "Unknown", Status: "observed", LastSeen: seenAt, Simulated: event.SimulationRunID != ""}
				if endpoint.Simulated {
					endpoint.OS = "Windows (simulated)"
					endpoint.Status = "simulation"
				}
				latest[event.HostID] = endpoint
			}
		}
		endpoints := make([]model.Endpoint, 0, len(latest))
		for _, endpoint := range latest {
			endpoints = append(endpoints, endpoint)
		}
		jsonOut(w, endpoints)
	})
	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			jsonOut(w, d.Alerts)
		}
	})
	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			jsonOut(w, d.Incidents)
		}
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			jsonOut(w, d.Audit)
		}
	})
	mux.HandleFunc("PATCH /api/alerts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var update struct {
			Status       *string `json:"status"`
			AnalystNotes *string `json:"analyst_notes"`
			Assignee     *string `json:"assignee"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&update); err != nil {
			http.Error(w, "invalid update", http.StatusBadRequest)
			return
		}
		if update.Status != nil && *update.Status != "open" && *update.Status != "acknowledged" && *update.Status != "closed" {
			http.Error(w, "status must be open, acknowledged, or closed", http.StatusBadRequest)
			return
		}
		if (update.AnalystNotes != nil && len(*update.AnalystNotes) > 4000) || (update.Assignee != nil && len(*update.Assignee) > 120) {
			http.Error(w, "update field too long", http.StatusBadRequest)
			return
		}
		alert, found, err := db.UpdateAlert(r.PathValue("id"), update.Status, update.AnalystNotes, update.Assignee)
		if err != nil {
			http.Error(w, "could not persist alert update", http.StatusInternalServerError)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		jsonOut(w, alert)
	})
	mux.HandleFunc("PATCH /api/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var update struct {
			Status       *string `json:"status"`
			AnalystNotes *string `json:"analyst_notes"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&update); err != nil {
			http.Error(w, "invalid update", http.StatusBadRequest)
			return
		}
		if update.Status != nil && *update.Status != "open" && *update.Status != "investigating" && *update.Status != "resolved" {
			http.Error(w, "status must be open, investigating, or resolved", http.StatusBadRequest)
			return
		}
		if update.AnalystNotes != nil && len(*update.AnalystNotes) > 4000 {
			http.Error(w, "note too long", http.StatusBadRequest)
			return
		}
		incident, found, err := db.UpdateIncident(r.PathValue("id"), update.Status, update.AnalystNotes)
		if err != nil {
			http.Error(w, "could not persist incident update", http.StatusInternalServerError)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		jsonOut(w, incident)
	})
	mux.HandleFunc("DELETE /api/simulations/{run}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		runID := r.PathValue("run")
		if runID == "" || len(runID) > 128 {
			http.Error(w, "invalid run ID", http.StatusBadRequest)
			return
		}
		if err := db.RemoveSimulation(runID); err != nil {
			http.Error(w, "could not reset simulation", http.StatusInternalServerError)
			return
		}
		jsonOut(w, map[string]any{"reset": true, "run_id": runID})
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, detection.Rules) })
	mux.HandleFunc("/api/scenarios", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, simulator.All()) })
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !auth(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var e model.Event
		if er := json.NewDecoder(r.Body).Decode(&e); er != nil {
			http.Error(w, "invalid event: "+er.Error(), 400)
			return
		}
		if er := valid(e); er != "" {
			http.Error(w, er, 400)
			return
		}
		process(w, db, e)
	})
	mux.HandleFunc("/api/simulate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !auth(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		var req struct {
			ScenarioID string `json:"scenario_id"`
			RunID      string `json:"run_id"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		var selected *simulator.Scenario
		for _, s := range simulator.All() {
			if s.ID == req.ScenarioID {
				copy := s
				selected = &copy
				break
			}
		}
		if selected == nil {
			http.Error(w, "unknown scenario", 404)
			return
		}
		if req.RunID == "" {
			req.RunID = fmt.Sprintf("SIM-%d", time.Now().UnixNano())
		}
		beforeData, ok := readData(w, db)
		if !ok {
			return
		}
		before := len(beforeData.Alerts)
		for index, event := range selected.Events {
			event.SimulationRunID = req.RunID
			event.Time = time.Now().UTC().Add(time.Duration(len(beforeData.Events)+index) * time.Millisecond)
			event.ID = req.RunID + "-" + event.ID
			if _, err := processEvent(db, event); err != nil {
				http.Error(w, "could not persist simulation event", http.StatusInternalServerError)
				return
			}
		}
		d, ok := readData(w, db)
		if !ok {
			return
		}
		actual := map[string]bool{}
		for _, a := range d.Alerts {
			if a.SimulationRunID == req.RunID {
				actual[a.RuleID] = true
			}
		}
		detected := []string{}
		missed := []string{}
		for _, id := range selected.ExpectedRuleIDs {
			if actual[id] {
				detected = append(detected, id)
			} else {
				missed = append(missed, id)
			}
		}
		unexpected := []string{}
		for id := range actual {
			expect := false
			for _, x := range selected.ExpectedRuleIDs {
				if x == id {
					expect = true
				}
			}
			if !expect {
				unexpected = append(unexpected, id)
			}
		}
		report := map[string]any{"scenario": selected.Name, "scenario_id": selected.ID, "scenario_version": "1.0", "dataset_version": "1.0", "rule_set_version": "1", "simulation_seed": "deterministic-fixture-v1", "run_id": req.RunID, "event_count": len(selected.Events), "expected_alerts": selected.ExpectedRuleIDs, "detected": detected, "missed": missed, "unexpected": unexpected, "success": len(missed) == 0, "precision": ratio(len(detected), len(detected)+len(unexpected)), "recall": ratio(len(detected), len(selected.ExpectedRuleIDs)), "errors": []string{}, "alert_count": len(d.Alerts) - before}
		jsonOut(w, report)
	})
	mux.Handle("/", http.FileServer(http.Dir("web")))
	return mux
}

func process(w http.ResponseWriter, db store.Repository, e model.Event) {
	a, err := processEvent(db, e)
	if errors.Is(err, store.ErrDuplicateEvent) {
		http.Error(w, "event ID already exists", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "could not persist event", http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{"accepted": true, "event_id": e.ID, "alerts": a})
}

func readData(w http.ResponseWriter, db store.Repository) (store.Data, bool) {
	data, err := db.ReadSnapshot()
	if err != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return store.Data{}, false
	}
	return data, true
}

func processEvent(db store.Repository, e model.Event) ([]model.Alert, error) {
	e.IngestedAt = time.Now().UTC()
	previous, err := db.RecentEvents(e, 10*time.Minute, 500)
	if err != nil {
		return nil, err
	}
	matches := detection.Evaluate(e, previous)
	alerts := []model.Alert{}
	for _, finding := range matches {
		rule := finding.Rule
		alerts = append(alerts, model.Alert{ID: fmt.Sprintf("ALT-%s-%s", e.ID, rule.ID), RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity, Confidence: rule.Confidence, Technique: rule.Technique, HostID: e.HostID, Hostname: e.Hostname, EventIDs: finding.EventIDs, Evidence: finding.Evidence, CreatedAt: time.Now().UTC(), SimulationRunID: e.SimulationRunID, Status: "open"})
	}
	if err := db.AddEvent(e, alerts); err != nil {
		return nil, err
	}
	return alerts, nil
}
func valid(e model.Event) string {
	if e.ID == "" || e.HostID == "" || e.Hostname == "" || e.Type == "" || e.Source == "" {
		return "id, host_id, hostname, source and type are required"
	}
	if len(e.ID) > 128 || len(e.Hostname) > 255 || len(e.CommandLine) > 4096 {
		return "field length limit exceeded"
	}
	if e.SchemaVersion != "1.0" {
		return "unsupported schema_version (expected 1.0)"
	}
	if e.Time.IsZero() {
		return "time is required"
	}
	return ""
}
func auth(r *http.Request, t string) bool {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == t && r.Header.Get("Authorization") != ""
}
func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func countLive(a []model.Incident) int {
	n := 0
	for _, i := range a {
		if i.SimulationRunID == "" && i.Status == "open" {
			n++
		}
	}
	return n
}
func ratio(a, b int) any {
	if b == 0 {
		return nil
	}
	return float64(a) / float64(b)
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
