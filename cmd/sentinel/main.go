package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	path := env("SENTINEL_DB", "sentinel-data.json")
	db, e := store.Open(path)
	if e != nil {
		log.Fatal(e)
	}
	token := os.Getenv("SENTINEL_ADMIN_TOKEN")
	if token == "" {
		b := make([]byte, 24)
		if _, e = rand.Read(b); e != nil {
			log.Fatal(e)
		}
		token = hex.EncodeToString(b)
		log.Printf("Temporary analyst token (set SENTINEL_ADMIN_TOKEN to persist): %s", token)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, map[string]any{"status": "ok", "mode": "local-development", "schema_version": "1.0"})
	})
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		d := db.Snapshot()
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
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, db.Snapshot().Events) })
	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, db.Snapshot().Alerts) })
	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, db.Snapshot().Incidents) })
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, db.Snapshot().Audit) })
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
		before := len(db.Snapshot().Alerts)
		for _, event := range selected.Events {
			event.SimulationRunID = req.RunID
			event.Time = time.Now().UTC().Add(time.Duration(len(db.Snapshot().Events)) * time.Millisecond)
			event.ID = req.RunID + "-" + event.ID
			processEvent(db, event)
		}
		d := db.Snapshot()
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
	addr := env("SENTINEL_ADDR", "127.0.0.1:8080")
	server := &http.Server{Addr: addr, Handler: headers(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("SENTINEL listening on http://%s", addr)
	if cert, key := os.Getenv("SENTINEL_TLS_CERT"), os.Getenv("SENTINEL_TLS_KEY"); cert != "" && key != "" {
		log.Fatal(server.ListenAndServeTLS(cert, key))
	}
	log.Fatal(server.ListenAndServe())
}
func process(w http.ResponseWriter, db *store.Store, e model.Event) {
	a := processEvent(db, e)
	jsonOut(w, map[string]any{"accepted": true, "event_id": e.ID, "alerts": a})
}
func processEvent(db *store.Store, e model.Event) []model.Alert {
	e.IngestedAt = time.Now().UTC()
	matches := detection.Match(e)
	alerts := []model.Alert{}
	for _, rule := range matches {
		alerts = append(alerts, model.Alert{ID: fmt.Sprintf("ALT-%s-%s", e.ID, rule.ID), RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity, Confidence: rule.Confidence, Technique: rule.Technique, HostID: e.HostID, Hostname: e.Hostname, EventIDs: []string{e.ID}, Evidence: fmt.Sprintf("%s matched %s containing %q", rule.Field, rule.ID, rule.Contains), CreatedAt: time.Now().UTC(), SimulationRunID: e.SimulationRunID, Status: "open"})
	}
	if err := db.AddEvent(e, alerts); err != nil {
		log.Printf("persist event: %v", err)
	}
	return alerts
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
