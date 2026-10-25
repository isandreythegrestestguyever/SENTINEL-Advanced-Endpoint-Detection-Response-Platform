package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
	retentionWindow, err := parseRetentionWindow(os.Getenv("SENTINEL_RETENTION_DAYS"))
	if err != nil {
		log.Fatal(err)
	}
	token := os.Getenv("SENTINEL_ADMIN_TOKEN")
	analystToken := os.Getenv("SENTINEL_ANALYST_TOKEN")
	if token == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		token = hex.EncodeToString(b)
		log.Printf("Temporary administrator token (set SENTINEL_ADMIN_TOKEN to persist): %s", token)
	}
	if analystToken == token {
		log.Fatal("SENTINEL_ANALYST_TOKEN and SENTINEL_ADMIN_TOKEN must be different")
	}
	if analystToken == "" {
		log.Printf("SENTINEL_ANALYST_TOKEN is unset; the administrator token can access analyst routes")
	}
	tlsConfig, err := tlsConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	mux := routes(db, AccessTokens{
		Admin: token, Analyst: analystToken,
		RequireClientCertHostBinding: tlsConfig.ClientCAs != nil,
	})
	addr := env("SENTINEL_ADDR", "127.0.0.1:8080")
	server := &http.Server{Addr: addr, Handler: headers(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, TLSConfig: tlsConfig}
	serveErrors := make(chan error, 1)
	if cert := os.Getenv("SENTINEL_TLS_CERT"); cert != "" {
		key := os.Getenv("SENTINEL_TLS_KEY")
		log.Printf("SENTINEL listening on https://%s (minimum TLS 1.3)", addr)
		go func() { serveErrors <- server.ListenAndServeTLS(cert, key) }()
	} else {
		log.Printf("SENTINEL listening on http://%s", addr)
		go func() { serveErrors <- server.ListenAndServe() }()
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if retentionWindow > 0 {
		go retentionLoop(shutdownContext, db, retentionWindow)
	}
	select {
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown: %v", err)
			if closeErr := server.Close(); closeErr != nil {
				log.Printf("force close: %v", closeErr)
			}
		}
		if err := <-serveErrors; !errors.Is(err, http.ErrServerClosed) && err != nil {
			log.Printf("HTTP server stopped: %v", err)
		}
	}
}

func parseRetentionWindow(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 || days > 36500 {
		return 0, errors.New("SENTINEL_RETENTION_DAYS must be an integer from 0 to 36500")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func retentionLoop(ctx context.Context, db store.Repository, retentionWindow time.Duration) {
	prune := func() {
		cutoff := time.Now().UTC().Add(-retentionWindow)
		stats, err := db.PruneBefore(cutoff)
		if err != nil {
			log.Printf("retention cleanup failed: %v", err)
			return
		}
		if stats.Events+stats.Alerts+stats.Incidents+stats.Audit+stats.Endpoints > 0 {
			log.Printf("retention removed records: %+v", stats)
		}
	}
	prune()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

func tlsConfigFromEnv() (*tls.Config, error) {
	certPath, keyPath, caPath := os.Getenv("SENTINEL_TLS_CERT"), os.Getenv("SENTINEL_TLS_KEY"), os.Getenv("SENTINEL_CLIENT_CA")
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("SENTINEL_TLS_CERT and SENTINEL_TLS_KEY must be configured together")
	}
	if caPath != "" && certPath == "" {
		return nil, errors.New("SENTINEL_CLIENT_CA requires HTTPS certificate and key configuration")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if caPath == "" {
		return config, nil
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA bundle: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("SENTINEL_CLIENT_CA did not contain a usable PEM certificate")
	}
	config.ClientCAs = clientCAs
	// Browser analysts may use bearer auth without a client cert. If a cert is
	// presented, TLS verifies it; the ingest handler then requires its host URI.
	config.ClientAuth = tls.VerifyClientCertIfGiven
	return config, nil
}

type AccessTokens struct {
	Admin                        string
	Analyst                      string
	RequireClientCertHostBinding bool
}

func routes(db store.Repository, tokens AccessTokens) http.Handler {
	sigmaEngine, err := detection.DefaultSigmaEngine()
	if err != nil {
		panic(fmt.Errorf("load bundled Sigma rules: %w", err))
	}
	mux := http.NewServeMux()
	read := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if accessRole(r, tokens) == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			handler(w, r)
		}
	}
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		jsonOut(w, map[string]any{"status": "ok", "mode": "local-development", "schema_version": "1.0"})
	})
	mux.HandleFunc("/api/overview", read(func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if !ok {
			return
		}
		by := map[string]int{}
		hosts := map[string]bool{}
		liveEvents, simulationEvents := 0, 0
		liveAlerts, simulationAlerts := 0, 0
		liveIncidents, simulationIncidents := 0, 0
		openSimulationIncidents := 0
		for _, a := range d.Alerts {
			if a.SimulationRunID == "" {
				liveAlerts++
				by[a.Severity]++
			} else {
				simulationAlerts++
			}
		}
		for _, ev := range d.Events {
			if ev.SimulationRunID == "" {
				liveEvents++
				hosts[ev.HostID] = true
			} else {
				simulationEvents++
			}
		}
		for _, incident := range d.Incidents {
			if incident.SimulationRunID == "" {
				liveIncidents++
			} else {
				simulationIncidents++
				if incident.Status == "open" {
					openSimulationIncidents++
				}
			}
		}
		connected := 0
		for _, endpoint := range d.Endpoints {
			if isFreshHeartbeat(endpoint.LastHeartbeat, time.Now().UTC()) {
				connected++
				hosts[endpoint.HostID] = true
			}
		}
		jsonOut(w, map[string]any{
			"monitored_endpoints": len(hosts), "connected_sensors": connected,
			"open_incidents": countLive(d.Incidents), "alerts_by_severity": by,
			// Keep the legacy totals while exposing provenance-separated counts.
			"events": len(d.Events), "alerts": len(d.Alerts),
			"live_events": liveEvents, "live_alerts": liveAlerts, "live_incidents": liveIncidents,
			"simulation_events": simulationEvents, "simulation_alerts": simulationAlerts, "simulation_incidents": simulationIncidents,
			"simulation_open_incidents": openSimulationIncidents,
			"mode":                      "LOCAL DEVELOPMENT",
		})
	}))
	mux.HandleFunc("/api/events", read(func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil || parsed < 1 || parsed > store.MaxEventPageSize {
				http.Error(w, "limit must be between 1 and 500", http.StatusBadRequest)
				return
			}
			limit = parsed
		}
		items, nextCursor, err := db.ReadEventsPage(limit, r.URL.Query().Get("cursor"))
		if err != nil {
			if errors.Is(err, store.ErrInvalidEventCursor) || errors.Is(err, store.ErrInvalidEventPageSize) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "could not read event page", http.StatusInternalServerError)
			return
		}
		if items == nil {
			items = []model.Event{}
		}
		jsonOut(w, map[string]any{"items": items, "next_cursor": nextCursor})
	}))
	mux.HandleFunc("/api/endpoints", read(func(w http.ResponseWriter, r *http.Request) {
		latest := map[string]model.Endpoint{}
		d, ok := readData(w, db)
		if !ok {
			return
		}
		now := time.Now().UTC()
		for _, endpoint := range d.Endpoints {
			if isFreshHeartbeat(endpoint.LastHeartbeat, now) {
				endpoint.Status = "online"
			} else {
				endpoint.Status = "stale"
			}
			latest[endpoint.HostID] = endpoint
		}
		for _, event := range d.Events {
			seenAt := event.IngestedAt
			if seenAt.IsZero() {
				seenAt = event.Time
			}
			endpoint, exists := latest[event.HostID]
			if !exists {
				endpoint = model.Endpoint{HostID: event.HostID, Hostname: event.Hostname, OS: "Unknown", Status: "observed", LastSeen: seenAt, Simulated: event.SimulationRunID != ""}
				if endpoint.Simulated {
					endpoint.OS = "Windows (simulated)"
					endpoint.Status = "simulation"
				}
			} else if endpoint.LastHeartbeat.IsZero() {
				if seenAt.After(endpoint.LastSeen) {
					endpoint.LastSeen = seenAt
					endpoint.Hostname = event.Hostname
				}
			}
			if seenAt.After(endpoint.LastEventAt) {
				endpoint.LastEventAt = seenAt
			}
			latest[event.HostID] = endpoint
		}
		endpoints := make([]model.Endpoint, 0, len(latest))
		for _, endpoint := range latest {
			endpoints = append(endpoints, endpoint)
		}
		sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].HostID < endpoints[j].HostID })
		jsonOut(w, endpoints)
	}))
	mux.HandleFunc("/api/alerts", read(func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			items := d.Alerts
			if items == nil {
				items = []model.Alert{}
			}
			jsonOut(w, items)
		}
	}))
	mux.HandleFunc("/api/incidents", read(func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			items := d.Incidents
			if items == nil {
				items = []model.Incident{}
			}
			jsonOut(w, items)
		}
	}))
	mux.HandleFunc("/api/audit", read(func(w http.ResponseWriter, r *http.Request) {
		d, ok := readData(w, db)
		if ok {
			items := d.Audit
			if items == nil {
				items = []map[string]any{}
			}
			jsonOut(w, items)
		}
	}))
	mux.HandleFunc("PATCH /api/alerts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if accessRole(r, tokens) == "" {
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
		if accessRole(r, tokens) == "" {
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
		if accessRole(r, tokens) != "admin" {
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
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, detection.AllRules(sigmaEngine)) })
	mux.HandleFunc("POST /api/rules/test", func(w http.ResponseWriter, r *http.Request) {
		if accessRole(r, tokens) == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var request struct {
			Rule  string      `json:"rule"`
			Event model.Event `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid Sigma test request", http.StatusBadRequest)
			return
		}
		if message := valid(request.Event); message != "" {
			http.Error(w, "invalid test event: "+message, http.StatusBadRequest)
			return
		}
		result, err := detection.TestSigmaRule(request.Rule, request.Event)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonOut(w, result)
	})
	mux.HandleFunc("/api/scenarios", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, simulator.All()) })
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if accessRole(r, tokens) == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var heartbeat model.AgentHeartbeat
		if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
			http.Error(w, "invalid heartbeat", http.StatusBadRequest)
			return
		}
		if message := validHeartbeat(heartbeat); message != "" {
			http.Error(w, message, http.StatusBadRequest)
			return
		}
		if tokens.RequireClientCertHostBinding && !clientCertificateIdentifiesHost(r, heartbeat.HostID) {
			http.Error(w, "client certificate is not enrolled for this host_id", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		endpoint := model.Endpoint{
			HostID: heartbeat.HostID, Hostname: heartbeat.Hostname, OS: heartbeat.OS,
			AgentVersion: heartbeat.AgentVersion, TelemetrySources: heartbeat.TelemetrySources,
			CollectionCapabilities: heartbeat.CollectionCapabilities, Status: "online",
			LastSeen: now, LastHeartbeat: now,
		}
		if err := db.UpsertEndpoint(endpoint); err != nil {
			http.Error(w, "could not persist heartbeat", http.StatusInternalServerError)
			return
		}
		jsonOut(w, map[string]any{"accepted": true, "host_id": endpoint.HostID, "last_heartbeat": endpoint.LastHeartbeat})
	})
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if accessRole(r, tokens) == "" {
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
		if tokens.RequireClientCertHostBinding && !clientCertificateIdentifiesHost(r, e.HostID) {
			http.Error(w, "client certificate is not enrolled for this host_id", http.StatusForbidden)
			return
		}
		process(w, db, e, sigmaEngine)
	})
	mux.HandleFunc("/api/simulate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if accessRole(r, tokens) == "" {
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
		if len(req.RunID) > 128 || strings.TrimSpace(req.RunID) != req.RunID {
			http.Error(w, "invalid run_id", http.StatusBadRequest)
			return
		}
		if _, ok := readData(w, db); !ok {
			return
		}
		for _, event := range selected.Events {
			event.SimulationRunID = req.RunID
			event.ID = req.RunID + "-" + event.ID
			if _, err := processEventWithSigma(db, event, sigmaEngine); err != nil {
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
		actualIDs := make([]string, 0, len(actual))
		for id := range actual {
			actualIDs = append(actualIDs, id)
		}
		evaluation := evaluateScenario(selected.ExpectedRuleIDs, actualIDs)
		runAlertCount := 0
		for _, alert := range d.Alerts {
			if alert.SimulationRunID == req.RunID {
				runAlertCount++
			}
		}
		report := map[string]any{"scenario": selected.Name, "scenario_id": selected.ID, "scenario_version": "1.0", "dataset_version": "1.0", "rule_set_version": "1", "simulation_seed": "deterministic-fixture-v1", "run_id": req.RunID, "event_count": len(selected.Events), "expected_alerts": selected.ExpectedRuleIDs, "detected": evaluation.Detected, "missed": evaluation.Missed, "unexpected": evaluation.Unexpected, "success": evaluation.Success, "precision": ratio(len(evaluation.Detected), len(evaluation.Detected)+len(evaluation.Unexpected)), "recall": ratio(len(evaluation.Detected), len(selected.ExpectedRuleIDs)), "errors": []string{}, "alert_count": runAlertCount}
		jsonOut(w, report)
	})
	mux.Handle("/", http.FileServer(http.Dir("web")))
	return newRateLimiter().wrap(mux)
}

type scenarioEvaluation struct {
	Detected   []string
	Missed     []string
	Unexpected []string
	Success    bool
}

func evaluateScenario(expectedIDs, actualIDs []string) scenarioEvaluation {
	expected := make(map[string]struct{}, len(expectedIDs))
	actual := make(map[string]struct{}, len(actualIDs))
	for _, id := range expectedIDs {
		expected[id] = struct{}{}
	}
	for _, id := range actualIDs {
		actual[id] = struct{}{}
	}
	out := scenarioEvaluation{Detected: []string{}, Missed: []string{}, Unexpected: []string{}}
	for id := range expected {
		if _, ok := actual[id]; ok {
			out.Detected = append(out.Detected, id)
		} else {
			out.Missed = append(out.Missed, id)
		}
	}
	for id := range actual {
		if _, ok := expected[id]; !ok {
			out.Unexpected = append(out.Unexpected, id)
		}
	}
	sort.Strings(out.Detected)
	sort.Strings(out.Missed)
	sort.Strings(out.Unexpected)
	out.Success = len(out.Missed) == 0 && len(out.Unexpected) == 0
	return out
}

func process(w http.ResponseWriter, db store.Repository, e model.Event, sigmaEngine *detection.SigmaEngine) {
	a, err := processEventWithSigma(db, e, sigmaEngine)
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
	return processEventWithSigma(db, e, nil)
}

func processEventWithSigma(db store.Repository, e model.Event, sigmaEngine *detection.SigmaEngine) ([]model.Alert, error) {
	model.RedactSensitive(&e)
	e.IngestedAt = time.Now().UTC()
	previous, err := db.RecentEvents(e, 10*time.Minute, 500)
	if err != nil {
		return nil, err
	}
	matches := detection.Evaluate(e, previous)
	sigmaMatches, err := sigmaEngine.Evaluate(e)
	if err != nil {
		return nil, err
	}
	matches = append(matches, sigmaMatches...)
	alerts := []model.Alert{}
	for _, finding := range matches {
		rule := finding.Rule
		alerts = append(alerts, model.Alert{ID: fmt.Sprintf("ALT-%s-%s", e.ID, rule.ID), RuleID: rule.ID, RuleRevision: rule.Revision, Title: rule.Title, Severity: rule.Severity, Confidence: rule.Confidence, Technique: rule.Technique, HostID: e.HostID, Hostname: e.Hostname, EventIDs: finding.EventIDs, Evidence: finding.Evidence, CreatedAt: time.Now().UTC(), SimulationRunID: e.SimulationRunID, Status: "open"})
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
	if len(e.ID) > 128 || len(e.HostID) > 128 || len(e.Hostname) > 255 || len(e.CommandLine) > 4096 {
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

func validHeartbeat(heartbeat model.AgentHeartbeat) string {
	if heartbeat.HostID == "" || heartbeat.Hostname == "" || heartbeat.OS == "" || heartbeat.AgentVersion == "" {
		return "host_id, hostname, os, and agent_version are required"
	}
	if len(heartbeat.HostID) > 128 || len(heartbeat.Hostname) > 255 || len(heartbeat.OS) > 80 || len(heartbeat.AgentVersion) > 64 {
		return "heartbeat identity field length limit exceeded"
	}
	if len(heartbeat.TelemetrySources) == 0 || len(heartbeat.TelemetrySources) > 32 || len(heartbeat.CollectionCapabilities) > 32 {
		return "heartbeat source or capability count is outside limits"
	}
	for _, value := range append(append([]string{}, heartbeat.TelemetrySources...), heartbeat.CollectionCapabilities...) {
		if strings.TrimSpace(value) == "" || len(value) > 128 {
			return "heartbeat source and capability values must contain 1 to 128 bytes"
		}
	}
	return ""
}

func isFreshHeartbeat(lastHeartbeat, now time.Time) bool {
	return !lastHeartbeat.IsZero() && !lastHeartbeat.After(now) && now.Sub(lastHeartbeat) <= 90*time.Second
}

func auth(r *http.Request, t string) bool {
	return bearerMatches(r.Header.Get("Authorization"), t)
}

func accessRole(r *http.Request, tokens AccessTokens) string {
	header := r.Header.Get("Authorization")
	if bearerMatches(header, tokens.Admin) {
		return "admin"
	}
	if bearerMatches(header, tokens.Analyst) {
		return "analyst"
	}
	return ""
}

func clientCertificateIdentifiesHost(r *http.Request, hostID string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	for _, identity := range r.TLS.PeerCertificates[0].URIs {
		if identity.Scheme == "spiffe" && identity.Host == "sentinel.local" && identity.User == nil &&
			identity.EscapedPath() == "/endpoint/"+url.PathEscape(hostID) &&
			identity.RawQuery == "" && identity.Fragment == "" {
			return true
		}
	}
	return false
}

func bearerMatches(header, token string) bool {
	const prefix = "Bearer "
	if token == "" || !strings.HasPrefix(header, prefix) || len(header) == len(prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), []byte(token)) == 1
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
