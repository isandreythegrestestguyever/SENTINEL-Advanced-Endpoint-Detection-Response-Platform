package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/store"
)

func TestIngestAndAnalystWorkflow(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "test-token"}))
	event := model.Event{
		ID: "evt-1", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "lab-1",
		Hostname: "LAB-1", Source: "test", Type: "process_start", Category: "endpoint",
		CommandLine: "powershell.exe -EncodedCommand SAMPLE --token=sample-only-secret", SimulationRunID: "run-1",
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	response := send(t, handler, http.MethodPost, "/api/ingest", body, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated ingest status = %d, want 401", response.Code)
	}

	response = send(t, handler, http.MethodPost, "/api/ingest", body, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var accepted struct {
		Accepted bool          `json:"accepted"`
		Alerts   []model.Alert `json:"alerts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted || len(accepted.Alerts) != 1 || accepted.Alerts[0].RuleID != "SEN-EXEC-001" {
		t.Fatalf("unexpected ingest result: %#v", accepted)
	}
	stored := db.Snapshot()
	if len(stored.Events) != 1 || stored.Events[0].CommandLine == "" || strings.Contains(stored.Events[0].CommandLine, "sample-only-secret") || !strings.Contains(stored.Events[0].CommandLine, "[REDACTED]") {
		t.Fatalf("ingested command line was not safely redacted before storage: %#v", stored.Events)
	}

	response = send(t, handler, http.MethodPost, "/api/ingest", body, "test-token")
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate ingest status = %d, want 409", response.Code)
	}

	alertID := accepted.Alerts[0].ID
	patchJSON(t, handler, "/api/alerts/"+alertID, `{"status":"acknowledged","analyst_notes":"reviewed","assignee":"analyst-1"}`, "test-token", http.StatusOK)
	updated := patchJSON(t, handler, "/api/alerts/"+alertID, `{"analyst_notes":"","assignee":""}`, "test-token", http.StatusOK)
	var alert model.Alert
	if err := json.Unmarshal(updated, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.Status != "acknowledged" || alert.AnalystNotes != "" || alert.Assignee != "" {
		t.Fatalf("partial update did not preserve status and clear notes: %#v", alert)
	}

	response = send(t, handler, http.MethodGet, "/api/incidents", nil, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated incident read status = %d, want 401", response.Code)
	}
	response = send(t, handler, http.MethodGet, "/api/incidents", nil, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("incident list status = %d", response.Code)
	}
	var incidents []model.Incident
	if err := json.NewDecoder(response.Body).Decode(&incidents); err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].SimulationRunID != "run-1" {
		t.Fatalf("unexpected incident list: %#v", incidents)
	}
	patchJSON(t, handler, "/api/incidents/"+incidents[0].ID, `{"status":"investigating","analyst_notes":"triaged"}`, "test-token", http.StatusOK)

	var overview struct {
		Events              int `json:"events"`
		Alerts              int `json:"alerts"`
		LiveEvents          int `json:"live_events"`
		LiveAlerts          int `json:"live_alerts"`
		LiveIncidents       int `json:"live_incidents"`
		SimulationEvents    int `json:"simulation_events"`
		SimulationAlerts    int `json:"simulation_alerts"`
		SimulationIncidents int `json:"simulation_incidents"`
		SimulationOpenCases int `json:"simulation_open_incidents"`
	}
	response = send(t, handler, http.MethodGet, "/api/overview", nil, "test-token")
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&overview) != nil {
		t.Fatalf("overview request failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if overview.Events != 1 || overview.Alerts != 1 || overview.LiveEvents != 0 || overview.LiveAlerts != 0 || overview.LiveIncidents != 0 || overview.SimulationEvents != 1 || overview.SimulationAlerts != 1 || overview.SimulationIncidents != 1 || overview.SimulationOpenCases != 0 {
		t.Fatalf("simulation-only counts crossed the live boundary: %#v", overview)
	}

	liveEvent := event
	liveEvent.ID = "evt-live-1"
	liveEvent.HostID = "prod-host-1"
	liveEvent.Hostname = "PROD-HOST-1"
	liveEvent.SimulationRunID = ""
	liveBody, err := json.Marshal(liveEvent)
	if err != nil {
		t.Fatal(err)
	}
	response = send(t, handler, http.MethodPost, "/api/ingest", liveBody, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("live ingest status = %d, want 200: %s", response.Code, response.Body.String())
	}
	response = send(t, handler, http.MethodGet, "/api/overview", nil, "test-token")
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&overview) != nil {
		t.Fatalf("overview request failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if overview.Events != 2 || overview.Alerts != 2 || overview.LiveEvents != 1 || overview.LiveAlerts != 1 || overview.LiveIncidents != 1 || overview.SimulationEvents != 1 || overview.SimulationAlerts != 1 || overview.SimulationIncidents != 1 || overview.SimulationOpenCases != 0 {
		t.Fatalf("overview did not distinguish live and simulation records: %#v", overview)
	}

	response = send(t, handler, http.MethodDelete, "/api/simulations/run-1", nil, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("simulation reset status = %d, want 200", response.Code)
	}
	if data := db.Snapshot(); len(data.Events) != 1 || len(data.Alerts) != 1 || len(data.Incidents) != 1 || data.Events[0].ID != liveEvent.ID || data.Events[0].SimulationRunID != "" {
		t.Fatalf("simulation reset removed live data or left simulation data: %#v", data)
	}
}

func TestBundledSigmaRuleCreatesAlertThroughAuthenticatedIngest(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token"}))
	event := model.Event{
		ID: "sigma-live-1", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "endpoint-1",
		Hostname: "ENDPOINT-1", Source: "windows-eventlog", Category: "process", Type: "process_start",
		Image: `C:\Users\Public\Tools\support.exe`,
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	response := send(t, handler, http.MethodPost, "/api/ingest", body, "admin-token")
	if response.Code != http.StatusOK {
		t.Fatalf("Sigma-backed ingestion status = %d: %s", response.Code, response.Body.String())
	}
	var accepted struct {
		Alerts []model.Alert `json:"alerts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&accepted); err != nil {
		t.Fatal(err)
	}
	if len(accepted.Alerts) != 1 {
		t.Fatalf("expected one Sigma alert, got %#v", accepted.Alerts)
	}
	alert := accepted.Alerts[0]
	if alert.RuleID != "SEN-SIGMA-PUBLIC-001" || alert.RuleRevision != 1 || alert.Severity != "medium" || alert.Confidence != 0 || len(alert.EventIDs) != 1 || alert.EventIDs[0] != event.ID || !strings.Contains(alert.Evidence, "7b0cbd19-cc70-4a9b-b6d1-87c51756a422") {
		t.Fatalf("unexpected active Sigma alert: %#v", alert)
	}
	response = send(t, handler, http.MethodGet, "/api/rules", nil, "admin-token")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"kind":"sigma"`) || !strings.Contains(response.Body.String(), "SEN-SIGMA-PUBLIC-001") {
		t.Fatalf("active Sigma rule missing from catalog: status=%d body=%s", response.Code, response.Body.String())
	}

	event.ID = "sigma-live-2"
	event.Category = "network"
	event.Type = "network_connection"
	body, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	response = send(t, handler, http.MethodPost, "/api/ingest", body, "admin-token")
	if response.Code != http.StatusOK {
		t.Fatalf("unrelated event ingest status = %d: %s", response.Code, response.Body.String())
	}
	accepted = struct {
		Alerts []model.Alert `json:"alerts"`
	}{}
	if err := json.NewDecoder(response.Body).Decode(&accepted); err != nil || len(accepted.Alerts) != 0 {
		t.Fatalf("process_creation Sigma rule matched unrelated source: alerts=%#v err=%v", accepted.Alerts, err)
	}
}

func TestAuthRequiresBearerScheme(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	for _, value := range []string{"", "test-token", "Bearer ", "Bearer wrong"} {
		request.Header.Set("Authorization", value)
		if auth(request, "test-token") {
			t.Errorf("auth accepted invalid authorization value %q", value)
		}
	}
	request.Header.Set("Authorization", "Bearer test-token")
	if !auth(request, "test-token") {
		t.Fatal("auth rejected a valid bearer token")
	}
}

func TestSigmaRuleTestRouteRequiresAuthAndDoesNotPersist(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token", Analyst: "analyst-token"}))
	request := struct {
		Rule  string      `json:"rule"`
		Event model.Event `json:"event"`
	}{
		Rule: `title: Encoded PowerShell
id: 7ad5e09c-34f5-4e22-8c22-355a4fb27810
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: encodedcommand
  condition: selection
level: high
`,
		Event: model.Event{ID: "sigma-test-event", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "sigma-host", Hostname: "SIGMA-HOST", Source: "test", Type: "process_start", CommandLine: "powershell.exe -EncodedCommand SAMPLE"},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if response := send(t, handler, http.MethodPost, "/api/rules/test", body, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Sigma test status = %d, want 401", response.Code)
	}
	response := send(t, handler, http.MethodPost, "/api/rules/test", body, "analyst-token")
	if response.Code != http.StatusOK {
		t.Fatalf("Sigma test status = %d: %s", response.Code, response.Body.String())
	}
	var result struct {
		Matched bool `json:"matched"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || !result.Matched {
		t.Fatalf("Sigma test result = %#v, err=%v", result, err)
	}
	if data := db.Snapshot(); len(data.Events) != 0 || len(data.Alerts) != 0 || len(data.Audit) != 0 {
		t.Fatalf("read-only Sigma test modified stored data: %#v", data)
	}
}

func TestScenarioEvaluationFailsMissedAndUnexpectedRules(t *testing.T) {
	passed := evaluateScenario([]string{"SEN-A", "SEN-B"}, []string{"SEN-A", "SEN-B", "SEN-B"})
	if !passed.Success || len(passed.Detected) != 2 || len(passed.Missed) != 0 || len(passed.Unexpected) != 0 {
		t.Fatalf("matching rules should pass with duplicate IDs deduplicated: %#v", passed)
	}

	unexpected := evaluateScenario([]string{"SEN-A"}, []string{"SEN-A", "SEN-X"})
	if unexpected.Success || len(unexpected.Missed) != 0 || len(unexpected.Unexpected) != 1 || unexpected.Unexpected[0] != "SEN-X" {
		t.Fatalf("unexpected rule should fail the scenario: %#v", unexpected)
	}

	missed := evaluateScenario([]string{"SEN-A"}, nil)
	if missed.Success || len(missed.Missed) != 1 || missed.Missed[0] != "SEN-A" {
		t.Fatalf("missed expected rule should fail the scenario: %#v", missed)
	}
}

func TestRetentionWindowConfiguration(t *testing.T) {
	for _, test := range []struct {
		input string
		want  time.Duration
		bad   bool
	}{
		{input: "", want: 0},
		{input: "0", want: 0},
		{input: "30", want: 30 * 24 * time.Hour},
		{input: "-1", bad: true},
		{input: "36501", bad: true},
		{input: "many", bad: true},
	} {
		got, err := parseRetentionWindow(test.input)
		if (err != nil) != test.bad || (!test.bad && got != test.want) {
			t.Errorf("parseRetentionWindow(%q) = %s, %v; want %s, bad=%v", test.input, got, err, test.want, test.bad)
		}
	}
}

func TestRateLimiterBoundsWritesByClientAndRefills(t *testing.T) {
	now := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	limiter := newRateLimiter()
	limiter.now = func() time.Time { return now }
	limiter.policies["ingest"] = ratePolicy{rate: 1, burst: 2}
	called := 0
	handler := limiter.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(remote string, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = remote
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	for i := 0; i < 2; i++ {
		if response := request("192.0.2.10:4000", "/api/ingest"); response.Code != http.StatusNoContent {
			t.Fatalf("request %d unexpectedly limited: %d", i+1, response.Code)
		}
	}
	limited := request("192.0.2.10:4000", "/api/ingest")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("excess ingest request was not bounded with Retry-After: status=%d headers=%v", limited.Code, limited.Header())
	}
	if response := request("192.0.2.11:4000", "/api/ingest"); response.Code != http.StatusNoContent {
		t.Fatalf("one client exhausted another client's budget: %d", response.Code)
	}
	now = now.Add(time.Second)
	if response := request("192.0.2.10:4000", "/api/ingest"); response.Code != http.StatusNoContent {
		t.Fatalf("token bucket did not refill: %d", response.Code)
	}
	if response := request("192.0.2.10:4000", "/api/health"); response.Code != http.StatusNoContent {
		t.Fatalf("read-only route was rate limited: %d", response.Code)
	}
	if called != 5 {
		t.Fatalf("downstream handler called %d times, want 5", called)
	}
}

func TestEventValidationBoundsHostIdentity(t *testing.T) {
	event := model.Event{ID: "bounded", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "host-1", Hostname: "HOST-1", Source: "test", Type: "process_start"}
	if message := valid(event); message != "" {
		t.Fatalf("valid event rejected: %s", message)
	}
	event.HostID = string(bytes.Repeat([]byte{'h'}, 129))
	if message := valid(event); message == "" {
		t.Fatal("event with oversized host_id was accepted")
	}
}

func TestAnalystCanReadButCannotResetSimulation(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token", Analyst: "analyst-token"}))
	response := send(t, handler, http.MethodGet, "/api/events", nil, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated event read status = %d, want 401", response.Code)
	}
	response = send(t, handler, http.MethodGet, "/api/events", nil, "analyst-token")
	if response.Code != http.StatusOK {
		t.Fatalf("analyst event read status = %d, want 200", response.Code)
	}
	response = send(t, handler, http.MethodDelete, "/api/simulations/run-1", nil, "analyst-token")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("analyst simulation reset status = %d, want 401", response.Code)
	}
	response = send(t, handler, http.MethodDelete, "/api/simulations/run-1", nil, "admin-token")
	if response.Code != http.StatusOK {
		t.Fatalf("administrator simulation reset status = %d, want 200", response.Code)
	}
}

func TestEmptyReadCollectionsReturnJSONArrays(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token"}))
	for _, path := range []string{"/api/alerts", "/api/incidents", "/api/audit"} {
		response := send(t, handler, http.MethodGet, path, nil, "admin-token")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, response.Code)
		}
		var items []json.RawMessage
		if err := json.NewDecoder(response.Body).Decode(&items); err != nil {
			t.Fatalf("GET %s did not return a JSON array: %v", path, err)
		}
		if items == nil || len(items) != 0 {
			t.Fatalf("GET %s = %s, want []", path, response.Body.String())
		}
	}
	response := send(t, handler, http.MethodGet, "/api/events", nil, "admin-token")
	var page struct {
		Items []model.Event `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Items == nil {
		t.Fatal("GET /api/events returned null items, want []")
	}
}

func TestEventsAPIUsesBoundedCursorPages(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"page-a", "page-b", "page-c"} {
		event := model.Event{ID: id, SchemaVersion: "1.0", Time: now, IngestedAt: now, HostID: "page-host", Hostname: "PAGE-HOST", Source: "test", Type: "page_test"}
		if err := db.AddEvent(event, nil); err != nil {
			t.Fatal(err)
		}
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token"}))
	if response := send(t, handler, http.MethodGet, "/api/events?limit=1", nil, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated page status = %d, want 401", response.Code)
	}
	response := send(t, handler, http.MethodGet, "/api/events?limit=1", nil, "admin-token")
	var page struct {
		Items      []model.Event `json:"items"`
		NextCursor string        `json:"next_cursor"`
	}
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&page) != nil || len(page.Items) != 1 || page.Items[0].ID != "page-c" || page.NextCursor == "" {
		t.Fatalf("first API page = %#v, status=%d", page, response.Code)
	}
	path := "/api/events?limit=1&cursor=" + url.QueryEscape(page.NextCursor)
	response = send(t, handler, http.MethodGet, path, nil, "admin-token")
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&page) != nil || len(page.Items) != 1 || page.Items[0].ID != "page-b" {
		t.Fatalf("second API page = %#v, status=%d", page, response.Code)
	}
	if response := send(t, handler, http.MethodGet, "/api/events?limit=501", nil, "admin-token"); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized page limit status = %d, want 400", response.Code)
	}
	if response := send(t, handler, http.MethodGet, "/api/events?cursor=not-a-cursor", nil, "admin-token"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor status = %d, want 400", response.Code)
	}
}

func TestHeartbeatRegistersFleetAndExpiresSensorStatus(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "admin-token", Analyst: "agent-token"}))
	heartbeat := model.AgentHeartbeat{
		HostID: "agent-1", Hostname: "AGENT-1", OS: "Windows 11", AgentVersion: "0.1.0",
		TelemetrySources:       []string{"Security", "Microsoft-Windows-Sysmon/Operational"},
		CollectionCapabilities: []string{"process", "authentication", "network"},
	}
	body, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if response := send(t, handler, http.MethodPost, "/api/heartbeat", body, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated heartbeat status = %d, want 401", response.Code)
	}
	response := send(t, handler, http.MethodPost, "/api/heartbeat", body, "agent-token")
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d: %s", response.Code, response.Body.String())
	}
	if len(db.Snapshot().Endpoints) != 1 || db.Snapshot().Endpoints[0].HostID != heartbeat.HostID {
		t.Fatalf("heartbeat did not register endpoint: %#v", db.Snapshot().Endpoints)
	}

	response = send(t, handler, http.MethodGet, "/api/endpoints", nil, "admin-token")
	var endpoints []model.Endpoint
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&endpoints) != nil {
		t.Fatalf("endpoint inventory returned %d: %s", response.Code, response.Body.String())
	}
	if len(endpoints) != 1 || endpoints[0].Status != "online" || endpoints[0].AgentVersion != "0.1.0" || len(endpoints[0].TelemetrySources) != 2 {
		t.Fatalf("unexpected online endpoint view: %#v", endpoints)
	}
	response = send(t, handler, http.MethodGet, "/api/overview", nil, "admin-token")
	var overview struct {
		ConnectedSensors int `json:"connected_sensors"`
	}
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&overview) != nil || overview.ConnectedSensors != 1 {
		t.Fatalf("overview did not count fresh sensor heartbeat: status=%d data=%#v", response.Code, overview)
	}

	stale := endpoints[0]
	stale.LastHeartbeat = time.Now().UTC().Add(-2 * time.Minute)
	stale.LastSeen = stale.LastHeartbeat
	if err := db.UpsertEndpoint(stale); err != nil {
		t.Fatal(err)
	}
	response = send(t, handler, http.MethodGet, "/api/endpoints", nil, "admin-token")
	endpoints = nil
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&endpoints) != nil || len(endpoints) != 1 || endpoints[0].Status != "stale" {
		t.Fatalf("expired heartbeat was not marked stale: status=%d endpoints=%#v", response.Code, endpoints)
	}
	response = send(t, handler, http.MethodGet, "/api/overview", nil, "admin-token")
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&overview) != nil || overview.ConnectedSensors != 0 {
		t.Fatalf("stale heartbeat counted as connected: status=%d data=%#v", response.Code, overview)
	}
}

func TestMtlSIngestBindsCertificateUriToEventHost(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("spiffe://sentinel.local/endpoint/host-1")
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "test-token", RequireClientCertHostBinding: true}))
	certificate := &x509.Certificate{URIs: []*url.URL{identity}}

	otherHost := model.Event{ID: "other-host-event", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "host-2", Hostname: "HOST-2", Source: "test", Type: "process_start"}
	body, err := json.Marshal(otherHost)
	if err != nil {
		t.Fatal(err)
	}
	response := sendWithPeerCertificate(t, handler, body, "test-token", certificate)
	if response.Code != http.StatusForbidden {
		t.Fatalf("certificate for host-1 ingested host-2 event: status %d", response.Code)
	}
	if got := len(db.Snapshot().Events); got != 0 {
		t.Fatalf("mismatched certificate wrote %d events", got)
	}

	otherHost.ID = "matching-host-event"
	otherHost.HostID = "host-1"
	otherHost.Hostname = "HOST-1"
	body, err = json.Marshal(otherHost)
	if err != nil {
		t.Fatal(err)
	}
	response = sendWithPeerCertificate(t, handler, body, "test-token", certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("certificate host identity was rejected: status %d", response.Code)
	}
	response = sendWithPeerCertificate(t, handler, body, "test-token", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing client certificate was accepted: status %d", response.Code)
	}

	heartbeat := model.AgentHeartbeat{HostID: "host-2", Hostname: "HOST-2", OS: "Windows", AgentVersion: "0.1.0", TelemetrySources: []string{"Security"}, CollectionCapabilities: []string{"windows_event_log"}}
	body, err = json.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	response = sendWithPeerCertificatePath(t, handler, "/api/heartbeat", body, "test-token", certificate)
	if response.Code != http.StatusForbidden {
		t.Fatalf("certificate for host-1 registered host-2 heartbeat: status %d", response.Code)
	}
	heartbeat.HostID, heartbeat.Hostname = "host-1", "HOST-1"
	body, err = json.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	response = sendWithPeerCertificatePath(t, handler, "/api/heartbeat", body, "test-token", certificate)
	if response.Code != http.StatusOK {
		t.Fatalf("certificate host identity was rejected for heartbeat: status %d", response.Code)
	}
}

func TestTLSConfigurationCanRequireVerifiedClientCertificates(t *testing.T) {
	t.Setenv("SENTINEL_TLS_CERT", "")
	t.Setenv("SENTINEL_TLS_KEY", "")
	t.Setenv("SENTINEL_CLIENT_CA", "")
	config, err := tlsConfigFromEnv()
	if err != nil || config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.NoClientCert {
		t.Fatalf("default TLS configuration = %#v, %v", config, err)
	}

	t.Setenv("SENTINEL_TLS_CERT", "server.crt")
	t.Setenv("SENTINEL_TLS_KEY", "server.key")
	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINEL_CLIENT_CA", caPath)
	config, err = tlsConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.VerifyClientCertIfGiven || config.ClientCAs == nil {
		t.Fatalf("mTLS configuration is incomplete: %#v", config)
	}
	if _, err := tlsConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINEL_TLS_KEY", "")
	if _, err := tlsConfigFromEnv(); err == nil {
		t.Fatal("TLS configuration accepted a certificate without its key")
	}
}

func TestIngestTriggersBoundedAuthenticationCorrelation(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "test-token"}))
	base := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	for index := 0; index < 3; index++ {
		event := model.Event{ID: fmt.Sprintf("auth-%d", index), SchemaVersion: "1.0", Time: base.Add(time.Duration(index) * time.Minute), HostID: "auth-host", Hostname: "AUTH-HOST", Source: "test", Type: "authentication_failure", SimulationRunID: "auth-run"}
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		response := send(t, handler, http.MethodPost, "/api/ingest", body, "test-token")
		if response.Code != http.StatusOK {
			t.Fatalf("event %d ingest status = %d: %s", index+1, response.Code, response.Body.String())
		}
		var result struct {
			Alerts []model.Alert `json:"alerts"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if index < 2 && len(result.Alerts) != 0 {
			t.Fatalf("event %d alerted before threshold: %#v", index+1, result.Alerts)
		}
		if index == 2 {
			if len(result.Alerts) != 1 || result.Alerts[0].RuleID != "SEN-AUTH-003" || len(result.Alerts[0].EventIDs) != 3 {
				t.Fatalf("third event produced unexpected alert: %#v", result.Alerts)
			}
		}
	}
}

func TestAllScenarioExpectedRulesThroughHTTPPath(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "test-token"}))
	for _, scenario := range simulator.All() {
		found := map[string]bool{}
		runID := "http-" + scenario.ID
		for _, fixture := range scenario.Events {
			event := fixture
			event.ID = runID + "-" + fixture.ID
			event.SimulationRunID = runID
			body, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			response := send(t, handler, http.MethodPost, "/api/ingest", body, "test-token")
			if response.Code != http.StatusOK {
				t.Fatalf("%s event %s ingest status = %d: %s", scenario.ID, fixture.ID, response.Code, response.Body.String())
			}
			var result struct {
				Alerts []model.Alert `json:"alerts"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			for _, alert := range result.Alerts {
				found[alert.RuleID] = true
			}
		}
		for _, expected := range scenario.ExpectedRuleIDs {
			if !found[expected] {
				t.Errorf("%s did not produce %s through HTTP ingest", scenario.ID, expected)
			}
		}
		if err := db.RemoveSimulation(runID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSimulationEndpointPreservesFixtureTimeAndScopesReport(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, AccessTokens{Admin: "test-token"}))
	background := model.Event{ID: "background", SchemaVersion: "1.0", Time: time.Now().UTC(), HostID: "other-host", Hostname: "OTHER", Source: "test", Type: "process_start", CommandLine: "powershell.exe -EncodedCommand sample"}
	backgroundBody, err := json.Marshal(background)
	if err != nil {
		t.Fatal(err)
	}
	if response := send(t, handler, http.MethodPost, "/api/ingest", backgroundBody, "test-token"); response.Code != http.StatusOK {
		t.Fatalf("background event status = %d: %s", response.Code, response.Body.String())
	}

	requestBody := []byte(`{"scenario_id":"S01","run_id":"repeatable-run"}`)
	response := send(t, handler, http.MethodPost, "/api/simulate", requestBody, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("simulation status = %d: %s", response.Code, response.Body.String())
	}
	var report struct {
		Success    bool     `json:"success"`
		AlertCount int      `json:"alert_count"`
		EventCount int      `json:"event_count"`
		Detected   []string `json:"detected"`
	}
	if err := json.NewDecoder(response.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if !report.Success || report.AlertCount != 3 || report.EventCount != 2 {
		t.Fatalf("simulation report does not describe this run: %#v", report)
	}
	if !slices.Contains(report.Detected, "SEN-SIGMA-PUBLIC-001") {
		t.Fatalf("S01 simulation did not validate the bundled Sigma detection: %#v", report.Detected)
	}

	fixtures := simulator.All()[0].Events
	for _, event := range db.Snapshot().Events {
		if event.SimulationRunID != "repeatable-run" {
			continue
		}
		var fixtureTime time.Time
		for _, fixture := range fixtures {
			if event.ID == "repeatable-run-"+fixture.ID {
				fixtureTime = fixture.Time
				break
			}
		}
		if fixtureTime.IsZero() || !event.Time.Equal(fixtureTime) {
			t.Errorf("event %s time = %s, want deterministic fixture time %s", event.ID, event.Time, fixtureTime)
		}
	}
	if response := send(t, handler, http.MethodPost, "/api/simulate", []byte(`{"scenario_id":"S01","run_id":" bad"}`), "test-token"); response.Code != http.StatusBadRequest {
		t.Fatalf("simulation accepted invalid run id: %d", response.Code)
	}
}

func send(t *testing.T, handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func sendWithPeerCertificate(t *testing.T, handler http.Handler, body []byte, token string, certificate *x509.Certificate) *httptest.ResponseRecorder {
	return sendWithPeerCertificatePath(t, handler, "/api/ingest", body, token, certificate)
}

func sendWithPeerCertificatePath(t *testing.T, handler http.Handler, path string, body []byte, token string, certificate *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	if certificate != nil {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func patchJSON(t *testing.T, handler http.Handler, path, payload, token string, wantStatus int) []byte {
	t.Helper()
	response := send(t, handler, http.MethodPatch, path, []byte(payload), token)
	if response.Code != wantStatus {
		t.Fatalf("PATCH %s status = %d, want %d: %s", path, response.Code, wantStatus, response.Body.String())
	}
	return response.Body.Bytes()
}
