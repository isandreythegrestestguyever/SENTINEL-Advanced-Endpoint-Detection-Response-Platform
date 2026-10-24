package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		CommandLine: "powershell.exe -EncodedCommand SAMPLE", SimulationRunID: "run-1",
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

	response = send(t, handler, http.MethodDelete, "/api/simulations/run-1", nil, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("simulation reset status = %d, want 200", response.Code)
	}
	if data := db.Snapshot(); len(data.Events) != 0 || len(data.Alerts) != 0 || len(data.Incidents) != 0 {
		t.Fatalf("simulation reset left data behind: %#v", data)
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

func patchJSON(t *testing.T, handler http.Handler, path, payload, token string, wantStatus int) []byte {
	t.Helper()
	response := send(t, handler, http.MethodPatch, path, []byte(payload), token)
	if response.Code != wantStatus {
		t.Fatalf("PATCH %s status = %d, want %d: %s", path, response.Code, wantStatus, response.Body.String())
	}
	return response.Body.Bytes()
}
