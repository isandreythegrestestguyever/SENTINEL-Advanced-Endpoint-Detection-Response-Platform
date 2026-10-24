package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/store"
)

func TestIngestAndAnalystWorkflow(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := headers(routes(db, "test-token"))
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
