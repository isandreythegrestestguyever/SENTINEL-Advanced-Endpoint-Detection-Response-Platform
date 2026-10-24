package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type PostgresStore struct {
	pool *pgxpool.Pool
}

func OpenPostgres(ctx context.Context, connectionString string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	store := &PostgresStore{pool: pool}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
func (s *PostgresStore) Close()                         { s.pool.Close() }

func (s *PostgresStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sentinel_schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("initialize migration table: %w", err)
	}
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list database migrations: %w", err)
	}
	sort.Strings(files)
	for _, name := range files {
		var applied bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sentinel_schema_migrations WHERE version=$1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		source, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		for _, statement := range splitStatements(string(source)) {
			if _, err := tx.Exec(ctx, statement); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("apply migration %s: %w", name, err)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sentinel_schema_migrations(version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

func splitStatements(source string) []string {
	var statements []string
	for _, statement := range strings.Split(source, ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

func (s *PostgresStore) Snapshot() Data {
	data, err := s.ReadSnapshot()
	if err != nil {
		log.Printf("read PostgreSQL snapshot: %v", err)
		return Data{}
	}
	return data
}

func (s *PostgresStore) ReadSnapshot() (Data, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var data Data
	if err := loadJSONRows(ctx, s.pool, `SELECT payload FROM events ORDER BY event_time, event_id`, func(raw []byte) error {
		var item model.Event
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		data.Events = append(data.Events, item)
		return nil
	}); err != nil {
		return Data{}, err
	}
	if err := loadJSONRows(ctx, s.pool, `SELECT payload FROM alerts ORDER BY created_at, alert_id`, func(raw []byte) error {
		var item model.Alert
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		data.Alerts = append(data.Alerts, item)
		return nil
	}); err != nil {
		return Data{}, err
	}
	if err := loadJSONRows(ctx, s.pool, `SELECT payload FROM incidents ORDER BY updated_at, incident_id`, func(raw []byte) error {
		var item model.Incident
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		data.Incidents = append(data.Incidents, item)
		return nil
	}); err != nil {
		return Data{}, err
	}
	if err := loadJSONRows(ctx, s.pool, `SELECT payload FROM audit_log ORDER BY audit_id`, func(raw []byte) error {
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		data.Audit = append(data.Audit, item)
		return nil
	}); err != nil {
		return Data{}, err
	}
	return data, nil
}

func loadJSONRows(ctx context.Context, pool *pgxpool.Pool, query string, appendRow func([]byte) error) error {
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		if err := appendRow(payload); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *PostgresStore) AddEvent(event model.Event, alerts []model.Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	eventPayload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO events(event_id,host_id,simulation_run_id,event_time,ingested_at,payload) VALUES($1,$2,$3,$4,$5,$6)`, event.ID, event.HostID, event.SimulationRunID, event.Time, event.IngestedAt, eventPayload)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateEvent
		}
		return err
	}
	for _, alert := range alerts {
		if err := insertAlert(ctx, tx, alert); err != nil {
			return err
		}
		if err := attachAlertToIncident(ctx, tx, alert); err != nil {
			return err
		}
	}
	if err := insertAudit(ctx, tx, map[string]any{"action": "event.ingested", "event_id": event.ID, "time": time.Now().UTC()}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertAlert(ctx context.Context, tx pgx.Tx, alert model.Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alerts(alert_id,host_id,simulation_run_id,created_at,payload) VALUES($1,$2,$3,$4,$5)`, alert.ID, alert.HostID, alert.SimulationRunID, alert.CreatedAt, payload); err != nil {
		return err
	}
	for _, eventID := range alert.EventIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO alert_events(alert_id,event_id) VALUES($1,$2)`, alert.ID, eventID); err != nil {
			return err
		}
	}
	return nil
}

func attachAlertToIncident(ctx context.Context, tx pgx.Tx, alert model.Alert) error {
	lockID := alert.HostID + "\x00" + alert.SimulationRunID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockID); err != nil {
		return err
	}
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM incidents WHERE host_id=$1 AND simulation_run_id=$2 AND updated_at >= $3 ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`, alert.HostID, alert.SimulationRunID, alert.CreatedAt.Add(-30*time.Minute)).Scan(&payload)
	var incident model.Incident
	if errors.Is(err, pgx.ErrNoRows) {
		incident = model.Incident{ID: "INC-" + alert.ID, HostID: alert.HostID, Hostname: alert.Hostname, Severity: alert.Severity, Status: "open", SimulationRunID: alert.SimulationRunID, UpdatedAt: alert.CreatedAt}
	} else if err != nil {
		return err
	} else if err := json.Unmarshal(payload, &incident); err != nil {
		return err
	}
	incident.AlertIDs = append(incident.AlertIDs, alert.ID)
	incident.UpdatedAt = alert.CreatedAt
	if severityRank(alert.Severity) > severityRank(incident.Severity) {
		incident.Severity = alert.Severity
	}
	encoded, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO incidents(incident_id,host_id,simulation_run_id,updated_at,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(incident_id) DO UPDATE SET updated_at=EXCLUDED.updated_at,payload=EXCLUDED.payload`, incident.ID, incident.HostID, incident.SimulationRunID, incident.UpdatedAt, encoded)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO incident_alerts(incident_id,alert_id) VALUES($1,$2)`, incident.ID, alert.ID)
	return err
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func (s *PostgresStore) UpdateAlert(id string, status, note, assignee *string) (model.Alert, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Alert{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM alerts WHERE alert_id=$1 FOR UPDATE`, id).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Alert{}, false, nil
	}
	if err != nil {
		return model.Alert{}, false, err
	}
	var alert model.Alert
	if err := json.Unmarshal(payload, &alert); err != nil {
		return model.Alert{}, false, err
	}
	if status != nil {
		alert.Status = *status
	}
	if note != nil {
		alert.AnalystNotes = *note
	}
	if assignee != nil {
		alert.Assignee = *assignee
	}
	payload, err = json.Marshal(alert)
	if err != nil {
		return model.Alert{}, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET payload=$2 WHERE alert_id=$1`, id, payload); err != nil {
		return model.Alert{}, false, err
	}
	if err := insertAudit(ctx, tx, map[string]any{"action": "alert.updated", "alert_id": id, "status": alert.Status, "time": time.Now().UTC()}); err != nil {
		return model.Alert{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Alert{}, false, err
	}
	return alert, true, nil
}

func (s *PostgresStore) UpdateIncident(id string, status, note *string) (model.Incident, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Incident{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM incidents WHERE incident_id=$1 FOR UPDATE`, id).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Incident{}, false, nil
	}
	if err != nil {
		return model.Incident{}, false, err
	}
	var incident model.Incident
	if err := json.Unmarshal(payload, &incident); err != nil {
		return model.Incident{}, false, err
	}
	if status != nil {
		incident.Status = *status
	}
	if note != nil {
		incident.AnalystNotes = *note
	}
	incident.UpdatedAt = time.Now().UTC()
	payload, err = json.Marshal(incident)
	if err != nil {
		return model.Incident{}, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET updated_at=$2,payload=$3 WHERE incident_id=$1`, id, incident.UpdatedAt, payload); err != nil {
		return model.Incident{}, false, err
	}
	if err := insertAudit(ctx, tx, map[string]any{"action": "incident.updated", "incident_id": id, "status": incident.Status, "time": time.Now().UTC()}); err != nil {
		return model.Incident{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Incident{}, false, err
	}
	return incident, true, nil
}

func (s *PostgresStore) RemoveSimulation(runID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM incidents WHERE simulation_run_id=$1`, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE simulation_run_id=$1`, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM events WHERE simulation_run_id=$1`, runID); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, map[string]any{"action": "simulation.reset", "run_id": runID, "time": time.Now().UTC()}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertAudit(ctx context.Context, tx pgx.Tx, entry map[string]any) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(created_at,payload) VALUES($1,$2)`, time.Now().UTC(), payload)
	return err
}
