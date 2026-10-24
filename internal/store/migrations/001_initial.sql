CREATE TABLE IF NOT EXISTS events (
    event_id text PRIMARY KEY,
    host_id text NOT NULL,
    simulation_run_id text NOT NULL DEFAULT '',
    event_time timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS events_host_time_idx ON events (host_id, event_time DESC);
CREATE INDEX IF NOT EXISTS events_run_idx ON events (simulation_run_id) WHERE simulation_run_id <> '';

CREATE TABLE IF NOT EXISTS alerts (
    alert_id text PRIMARY KEY,
    host_id text NOT NULL,
    simulation_run_id text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS alerts_host_created_idx ON alerts (host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_run_idx ON alerts (simulation_run_id) WHERE simulation_run_id <> '';

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id text NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id text NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id text PRIMARY KEY,
    host_id text NOT NULL,
    simulation_run_id text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_host_updated_idx ON incidents (host_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS incidents_run_idx ON incidents (simulation_run_id) WHERE simulation_run_id <> '';

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id text NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id text NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id bigserial PRIMARY KEY,
    created_at timestamptz NOT NULL,
    payload jsonb NOT NULL
);
