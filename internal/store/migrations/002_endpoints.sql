CREATE TABLE IF NOT EXISTS endpoints (
    host_id text PRIMARY KEY,
    last_heartbeat timestamptz NOT NULL,
    payload jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS endpoints_last_heartbeat_idx ON endpoints (last_heartbeat DESC);
