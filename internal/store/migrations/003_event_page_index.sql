CREATE INDEX IF NOT EXISTS events_ingested_page_idx ON events (ingested_at DESC, event_id DESC);
