# Development

Use Go 1.25+ and a modern browser. The backend uses Go's standard library plus its pinned PostgreSQL driver; the dashboard needs no build step or third-party runtime packages.

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
SENTINEL_ADMIN_TOKEN='local-development-admin' \
SENTINEL_ANALYST_TOKEN='local-development-analyst' \
go run ./cmd/sentinel
```

Never use a real secret as a development token. Keep the listener on loopback. The administrator token can access every API route and reset simulations. The optional analyst token can read telemetry and submit events or analyst updates, but cannot reset simulations. Both values must differ. The JSON store is generated at runtime and ignored by Git. Tests do not verify a Windows sensor or deployment hardening.
