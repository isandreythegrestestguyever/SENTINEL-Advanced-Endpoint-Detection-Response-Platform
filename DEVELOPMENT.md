# Development

Use Go 1.22+ and a modern browser. The backend uses only Go's standard library; the dashboard needs no build step or third-party runtime packages.

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
SENTINEL_ADMIN_TOKEN='local-development-secret' go run ./cmd/sentinel
```

Never use a real secret as a development token. Keep the listener on loopback. The JSON store is generated at runtime and ignored by Git. Tests check that scenario expected rules have matching events; they do not verify a Windows sensor or deployment hardening.
