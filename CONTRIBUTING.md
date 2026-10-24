# Contributing

Keep replay and live provenance distinct, preserve the loopback-first default, and avoid unsupported security or platform claims. Include a focused test and update documentation for behavior changes.

Before submitting:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
```

Do not include endpoint logs, credentials, certificates, or private telemetry. See [SECURITY.md](SECURITY.md) for vulnerability reports.
