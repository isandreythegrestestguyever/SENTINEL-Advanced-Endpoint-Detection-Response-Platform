# Testing and verification

Run the scenario assertion test and static analysis with:

```sh
go test ./...
go vet ./...
```

The delivery environment's Go 1.26.4 executable failed before compilation: package resolution said standard library packages such as `crypto/rand`, `fmt`, and `net/http` were “not in std”, pointing at its configured GOROOT. This does not establish whether source compiles. Re-run with a working toolchain.

## Manual smoke path

1. Start `go run ./cmd/sentinel`; verify `/api/health` reports `ok`.
2. Open dashboard and confirm zero live sensors and a no-live-sensor notice.
3. Set the token and run all six scenarios.
4. Confirm each report passes and alerts carry simulation provenance.
5. Restart on the same data path and check persisted state.
6. Try an unauthenticated write (expect 401) and an invalid event with a token (expect 400).

No browser automation, Windows integration, load benchmark, or production security test is claimed as run.
