# Reproducible benchmark checks

Run the local rule-engine benchmarks from the repository root:

```sh
GOMAXPROCS=1 go test -run '^$' -bench '^BenchmarkEvaluate' -benchmem -count=5 ./internal/detection
```

The benchmarks cover a single-event rule evaluation and a three-event authentication threshold evaluation with two prior matching records. Go's benchmark output reports elapsed time and allocations per operation. The fixture is deterministic and does not access a database or Windows APIs.

These numbers measure only the detection package's CPU and allocation cost. They do not measure HTTP ingestion, PostgreSQL, end-to-end latency, agent resource use, sustained event loss, or recovery under load. Results depend on hardware, operating system, Go version, and background load; do not treat them as a production capacity claim. Record those details alongside any comparison.

## Local baseline

The baseline below is recorded from the SENTINEL development checkout. It is a reproducibility reference, not a performance target. Environment: Apple M4, macOS Darwin 24.6.0, Go 1.26.4, arm64, `GOMAXPROCS=1`. Five runs were collected; median `ns/op` is shown in the summary, while allocation counts were identical across runs.

```text
BenchmarkEvaluateSingleEvent:       606.1 ns/op, 416 B/op, 7 allocs/op (median)
BenchmarkEvaluateCorrelatedEvents:  683.5 ns/op, 1296 B/op, 8 allocs/op (median)
```

The five observed times for single-event evaluation were 614.1, 583.9, 563.4, 675.0, and 606.1 ns/op. Correlated evaluation was 678.4, 683.5, 721.8, 704.5, and 680.5 ns/op. This small local run is sensitive to laptop activity and does not justify extrapolating endpoint capacity.
