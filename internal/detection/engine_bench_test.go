package detection

import (
	"testing"
	"time"

	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/model"
)

func BenchmarkEvaluateSingleEvent(b *testing.B) {
	event := model.Event{
		ID: "bench-single", HostID: "bench-host", Hostname: "BENCH-HOST",
		Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Type: "process_start", Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: "powershell.exe -encodedcommand synthetic-fixture",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		Evaluate(event, nil)
	}
}

func BenchmarkEvaluateCorrelatedEvents(b *testing.B) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	previous := []model.Event{
		{ID: "bench-auth-1", HostID: "bench-host", SimulationRunID: "bench-run", Time: base, Type: "authentication_failure"},
		{ID: "bench-auth-2", HostID: "bench-host", SimulationRunID: "bench-run", Time: base.Add(time.Second), Type: "authentication_failure"},
	}
	event := model.Event{ID: "bench-auth-3", HostID: "bench-host", SimulationRunID: "bench-run", Time: base.Add(2 * time.Second), Type: "authentication_failure"}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		Evaluate(event, previous)
	}
}
