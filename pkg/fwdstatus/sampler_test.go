package fwdstatus

import (
	"testing"
	"time"
)

// buildSnapshot constructs a deterministic snapshot for testing
// window lookups. Samples are 1s apart ending at `now`.
// daemonCPUNs advances by daemonRatePerSec ns per second.
// workerActive advances by activeRatePerSec per total worker
// wall; each sample's worker_wall advances by numWorkers·1e9 ns
// per second (N workers each accumulate 1s of wall per real second).
func buildSnapshot(now time.Time, count int, daemonRate, activeRate, numWorkers uint64) SamplerSnapshot {
	samples := make([]cpuSample, count)
	for i := 0; i < count; i++ {
		samples[i] = cpuSample{
			wall:           now.Add(-time.Duration(count-1-i) * time.Second),
			daemonCPUNs:    uint64(i) * daemonRate,
			workerActiveNs: uint64(i) * activeRate,
			workerWallNs:   uint64(i) * numWorkers * 1_000_000_000,
		}
	}
	return SamplerSnapshot{Samples: samples, Now: now}
}

// Compute windows for a populated snapshot and assert values.
func TestComputeCPUWindows_Populated(t *testing.T) {
	// 400 samples covers all three windows comfortably.
	// Daemon: 500 Mns CPU per 1s wall = 50% per-core.
	// Worker: 2 workers; active = 400 Mns per worker-second = 40%.
	now := time.Now()
	snap := buildSnapshot(now, 400,
		500_000_000,          // daemonRate: 500 Mns per sec = 50%/core
		800_000_000,          // activeRate: 800 Mns/total-sec → per 2 workers = 400 Mns/worker/sec = 40%
		2)

	dPct, wPct, dValid, wValid := computeCPUWindows(snap)
	for i, label := range []string{"5s", "1m", "5m"} {
		if !dValid[i] {
			t.Errorf("daemon %s should be valid", label)
			continue
		}
		if !wValid[i] {
			t.Errorf("worker %s should be valid", label)
			continue
		}
		if dPct[i] < 49 || dPct[i] > 51 {
			t.Errorf("daemon %s: got %.1f, want ~50", label, dPct[i])
		}
		if wPct[i] < 39 || wPct[i] > 41 {
			t.Errorf("worker %s: got %.1f, want ~40", label, wPct[i])
		}
	}
}

// Short uptime: only 10 samples (≈10s). 5s window valid; 1m and 5m invalid.
func TestComputeCPUWindows_ShortUptime(t *testing.T) {
	now := time.Now()
	snap := buildSnapshot(now, 10, 100_000_000, 500_000_000, 1)
	_, _, dValid, wValid := computeCPUWindows(snap)
	if !dValid[CPUWindow5s] {
		t.Error("5s should be valid at 10 samples")
	}
	if !wValid[CPUWindow5s] {
		t.Error("worker 5s should be valid at 10 samples")
	}
	if dValid[CPUWindow1m] {
		t.Error("1m should NOT be valid at 10 samples")
	}
	if dValid[CPUWindow5m] {
		t.Error("5m should NOT be valid at 10 samples")
	}
}

// Empty snapshot → everything invalid.
func TestComputeCPUWindows_Empty(t *testing.T) {
	_, _, dValid, wValid := computeCPUWindows(SamplerSnapshot{})
	for i := 0; i < numCPUWindows; i++ {
		if dValid[i] {
			t.Errorf("empty: daemon[%d] should be invalid", i)
		}
		if wValid[i] {
			t.Errorf("empty: worker[%d] should be invalid", i)
		}
	}
}

// Single sample is not enough for rate computation.
func TestComputeCPUWindows_OneSample(t *testing.T) {
	now := time.Now()
	snap := buildSnapshot(now, 1, 100_000_000, 500_000_000, 1)
	_, _, dValid, wValid := computeCPUWindows(snap)
	for i := 0; i < numCPUWindows; i++ {
		if dValid[i] {
			t.Errorf("1-sample: daemon[%d] should be invalid", i)
		}
		if wValid[i] {
			t.Errorf("1-sample: worker[%d] should be invalid", i)
		}
	}
}

// Worker path inactive (userspace_wall doesn't advance) → worker
// windows stay invalid even when daemon windows are valid.
func TestComputeCPUWindows_WorkerWallFlat(t *testing.T) {
	now := time.Now()
	snap := buildSnapshot(now, 400, 100_000_000, 0, 0)
	_, _, dValid, wValid := computeCPUWindows(snap)
	for i, label := range []string{"5s", "1m", "5m"} {
		if !dValid[i] {
			t.Errorf("daemon %s should be valid", label)
		}
		if wValid[i] {
			t.Errorf("worker %s should be invalid (no worker wall advance)", label)
		}
	}
}

// findSampleAtOrBefore edge cases.
func TestFindSampleAtOrBefore(t *testing.T) {
	base := time.Unix(1000, 0)
	samples := []cpuSample{
		{wall: base.Add(0 * time.Second)},
		{wall: base.Add(1 * time.Second)},
		{wall: base.Add(2 * time.Second)},
		{wall: base.Add(3 * time.Second)},
	}
	cases := []struct {
		target time.Time
		want   int
	}{
		{base.Add(-1 * time.Second), -1}, // before all
		{base.Add(0 * time.Second), 0},   // exact oldest
		{base.Add(1500 * time.Millisecond), 1},
		{base.Add(3 * time.Second), 3}, // exact newest
		{base.Add(10 * time.Second), 3}, // after all → newest
	}
	for _, c := range cases {
		got := findSampleAtOrBefore(samples, c.target)
		if got != c.want {
			t.Errorf("target=%v: got %d, want %d", c.target, got, c.want)
		}
	}
}

// Format exercise: three valid windows render as three percentages.
func TestFormat_ThreeValidWindows(t *testing.T) {
	fs := &ForwardingStatus{
		State:                StateOnline,
		DaemonCPUWindows:     [numCPUWindows]float64{4, 3, 2},
		DaemonCPUWindowValid: [numCPUWindows]bool{true, true, true},
		WorkerCPUMode:        CPUModeWorkers,
		WorkerCPUWindows:     [numCPUWindows]float64{42, 38, 35},
		WorkerCPUWindowValid: [numCPUWindows]bool{true, true, true},
	}
	out := Format(fs)
	for _, want := range []string{"4%", "3%", "2%", "42%", "38%", "35%", "5s / 1m / 5m"} {
		if !contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Format exercise: short-uptime renders `-` for invalid columns.
func TestFormat_ShortUptimeRendersDash(t *testing.T) {
	fs := &ForwardingStatus{
		State:                StateOnline,
		DaemonCPUWindows:     [numCPUWindows]float64{5, 0, 0},
		DaemonCPUWindowValid: [numCPUWindows]bool{true, false, false},
		WorkerCPUMode:        CPUModeWorkers,
		WorkerCPUWindows:     [numCPUWindows]float64{0, 0, 0},
		WorkerCPUWindowValid: [numCPUWindows]bool{false, false, false},
	}
	out := Format(fs)
	// Daemon: 5% / - / -
	if !contains(out, "5%") {
		t.Errorf("missing 5%% daemon value: %s", out)
	}
	// We expect at least 5 occurrences of "-" (three daemon invalid
	// columns would be 2 of them; worker has all three invalid = 3).
	// Actually: daemon has 1 valid + 2 invalid; worker has 3 invalid.
	// So 5 "-" total.
	dashes := 0
	for _, r := range out {
		if r == '-' {
			dashes++
		}
	}
	if dashes < 5 {
		t.Errorf("expected ≥ 5 `-` chars (invalid columns), got %d in:\n%s", dashes, out)
	}
}

// contains is strings.Contains — kept local to avoid an extra import.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
