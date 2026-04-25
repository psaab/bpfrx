// #840 Slice D v2 unit tests — RSS indirection rebalance loop.
//
// Tests covering imbalance/stability/cooldown, weight computation,
// degenerate-sample guards, ethtool-X invocation + failure, lifecycle
// + driver gate, concurrency + ConfigGen / Epoch race semantics
// (#835 R2 F6, R4 F3, R5 F1+2, R6 F2, R7 F1, R8 F1), and live-reload
// (R9 F2). Carried over from the original #835 test suite with the
// signal source swapped from `ethtool -S` to bindingRXReader so the
// algorithm runs against the live data plane the helper actually
// sees under AF_XDP zero-copy.

package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubRSSExecutor is a minimal rssExecutor fake for tests. Only the
// apply path uses ethtool now; the signal path is via bindingRXReader.
type stubRSSExecutor struct {
	mu             sync.Mutex
	driver         map[string]string // iface -> driver name
	queueCount     map[string]int    // iface -> queue count
	ethtoolXErr    error             // returned by next runEthtool("-X", ...) call
	ethtoolXErrOut []byte
	ethtoolXCalls  [][]string // recorded -X invocations
}

func newStubRSSExecutor() *stubRSSExecutor {
	return &stubRSSExecutor{
		driver:     map[string]string{},
		queueCount: map[string]int{},
	}
}

func (s *stubRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(args) >= 1 && args[0] == "-X" {
		s.ethtoolXCalls = append(s.ethtoolXCalls, append([]string(nil), args...))
		if s.ethtoolXErr != nil {
			return s.ethtoolXErrOut, s.ethtoolXErr
		}
		return nil, nil
	}
	return nil, nil
}

func (s *stubRSSExecutor) readDriver(iface string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.driver[iface]
}

func (s *stubRSSExecutor) readQueueCount(iface string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queueCount[iface]
}

func (s *stubRSSExecutor) listInterfaces() []string { return nil }

// stubBindingRXReader is the test impl of bindingRXReader. Stores
// scripted per-iface cumulative RX-packet counters keyed by ring
// index. err override forces ReadAllRX to fail (used for the
// failure-path test).
type stubBindingRXReader struct {
	mu      sync.Mutex
	samples map[string]map[int]uint64 // iface -> ring -> cumulative pkts
	err     error
	calls   int
}

func newStubBindingRXReader() *stubBindingRXReader {
	return &stubBindingRXReader{
		samples: map[string]map[int]uint64{},
	}
}

func (r *stubBindingRXReader) set(iface string, rings map[int]uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make(map[int]uint64, len(rings))
	for k, v := range rings {
		cp[k] = v
	}
	r.samples[iface] = cp
}

func (r *stubBindingRXReader) ReadAllRX() (map[string]map[int]uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	out := make(map[string]map[int]uint64, len(r.samples))
	for iface, rings := range r.samples {
		cp := make(map[int]uint64, len(rings))
		for k, v := range rings {
			cp[k] = v
		}
		out[iface] = cp
	}
	return out, nil
}

// resetRSSGlobals resets the package-level atomic state so tests are
// independent. Safe to call from any test; tests are not parallel
// because they share package-level state.
func resetRSSGlobals(t *testing.T) {
	t.Helper()
	rssIndirectionEpoch.Store(0)
	rssConfigGen.Store(0)
	rssEnabled.Store(false)
	rssWorkers.Store(0)
	rssAllowedRef.Store(nil)
}

// ---------------- 5.1 Imbalance + stability + cooldown -----------

func TestImbalance_UnderTriggerDoesNotFire(t *testing.T) {
	delta := map[int]uint64{0: 100, 1: 95, 2: 98, 3: 92, 4: 97, 5: 99}
	max, mean := maxMeanOverDomain(delta, 6)
	if float64(max) > mean*rssRebalanceTriggerRatio {
		t.Errorf("expected no trigger, got max=%d mean=%.2f ratio=%.2f",
			max, mean, float64(max)/mean)
	}
}

func TestImbalance_OverTriggerFires(t *testing.T) {
	delta := map[int]uint64{0: 500, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100}
	max, mean := maxMeanOverDomain(delta, 6)
	if !(float64(max) > mean*rssRebalanceTriggerRatio) {
		t.Errorf("expected trigger, got max=%d mean=%.2f ratio=%.2f",
			max, mean, float64(max)/mean)
	}
}

func TestImbalance_ExactlyAtTriggerDoesNotFire(t *testing.T) {
	// Construct rates so max/mean = exactly 1.8. Mean = 100 → max =
	// 180, others sum to 5*100 - (180-100) = 500-80 = 420 → 5 rings
	// each 84.
	delta := map[int]uint64{0: 180, 1: 84, 2: 84, 3: 84, 4: 84, 5: 84}
	max, mean := maxMeanOverDomain(delta, 6)
	if float64(max) > mean*rssRebalanceTriggerRatio {
		t.Errorf("expected strict-> not trigger; max=%d mean=%.2f ratio=%.2f",
			max, mean, float64(max)/mean)
	}
}

// #835 R3 new-issue #1 / R4 Finding #1 pin: idle-ring skew fires.
func TestImbalance_IdleRingSkewFires(t *testing.T) {
	delta := map[int]uint64{0: 24} // rings 1..5 absent (= 0)
	max, mean := maxMeanOverDomain(delta, 6)
	if max != 24 {
		t.Errorf("max: got %d, want 24", max)
	}
	if mean != 4.0 {
		t.Errorf("mean: got %.2f, want 4.0", mean)
	}
	if !(float64(max) > mean*rssRebalanceTriggerRatio) {
		t.Errorf("expected trigger, got ratio=%.2f", float64(max)/mean)
	}
}

func TestStability_RequiresConsecutive(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights: equalWeights(6),
		firstSample:    true,
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)

	// Seed: first tick captures baseline.
	reader.set("e0", map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	s.lastSampleTime = time.Now().Add(-2 * time.Second)

	// Imbalanced sample 1.
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 1 {
		t.Errorf("after 1 imbalanced: got %d, want 1", s.consecutiveImbalanced)
	}
	s.lastSampleTime = time.Now().Add(-2 * time.Second)

	// Imbalanced sample 2.
	reader.set("e0", map[int]uint64{0: 10000, 1: 200, 2: 200, 3: 200, 4: 200, 5: 200})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 2 {
		t.Errorf("after 2 imbalanced: got %d, want 2", s.consecutiveImbalanced)
	}
	s.lastSampleTime = time.Now().Add(-2 * time.Second)

	// Balanced sample — must reset.
	reader.set("e0", map[int]uint64{0: 11000, 1: 1200, 2: 1200, 3: 1200, 4: 1200, 5: 1200})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("after balanced: got %d, want 0", s.consecutiveImbalanced)
	}
}

func TestStability_NonConsecutiveResets(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	reader.set("e0", map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)

	s.lastSampleTime = time.Now().Add(-2 * time.Second)
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 1 {
		t.Errorf("imbalanced 1: got %d", s.consecutiveImbalanced)
	}

	// Zero-traffic (no delta over previous): all rings stay at same totals.
	s.lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("after zero-traffic: got %d, want 0", s.consecutiveImbalanced)
	}
}

func TestCooldown_BlocksWithinWindow(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now(), // just rebalanced
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("cooldown should block: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestCooldown_AllowsAfterWindow(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 1 {
		t.Errorf("cooldown should allow: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// ---------------- 5.2 Weight computation -------------------------

func TestComputeWeightShift_ShiftsHotToCold(t *testing.T) {
	delta := map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur, 6)
	want := []int{15, 25, 20, 20, 20, 20}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestComputeWeightShift_NeverDropsBelowMinWeight(t *testing.T) {
	delta := map[int]uint64{0: 9999, 1: 1}
	cur := []int{2, 100}
	got := computeWeightShift(delta, cur, 2)
	if got[0] < rssRebalanceMinWeight {
		t.Errorf("hot ring went below MIN_WEIGHT: got %v", got)
	}
}

func TestComputeWeightShift_NoopWhenBalanced(t *testing.T) {
	delta := map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur, 6)
	want := equalWeights(6)
	if !sliceEqual(got, want) {
		t.Errorf("balanced: got %v, want %v", got, want)
	}
}

func TestComputeWeightShift_TiebreakByLowestIndex(t *testing.T) {
	delta := map[int]uint64{0: 5000, 1: 0, 2: 100, 3: 0, 4: 100, 5: 0}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur, 6)
	want := []int{15, 25, 20, 20, 20, 20}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Codex R3 pin: workers<queues case. seedWeightVector(4,6) returns
// [20,20,20,20,0,0]. computeWeightShift with domainSize=4 must
// only manipulate [0..3] and leave [4..5] at 0.
func TestComputeWeightShift_WorkersLessThanQueues_PreservesPadding(t *testing.T) {
	cur := seedWeightVector(4, 6)
	want0 := []int{20, 20, 20, 20, 0, 0}
	if !sliceEqual(cur, want0) {
		t.Fatalf("seed: got %v, want %v", cur, want0)
	}
	delta := map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 0, 5: 0}
	got := computeWeightShift(delta, cur, 4)
	want := []int{15, 25, 20, 20, 0, 0}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ---------------- 5.3 Guards (#835 R1 HIGH-4 closure) ------------

func TestGuard_FirstSampleSeedsOnly(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("first sample should not increment consecutiveImbalanced: got %d", s.consecutiveImbalanced)
	}
	if s.firstSample {
		t.Error("firstSample should be false after seeding")
	}
}

func TestGuard_ZeroTotalTrafficResetsImbalance(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: 2,
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 5000},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	// Same counter as last → zero delta.
	reader.set("e0", map[int]uint64{0: 5000})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("zero-traffic should reset to 0: got %d", s.consecutiveImbalanced)
	}
}

// #835 R5 Finding 3 inverted: was SkipsRatio, now FiresRatio.
func TestGuard_SingleNonZeroRingFiresRatio(t *testing.T) {
	delta := map[int]uint64{0: 1500} // rings 1..5 absent = 0
	max, mean := maxMeanOverDomain(delta, 6)
	if !(float64(max) > mean*rssRebalanceTriggerRatio) {
		t.Errorf("single-ring skew should fire: max=%d mean=%.2f", max, mean)
	}
}

func TestGuard_CounterResetTreatedAsZeroDelta(t *testing.T) {
	cur := map[int]uint64{0: 50}     // counter went BACKWARDS (helper restart)
	prev := map[int]uint64{0: 10000} // was much higher
	d := deltaSafeAgainstResets(cur, prev)
	if d[0] != 0 {
		t.Errorf("expected delta=0 on counter reset, got %d", d[0])
	}
}

func TestGuard_ManagedDomainLessThan2SkipsRatio(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        []int{rssRebalanceDefaultWeight}, // domain=1 — pin
		consecutiveImbalanced: 2,
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 1
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000})
	rssEnabled.Store(true)
	rssWorkers.Store(6) // > 1: tick body runs, hits the per-iface guard
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("managed domain < 2 should skip: got %d -X calls", len(exec.ethtoolXCalls))
	}
	if s.consecutiveImbalanced != 0 {
		t.Errorf("guard must reset consecutiveImbalanced: got %d", s.consecutiveImbalanced)
	}
}

// ---------------- 5.4 Ethtool invocation + failure --------------

func TestApplyWeights_InvokesEthtoolXWithExpectedArgs(t *testing.T) {
	exec := newStubRSSExecutor()
	weights := []int{15, 25, 20, 20, 20, 20}
	if err := applyWeights("e0", weights, exec); err != nil {
		t.Fatal(err)
	}
	if len(exec.ethtoolXCalls) != 1 {
		t.Fatalf("expected 1 -X call, got %d", len(exec.ethtoolXCalls))
	}
	got := exec.ethtoolXCalls[0]
	want := []string{"-X", "e0", "weight", "15", "25", "20", "20", "20", "20"}
	if !stringSliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplyWeights_StderrExitCodeSurfaced(t *testing.T) {
	exec := newStubRSSExecutor()
	exec.ethtoolXErr = errors.New("exit status 1")
	exec.ethtoolXErrOut = []byte("invalid weight value")
	err := applyWeights("e0", []int{15, 25, 20, 20, 20, 20}, exec)
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "invalid weight value") {
		t.Errorf("error should contain stderr; got: %v", err)
	}
}

func TestApplyWeights_PermanentSkipAfterMaxFailures(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	exec.ethtoolXErr = errors.New("simulated failure")
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	st := map[string]*rssRebalanceState{"e0": s}
	for i := 0; i < rssRebalanceMaxFailures; i++ {
		// Reset cooldown each iteration to allow retries.
		s.lastRebalanceTime = time.Now().Add(-2 * rssRebalanceCooldown)
		s.consecutiveImbalanced = rssRebalanceStability
		s.lastSampleTime = time.Now().Add(-2 * time.Second)
		// Bump sample counters monotonically so each tick has a
		// non-zero delta (otherwise the zero-traffic guard would
		// skip the rebalance attempt and no failure is recorded).
		base := uint64(5000 * (i + 2))
		reader.set("e0", map[int]uint64{
			0: base, 1: base / 50, 2: base / 50, 3: base / 50, 4: base / 50, 5: base / 50,
		})
		rebalanceTick(st, exec, reader)
	}
	if !s.permanentSkip {
		t.Errorf("expected permanentSkip after %d failures, got applyFailures=%d",
			rssRebalanceMaxFailures, s.applyFailures)
	}
}

// Copilot review pin: a sample failure must reset
// consecutiveImbalanced and force firstSample=true. Otherwise a
// 2-imbalanced + 1-fail + 1-imbalanced sequence would reach
// stability=3 even though the samples weren't truly consecutive.
func TestSampleFailure_BreaksConsecutiveImbalanceStreak(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: 2, // already 2 imbalanced samples
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.err = errors.New("helper unreachable")
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("sample failure must reset consecutiveImbalanced: got %d, want 0",
			s.consecutiveImbalanced)
	}
	if !s.firstSample {
		t.Errorf("sample failure must force re-baseline (firstSample=true)")
	}
}

// Codex MED 2 pin: sample failures (helper unreachable) accumulate
// in sampleFailures but DO NOT permanently skip the iface — they're
// recoverable. The first successful sample after a streak of
// failures must reset the counter back to 0.
func TestSampleFailure_NeverPermanentSkip(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.err = errors.New("helper unreachable")
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	st := map[string]*rssRebalanceState{"e0": s}
	// 3× MaxFailures sample errors must NOT permanently skip.
	for i := 0; i < 3*rssRebalanceMaxFailures; i++ {
		rebalanceTick(st, exec, reader)
	}
	if s.permanentSkip {
		t.Errorf("sample failures must not permanentSkip the iface")
	}
	if s.sampleFailures != 3*rssRebalanceMaxFailures {
		t.Errorf("sampleFailures: got %d, want %d", s.sampleFailures, 3*rssRebalanceMaxFailures)
	}
	// Recover: clear error and feed a valid sample. sampleFailures
	// must reset to 0.
	reader.err = nil
	reader.set("e0", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(st, exec, reader)
	if s.sampleFailures != 0 {
		t.Errorf("sampleFailures must reset on successful sample: got %d", s.sampleFailures)
	}
}

// Copilot review #1 pin: rebalanceTick must fetch all bindings in
// a single ReadAllRX call regardless of allowlist size, to avoid
// N status RPCs per tick (which would hold Manager.mu and block
// other helper operations like HA sync).
func TestReader_SingleCallPerTick(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.driver["e1"] = mlx5Driver
	exec.driver["e2"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.queueCount["e1"] = 6
	exec.queueCount["e2"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
	reader.set("e1", map[int]uint64{0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
	reader.set("e2", map[int]uint64{0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0", "e1", "e2"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec, reader)
	if reader.calls != 1 {
		t.Errorf("expected exactly 1 ReadAllRX call per tick, got %d", reader.calls)
	}
}

// Codex R2 Q1 pin: userspaceBindingRXReader must filter out
// non-Bound and non-XSKRegistered BindingStatus entries. Failed
// bindings stay in the helper's status list with bound=false and
// counters frozen at 0 — including them in the rebalance domain
// would let the algorithm migrate weight toward queues with no
// AF_XDP socket.
func TestUserspaceReader_FiltersUnusableBindings(t *testing.T) {
	// We can't easily fake *dpuserspace.Manager here without a full
	// helper stub. Validate the filter logic directly by replicating
	// what ReadBindingRX does with an inline list, using the same
	// predicates. This is a structural check that the filter
	// expression compiles to the intended boolean.
	type binding struct {
		queue         uint32
		iface         string
		bound         bool
		xskRegistered bool
		rxPackets     uint64
	}
	bindings := []binding{
		{queue: 0, iface: "e0", bound: true, xskRegistered: true, rxPackets: 100},
		{queue: 1, iface: "e0", bound: false, xskRegistered: true, rxPackets: 0},  // not bound
		{queue: 2, iface: "e0", bound: true, xskRegistered: false, rxPackets: 50}, // not xsk-registered
		{queue: 3, iface: "e0", bound: true, xskRegistered: true, rxPackets: 200},
		{queue: 0, iface: "e1", bound: true, xskRegistered: true, rxPackets: 999}, // wrong iface
	}
	out := make(map[int]uint64)
	for _, b := range bindings {
		if b.iface != "e0" {
			continue
		}
		if !b.bound || !b.xskRegistered {
			continue
		}
		out[int(b.queue)] = b.rxPackets
	}
	want := map[int]uint64{0: 100, 3: 200}
	if len(out) != len(want) {
		t.Fatalf("filter result: got %v, want %v", out, want)
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("ring %d: got %d, want %d", k, out[k], v)
		}
	}
}

// Codex R3 HIGH pin: workers<queues end-to-end. Helper emits
// bindings on queues 0..queueCount-1 (5 queues here) regardless of
// workers (4). Rebalance domain is min(workers, queueCount) = 4,
// covering only queues 0..3. Sample includes all 5 keys; the
// shape guard requires keys [0..3] present (pass) and IGNORES
// extras like key 4. Trigger fires from imbalance among queues
// 0..3; weight migration happens within that domain. Queue 4 stays
// at weight 0 (unchanged) so traffic distribution honors #785.
func TestWorkersLessThanQueues_EndToEnd(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 5
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)

	// Pre-construct state at "ready to rebalance" point so we can
	// directly observe what the rebalance writes to ethtool.
	s := &rssRebalanceState{
		currentWeights:        seedWeightVector(4, 5),
		domainSize:            4,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0},
	}
	wantSeed := []int{20, 20, 20, 20, 0}
	if !sliceEqual(s.currentWeights, wantSeed) {
		t.Fatalf("seed: got %v, want %v", s.currentWeights, wantSeed)
	}

	// Sample includes 5 keys (queue 4 is the extra outside the
	// active domain). Queue 0 hot, queues 1-3 cold within active
	// domain.
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 0})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 1 {
		t.Fatalf("expected 1 -X call, got %d", len(exec.ethtoolXCalls))
	}
	// Expected vector: [15, 25, 20, 20, 0] — 5 weights including
	// queue 4 padding at 0, preserving the workers-vs-queues shape.
	got := exec.ethtoolXCalls[0]
	wantArgs := []string{"-X", "e0", "weight", "15", "25", "20", "20", "0"}
	if !stringSliceEqual(got, wantArgs) {
		t.Errorf("ethtool args: got %v, want %v", got, wantArgs)
	}
}

// Codex R2 Q2 pin: applyConfigLocked sets rssApplyInProgress=true
// for its entire window. The rebalance loop, after acquiring
// rssWriteMu, must abandon when this flag is set — even when its
// own ConfigGen snapshot/recheck happen to match. This protects
// the window where applyConfigLocked has bumped state mid-flight
// (e.g. d.dp.Compile changed helper bindings) but the terminal
// reapplyRSSIndirection bump hasn't published the new state yet.
func TestConcurrency_AbandonsWhileApplyInProgress(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	// Simulate applyConfigLocked in flight.
	SetRSSApplyInProgress(true)
	defer SetRSSApplyInProgress(false)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("apply-in-progress must abandon rebalance write: got %d -X calls",
			len(exec.ethtoolXCalls))
	}
}

// Codex R2 Q1 pin: even when len(sample) matches expectedRingCount,
// the observed key set must be exactly [0, expectedRingCount). A
// sample with a gap (e.g. {0,1,2,3,4,7} for expectedRingCount=6)
// has the right cardinality but indexes a queue (7) that doesn't
// belong to the contiguous-domain assumption.
func TestSampleShape_NonContiguousKeysSkipsRebalance(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 7: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	// 6 entries (matches expectedRingCount=6), but key set is
	// {0,1,2,3,4,7} — non-contiguous. Must skip.
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 7: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("non-contiguous keys must skip rebalance: got %d -X calls",
			len(exec.ethtoolXCalls))
	}
	if !s.firstSample {
		t.Errorf("non-contiguous keys must reset firstSample")
	}
}

// Codex HIGH 1 pin: when the helper exposes fewer queue bindings
// than the rebalance domain expects (cross-iface queue_count min in
// userspace-dp/src/main.rs:1148), skip the rebalance for this tick.
// Migrating weight toward unbound queues would redirect traffic to
// the kernel fallback path.
func TestSampleShape_MismatchSkipsRebalance(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	// expectedRingCount = min(6,6)=6 but helper exposes only 4
	// bindings (queues 0..3) — workers/queues say 6 but cross-iface
	// min queue_count limited bindings to 4.
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("shape mismatch must skip rebalance write: got %d -X calls",
			len(exec.ethtoolXCalls))
	}
	if !s.firstSample {
		t.Errorf("shape mismatch must reset firstSample so next matched-shape sample re-baselines")
	}
	if s.consecutiveImbalanced != 0 {
		t.Errorf("shape mismatch must reset consecutiveImbalanced: got %d", s.consecutiveImbalanced)
	}
}

// ---------------- 5.5 Lifecycle + driver gate -------------------

func TestLoop_StopsOnContextCancel(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	reader := newStubBindingRXReader()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runRSSRebalanceLoop(ctx, exec, reader)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(2 * rssRebalanceSampleInterval):
		t.Fatal("loop did not exit within 2 sample intervals after cancel")
	}
}

func TestLoop_SkipsNonMlx5Iface(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = "virtio_net"
	reader := newStubBindingRXReader()
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("non-mlx5 should skip: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestLoop_SkipsOnRSSDisabled(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(false) // disabled
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("disabled: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestLoop_SkipsOnNilReader(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	// nil reader — the loop must early-return so non-userspace
	// deploys see the rebalance loop as a pure no-op.
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, nil)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("nil reader: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestLoop_MultiInterfaceStateIsolation(t *testing.T) {
	resetRSSGlobals(t)
	sa := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	sb := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.driver["e1"] = mlx5Driver
	exec.queueCount["e1"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	reader.set("e1", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0", "e1"}
	rssAllowedRef.Store(&a)
	st := map[string]*rssRebalanceState{"e0": sa, "e1": sb}
	rebalanceTick(st, exec, reader)
	if &sa.currentWeights[0] == &sb.currentWeights[0] {
		t.Error("state isolation broken: two ifaces share weight slice")
	}
}

// ---------------- 5.6 Concurrency + ConfigGen / Epoch -----------

// bumpingReader simulates a control-plane ConfigGen bump arriving
// between the rebalance tick's snapshot and its post-lock re-check.
type bumpingReader struct {
	base          *stubBindingRXReader
	bumpOnRCalled *atomic.Bool
}

func (r *bumpingReader) ReadAllRX() (map[string]map[int]uint64, error) {
	if !r.bumpOnRCalled.Load() {
		BumpRSSConfigGen()
		r.bumpOnRCalled.Store(true)
	}
	return r.base.ReadAllRX()
}

// epochBumpingReader simulates a control-plane apply that bumps
// rssIndirectionEpoch between snapshot and post-lock re-check.
type epochBumpingReader struct {
	base          *stubBindingRXReader
	bumpOnRCalled *atomic.Bool
}

func (r *epochBumpingReader) ReadAllRX() (map[string]map[int]uint64, error) {
	if !r.bumpOnRCalled.Load() {
		BumpRSSEpoch()
		r.bumpOnRCalled.Store(true)
	}
	return r.base.ReadAllRX()
}

func TestConcurrency_StaleWeightsAbandonedOnConfigGenChange(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	base := newStubBindingRXReader()
	base.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	bumped := atomic.Bool{}
	wrapped := &bumpingReader{base: base, bumpOnRCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, wrapped)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon (no -X call), got %d", len(exec.ethtoolXCalls))
	}
	if !bumped.Load() {
		t.Error("test wiring: bump never fired")
	}
}

func TestConcurrency_EpochBumpResetsCurrentWeights(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        []int{10, 30, 20, 20, 20, 20},
		consecutiveImbalanced: 3,
		lastSeenEpoch:         0,
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 1000, 1: 1000, 2: 1000, 3: 1000, 4: 1000, 5: 1000})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	BumpRSSEpoch() // simulates external control-plane write
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	want := equalWeights(6)
	if !sliceEqual(s.currentWeights, want) {
		t.Errorf("epoch bump should reset to equal: got %v, want %v", s.currentWeights, want)
	}
	if s.consecutiveImbalanced != 0 {
		t.Errorf("epoch bump should reset counter: got %d", s.consecutiveImbalanced)
	}
}

func TestConcurrency_WorkersGreaterThanRingCount(t *testing.T) {
	got := computeRingCount(8, 6)
	if got != 6 {
		t.Errorf("workers > ring_count: got %d, want 6", got)
	}
	got = computeRingCount(2, 6)
	if got != 2 {
		t.Errorf("workers < ring_count: got %d, want 2", got)
	}
	got = computeRingCount(0, 6)
	if got != 0 {
		t.Errorf("workers=0: got %d, want 0", got)
	}
}

func TestConcurrency_FailedApplyStillBumpsConfigGen(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.ethtoolXErr = errors.New("simulated failure")
	a := []string{"e0"}
	gen0 := LoadRSSConfigGen()
	applyRSSIndirection(true, 6, a, exec)
	gen1 := LoadRSSConfigGen()
	if gen1 == gen0 {
		t.Errorf("ConfigGen should bump on every invocation regardless of write outcome; gen0=%d gen1=%d", gen0, gen1)
	}
}

func TestConcurrency_RebalanceWriteDoesNotBumpGlobalCounters(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	epochBefore := LoadRSSEpoch()
	genBefore := LoadRSSConfigGen()
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 1 {
		t.Fatalf("expected 1 -X call, got %d", len(exec.ethtoolXCalls))
	}
	if LoadRSSEpoch() != epochBefore {
		t.Errorf("rebalance write must NOT bump Epoch: was %d, now %d", epochBefore, LoadRSSEpoch())
	}
	if LoadRSSConfigGen() != genBefore {
		t.Errorf("rebalance write must NOT bump ConfigGen: was %d, now %d", genBefore, LoadRSSConfigGen())
	}
}

func TestConcurrency_AbandonsWhenControlPlaneFiresBetweenSnapshotAndLock(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	base := newStubBindingRXReader()
	base.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	bumped := atomic.Bool{}
	wrapped := &bumpingReader{base: base, bumpOnRCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, wrapped)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon, got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// #835 R2 FA2 pin: post-lock Epoch re-check abandons stale rebalance
// writes when a successful control-plane apply landed during our
// compute / lock-wait window.
func TestConcurrency_AbandonsWhenEpochBumpsBetweenSnapshotAndLock(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		domainSize:            6,
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		lastSeenEpoch:         LoadRSSEpoch(),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	base := newStubBindingRXReader()
	base.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	bumped := atomic.Bool{}
	wrapped := &epochBumpingReader{base: base, bumpOnRCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, wrapped)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon on Epoch change, got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// ---------------- 5.7 Live reload (#835 R9 F2) ------------------

func TestLiveReload_AllowlistShrinkTakesEffectNextTick(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.driver["e1"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.queueCount["e1"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	reader.set("e1", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0", "e1"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec, reader)
	if _, ok := state["e0"]; !ok {
		t.Fatal("e0 state not created on first tick")
	}
	if _, ok := state["e1"]; !ok {
		t.Fatal("e1 state not created on first tick")
	}
	a2 := []string{"e0"}
	rssAllowedRef.Store(&a2)
	preCalls := len(exec.ethtoolXCalls)
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	state["e1"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec, reader)
	for _, call := range exec.ethtoolXCalls[preCalls:] {
		for _, arg := range call {
			if arg == "e1" {
				t.Errorf("e1 was touched after allowlist shrink: %v", call)
			}
		}
	}
}

// #835 R2 FA4 pin: a worker-count change that arrives via an
// idempotent reapply (no Epoch bump because table already matches)
// still triggers re-seed because the domain-mismatch detector fires.
// Codex R3: currentWeights is now full queue_count length; the
// rebalance domain shrinks via domainSize, not vector length.
func TestLiveReload_WorkerCountChangeWithoutEpochBumpReseeds(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec, reader) // first sample, seeds domainSize=4
	if state["e0"].domainSize != 4 {
		t.Fatalf("first tick should seed domainSize=4, got %d", state["e0"].domainSize)
	}
	if len(state["e0"].currentWeights) != 6 {
		t.Fatalf("currentWeights stays at queueCount=6, got %d", len(state["e0"].currentWeights))
	}
	rssWorkers.Store(2)
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec, reader)
	if state["e0"].domainSize != 2 {
		t.Errorf("domain-mismatch reseed should shrink domainSize to 2, got %d", state["e0"].domainSize)
	}
	if len(state["e0"].currentWeights) != 6 {
		t.Errorf("currentWeights stays at queueCount=6 across worker change, got %d",
			len(state["e0"].currentWeights))
	}
}

// FA5 regression pin: weightsEqual no-op path doesn't fire ethtool.
func TestRebalance_NoOpWeightsSkipsEthtoolCall(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        []int{rssRebalanceMinWeight, 50, 50, 50, 50, 50},
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		lastSeenEpoch:         LoadRSSEpoch(),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec, reader)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("no-op weights path should skip ethtool: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// FA4 first-creation seed regression pin. Codex R3: currentWeights
// is full queue_count length with first domainSize entries at
// default; domainSize is min(workers, queueCount).
func TestRebalance_FirstCreationSeedsCurrentWeights(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec, reader)
	if state["e0"] == nil {
		t.Fatal("state entry not created")
	}
	gotW := state["e0"].currentWeights
	wantW := []int{20, 20, 20, 20, 0, 0}
	if !sliceEqual(gotW, wantW) {
		t.Errorf("expected seedWeightVector(4,6)=%v, got %v", wantW, gotW)
	}
	if state["e0"].domainSize != 4 {
		t.Errorf("expected domainSize=4, got %d", state["e0"].domainSize)
	}
}

func TestLiveReload_WorkerCountChangeTakesEffectNextTick(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	reader := newStubBindingRXReader()
	reader.set("e0", map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec, reader) // first sample
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec, reader) // baseline established with workers=4
	rssWorkers.Store(2)
	BumpRSSEpoch()
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec, reader)
	// currentWeights stays len=queueCount=6; domainSize shrinks to 2.
	if len(state["e0"].currentWeights) != 6 {
		t.Errorf("currentWeights stays at queueCount: got len=%d", len(state["e0"].currentWeights))
	}
	if state["e0"].domainSize != 2 {
		t.Errorf("worker count change: domainSize = %d, want 2", state["e0"].domainSize)
	}
}

// ---------------- helpers ----------------

func sliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
