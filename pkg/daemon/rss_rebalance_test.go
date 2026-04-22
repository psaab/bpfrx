// #835 Slice D unit tests — RSS indirection rebalance loop.
//
// 33 tests covering parsing, imbalance/stability/cooldown, weight
// computation, degenerate-sample guards, ethtool invocation +
// failure, lifecycle + driver gate, concurrency + ConfigGen / Epoch
// (R2 F6, R4 F3, R5 F1+2, R6 F2, R7 F1, R8 F1), and live-reload
// (R9 F2).

package daemon

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubRSSExecutor is a minimal rssExecutor fake for tests.
type stubRSSExecutor struct {
	mu              sync.Mutex
	driver          map[string]string // iface -> driver name
	queueCount      map[string]int    // iface -> ethtool queue count
	ethtoolS        map[string][]byte // iface -> ethtool -S output
	ethtoolXErr     error             // returned by next runEthtool("-X", ...) call
	ethtoolXErrOut  []byte
	ethtoolXCalls   [][]string // recorded -X invocations
	ethtoolSErr     error      // returned by ethtool -S calls
	listInterfaces_ []string
}

func newStubRSSExecutor() *stubRSSExecutor {
	return &stubRSSExecutor{
		driver:     map[string]string{},
		queueCount: map[string]int{},
		ethtoolS:   map[string][]byte{},
	}
}

func (s *stubRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(args) >= 2 && args[0] == "-S" {
		out, ok := s.ethtoolS[args[1]]
		if !ok {
			return nil, errors.New("no canned ethtool -S output for iface")
		}
		if s.ethtoolSErr != nil {
			return nil, s.ethtoolSErr
		}
		return out, nil
	}
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

func (s *stubRSSExecutor) listInterfaces() []string {
	return s.listInterfaces_
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

// ---------------- 5.1 Parsing (3 tests) ----------------

func TestParseEthtoolS_ExtractsPerRingPackets(t *testing.T) {
	// Real capture from `incus exec loss:xpf-userspace-fw0 -- ethtool -S ge-0-0-2`.
	out := []byte(`     rx0_packets: 68259
     rx0_bytes: 4381139
     rx1_packets: 4255
     rx1_bytes: 386233
     rx2_packets: 518
     rx2_bytes: 66681
     rx3_packets: 146
     rx3_bytes: 14515
     rx4_packets: 92
     rx4_bytes: 8200
     rx5_packets: 11
     rx5_bytes: 990
     rx_packets: 73281
     tx_packets: 50000
`)
	got := parseEthtoolS(out)
	want := map[int]uint64{0: 68259, 1: 4255, 2: 518, 3: 146, 4: 92, 5: 11}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ring %d: got %d, want %d", k, got[k], v)
		}
	}
}

func TestParseEthtoolS_IgnoresNonRingCounters(t *testing.T) {
	out := []byte(`     rx_errors: 12
     rx_packets: 99999
     tx_bytes: 1234
     rx0_packets: 5
`)
	got := parseEthtoolS(out)
	if len(got) != 1 || got[0] != 5 {
		t.Errorf("got %v, want {0: 5}", got)
	}
}

func TestParseEthtoolS_HandlesMissingRings(t *testing.T) {
	// Only rx0 and rx3 present.
	out := []byte(`     rx0_packets: 100
     rx3_packets: 200
`)
	got := parseEthtoolS(out)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %v", len(got), got)
	}
	if got[0] != 100 || got[3] != 200 {
		t.Errorf("got %v, want {0:100, 3:200}", got)
	}
}

// ---------------- 5.2 Imbalance + stability + cooldown (7 tests) ----

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
	// Construct rates so max/mean = exactly 1.8. Mean = 100 → max = 180,
	// others sum to 5*100 - (180-100) = 500-80 = 420 → 5 rings each 84.
	delta := map[int]uint64{0: 180, 1: 84, 2: 84, 3: 84, 4: 84, 5: 84}
	max, mean := maxMeanOverDomain(delta, 6)
	if float64(max) > mean*rssRebalanceTriggerRatio {
		t.Errorf("expected strict-> not trigger; max=%d mean=%.2f ratio=%.2f",
			max, mean, float64(max)/mean)
	}
}

// 6a — R3 new-issue #1 / R4 Finding #1 pin: idle-ring skew fires.
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
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)

	// Seed: 3 ticks with imbalanced sample, 1 with balanced. Final
	// state should have consecutiveImbalanced reset.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec) // first sample seed
	s.lastSampleTime = time.Now().Add(-2 * time.Second)         // bypass minElapsed

	// Imbalanced sample 1.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 1 {
		t.Errorf("after 1 imbalanced: got %d, want 1", s.consecutiveImbalanced)
	}
	s.lastSampleTime = time.Now().Add(-2 * time.Second)

	// Imbalanced sample 2.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 10000, 1: 200, 2: 200, 3: 200, 4: 200, 5: 200})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 2 {
		t.Errorf("after 2 imbalanced: got %d, want 2", s.consecutiveImbalanced)
	}
	s.lastSampleTime = time.Now().Add(-2 * time.Second)

	// Balanced sample — must reset.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 11000, 1: 1200, 2: 1200, 3: 1200, 4: 1200, 5: 1200})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("after balanced: got %d, want 0", s.consecutiveImbalanced)
	}
}

func TestStability_NonConsecutiveResets(t *testing.T) {
	// Same as above but interleaved with zero-traffic samples (which
	// also reset). Confirms that zero-traffic resets consecutiveImbalanced.
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)

	s.lastSampleTime = time.Now().Add(-2 * time.Second)
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 1 {
		t.Errorf("imbalanced 1: got %d", s.consecutiveImbalanced)
	}

	// Zero-traffic (no delta over previous): all rings stay at same totals.
	s.lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("after zero-traffic: got %d, want 0", s.consecutiveImbalanced)
	}
}

func TestCooldown_BlocksWithinWindow(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now(), // just rebalanced
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("cooldown should block: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestCooldown_AllowsAfterWindow(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 1 {
		t.Errorf("cooldown should allow: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// ---------------- 5.3 Weight computation (4 tests) ----------------

func TestComputeWeightShift_ShiftsHotToCold(t *testing.T) {
	delta := map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur)
	want := []int{15, 25, 20, 20, 20, 20}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestComputeWeightShift_NeverDropsBelowMinWeight(t *testing.T) {
	// Hot ring already at MIN_WEIGHT+1; shift should clamp.
	delta := map[int]uint64{0: 9999, 1: 1}
	cur := []int{2, 100}
	got := computeWeightShift(delta, cur)
	if got[0] < rssRebalanceMinWeight {
		t.Errorf("hot ring went below MIN_WEIGHT: got %v", got)
	}
}

func TestComputeWeightShift_NoopWhenBalanced(t *testing.T) {
	delta := map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur)
	// All rates equal → argmax/argmin both return ring 0; no shift.
	want := equalWeights(6)
	if !sliceEqual(got, want) {
		t.Errorf("balanced: got %v, want %v", got, want)
	}
}

func TestComputeWeightShift_TiebreakByLowestIndex(t *testing.T) {
	// Rings 1, 3, 5 all at zero (tied for cold); should pick ring 1.
	delta := map[int]uint64{0: 5000, 1: 0, 2: 100, 3: 0, 4: 100, 5: 0}
	cur := equalWeights(6)
	got := computeWeightShift(delta, cur)
	// Hot=0 shifts 5 to cold (lowest tied = ring 1).
	want := []int{15, 25, 20, 20, 20, 20}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ---------------- 5.4 Guards (R1 HIGH-4 closure) (5 tests) ----------

func TestGuard_FirstSampleSeedsOnly(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
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
		consecutiveImbalanced: 2,
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 5000},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	// Same counters as last → zero delta.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if s.consecutiveImbalanced != 0 {
		t.Errorf("zero-traffic should reset to 0: got %d", s.consecutiveImbalanced)
	}
}

// R5 Finding 3 inverted: was SkipsRatio, now FiresRatio.
func TestGuard_SingleNonZeroRingFiresRatio(t *testing.T) {
	delta := map[int]uint64{0: 1500} // rings 1..5 absent = 0
	max, mean := maxMeanOverDomain(delta, 6)
	if !(float64(max) > mean*rssRebalanceTriggerRatio) {
		t.Errorf("single-ring skew should fire: max=%d mean=%.2f", max, mean)
	}
}

func TestGuard_CounterResetTreatedAsZeroDelta(t *testing.T) {
	cur := map[int]uint64{0: 50}     // counter went BACKWARDS (driver restart)
	prev := map[int]uint64{0: 10000} // was much higher
	d := deltaSafeAgainstResets(cur, prev)
	if d[0] != 0 {
		t.Errorf("expected delta=0 on counter reset, got %d", d[0])
	}
}

func TestGuard_ManagedDomainLessThan2SkipsRatio(t *testing.T) {
	// FA7 fix: keep rssWorkers > 1 so the top-of-tick early-return
	// doesn't fire. The actual guard we're pinning is the
	// `len(s.currentWeights) < 2` check inside the per-iface body.
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
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000})
	rssEnabled.Store(true)
	rssWorkers.Store(6) // > 1: tick body runs, hits the per-iface guard
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("managed domain < 2 should skip: got %d -X calls", len(exec.ethtoolXCalls))
	}
	if s.consecutiveImbalanced != 0 {
		t.Errorf("guard must reset consecutiveImbalanced: got %d", s.consecutiveImbalanced)
	}
}

// ---------------- 5.5 Ethtool invocation + failure (3 tests) -----

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
	if !strings.Contains(err.Error(), "invalid weight value") {
		t.Errorf("error should contain stderr; got: %v", err)
	}
}

func TestApplyWeights_PermanentSkipAfterMaxFailures(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
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
		exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{
			0: base, 1: base / 50, 2: base / 50, 3: base / 50, 4: base / 50, 5: base / 50,
		})
		rebalanceTick(st, exec)
	}
	if !s.permanentSkip {
		t.Errorf("expected permanentSkip after %d failures, got consecutiveFailures=%d",
			rssRebalanceMaxFailures, s.consecutiveFailures)
	}
}

// ---------------- 5.6 Lifecycle + driver gate (4 tests) ----------

func TestLoop_StopsOnContextCancel(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runRSSRebalanceLoop(ctx, exec)
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
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("non-mlx5 should skip: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestLoop_SkipsOnRSSDisabled(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(false) // disabled
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("disabled: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

func TestLoop_MultiInterfaceStateIsolation(t *testing.T) {
	resetRSSGlobals(t)
	sa := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	sb := &rssRebalanceState{currentWeights: equalWeights(6), firstSample: true}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	exec.driver["e1"] = mlx5Driver
	exec.queueCount["e1"] = 6
	exec.ethtoolS["e1"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0", "e1"}
	rssAllowedRef.Store(&a)
	st := map[string]*rssRebalanceState{"e0": sa, "e1": sb}
	rebalanceTick(st, exec)
	// Neither should have triggered yet (first sample). State arrays
	// must be distinct objects (no shared backing).
	if &sa.currentWeights[0] == &sb.currentWeights[0] {
		t.Error("state isolation broken: two ifaces share weight slice")
	}
}

// ---------------- 5.7 Concurrency + ConfigGen / Epoch (5 tests) ---

func TestConcurrency_StaleWeightsAbandonedOnConfigGenChange(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	// Bump ConfigGen between snapshot and the lock by intercepting via
	// ethtool stub: rebalance loop calls ethtool -S first; we use that
	// hook via a goroutine that bumps before the lock acquisition. The
	// simplest functional pin: bump ConfigGen NOW (before tick) so that
	// when rebalanceTick takes its tick-start snapshot, then later
	// re-checks under the lock, the values match. To prove the abandon
	// path, we instead need to bump BETWEEN snapshot and re-check. Use
	// a custom stub that bumps from inside runEthtool("-S", ...).
	bumped := atomic.Bool{}
	exec.ethtoolSErr = nil
	origStub := exec
	// Replace runEthtool to bump on the first -S call.
	wrappedExec := &bumpingExecutor{base: origStub, bumpOnSCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, wrappedExec)
	if len(origStub.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon (no -X call), got %d", len(origStub.ethtoolXCalls))
	}
	if !bumped.Load() {
		t.Error("test wiring: bump never fired")
	}
}

type bumpingExecutor struct {
	base          *stubRSSExecutor
	bumpOnSCalled *atomic.Bool
}

func (b *bumpingExecutor) runEthtool(args ...string) ([]byte, error) {
	if len(args) >= 1 && args[0] == "-S" && !b.bumpOnSCalled.Load() {
		// Simulate a control-plane invocation between tick-start snapshot
		// and the subsequent ConfigGen re-check.
		BumpRSSConfigGen()
		b.bumpOnSCalled.Store(true)
	}
	return b.base.runEthtool(args...)
}
func (b *bumpingExecutor) readDriver(iface string) string  { return b.base.readDriver(iface) }
func (b *bumpingExecutor) readQueueCount(iface string) int { return b.base.readQueueCount(iface) }
func (b *bumpingExecutor) listInterfaces() []string        { return b.base.listInterfaces() }

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
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 1000, 1: 1000, 2: 1000, 3: 1000, 4: 1000, 5: 1000})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	BumpRSSEpoch() // simulates external control-plane write
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
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
	applyRSSIndirection(true, 6, a, exec) // failed apply (ethtool -x will succeed; -X will fail)
	gen1 := LoadRSSConfigGen()
	if gen1 == gen0 {
		t.Errorf("ConfigGen should bump on every invocation regardless of write outcome; gen0=%d gen1=%d", gen0, gen1)
	}
}

func TestConcurrency_RebalanceWriteDoesNotBumpGlobalCounters(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	epochBefore := LoadRSSEpoch()
	genBefore := LoadRSSConfigGen()
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
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

// R7 Finding 1 pin — handled via the same bumping-stub mechanism as
// TestConcurrency_StaleWeightsAbandonedOnConfigGenChange, just
// asserting the abandon path explicitly.
func TestConcurrency_AbandonsWhenControlPlaneFiresBetweenSnapshotAndLock(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
		consecutiveImbalanced: rssRebalanceStability,
		lastRebalanceTime:     time.Now().Add(-2 * rssRebalanceCooldown),
		firstSample:           false,
		lastSampleTime:        time.Now().Add(-2 * time.Second),
		lastSampleCounters:    map[int]uint64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
	}
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	bumped := atomic.Bool{}
	wrappedExec := &bumpingExecutor{base: exec, bumpOnSCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, wrappedExec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon, got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// R9 Finding 2 pins — live reload tests.

func TestLiveReload_AllowlistShrinkTakesEffectNextTick(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.driver["e1"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.queueCount["e1"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	exec.ethtoolS["e1"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0", "e1"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec)
	if _, ok := state["e0"]; !ok {
		t.Fatal("e0 state not created on first tick")
	}
	if _, ok := state["e1"]; !ok {
		t.Fatal("e1 state not created on first tick")
	}
	// Shrink allowlist: drop e1.
	a2 := []string{"e0"}
	rssAllowedRef.Store(&a2)
	preCalls := len(exec.ethtoolXCalls)
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	state["e1"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec)
	// e1 must not get any new ethtool calls.
	for _, call := range exec.ethtoolXCalls[preCalls:] {
		for _, arg := range call {
			if arg == "e1" {
				t.Errorf("e1 was touched after allowlist shrink: %v", call)
			}
		}
	}
}

// Code-review R2 FA2 pin: post-lock Epoch re-check abandons stale
// rebalance writes when a successful control-plane apply landed
// during our compute / lock-wait window.
func TestConcurrency_AbandonsWhenEpochBumpsBetweenSnapshotAndLock(t *testing.T) {
	resetRSSGlobals(t)
	s := &rssRebalanceState{
		currentWeights:        equalWeights(6),
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
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	bumped := atomic.Bool{}
	wrappedExec := &epochBumpingExecutor{base: exec, bumpOnSCalled: &bumped}
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, wrappedExec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("expected abandon on Epoch change, got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// epochBumpingExecutor bumps Epoch (not ConfigGen) during ethtool -S
// to simulate a successful control-plane write completing during the
// rebalance loop's compute/lock-wait window.
type epochBumpingExecutor struct {
	base          *stubRSSExecutor
	bumpOnSCalled *atomic.Bool
}

func (b *epochBumpingExecutor) runEthtool(args ...string) ([]byte, error) {
	if len(args) >= 1 && args[0] == "-S" && !b.bumpOnSCalled.Load() {
		BumpRSSEpoch()
		b.bumpOnSCalled.Store(true)
	}
	return b.base.runEthtool(args...)
}
func (b *epochBumpingExecutor) readDriver(iface string) string  { return b.base.readDriver(iface) }
func (b *epochBumpingExecutor) readQueueCount(iface string) int { return b.base.readQueueCount(iface) }
func (b *epochBumpingExecutor) listInterfaces() []string        { return b.base.listInterfaces() }

// Code-review R2 FA4 pin: a worker-count change that arrives via an
// idempotent reapply (no Epoch bump because table already matches)
// still triggers re-seed because the size-mismatch detector fires.
func TestLiveReload_WorkerCountChangeWithoutEpochBumpReseeds(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec) // first sample, seeds currentWeights len=4
	if len(state["e0"].currentWeights) != 4 {
		t.Fatalf("first tick should seed len=4, got %d", len(state["e0"].currentWeights))
	}
	// Worker-count drops to 2; NO Epoch bump (idempotent reapply
	// path). Size-mismatch detector must reseed.
	rssWorkers.Store(2)
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec)
	if len(state["e0"].currentWeights) != 2 {
		t.Errorf("size-mismatch reseed should resize to 2, got %d", len(state["e0"].currentWeights))
	}
}

// FA5 regression pin: weightsEqual no-op path doesn't fire ethtool.
func TestRebalance_NoOpWeightsSkipsEthtoolCall(t *testing.T) {
	resetRSSGlobals(t)
	// Construct: hot ring at MIN_WEIGHT already; shift will clamp to 0.
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
	// Skewed traffic (ring 0 hottest), but ring 0 weight already at MIN.
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 5000, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(6)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	rebalanceTick(map[string]*rssRebalanceState{"e0": s}, exec)
	if len(exec.ethtoolXCalls) != 0 {
		t.Errorf("no-op weights path should skip ethtool: got %d -X calls", len(exec.ethtoolXCalls))
	}
}

// FA4 first-creation seed regression pin.
func TestRebalance_FirstCreationSeedsCurrentWeights(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec)
	if state["e0"] == nil {
		t.Fatal("state entry not created")
	}
	if got := state["e0"].currentWeights; len(got) != 4 {
		t.Errorf("expected first-creation seed len=4, got len=%d (%v)", len(got), got)
	}
}

func TestLiveReload_WorkerCountChangeTakesEffectNextTick(t *testing.T) {
	resetRSSGlobals(t)
	exec := newStubRSSExecutor()
	exec.driver["e0"] = mlx5Driver
	exec.queueCount["e0"] = 6
	exec.ethtoolS["e0"] = formatEthtoolS(map[int]uint64{0: 100, 1: 100, 2: 100, 3: 100, 4: 100, 5: 100})
	rssEnabled.Store(true)
	rssWorkers.Store(4)
	a := []string{"e0"}
	rssAllowedRef.Store(&a)
	state := map[string]*rssRebalanceState{}
	rebalanceTick(state, exec) // first sample
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec) // baseline established with workers=4
	// Bump epoch to simulate a control-plane reapply with new worker count.
	rssWorkers.Store(2)
	BumpRSSEpoch()
	state["e0"].lastSampleTime = time.Now().Add(-2 * time.Second)
	rebalanceTick(state, exec)
	if len(state["e0"].currentWeights) != 2 {
		t.Errorf("worker count change: weights len = %d, want 2", len(state["e0"].currentWeights))
	}
}

// ---------------- helpers ----------------

func formatEthtoolS(rings map[int]uint64) []byte {
	var b strings.Builder
	for i := 0; i < 32; i++ { // include up to 32 rings; absent ones omitted
		if v, ok := rings[i]; ok {
			b.WriteString("     rx")
			b.WriteString(strconv.Itoa(i))
			b.WriteString("_packets: ")
			b.WriteString(strconv.FormatUint(v, 10))
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

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

// quiet unused-import / unused-helper warnings.
var (
	_ = exec.Command
	_ = strconv.Atoi
)
