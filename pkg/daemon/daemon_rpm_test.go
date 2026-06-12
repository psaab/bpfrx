package daemon

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
)

func rpmTestConfig(target string) *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: target, TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMConfigHashGating is the #1827 PR-1a gating test: the
// probe set is re-applied only when the rendered RPM stanza actually
// changed — unrelated re-applies of the same config are skipped so
// probe state is never wiped.
func TestReconcileRPMConfigHashGating(t *testing.T) {
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	defer d.rpm.StopAll()

	cfg := rpmTestConfig("192.0.2.1")
	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}
	if d.reconcileRPM(cfg) {
		t.Fatal("identical config must be hash-gated (no re-apply)")
	}
	// A semantically identical but freshly-built config object must
	// also be gated (hash is content-based, not pointer-based).
	if d.reconcileRPM(rpmTestConfig("192.0.2.1")) {
		t.Fatal("equal-content config must be hash-gated")
	}
	// A real change re-applies.
	if !d.reconcileRPM(rpmTestConfig("192.0.2.2")) {
		t.Fatal("changed RPM stanza must re-apply")
	}
	// Removing the stanza re-applies (stops probes) once, then gates.
	empty := &config.Config{}
	if !d.reconcileRPM(empty) {
		t.Fatal("RPM removal must re-apply (stop probes)")
	}
	if d.reconcileRPM(empty) {
		t.Fatal("steady-state empty config must be gated")
	}
	if got := d.rpm.Results(); len(got) != 0 {
		t.Fatalf("probes still running after removal: %+v", got)
	}
}

func TestRPMConfigHashSensitivity(t *testing.T) {
	base := rpmTestConfig("192.0.2.1").Services.RPM
	h1 := rpmConfigHash(base, nil)
	h2 := rpmConfigHash(base, nil)
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if h1 == rpmConfigHash(nil, nil) {
		t.Fatal("nil config must hash differently from configured probes")
	}
	// RETH map participates (it changes destination-interface resolution).
	if h1 == rpmConfigHash(base, map[string]string{"reth0": "ge-0/0/2"}) {
		t.Fatal("reth map must participate in the hash")
	}
	withPin := rpmTestConfig("192.0.2.1").Services.RPM
	withPin.Probes["WAN"].Tests["t"].NextHop = "10.0.0.1"
	if h1 == rpmConfigHash(withPin, nil) {
		t.Fatal("next-hop change must change the hash")
	}
}

// rpmPinnedTestConfig returns a config whose single test carries a
// next-hop pin (so BuildProbePins yields one pin).
func rpmPinnedTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "192.0.2.1", NextHop: "10.0.0.1",
				DestinationInterface: "ge-0/0/2", TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMPinFailureRetry is the #1895 daemon-side contract:
// pin install failures are threaded into the RPM manager, hash-gated
// reconciles retry ONLY the pin install (no probe restart), and the
// retry stops once the install recovers.
func TestReconcileRPMPinFailureRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	retFailed := map[string]error{"WAN/t": fmt.Errorf("egress interface missing")}
	d := &Daemon{rpm: rpm.New(), daemonCtx: ctx}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		calls++
		if len(pins) != 1 || pins[0].TestKey != "WAN/t" {
			t.Fatalf("unexpected pins: %+v", pins)
		}
		// Codex PR #1899 r1 MAJOR-1: while the band is being
		// cleared-and-reprogrammed, every pin must already be held
		// (pre-marked) so a live probe cannot race the reprogram and
		// false-PASS through the main table.
		if got := d.rpm.PinInstallFailureCount(); got != len(pins) {
			t.Fatalf("pins not pre-held during reprogram: count = %d, want %d", got, len(pins))
		}
		return retFailed
	}
	defer d.rpm.StopAll()

	cfg := rpmPinnedTestConfig()
	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}
	if calls != 1 {
		t.Fatalf("pin apply calls = %d, want 1", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("failure not threaded into rpm manager: count = %d, want 1", got)
	}

	// Hash-gated call: no probe re-apply, but the failed pin install
	// is retried.
	if d.reconcileRPM(cfg) {
		t.Fatal("identical config must stay hash-gated while pins retry")
	}
	if calls != 2 {
		t.Fatalf("pin apply calls = %d, want 2 (retry under unchanged hash)", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("still-failed retry must keep the failure: count = %d", got)
	}

	// Recovery: the next gated call retries, succeeds, clears the
	// manager state, and stops retrying afterwards.
	retFailed = nil
	if d.reconcileRPM(cfg) {
		t.Fatal("recovery retry must not count as a probe re-apply")
	}
	if calls != 3 {
		t.Fatalf("pin apply calls = %d, want 3", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("recovered pins must clear the failure: count = %d", got)
	}
	if d.reconcileRPM(cfg); calls != 3 {
		t.Fatalf("pin apply calls = %d, want 3 (no retry once recovered)", calls)
	}
}

// TestReconcileRPMNoInstallerHoldsPinnedTests: next-hop pins configured
// but no routing manager (and no seam) — every pin must be marked
// failed so rpm holds those tests; marks alone would otherwise send
// marked-but-unbacked probes through the main table (Codex PR #1899
// r1 MAJOR-2).
func TestReconcileRPMNoInstallerHoldsPinnedTests(t *testing.T) {
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	defer d.rpm.StopAll()

	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("first reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("pinned test without installer must be held: count = %d, want 1", got)
	}
	// Unpinned configs never report installer failures.
	if !d.reconcileRPM(rpmTestConfig("192.0.2.9")) {
		t.Fatal("config change must re-apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("unpinned config must clear held pins: count = %d", got)
	}
	// Removing RPM entirely releases everything (Codex r3: the
	// no-installer path shares the hold-then-publish-after-Apply
	// ordering, so removal cannot leave stale holds — or release an
	// old hold before the old goroutines are drained).
	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("pinned config must re-apply")
	}
	if !d.reconcileRPM(&config.Config{}) {
		t.Fatal("RPM removal must re-apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("RPM removal must clear held pins: count = %d", got)
	}
}

// rpmTwoPinConfig returns a config with two pinned tests.
func rpmTwoPinConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"a": {Name: "a", Target: "192.0.2.1", NextHop: "10.0.0.1",
				DestinationInterface: "ge-0/0/1", TestInterval: 3600},
			"b": {Name: "b", Target: "192.0.2.2", NextHop: "10.0.1.1",
				DestinationInterface: "ge-0/0/2", TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMFullApplyHoldsUnionOfOldAndNewPins: on a config
// change, the band reprogram must run with BOTH the old (live) pinned
// tests and the new pin set held — a removed/reordered old pin's live
// goroutine must not send against the band in flux (Codex PR #1899
// r2) — and the real results must only be published after rpm.Apply.
func TestReconcileRPMFullApplyHoldsUnionOfOldAndNewPins(t *testing.T) {
	var heldAtInstall []int
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		heldAtInstall = append(heldAtInstall, d.rpm.PinInstallFailureCount())
		return nil
	}
	defer d.rpm.StopAll()

	// First apply: no live marks yet — hold covers the 2 new pins.
	if !d.reconcileRPM(rpmTwoPinConfig()) {
		t.Fatal("first reconcile must apply")
	}
	// Config change drops WAN/a: the hold must cover the union of the
	// 2 live old pins and the 1 surviving new pin = 2 keys.
	one := rpmTwoPinConfig()
	delete(one.Services.RPM.Probes["WAN"].Tests, "a")
	if !d.reconcileRPM(one) {
		t.Fatal("changed config must re-apply")
	}
	want := []int{2, 2} // first apply: 2 new; second: union{a,b}∪{b} = 2
	if len(heldAtInstall) != 2 || heldAtInstall[0] != want[0] || heldAtInstall[1] != want[1] {
		t.Fatalf("held counts at install time = %v, want %v", heldAtInstall, want)
	}
	// All installs succeeded: published results clear every hold.
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("holds not released after publish: count = %d", got)
	}
}

// TestProbePinPeriodicRetryRecoversWithoutCommit is the #1895 AGY-fold
// contract: a pin that fails at apply time (boot ordering — egress
// link not yet up) recovers via the slow periodic retry loop with NO
// commit and NO RG transition, and the loop stops once every pin is
// installed.
func TestProbePinPeriodicRetryRecoversWithoutCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	linkUp := false
	calls := 0
	d := &Daemon{rpm: rpm.New(), daemonCtx: ctx, probePinRetryEvery: 5 * time.Millisecond}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if !linkUp {
			return map[string]error{pins[0].TestKey: fmt.Errorf("egress interface missing")}
		}
		return nil
	}
	defer d.rpm.StopAll()

	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("first reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("pin must be held after failed apply: count = %d", got)
	}

	// The "link appears" with no further reconcileRPM calls: the
	// periodic loop must recover the pin on its own.
	mu.Lock()
	linkUp = true
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && d.rpm.PinInstallFailureCount() != 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("periodic retry did not recover the pin without a commit: count = %d", got)
	}

	// The loop stops once recovered: no further installer calls.
	mu.Lock()
	settled := calls
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	final := calls
	mu.Unlock()
	if final != settled {
		t.Fatalf("retry loop kept running after recovery: %d -> %d installer calls", settled, final)
	}
	d.rpmMu.Lock()
	active := d.rpmPinRetryActive
	d.rpmMu.Unlock()
	if active {
		t.Fatal("rpmPinRetryActive still set after recovery")
	}
}
