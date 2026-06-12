package daemon

import (
	"context"
	"fmt"
	"testing"

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
	var calls int
	retFailed := map[string]error{"WAN/t": fmt.Errorf("egress interface missing")}
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
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
}
