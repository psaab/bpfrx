package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
