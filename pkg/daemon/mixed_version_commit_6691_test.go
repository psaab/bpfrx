package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestMixedVersionHelperRefusalFailsTheCommit_6691 is the COMMIT-PATH half of
// the #6691 mixed-version matrix: what a control plane does when it
// meets an under-version helper on a config the secure-tunnel gate does NOT
// arm for — which is every reference cluster this project runs (the loss
// userspace cluster compiles to 16 interface rows and zero flagged ones; see
// TestMixedVersionMatrix_6691).
//
// This exists because the existing #5679 proof injects a GENERIC apply failure
// ("control-socket sync failed"), which leaves open whether the CLASSIFICATION
// is specific to that wording. Here the injected error carries the helper's
// actual refusal text, so the classification is measured against the string
// that will really arrive.
//
// WHAT THIS TEST DOES NOT PROVE, stated plainly because an earlier revision of
// this comment implied otherwise ("the injected error is the REAL one … wrapped
// the way process_control.go wraps an ok=false response"). It is a pre-formed
// error VALUE handed to a fake dataplane. No control socket is opened, no helper
// response is decoded, and process_control.go's ok=false handling never runs.
// The refusal string here is a hand-copied literal, so this test cannot catch a
// change to the text the helper emits or to how the Go side wraps it — a
// reworded refusal would leave this test green and the classification untested
// for the new wording.
//
// The two ends of that chain are pinned elsewhere, and NEITHER is pinned by this
// test: the emitted text by userspace-dp/src/server/tests.rs (the helper's own
// assertion on "unsupported snapshot protocol version"), and the pass-through by
// process_control.go, which returns errors.New(resp.Error) verbatim. That
// pass-through is READ, not measured, in this round.
//
// What IS measured here is the step the #5679 proof left as a read: an apply
// error carrying this text takes the ORDINARY class, so the commit fails through
// the deferred path and the helper is NOT disarmed.
//
// The measured outcome is a CLEAN REFUSAL, not a wrong answer: the commit
// FAILS, and because the class is not a gate sentinel the helper is NOT
// disarmed — it refused the new snapshot, so it is still enforcing its
// previous-good image and forwarding. Disarming it would convert a handshake
// disagreement into a dataplane outage.
//
// FAIL-ON-REVERT: classify the version refusal as a required-protocol-gate
// sentinel and the peer-sync assertion reds (it would become an abort-class
// error); delete the `applyErr = err` deferred capture and the commit-failure
// assertion reds.
func TestMixedVersionHelperRefusalFailsTheCommit_6691(t *testing.T) {
	installFakeNetworkctl(t)

	for _, tc := range []struct {
		name    string
		refusal error
	}{
		{
			// Direction A: new Go (v7) publishing to an old helper (v6).
			name:    "v7 control plane against a v6 helper",
			refusal: errors.New("unsupported snapshot protocol version 7 (want 6)"),
		},
		{
			// Direction B: an old control plane (v6) publishing to this helper
			// (v7). The helper's check is `snapshot.version != CONST`, so the
			// two directions are the same line with the operands swapped.
			name:    "v6 control plane against a v7 helper",
			refusal: errors.New("unsupported snapshot protocol version 6 (want 7)"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			injected := fmt.Errorf("publish userspace snapshot: %w", tc.refusal)

			// PREMISE: this must be the ORDINARY class. If a future change
			// reclassifies it, the assertions below stop describing the path
			// they name and this test must be re-read, not silently repurposed.
			if compileErrorMustAbortApply(injected) {
				t.Fatal("premise broken: the helper's version refusal is abort-class, " +
					"so it DISARMS the helper. That is the wrong action for a refusal " +
					"the helper answered by keeping its previous-good snapshot")
			}

			dp := &runtimeOnlyApplyTestDP{applyErr: injected}
			d := &Daemon{
				networkd: networkd.NewInDir(t.TempDir()),
				store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
				vrrpMgr:  vrrp.NewManager(),
				opts:     Options{NoDataplane: true},
			}
			// #2114 (master, #6743): the runtime dataplane is published
			// through an atomic cell, not a struct field. Setting `dp:` in
			// the literal no longer compiles, and — more to the point — would
			// not be visible to the readers applyConfigLocked goes through.
			d.setDataplane(dp)

			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
			}

			err := d.applyConfigLocked(context.Background(), cfg)
			if err == nil {
				t.Fatal("the commit REPORTED SUCCESS while the helper refused the " +
					"snapshot on protocol version — the committed config is promoted and " +
					"persisted but the dataplane is enforcing the previous one. That is " +
					"a WRONG ANSWER, not a clean refusal")
			}
			if !errors.Is(err, tc.refusal) {
				t.Fatalf("commit error must surface the helper's refusal; got %v", err)
			}
			if dp.applyCalls != 1 {
				t.Fatalf("dataplane ApplyConfig calls = %d, want 1", dp.applyCalls)
			}
			// The helper is NOT disarmed — it is still forwarding its
			// previous-good image, so the standby must still converge.
			if applyErrSkipsPeerSync(err) {
				t.Error("a version refusal skipped the peer config-sync, which is the " +
					"DISARMED-helper behaviour. The helper refused the snapshot and is " +
					"still armed on its previous-good image, so the standby has to " +
					"converge (#4034)")
			}
			// And it must not be mistaken for the secure-tunnel gate, whose
			// action is deliberately the opposite (abort + disarm).
			if errors.Is(err, dpuserspace.ErrSecureTunnelProtocolIncompatible) {
				t.Error("a plain version refusal surfaced the secure-tunnel gate sentinel")
			}
		})
	}
}
