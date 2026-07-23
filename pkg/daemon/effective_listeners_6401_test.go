// RED-on-revert net for the #6401 fold: the HTTP REST listener state the
// `show system services` snapshot reports (managementReconciler.effectiveHTTPListener)
// must DISTINGUISH three states — Disabled (no --api-addr, nil reconciler),
// Failed (configured but the boot bind failed), and Listening (converged). The
// pre-fold accessor returned a bare address ("" for BOTH disabled and failed),
// so a failed bind was misreported as "disabled". These assert the three states
// are distinct, and that a Listening bind reports the ACTUAL bound address (an
// ephemeral :0 resolves to a concrete port).
package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/sysservices"
)

func TestEffectiveHTTPListenerStatesDistinct(t *testing.T) {
	// Disabled: nil reconciler — an empty --api-addr, where Daemon.Run never
	// started the HTTP listener.
	var nilM *managementReconciler
	if got := nilM.effectiveHTTPListener(); got.State != sysservices.StateDisabled {
		t.Errorf("nil reconciler state = %v, want StateDisabled: %+v", got.State, got)
	}

	// Failed: configured but the boot bind failed (fake factory refuses the
	// addr, so startTo returns an error and curSet stays false).
	reg := newFakeReg()
	reg.failAddr["10.0.0.1:8080"] = true
	mFail := newTestMgmt(reg)
	if err := mFail.startTo(context.Background(), cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
		t.Fatal("startTo should fail when the fake factory refuses the bind")
	}
	failLn := mFail.effectiveHTTPListener()
	if failLn.State != sysservices.StateFailed {
		t.Errorf("failed boot bind state = %v, want StateFailed: %+v", failLn.State, failLn)
	}
	if failLn.Addr != "10.0.0.1:8080" {
		t.Errorf("failed listener addr = %q, want the attempted 10.0.0.1:8080", failLn.Addr)
	}

	// Listening: converged bind (fake factory accepts).
	regOK := newFakeReg()
	mOK := newTestMgmt(regOK)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mOK.startTo(ctx, cfgFor(regOK, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("startTo: %v", err)
	}
	if got := mOK.effectiveHTTPListener(); got.State != sysservices.StateListening {
		t.Errorf("converged bind state = %v, want StateListening: %+v", got.State, got)
	}

	// The three states are mutually distinct — the crux of the fold.
	if sysservices.StateDisabled == sysservices.StateFailed ||
		sysservices.StateFailed == sysservices.StateListening {
		t.Fatal("listener states are not distinct")
	}
}

// TestEffectiveHTTPListenerEphemeralPort drives a REAL bind on 127.0.0.1:0 and
// asserts the reported address is the concrete ephemeral port the socket bound,
// not the requested ":0" — the #6401 point-4 fold that sources the address from
// the live listener's Addr (api.Server.EffectiveHTTPAddr) rather than the
// requested endpoint fingerprint.
func TestEffectiveHTTPListenerEphemeralPort(t *testing.T) {
	m := newManagementReconciler(&Daemon{}, api.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.startTo(ctx, api.Config{Addr: "127.0.0.1:0"}); err != nil {
		t.Fatalf("startTo real bind: %v", err)
	}
	got := m.effectiveHTTPListener()
	if got.State != sysservices.StateListening {
		t.Fatalf("real bind state = %v, want StateListening: %+v", got.State, got)
	}
	if got.Addr == "" || strings.HasSuffix(got.Addr, ":0") {
		t.Errorf("ephemeral bind addr not resolved to a concrete port: %q", got.Addr)
	}
}
