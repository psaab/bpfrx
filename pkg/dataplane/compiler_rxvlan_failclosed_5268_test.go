package dataplane

// #5268 (High, security): a non-fatal ensureRxVlanOff failure let HW-stripped
// 802.1Q traffic bypass zone classification. The XDP dataplane derives VLAN
// (security-domain) identity SOLELY from the in-frame tag; if a NIC's RX-VLAN
// offload strips the tag into skb->vlan_tci (unreadable by XDP) and xpf cannot
// disable it, tagged frames parse as vlan_id=0 and fall back to the parent
// ifindex → the parent's / first-subinterface's zone → untrusted VLAN traffic
// classified into a TRUSTED zone. The fix makes RX-VLAN-offload-disable an
// activation precondition — but ONLY for a parent that carries configured VLAN
// subinterfaces (a plain parent, or a NIC that legitimately lacks the offload
// knob when no VLANs are present, is unaffected).

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// mockEthtool substitutes the package `runEthtool` for the duration of the test.
func mockEthtool(t *testing.T, fn func(args ...string) ([]byte, error)) {
	t.Helper()
	orig := runEthtool
	runEthtool = fn
	t.Cleanup(func() { runEthtool = orig })
}

func newRxVlanResult() *CompileResult {
	return &CompileResult{rxVlanOffCache: make(map[string]bool)}
}

func cfgWithVlanSubif() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0-0-0": {
					Name: "ge-0-0-0",
					Units: map[int]*config.InterfaceUnit{
						0:  {Number: 0, VlanID: 0},
						50: {Number: 50, VlanID: 50},
					},
				},
			},
		},
	}
}

func cfgPlainParent() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0-0-0": {
					Name:  "ge-0-0-0",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 0}},
				},
			},
		},
	}
}

// ---- ensureRxVlanOff error contract (#5268) -------------------------------

// Offload reported ON and `-K rxvlan off` fails → error (the dangerous case:
// the NIC WILL strip tags and we could not stop it).
func TestEnsureRxVlanOffErrorWhenOnAndDisableFails_5268(t *testing.T) {
	calls := 0
	mockEthtool(t, func(args ...string) ([]byte, error) {
		calls++
		switch args[0] {
		case "-k":
			return []byte("Features for ge-0-0-0:\nrx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("Cannot set device feature settings: not supported"),
				errors.New("exit status 1")
		}
		return nil, errors.New("unexpected ethtool " + args[0])
	})
	err := newRxVlanResult().ensureRxVlanOff("ge-0-0-0")
	if err == nil {
		t.Fatal("ensureRxVlanOff must return an error when the offload is ON and cannot be disabled")
	}
	if calls != 2 {
		t.Fatalf("expected -k then -K (2 calls), got %d", calls)
	}
}

// Already `off [fixed]` (e.g. virtio) → nil, and `-K` is NEVER attempted (a
// toggle would drive a needless driver reset).
func TestEnsureRxVlanOffNilWhenAlreadyOffFixed_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if args[0] == "-k" {
			return []byte("Features for ge-0-0-0:\nrx-vlan-offload: off [fixed]\n"), nil
		}
		t.Fatalf("must NOT call ethtool %v when already off", args)
		return nil, nil
	})
	if err := newRxVlanResult().ensureRxVlanOff("ge-0-0-0"); err != nil {
		t.Fatalf("already-off must return nil, got %v", err)
	}
}

// Feature ABSENT from a successful query (NIC has no rx-vlan-offload knob) →
// nil, `-K` NEVER attempted. This is the virtio-safe path that must NOT falsely
// trip the fail-closed gate.
func TestEnsureRxVlanOffNilWhenFeatureAbsent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if args[0] == "-k" {
			return []byte("Features for ge-0-0-0:\ntx-checksumming: on\nscatter-gather: on\n"), nil
		}
		t.Fatalf("must NOT call ethtool %v when the feature is absent", args)
		return nil, nil
	})
	if err := newRxVlanResult().ensureRxVlanOff("ge-0-0-0"); err != nil {
		t.Fatalf("feature-absent must return nil, got %v", err)
	}
}

// Query fails but the disable SUCCEEDS → nil (we achieved "off").
func TestEnsureRxVlanOffNilWhenQueryFailsButDisableOk_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return nil, errors.New("ethtool -k failed")
		case "-K":
			return []byte(""), nil
		}
		return nil, errors.New("unexpected")
	})
	if err := newRxVlanResult().ensureRxVlanOff("ge-0-0-0"); err != nil {
		t.Fatalf("query-fail + disable-ok must return nil, got %v", err)
	}
}

// Query fails AND the disable fails → error (state unknown, could not confirm).
func TestEnsureRxVlanOffErrorWhenQueryAndDisableFail_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		return nil, errors.New("ethtool unavailable")
	})
	if err := newRxVlanResult().ensureRxVlanOff("ge-0-0-0"); err == nil {
		t.Fatal("query-fail + disable-fail must return an error")
	}
}

// Cached-off short-circuits with no ethtool call.
func TestEnsureRxVlanOffCachedShortCircuits_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		t.Fatalf("cached off must not call ethtool %v", args)
		return nil, nil
	})
	r := newRxVlanResult()
	r.rxVlanOffCache["ge-0-0-0"] = true
	if err := r.ensureRxVlanOff("ge-0-0-0"); err != nil {
		t.Fatalf("cached-off must return nil, got %v", err)
	}
}

// ---- parentHasVlanSubinterface (#5268 gate input) -------------------------

func TestParentHasVlanSubinterface_5268(t *testing.T) {
	if !parentHasVlanSubinterface(cfgWithVlanSubif(), "ge-0-0-0") {
		t.Fatal("a config with a VlanID>0 unit must report a VLAN subinterface")
	}
	if parentHasVlanSubinterface(cfgPlainParent(), "ge-0-0-0") {
		t.Fatal("a config with only VlanID==0 units must NOT report a VLAN subinterface")
	}
	if parentHasVlanSubinterface(cfgWithVlanSubif(), "ge-0-0-9") {
		t.Fatal("an unknown interface name must report no VLAN subinterface")
	}
	if parentHasVlanSubinterface(nil, "ge-0-0-0") {
		t.Fatal("nil config must report no VLAN subinterface")
	}
}

// ---- THE FAIL-ON-REVERT: activation gate (#5268) --------------------------

// FAIL-ON-REVERT: a parent that carries a configured VLAN subinterface whose
// RX-VLAN offload could NOT be disabled MUST fail activation closed
// (rxVlanOffloadActivationError returns a non-nil error, which the compile path
// at compiler_iface.go returns). The `ensureErr` is produced by the REAL
// ensureRxVlanOff over a mocked ethtool that reports the offload ON and fails
// the disable. Reverting the fix (gate returns nil / warn-and-continue) makes
// the assertion RED.
func TestRxVlanFailClosedOnVlanParent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("not supported"), errors.New("exit status 1")
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := newRxVlanResult().ensureRxVlanOff("ge-0-0-0")
	if ensureErr == nil {
		t.Fatal("precondition: ensureRxVlanOff must fail for an ON-and-undisable-able offload")
	}
	if err := rxVlanOffloadActivationError(cfgWithVlanSubif(), "ge-0-0-0", "ge-0-0-0", ensureErr); err == nil {
		t.Fatal("#5268: a VLAN-subinterface parent whose rxvlan offload cannot be disabled MUST fail activation closed")
	}
}

// NEGATIVE SCOPE: a PLAIN parent (no configured VLAN subinterfaces) whose
// rxvlan disable fails must STILL succeed — the offload state is irrelevant when
// no tag-based zone classification is in use. Stays GREEN on revert.
func TestRxVlanTolerantOnPlainParent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("not supported"), errors.New("exit status 1")
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := newRxVlanResult().ensureRxVlanOff("ge-0-0-0")
	if ensureErr == nil {
		t.Fatal("precondition: ensureRxVlanOff must fail here too")
	}
	if err := rxVlanOffloadActivationError(cfgPlainParent(), "ge-0-0-0", "ge-0-0-0", ensureErr); err != nil {
		t.Fatalf("#5268 negative scope: a plain parent must NOT fail activation on a rxvlan disable failure, got %v", err)
	}
}

// A successful disable on a VLAN parent must NOT fail activation (happy path).
func TestRxVlanNoErrorOnVlanParentWhenDisableOk_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte(""), nil
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := newRxVlanResult().ensureRxVlanOff("ge-0-0-0")
	if ensureErr != nil {
		t.Fatalf("disable succeeded, ensureRxVlanOff must return nil, got %v", ensureErr)
	}
	if err := rxVlanOffloadActivationError(cfgWithVlanSubif(), "ge-0-0-0", "ge-0-0-0", ensureErr); err != nil {
		t.Fatalf("a successful disable must not fail activation, got %v", err)
	}
}
