package userspace

import (
	"errors"
	"testing"
)

// #6691 B2 — the v5 protocol bump and its required-protocol gate.
//
// `InterfaceSnapshot.secure_tunnel` is a NEW field that is AUTHORITATIVE over
// existing behaviour: the helper's binding admission refuses a candidate on it.
// The repo rule (userspace-dp/src/server/README.md) is to bump the snapshot
// protocol version whenever that happens, and this PR shipped the field at an
// unchanged version 4 — the same shape as #5488.
//
// WHAT AN OLD HELPER ACTUALLY DOES, which is why this is not cosmetic. A v4
// helper decodes the snapshot, ignores the unknown `secure_tunnel` tag, and
// plans the xfrmi as an ordinary AF_XDP candidate. Its queue count is the
// GLOBAL MINIMUM across candidates (replan_bindings_from_candidates,
// userspace-dp/src/server/helpers/planning.rs) and an xfrm interface has
// exactly ONE RX queue — measured on a real device: `ip -d link` reports
// `numrxqueues 1` and `/sys/class/net/<if>/queues` holds a single `rx-0`, the
// same entry userspaceRXQueueCount counts. So the ignored flag does not cost
// the tunnel a binding; it re-plans EVERY physical interface on the box onto
// one queue and one worker (#3091). Nothing on the wire is malformed, so the
// same-version equality check and the snapshot content hash both see a
// perfectly good snapshot.

// preV5SnapshotProtocolVersion is the version this PR shipped the
// `secure_tunnel` field at before the #6691 round-8 bump — the version whose
// readers cannot see the field. A LITERAL, not `ProtocolVersion - 1`, for the
// same reason preV4SnapshotProtocolVersion is: the property under test is that
// the current version no longer COLLIDES with the version that misreads the
// snapshot, so tracking the constant would make the test vacuous the moment
// the constant moves again.
const preV5SnapshotProtocolVersion = 4

// preV5HelperAcceptsSnapshot models the exact-equality version gate a pre-v5
// helper applies before touching any dataplane state
// (userspace-dp/src/server/handlers/snapshot.rs).
func preV5HelperAcceptsSnapshot(version int) bool {
	return version == preV5SnapshotProtocolVersion
}

// preV5HelperPlansBinding models a pre-v5 helper's binding admission: the
// current predicate MINUS the `secure_tunnel` arm, which such a helper does not
// have. Everything else is unchanged, so this isolates the one field.
func preV5HelperPlansBinding(iface InterfaceSnapshot) bool {
	if iface.Zone == "" || iface.Tunnel || iface.LocalFabric != "" {
		return false
	}
	base := iface.Name
	for i := 0; i < len(base); i++ {
		if base[i] == '.' {
			base = base[:i]
			break
		}
	}
	switch {
	case len(base) >= 3 && base[:3] == "fxp",
		len(base) >= 2 && base[:2] == "em",
		len(base) >= 3 && base[:3] == "fab",
		base == "lo0":
		return false
	}
	switch iface.Zone {
	case "mgmt", "control":
		return false
	}
	return true
}

// TestSecureTunnelFieldIsNotIgnorableByAPreV5Helper is the #6691 B2
// regression: the version must have MOVED off the value whose readers ignore
// the field, and the gate must turn the resulting refusal into a fail-closed
// disarm plus an aborted commit.
//
// FAIL-ON-REVERT: set ProtocolVersion back to 4 and the first assertion reds
// (a pre-v5 helper accepts the snapshot); drop
// ensureSecureTunnelProtocolLocked from ensureRequiredSnapshotProtocolLocked
// and the gate assertion reds; drop the sentinel from
// requiredProtocolGateSentinels and the abort-set assertion reds.
func TestSecureTunnelFieldIsNotIgnorableByAPreV5Helper(t *testing.T) {
	if ProtocolVersion <= preV5SnapshotProtocolVersion {
		t.Fatalf("ProtocolVersion = %d, must be > %d: `secure_tunnel` became authoritative "+
			"over binding admission, so a reader that cannot see it must not share our version",
			ProtocolVersion, preV5SnapshotProtocolVersion)
	}

	cfg, unitRef, wantDev := spellingConfig(t, "st0.0", "st0", 0)
	restore := stubLinkSnapshot5619(t, map[string]int{wantDev: 42, "ge-0-0-0": 11})
	defer restore()

	// PREMISE: the snapshot really does carry a flagged row, and it really
	// does resolve to a device — otherwise every assertion below is vacuous.
	var tunnelRow *InterfaceSnapshot
	for i := range buildInterfaceSnapshots(cfg) {
		row := buildInterfaceSnapshots(cfg)[i]
		if row.Name == unitRef {
			tunnelRow = &row
			break
		}
	}
	if tunnelRow == nil || !tunnelRow.SecureTunnel || tunnelRow.Ifindex <= 0 {
		t.Fatalf("premise broken: %q row = %+v, want SecureTunnel with a resolved ifindex",
			unitRef, tunnelRow)
	}

	// 1. THE OLD READER MISBEHAVES. Stated so the gate has a documented reason
	//    rather than an asserted one: a pre-v5 helper plans the xfrmi, and the
	//    planner's global-minimum queue count then collapses the box.
	if !preV5HelperPlansBinding(*tunnelRow) {
		t.Fatalf("premise broken: a pre-v5 helper must PLAN this row (it cannot see "+
			"secure_tunnel); row = %+v", tunnelRow)
	}

	// 2. THE VERSION KEEPS IT AWAY FROM THAT READER. The daemon stamps its own
	//    ProtocolVersion onto every snapshot; a pre-v5 helper must refuse it.
	snap := &ConfigSnapshot{Version: ProtocolVersion}
	if preV5HelperAcceptsSnapshot(snap.Version) {
		t.Errorf("a pre-v5 helper ACCEPTS the snapshot at version %d: it ignores secure_tunnel, "+
			"plans an AF_XDP binding for the xfrmi, and its one RX queue becomes the global "+
			"minimum — every interface collapses to one queue and one worker (#3091)",
			snap.Version)
	}

	// 3. AND THE REFUSAL IS FAIL-CLOSED. A refused snapshot alone leaves the
	//    old helper ARMED on its previous-good image while the commit reports
	//    success. Drive the REAL dispatcher, not the gate function, so the
	//    wiring is what is under test.
	m := New()
	m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion
	gateErr := m.ensureRequiredSnapshotProtocolLocked(cfg)
	if !errors.Is(gateErr, ErrSecureTunnelProtocolIncompatible) {
		t.Errorf("ensureRequiredSnapshotProtocolLocked against a pre-v5 helper = %v, want "+
			"ErrSecureTunnelProtocolIncompatible — the helper must be disarmed, not handed a "+
			"snapshot whose secure_tunnel flag it will ignore", gateErr)
	}
	// #2138: a gate that disarms but is missing from the abort set promotes the
	// commit against a disarmed dataplane.
	if !IsRequiredProtocolGateError(gateErr) {
		t.Errorf("IsRequiredProtocolGateError(%v) = false, want true — the #6691 gate must "+
			"abort the commit", gateErr)
	}

	// 4. A CURRENT HELPER IS NOT GATED.
	m2 := New()
	m2.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	if err := m2.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
		t.Errorf("current-version helper gated: %v, want nil", err)
	}
}

// TestSecureTunnelGateIsScopedToConfigsThatDeriveAnXfrmi is the negative
// control. A config with no route-based IPsec cannot be misread by a pre-v5
// helper — there is no flagged row for it to ignore — so it must NOT be gated.
// Without this, the fix disarms every operator on an older helper for a field
// none of their interfaces carry.
func TestSecureTunnelGateIsScopedToConfigsThatDeriveAnXfrmi(t *testing.T) {
	cfg := compileForTest5619(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	if configHasSecureTunnel(cfg) {
		t.Fatal("premise broken: this config derives no xfrmi")
	}

	m := New()
	m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion
	if err := m.ensureSecureTunnelProtocolLocked(cfg); err != nil {
		t.Errorf("a config with no secure tunnel was gated against a pre-v5 helper: %v", err)
	}
}

// TestSecureTunnelGateSeesEverySpelling: the gate's arming predicate walks the
// same refs the snapshot builder walks, so it must arm for every spelling the
// builder flags. A gate that fires for `st0.0` but not `st10.5` would leave the
// multi-digit spellings ungated on exactly the upgrade this exists to stop.
func TestSecureTunnelGateSeesEverySpelling(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, _ := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
			if !configHasSecureTunnel(cfg) {
				t.Fatalf("configHasSecureTunnel = false for bind-interface %q; the v5 gate "+
					"would not arm and a pre-v5 helper would plan its binding", tc.bindIface)
			}
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion
			if err := m.ensureSecureTunnelProtocolLocked(cfg); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
				t.Fatalf("gate for bind-interface %q = %v, want ErrSecureTunnelProtocolIncompatible",
					tc.bindIface, err)
			}
		})
	}
}
