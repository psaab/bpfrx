package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// session_ingress_fold_import_7095_test.go — #7095, the RECEIVING half.
//
// The sender ships a fold of a name both chassis agree on; this side turns it
// back into a LOCAL {ifindex, vlan} before the helper stores it. The cells below
// bind that translation and, more importantly, the three ways it must decline.
//
// Declining matters more than resolving here. #6928 imported 0 on purpose,
// because naming the wrong NIC is worse than naming none — so every path that
// cannot be sure must reach 0, not a guess.

func managerWithFoldResolver7095(fn func(uint32) (uint32, uint16, bool)) *Manager {
	m := &Manager{}
	m.SetIngressFoldResolver(fn)
	return m
}

func TestImportResolvesFoldToLocalIfindex_7095(t *testing.T) {
	const fold = 0x51DE51DE
	m := managerWithFoldResolver7095(func(got uint32) (uint32, uint16, bool) {
		if got != fold {
			t.Errorf("resolver called with fold %#x, want %#x", got, fold)
		}
		return 42, 50, true
	})
	val := &dataplane.SessionValue{IngressIfaceFold: fold}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{}, val)
	if req.IngressIfindex != 42 || req.IngressVLANID != 50 {
		t.Fatalf("import resolved to {ifindex:%d vlan:%d}, want {42 50} — the peer's "+
			"fold must become THIS node's numbers, which is the whole reason an "+
			"ifindex is not what crosses the wire (#7095)",
			req.IngressIfindex, req.IngressVLANID)
	}
}

// TestImportDeclinesRatherThanGuesses_7095 covers every path to "no identity".
// Each is a case where naming a device would be a confident lie.
func TestImportDeclinesRatherThanGuesses_7095(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fold     uint32
		resolver func(uint32) (uint32, uint16, bool)
	}{
		{
			// A legacy peer sends no wire field; it decodes to 0.
			name: "legacy_peer_absent_field", fold: 0,
			resolver: func(uint32) (uint32, uint16, bool) { return 9, 9, true },
		},
		{
			// #7096: a fabric-redirected session records no ingress identity,
			// because the fabric stamp carries a u16 zone id and nothing else —
			// the peer's real ingress interface is not knowable here at all.
			name: "fabric_redirected_records_nothing", fold: 0,
			resolver: func(uint32) (uint32, uint16, bool) { return 9, 9, true },
		},
		{
			// This node does not have the interface the peer named (its config
			// is ahead of ours), or two stable names collided on one fold.
			name: "unknown_or_ambiguous_fold", fold: 0x1234,
			resolver: func(uint32) (uint32, uint16, bool) { return 0, 0, false },
		},
		{
			// No resolver wired yet: the pre-#7095 behaviour, not an error.
			name: "resolver_unset", fold: 0x1234, resolver: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := managerWithFoldResolver7095(tc.resolver)
			val := &dataplane.SessionValue{IngressIfaceFold: tc.fold}
			req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{}, val)
			if req.IngressIfindex != 0 || req.IngressVLANID != 0 {
				t.Fatalf("import produced {ifindex:%d vlan:%d} for %s; it must be {0 0}. "+
					"A non-zero value here names a device on evidence this node does not "+
					"have, which is the confidently-wrong rendering #6928 refused to ship",
					req.IngressIfindex, req.IngressVLANID, tc.name)
			}
		})
	}
}

// TestImportResolvesFoldV6_7095: v6 sessions travel through a SEPARATE request
// builder. Wiring only v4 leaves every IPv6 session degraded after a failover
// with the v4 cells still green.
func TestImportResolvesFoldV6_7095(t *testing.T) {
	m := managerWithFoldResolver7095(func(uint32) (uint32, uint16, bool) { return 7, 80, true })
	val := &dataplane.SessionValueV6{IngressIfaceFold: 0xFEED}
	req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{}, val)
	if req.IngressIfindex != 7 || req.IngressVLANID != 80 {
		t.Fatalf("v6 import resolved to {ifindex:%d vlan:%d}, want {7 80}",
			req.IngressIfindex, req.IngressVLANID)
	}
}
