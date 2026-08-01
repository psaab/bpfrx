package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6198 regression coverage for the node-local BPF-ABI SessionID minted by the
// HA-synced session converters.
//
// The pre-fix composition was:
//
//	SessionID: uint64(now)<<16 | uint64(delta.Slot&0xffff)
//
// `now` is CLOCK_MONOTONIC SECONDS and `delta.Slot` is the AF_XDP BINDING slot
// (`BindingIdentity.slot` — one per interface/queue, a handful per node), which
// the binary event stream carrying the primary delta path never even decodes
// (`decodeSessionEvent` leaves it 0). Every session converted within one
// monotonic second therefore collapsed onto ONE id.

func sessionDeltaV4ForSessionID(srcPort uint16, slot uint32) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 2, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200",
		SrcPort: srcPort, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		Slot: slot,
	}
}

func sessionDeltaV6ForSessionID(srcPort uint16, slot uint32) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 10, Protocol: 6,
		SrcIP: "2001:559:8585:bf01::102", DstIP: "2001:559:8585:80::200",
		SrcPort: srcPort, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		Slot: slot,
	}
}

// TestUserspaceSyncedSessionIDDistinctPerSession6198 is the fail-on-revert pin.
//
// It converts many DISTINCT sessions that share the binding slot the event
// stream actually produces (0) and asserts every minted SessionID is unique.
// Restoring `uint64(now)<<16 | uint64(delta.Slot&0xffff)` makes this RED as an
// assertion: a few hundred conversions cannot span a monotonic second boundary
// more than once, so the pre-fix code yields at most two distinct ids.
func TestUserspaceSyncedSessionIDDistinctPerSession6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	const sessions = 512

	for _, tc := range []struct {
		name    string
		convert func(uint16, uint32) (uint64, bool)
	}{
		{
			name: "v4",
			convert: func(port uint16, slot uint32) (uint64, bool) {
				_, val, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(port, slot), zoneIDs)
				return val.SessionID, ok
			},
		},
		{
			name: "v6",
			convert: func(port uint16, slot uint32) (uint64, bool) {
				_, val, ok := userspaceSessionFromDeltaV6(sessionDeltaV6ForSessionID(port, slot), zoneIDs)
				return val.SessionID, ok
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[uint64]uint16, sessions)
			for i := 0; i < sessions; i++ {
				port := uint16(30000 + i)
				id, ok := tc.convert(port, 0)
				if !ok {
					t.Fatalf("expected %s delta (src port %d) to convert", tc.name, port)
				}
				if prev, dup := seen[id]; dup {
					t.Fatalf("%s SessionID collision: src ports %d and %d both minted id %#x "+
						"(%d distinct sessions produced only %d distinct ids) — the synced "+
						"session id is not an identity",
						tc.name, prev, port, id, i+1, len(seen))
				}
				seen[id] = port
			}
			if len(seen) != sessions {
				t.Fatalf("%s: %d distinct ids for %d sessions", tc.name, len(seen), sessions)
			}
		})
	}
}

// TestUserspaceSyncedSessionIDSlotBoundary6198 covers the literal aliasing the
// issue names: slots that differ by a multiple of 65536 are indistinguishable
// under `Slot & 0xffff`. Slot no longer participates in the identity at all, so
// these sessions get distinct ids. Restoring the mask makes the 65536/65537
// pairs collide with 0/1 within a monotonic second.
func TestUserspaceSyncedSessionIDSlotBoundary6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	slots := []uint32{0, 1, 65535, 65536, 65537, 131072}

	seen := make(map[uint64]uint32, len(slots))
	for i, slot := range slots {
		// Distinct sessions (distinct source ports) that happen to land on
		// different binding slots — including slots that alias under the old
		// 16-bit mask.
		_, val, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(uint16(40000+i), slot), zoneIDs)
		if !ok {
			t.Fatalf("expected delta on slot %d to convert", slot)
		}
		if prev, dup := seen[val.SessionID]; dup {
			t.Fatalf("SessionID collision: slots %d and %d both minted id %#x — "+
				"slot %d aliases slot %d under a 16-bit mask", prev, slot, val.SessionID, slot, prev)
		}
		seen[val.SessionID] = slot
	}
}

// TestUserspaceSyncedSessionIDDistinctSlotsBelowBoundary6198 is the NEGATIVE
// CONTROL: it must pass BOTH with and without the fix.
//
// Two sessions on distinct binding slots BELOW the 16-bit boundary always got
// distinct ids, because the pre-fix composition put the slot in the low 16 bits
// (`now<<16 | slot`), so slots 1 and 2 differ regardless of `now`. A control
// that also reds on revert would be a co-signer, not a control.
func TestUserspaceSyncedSessionIDDistinctSlotsBelowBoundary6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}

	_, valA, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(41000, 1), zoneIDs)
	if !ok {
		t.Fatal("expected slot-1 delta to convert")
	}
	_, valB, ok := userspaceSessionFromDeltaV4(sessionDeltaV4ForSessionID(41001, 2), zoneIDs)
	if !ok {
		t.Fatal("expected slot-2 delta to convert")
	}
	if valA.SessionID == valB.SessionID {
		t.Fatalf("slots 1 and 2 shared SessionID %#x", valA.SessionID)
	}
}

// TestUserspaceSyncedSessionIDNamespaceDisjointFromDataplane6198 pins the
// namespace reservation: a Go-minted id must never be mistakable for a Rust
// dataplane id (`(worker_id & 0xFFFF) << 48 | counter48`, worker ids being tiny
// queue indices), because both are written into the same BPF conntrack mirror
// field. It also pins the "never 0" property — 0 is the sentinel that makes
// `flowSessionDisplayID` fall back to the per-row ordinal.
func TestUserspaceSyncedSessionIDNamespaceDisjointFromDataplane6198(t *testing.T) {
	for i := 0; i < 64; i++ {
		id := nextUserspaceSyncedSessionID()
		if id == 0 {
			t.Fatal("minted the 0 sentinel")
		}
		if hi := id >> 48; hi != 0xFFFF {
			t.Fatalf("minted id %#x has namespace %#x, want %#x — it could alias a "+
				"dataplane id from worker %d", id, hi, 0xFFFF, hi)
		}
	}
}

// TestUserspaceForwardWireAliasSharesBaseSessionID6198 pins that the
// fabric-redirect forward-wire alias entry carries the SAME SessionID as its
// base entry: they are two conntrack keys for ONE logical session. Re-converting
// the delta for the alias (the pre-#6198 shape) would mint a second id.
func TestUserspaceForwardWireAliasSharesBaseSessionID6198(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}

	deltaV4 := sessionDeltaV4ForSessionID(39906, 0)
	deltaV4.NATSrcIP = "172.16.80.8"
	deltaV4.NATSrcPort = 39906
	baseKeyV4, baseValV4, ok := userspaceSessionFromDeltaV4(deltaV4, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	_, aliasValV4, ok := userspaceForwardWireAliasV4(baseKeyV4, baseValV4, deltaV4)
	if !ok {
		t.Fatal("expected v4 forward-wire alias")
	}
	if aliasValV4.SessionID != baseValV4.SessionID {
		t.Fatalf("v4 alias SessionID %#x != base %#x", aliasValV4.SessionID, baseValV4.SessionID)
	}

	deltaV6 := sessionDeltaV6ForSessionID(50952, 0)
	deltaV6.NATSrcIP = "2001:559:8585:80::8"
	deltaV6.NATSrcPort = 50952
	baseKeyV6, baseValV6, ok := userspaceSessionFromDeltaV6(deltaV6, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	_, aliasValV6, ok := userspaceForwardWireAliasV6(baseKeyV6, baseValV6, deltaV6)
	if !ok {
		t.Fatal("expected v6 forward-wire alias")
	}
	if aliasValV6.SessionID != baseValV6.SessionID {
		t.Fatalf("v6 alias SessionID %#x != base %#x", aliasValV6.SessionID, baseValV6.SessionID)
	}
}
