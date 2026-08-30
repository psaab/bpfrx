package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// gre_sync_discriminator_7188_test.go — #7188.
//
// GRE is IP protocol 47 and carries no L4 ports, so two RFC 2890 tunnels
// between one pair of outer endpoints convert to the SAME dataplane.SessionKey.
// The identity that separates them is the helper's TunnelDiscriminator, carried
// across this layer as a value field.
//
// THE FIXTURE IS THE WHOLE TEST. One tunnel proves nothing here: every
// assertion below passes with the discriminator dropped entirely unless two
// records share a key. These cells are built from the smallest shape in which
// dropping it changes an outcome.

// greDelta7188 is one keyed-GRE transit session. Everything except the
// discriminator is held constant on purpose — including the zero ports, which
// are what the shim actually stamps for protocol 47.
func greDelta7188(discriminator uint64) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event:               "open",
		AddrFamily:          dataplane.AFInet,
		Protocol:            47,
		SrcIP:               "198.51.100.7",
		DstIP:               "203.0.113.9",
		SrcPort:             0,
		DstPort:             0,
		IngressZone:         "lan",
		EgressZone:          "wan",
		OwnerRGID:           1,
		EgressIfindex:       12,
		TunnelDiscriminator: discriminator,
	}
}

// keyed7188 mirrors the helper's Keyed(k) encoding: bit 32 set, RFC 2890 key in
// the low 32 bits. Go never interprets the tag — it carries it — so the test
// only needs two DISTINCT values that a real helper would produce.
func keyed7188(key uint32) uint64 { return uint64(1)<<32 | uint64(key) }

// TestGREDeltaCarriesTheTunnelDiscriminatorIntoTheSessionValue7188 binds the
// converter assignment itself.
//
// FAIL-ON-REVERT: delete `val.TunnelDiscriminator = delta.TunnelDiscriminator`
// from userspaceSessionFromDeltaV4 and this fires. Without it the value reaching
// the cluster encoder is 0 — the RESERVED "not carried" tag — so a fully
// capable peer looks to the receiver exactly like one that predates the field.
func TestGREDeltaCarriesTheTunnelDiscriminatorIntoTheSessionValue7188(t *testing.T) {
	_, _, cfg := snapshot6031Daemon()
	_, val, ok := userspaceSessionFromDeltaV4(greDelta7188(keyed7188(100)), buildZoneIDs(cfg))
	if !ok {
		t.Fatal("fixture: the keyed-GRE delta must convert, or every assertion is vacuous")
	}
	if val.TunnelDiscriminator != keyed7188(100) {
		t.Fatalf("SessionValue.TunnelDiscriminator = %#x, want %#x — the value that "+
			"rides the cluster wire is the only thing separating two RFC 2890 tunnels "+
			"between the same outer endpoints",
			val.TunnelDiscriminator, keyed7188(100))
	}
}

// The V6 converter is a SEPARATE function; wiring only V4 leaves every IPv6 GRE
// tunnel aliased after a failover while the cell above stays green.
func TestGREDeltaCarriesTheTunnelDiscriminatorIntoTheV6SessionValue7188(t *testing.T) {
	_, _, cfg := snapshot6031Daemon()
	delta := greDelta7188(keyed7188(200))
	delta.AddrFamily = dataplane.AFInet6
	delta.SrcIP = "2001:db8::7"
	delta.DstIP = "2001:db8::9"
	_, val, ok := userspaceSessionFromDeltaV6(delta, buildZoneIDs(cfg))
	if !ok {
		t.Fatal("fixture: the v6 keyed-GRE delta must convert")
	}
	if val.TunnelDiscriminator != keyed7188(200) {
		t.Fatalf("SessionValueV6.TunnelDiscriminator = %#x, want %#x",
			val.TunnelDiscriminator, keyed7188(200))
	}
}

// TestBulkWindowKeepsBothKeyedTunnelsSharingA5Tuple7188 is the cell that needs
// TWO tunnels.
//
// The cold-prime window dedupes into a map before it is framed. Keyed on
// dataplane.SessionKey alone, two RFC 2890 tunnels between the same outer
// endpoints collide and the later delta silently overwrites the earlier one —
// so the standby is primed with ONE session for two tunnels, and since #5085 it
// then DELETES nothing it holds for the other. The window has to carry both.
//
// FAIL-ON-REVERT: drop `discriminator` from snapshotDedupKeyV4 (or key the map
// on dataplane.SessionKey again) and the count falls to 1.
func TestBulkWindowKeepsBothKeyedTunnelsSharingA5Tuple7188(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	first := greDelta7188(keyed7188(100))
	second := greDelta7188(keyed7188(200))
	// Proof the fixture is the aliasing shape and not two unrelated flows: the
	// converted keys must be EQUAL, so only the discriminator can separate them.
	keyFirst, _, ok1 := userspaceSessionFromDeltaV4(first, buildZoneIDs(cfg))
	keySecond, _, ok2 := userspaceSessionFromDeltaV4(second, buildZoneIDs(cfg))
	if !ok1 || !ok2 {
		t.Fatalf("fixture: both keyed-GRE deltas must convert (ok1=%v ok2=%v)", ok1, ok2)
	}
	if keyFirst != keySecond {
		t.Fatalf("fixture is not the aliasing shape: the two tunnels converted to "+
			"DIFFERENT session keys (%+v vs %+v), so this test would pass with the "+
			"discriminator dropped entirely", keyFirst, keySecond)
	}

	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{first, second}}
	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if len(snap.V4) != 2 {
		t.Fatalf("the cold-prime window framed %d session(s) for TWO RFC 2890 tunnels "+
			"between the same outer endpoints; one means the window aliased them and "+
			"the standby is primed with a single session for both (#7188): %+v",
			len(snap.V4), snap.V4)
	}
	seen := map[uint64]bool{}
	for _, e := range snap.V4 {
		seen[e.Value.TunnelDiscriminator] = true
	}
	if !seen[keyed7188(100)] || !seen[keyed7188(200)] {
		t.Fatalf("the window must carry BOTH discriminators; got %v", seen)
	}
}

// A close retracts the tunnel it names and ONLY that one.
//
// Retracting on the 5-tuple alone would take both tunnels out of the window,
// and the peer would then delete a session that is still live — the same
// aliasing defect pointed the other way. This is the cell that catches a
// deleteV4 which ignores the value it is now handed.
func TestBulkWindowCloseRetractsOnlyTheNamedTunnel7188(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	open100 := greDelta7188(keyed7188(100))
	open200 := greDelta7188(keyed7188(200))
	close100 := greDelta7188(keyed7188(100))
	close100.Event = "close"

	exporter := &recordingExporter{
		deltas: []dpuserspace.SessionDeltaInfo{open100, open200, close100},
	}
	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if len(snap.V4) != 1 {
		t.Fatalf("closing ONE of two same-endpoint tunnels must leave exactly one in "+
			"the window, got %d: %+v", len(snap.V4), snap.V4)
	}
	if snap.V4[0].Value.TunnelDiscriminator != keyed7188(200) {
		t.Fatalf("the surviving session is %#x, want %#x — the close retracted the "+
			"wrong tunnel, which means it matched on the shared 5-tuple",
			snap.V4[0].Value.TunnelDiscriminator, keyed7188(200))
	}
}
