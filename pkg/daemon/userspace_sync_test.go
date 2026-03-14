package daemon

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/bpfrx/pkg/cluster"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
)

func TestUserspaceSessionFromDeltaV4(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    2,
		Protocol:      6,
		SrcIP:         "10.0.61.102",
		DstIP:         "172.16.80.200",
		SrcPort:       12345,
		DstPort:       5201,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
		NATSrcIP:      "172.16.80.8",
	}

	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if key.SrcPort != 12345 || key.DstPort != 5201 {
		t.Fatalf("unexpected key ports: %+v", key)
	}
	if val.IngressZone != 1 || val.EgressZone != 2 {
		t.Fatalf("unexpected zones: %+v", val)
	}
	if val.Flags == 0 {
		t.Fatalf("expected NAT/session flags to be set")
	}
	if got := val.NATSrcIP; got != binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}) {
		t.Fatalf("unexpected nat src ip: %08x", got)
	}
}

func TestUserspaceSessionFromDeltaV6(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    10,
		Protocol:      17,
		SrcIP:         "2001:559:8585:ef00::100",
		DstIP:         "2001:559:8585:80::200",
		SrcPort:       5555,
		DstPort:       53,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
		NATSrcIP:      "2001:559:8585:80::8",
	}

	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if key.SrcPort != 5555 || key.DstPort != 53 {
		t.Fatalf("unexpected key ports: %+v", key)
	}
	if val.IngressZone != 1 || val.EgressZone != 2 {
		t.Fatalf("unexpected zones: %+v", val)
	}
	if val.Flags == 0 {
		t.Fatalf("expected NAT/session flags to be set")
	}
	if val.NATSrcIP == [16]byte{} {
		t.Fatalf("expected NAT src v6 address to be set")
	}
}

func TestShouldSyncUserspaceDeltaPrefersOwnerRG(t *testing.T) {
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return false },
			IsPrimaryForRGFn: func(rgID int) bool { return rgID == 2 },
		},
	}
	if !d.shouldSyncUserspaceDelta(dpuserspace.SessionDeltaInfo{OwnerRGID: 2}, 1) {
		t.Fatal("expected owner RG primary to allow sync")
	}
	if d.shouldSyncUserspaceDelta(dpuserspace.SessionDeltaInfo{OwnerRGID: 1}, 1) {
		t.Fatal("expected non-primary owner RG to block sync")
	}
}

func TestShouldSyncUserspaceDeltaFallsBackToZone(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return false },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1})
	d := &Daemon{sessionSync: ss}
	if d.shouldSyncUserspaceDelta(dpuserspace.SessionDeltaInfo{}, 1) {
		t.Fatal("expected fallback zone sync to be false when RG 1 is not local primary")
	}
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	if !d.shouldSyncUserspaceDelta(dpuserspace.SessionDeltaInfo{}, 1) {
		t.Fatal("expected fallback zone sync to use ShouldSyncZone")
	}
}
