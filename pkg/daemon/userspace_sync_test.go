package daemon

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
)

type fakeUserspaceDeltaDrainer struct {
	batches [][]dpuserspace.SessionDeltaInfo
	calls   int
}

func (f *fakeUserspaceDeltaDrainer) DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	f.calls++
	if len(f.batches) == 0 {
		return nil, dpuserspace.ProcessStatus{}, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	return batch, dpuserspace.ProcessStatus{}, nil
}

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
		TXIfindex:     11,
		TXVLANID:      80,
		NeighborMAC:   "aa:bb:cc:dd:ee:ff",
		SrcMAC:        "02:bf:72:00:50:08",
		NATSrcIP:      "172.16.80.8",
		NATSrcPort:    40000,
		FabricIngress: true,
	}

	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if userspaceNetworkToHost16(key.SrcPort) != 12345 || userspaceNetworkToHost16(key.DstPort) != 5201 {
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
	if userspaceNetworkToHost16(val.NATSrcPort) != 40000 {
		t.Fatalf("unexpected nat src port: %d", val.NATSrcPort)
	}
	if val.FibIfindex != 11 || val.FibVlanID != 80 {
		t.Fatalf("unexpected fib egress metadata: ifindex=%d vlan=%d", val.FibIfindex, val.FibVlanID)
	}
	if val.FibDmac != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("unexpected fib dmac: %v", val.FibDmac)
	}
	if val.FibSmac != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("unexpected fib smac: %v", val.FibSmac)
	}
	if userspaceNetworkToHost16(val.ReverseKey.DstPort) != 40000 {
		t.Fatalf("unexpected reverse dst port: %d", val.ReverseKey.DstPort)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceFabricIngress == 0 {
		t.Fatalf("expected fabric ingress marker in log flags: %#x", val.LogFlags)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorMarksRetryableSyncErrors(t *testing.T) {
	err := wrapUserspaceManualFailoverPrepareError(
		errors.New("session sync peer not quiescent before demotion: timed out"),
	)
	var retryable *cluster.RetryablePreFailoverError
	if !errors.As(err, &retryable) {
		t.Fatalf("expected retryable pre-failover error, got %T", err)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorLeavesFatalErrors(t *testing.T) {
	src := errors.New("prepare failed")
	err := wrapUserspaceManualFailoverPrepareError(src)
	if err != src {
		t.Fatalf("expected original error to be preserved, got %v", err)
	}
}

func TestUserspaceSessionFromDeltaV4CarriesTunnelEndpointMetadata(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "sfmix": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:            "open",
		AddrFamily:       2,
		Protocol:         1,
		SrcIP:            "10.0.61.102",
		DstIP:            "10.255.192.41",
		SrcPort:          4459,
		DstPort:          4459,
		IngressZone:      "lan",
		EgressZone:       "sfmix",
		EgressIfindex:    586,
		TXIfindex:        24,
		TunnelEndpointID: 3,
		TXVLANID:         80,
		NeighborMAC:      "aa:bb:cc:dd:ee:ff",
		SrcMAC:           "02:bf:72:00:50:08",
		NATSrcIP:         "10.255.192.42",
	}

	_, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 tunnel delta to convert")
	}
	if val.FibIfindex != 0 {
		t.Fatalf("unexpected fib ifindex: %d", val.FibIfindex)
	}
	if val.FibGen != 3 {
		t.Fatalf("unexpected fib gen tunnel id: %d", val.FibGen)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint == 0 {
		t.Fatalf("expected tunnel endpoint marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceForwardWireAliasFromDeltaV4UsesNATTuple(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  dataplane.AFInet,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     39906,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
		NATSrcPort:  39906,
	}

	key, _, ok := userspaceForwardWireAliasFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 forward-wire alias")
	}
	if got := key.SrcIP; got != [4]byte{172, 16, 80, 8} {
		t.Fatalf("unexpected forward-wire src ip: %v", got)
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != 39906 {
		t.Fatalf("unexpected forward-wire src port: %d", got)
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
		TXIfindex:     11,
		TXVLANID:      80,
		NeighborMAC:   "00:11:22:33:44:55",
		SrcMAC:        "02:bf:72:00:50:08",
		NATSrcIP:      "2001:559:8585:80::8",
		NATSrcPort:    40000,
		FabricIngress: true,
	}

	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if userspaceNetworkToHost16(key.SrcPort) != 5555 || userspaceNetworkToHost16(key.DstPort) != 53 {
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
	if userspaceNetworkToHost16(val.NATSrcPort) != 40000 {
		t.Fatalf("unexpected nat src port: %d", val.NATSrcPort)
	}
	if val.FibIfindex != 11 || val.FibVlanID != 80 {
		t.Fatalf("unexpected fib egress metadata: ifindex=%d vlan=%d", val.FibIfindex, val.FibVlanID)
	}
	if val.FibDmac != [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("unexpected fib dmac: %v", val.FibDmac)
	}
	if val.FibSmac != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("unexpected fib smac: %v", val.FibSmac)
	}
	if userspaceNetworkToHost16(val.ReverseKey.DstPort) != 40000 {
		t.Fatalf("unexpected reverse dst port: %d", val.ReverseKey.DstPort)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceFabricIngress == 0 {
		t.Fatalf("expected fabric ingress marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceSessionFromDeltaV6CarriesTunnelEndpointMetadata(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "sfmix": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:            "open",
		AddrFamily:       10,
		Protocol:         17,
		SrcIP:            "2001:559:8585:ef00::100",
		DstIP:            "2001:db8::1",
		SrcPort:          5555,
		DstPort:          53,
		IngressZone:      "lan",
		EgressZone:       "sfmix",
		EgressIfindex:    586,
		TXIfindex:        24,
		TunnelEndpointID: 7,
		TXVLANID:         80,
		NeighborMAC:      "00:11:22:33:44:55",
		SrcMAC:           "02:bf:72:00:50:08",
		NATSrcIP:         "2001:db8::2",
	}

	_, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 tunnel delta to convert")
	}
	if val.FibIfindex != 0 {
		t.Fatalf("unexpected fib ifindex: %d", val.FibIfindex)
	}
	if val.FibGen != 7 {
		t.Fatalf("unexpected fib gen tunnel id: %d", val.FibGen)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint == 0 {
		t.Fatalf("expected tunnel endpoint marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceForwardWireAliasFromDeltaV6UsesNATTuple(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  dataplane.AFInet6,
		Protocol:    6,
		SrcIP:       "2001:559:8585:ef00::100",
		DstIP:       "2001:559:8585:80::200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "2001:559:8585:80::8",
		NATSrcPort:  50952,
	}

	key, _, ok := userspaceForwardWireAliasFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 forward-wire alias")
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != 50952 {
		t.Fatalf("unexpected forward-wire src port: %d", got)
	}
	if key.SrcIP == [16]byte{} {
		t.Fatal("expected forward-wire src ip to be rewritten")
	}
}

func TestUserspaceSessionFromDeltaUsesNetworkByteOrderPorts(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  2,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
	}

	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if key.SrcPort == delta.SrcPort || key.DstPort == delta.DstPort {
		t.Fatalf("ports were not converted to network order: %+v", key)
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != delta.SrcPort {
		t.Fatalf("src port roundtrip = %d, want %d", got, delta.SrcPort)
	}
	if got := userspaceNetworkToHost16(key.DstPort); got != delta.DstPort {
		t.Fatalf("dst port roundtrip = %d, want %d", got, delta.DstPort)
	}
}

func TestUserspaceSessionFromDeltaV4PreservesPortForAddressOnlySNAT(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  2,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
	}

	_, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if got := userspaceNetworkToHost16(val.NATSrcPort); got != delta.SrcPort {
		t.Fatalf("nat src port roundtrip = %d, want %d", got, delta.SrcPort)
	}
}

func TestUserspaceSessionFromDeltaV6PreservesPortForAddressOnlySNAT(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  10,
		Protocol:    6,
		SrcIP:       "2001:559:8585:ef00::100",
		DstIP:       "2001:559:8585:80::200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "2001:559:8585:80::8",
	}

	_, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if got := userspaceNetworkToHost16(val.NATSrcPort); got != delta.SrcPort {
		t.Fatalf("nat src port roundtrip = %d, want %d", got, delta.SrcPort)
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

func TestShouldSyncUserspaceDeltaAllowsStaleOwnerFabricRedirect(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return false },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1})
	d := &Daemon{sessionSync: ss}
	delta := dpuserspace.SessionDeltaInfo{
		OwnerRGID:      1,
		FabricRedirect: true,
		FabricIngress:  false,
		IngressZone:    "lan",
		EgressZone:     "wan",
		EgressIfindex:  3,
		TXIfindex:      3,
		NeighborMAC:    "aa:bb:cc:dd:ee:ff",
		SrcMAC:         "02:bf:72:aa:00:01",
	}
	if !d.shouldSyncUserspaceDelta(delta, 1) {
		t.Fatal("expected stale-owner fabric redirect delta to be synced")
	}
}

func TestShouldSyncUserspaceDeltaDoesNotBypassFabricIngress(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return false },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1})
	d := &Daemon{sessionSync: ss}
	delta := dpuserspace.SessionDeltaInfo{
		OwnerRGID:      1,
		FabricRedirect: true,
		FabricIngress:  true,
	}
	if d.shouldSyncUserspaceDelta(delta, 1) {
		t.Fatal("expected fabric-ingress delta to remain blocked on standby")
	}
}

func TestDrainUserspaceSessionDeltasWithConfigDrainsPreparedBatches(t *testing.T) {
	buildDelta := func(srcPort uint16) dpuserspace.SessionDeltaInfo {
		return dpuserspace.SessionDeltaInfo{
			Event:         "open",
			AddrFamily:    dataplane.AFInet,
			Protocol:      6,
			SrcIP:         "10.0.61.102",
			DstIP:         "172.16.80.200",
			SrcPort:       srcPort,
			DstPort:       5201,
			IngressZone:   "lan",
			EgressZone:    "wan",
			OwnerRGID:     1,
			EgressIfindex: 12,
			TXIfindex:     11,
			TXVLANID:      80,
			NeighborMAC:   "aa:bb:cc:dd:ee:ff",
			SrcMAC:        "02:bf:72:00:50:08",
			NATSrcIP:      "172.16.80.8",
			NATSrcPort:    40000 + srcPort,
		}
	}

	firstBatch := make([]dpuserspace.SessionDeltaInfo, 256)
	for i := range firstBatch {
		firstBatch[i] = buildDelta(uint16(10000 + i))
	}
	secondBatch := []dpuserspace.SessionDeltaInfo{buildDelta(20001)}
	drainer := &fakeUserspaceDeltaDrainer{
		batches: [][]dpuserspace.SessionDeltaInfo{firstBatch, secondBatch},
	}
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return true },
			IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
		},
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}

	queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 8)
	if err != nil {
		t.Fatalf("drainUserspaceSessionDeltasWithConfig() error = %v", err)
	}
	if queued != 257 {
		t.Fatalf("queued = %d, want 257", queued)
	}
	if drainer.calls != 2 {
		t.Fatalf("drain calls = %d, want 2", drainer.calls)
	}
}
