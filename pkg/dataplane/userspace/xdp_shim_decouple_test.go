package userspace

import (
	"encoding/binary"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestProgramBootstrapMapsDoesNotRequireLegacyFallbackProgram(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	injectCtrlAndBindingMaps(t, m)
	injectUserspaceBootstrapMaps(t, m)

	if err := m.programBootstrapMapsLocked(&ConfigSnapshot{}, config.UserspaceConfig{Workers: 1}); err != nil {
		t.Fatalf("programBootstrapMapsLocked without legacy fallback program: %v", err)
	}
}

func TestXSKLivenessFailureRestoresUserspaceShimEntry(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.XDPEntryProg = "xdp_main_prog"
	injectShimProgramName(t, m.bpfShim, userspaceXDPEntryProg)
	injectCtrlAndBindingMaps(t, m)
	m.neighborsPrewarmed = true
	m.xskProbeStart = time.Now().Add(-11 * time.Second)

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
		}},
	}

	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if !m.xskLivenessFailed {
		t.Fatal("xskLivenessFailed = false, want true after expired liveness probe")
	}
	if got := m.bpfShim.XDPEntryProg; got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProg = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func TestUserspaceXDPDegradedCtrlDisabledDropsTransit(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	})

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		[4]byte{203, 0, 113, 20},
	))
	if ret != xdpActionDrop {
		t.Fatalf("ctrl-disabled transit action = %d, want XDP_DROP", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPFallbackStat(t, coll, "transit_drop")
}

func TestUserspaceXDPDegradedCtrlDisabledPassesLocalControl(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	local := [4]byte{192, 0, 2, 1}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestLocalV4(t, coll, local)

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		local,
	))
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled local action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPFallbackStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPFallbackStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPBindingNotReadyDropsTransitButPassesLocalControl(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dst      [4]byte
		local    bool
		want     uint32
		statName string
	}{
		{
			name:     "transit",
			dst:      [4]byte{203, 0, 113, 20},
			want:     xdpActionDrop,
			statName: "transit_drop",
		},
		{
			name:     "local",
			dst:      [4]byte{192, 0, 2, 1},
			local:    true,
			want:     xdpActionPass,
			statName: "pass_to_kernel",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            1,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: 30000,
			})
			updateUserspaceXDPTestIngress(t, coll, 0)
			updateUserspaceXDPTestBinding(t, coll, 0, userspaceBindingValue{
				Slot:  0,
				Flags: 2, // non-zero but not userspaceBindingReady
			})
			if tc.local {
				updateUserspaceXDPTestLocalV4(t, coll, tc.dst)
			}

			ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
				[4]byte{198, 51, 100, 10},
				tc.dst,
			))
			if ret != tc.want {
				t.Fatalf("binding-not-ready %s action = %d, want %d", tc.name, ret, tc.want)
			}
			assertUserspaceXDPFallbackStat(t, coll, "binding_not_ready")
			assertUserspaceXDPFallbackStat(t, coll, tc.statName)
		})
	}
}

func TestUserspaceXDPIPLocalControlUsesCPUMapWhenAvailable(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	enableUserspaceXDPTestCPUMap(t, coll)
	local := [4]byte{192, 0, 2, 1}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestLocalV4(t, coll, local)

	ret := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		local,
	))
	if ret != xdpActionRedirect {
		t.Fatalf("ctrl-disabled local action with cpumap = %d, want XDP_REDIRECT", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPFallbackStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPFallbackStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPNDPUsesCPUMapWhenAvailable(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	enableUserspaceXDPTestCPUMap(t, coll)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestIngress(t, coll, 0)
	updateUserspaceXDPTestBinding(t, coll, 0, userspaceBindingValue{
		Slot:  0,
		Flags: userspaceBindingReady,
	})

	ret := runUserspaceXDPTestPacket(t, coll, icmpv6TestPacket(
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		136,
	))
	if ret != xdpActionRedirect {
		t.Fatalf("NDP action with cpumap = %d, want XDP_REDIRECT", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "early_filter")
	assertUserspaceXDPFallbackStat(t, coll, "pass_to_kernel")
}

func TestUserspaceXDPDegradedESPToInterfaceNATPassesLocalControl(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	natLocal := [4]byte{192, 0, 2, 254}
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	})
	updateUserspaceXDPTestInterfaceNATV4(t, coll, natLocal)

	ret := runUserspaceXDPTestPacket(t, coll, espIPv4TestPacket(
		[4]byte{198, 51, 100, 10},
		natLocal,
	))
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled ESP to interface NAT action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPFallbackStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPFallbackStatAbsent(t, coll, "transit_drop")
}

func TestUserspaceXDPDegradedNonIPL2PassesDirect(t *testing.T) {
	coll := loadUserspaceXDPTestCollection(t)
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagCPUMap,
		HeartbeatTimeoutMS: 30000,
	})

	ret := runUserspaceXDPTestPacket(t, coll, arpTestPacket())
	if ret != xdpActionPass {
		t.Fatalf("ctrl-disabled ARP action = %d, want XDP_PASS", ret)
	}
	assertUserspaceXDPFallbackStat(t, coll, "ctrl_disabled")
	assertUserspaceXDPFallbackStat(t, coll, "pass_to_kernel")
	assertUserspaceXDPFallbackStatAbsent(t, coll, "transit_drop")
}

func injectUserspaceBootstrapMaps(t *testing.T, m *Manager) {
	t.Helper()
	injectShimMapSpec(t, m.bpfShim, "userspace_heartbeat", &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4096,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_ingress_ifaces", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: dataplane.MaxInterfaces,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_local_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v4", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8192,
	})
	injectShimMapSpec(t, m.bpfShim, "userspace_interface_nat_v6", &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 8192,
	})
}

func injectShimMapSpec(t *testing.T, bpfShim *dataplane.Manager, name string, spec *ebpf.MapSpec) {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatalf("new %s map: %v", name, err)
	}
	t.Cleanup(func() { m.Close() })
	injectShimMap(t, bpfShim, name, m)
}

func injectShimProgramName(t *testing.T, bpfShim *dataplane.Manager, name string) {
	t.Helper()
	managerValue := reflect.ValueOf(bpfShim)
	if managerValue.Kind() != reflect.Ptr || managerValue.IsNil() {
		t.Fatalf("injectShimProgramName: expected non-nil pointer, got %T", bpfShim)
	}
	managerElem := managerValue.Elem()
	rv := managerElem.FieldByName("programs")
	if !rv.IsValid() {
		t.Fatal("injectShimProgramName: dataplane.Manager has no field named \"programs\"")
	}
	rm := reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()
	if rm.IsNil() {
		rm.Set(reflect.MakeMap(rv.Type()))
	}
	// SwapXDPEntryProg only needs the name to exist when no links are
	// attached, so a nil *ebpf.Program is sufficient for this unit test.
	rm.SetMapIndex(reflect.ValueOf(name), reflect.Zero(rv.Type().Elem()))
}

const (
	xdpActionDrop     = 1
	xdpActionPass     = 2
	xdpActionRedirect = 4
)

func loadUserspaceXDPTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(filepath.Join("..", "userspace_xdp_bpfel.o"))
	if err != nil {
		t.Fatalf("load userspace_xdp_bpfel.o spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") ||
			strings.Contains(err.Error(), "permission denied") {
			t.Skipf("load userspace XDP collection: %v", err)
		}
		t.Fatalf("load userspace XDP collection: %v", err)
	}
	t.Cleanup(func() { coll.Close() })
	return coll
}

func updateUserspaceXDPTestCtrl(t *testing.T, coll *ebpf.Collection, ctrl userspaceCtrlValue) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_ctrl", uint32(0), ctrl)
}

func updateUserspaceXDPTestBinding(t *testing.T, coll *ebpf.Collection, idx uint32, binding userspaceBindingValue) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_bindings", idx, binding)
}

func updateUserspaceXDPTestIngress(t *testing.T, coll *ebpf.Collection, ifindex uint32) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_ingress_ifaces", ifindex, uint8(1))
}

func updateUserspaceXDPTestLocalV4(t *testing.T, coll *ebpf.Collection, ip [4]byte) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_local_v4", binary.BigEndian.Uint32(ip[:]), uint8(1))
}

func updateUserspaceXDPTestInterfaceNATV4(t *testing.T, coll *ebpf.Collection, ip [4]byte) {
	t.Helper()
	updateUserspaceXDPTestMap(t, coll, "userspace_interface_nat_v4", binary.BigEndian.Uint32(ip[:]), uint8(1))
}

func enableUserspaceXDPTestCPUMap(t *testing.T, coll *ebpf.Collection) {
	t.Helper()
	m := coll.Maps["userspace_cpumap"]
	if m == nil {
		t.Fatal("userspace_cpumap map not loaded")
	}
	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 2048)
	cpus := runtime.NumCPU()
	if cpus > 256 {
		cpus = 256
	}
	for cpu := 0; cpu < cpus; cpu++ {
		if err := m.Update(uint32(cpu), val, ebpf.UpdateAny); err != nil {
			t.Skipf("update userspace_cpumap cpu %d: %v", cpu, err)
		}
	}
}

func updateUserspaceXDPTestMap(t *testing.T, coll *ebpf.Collection, name string, key any, value any) {
	t.Helper()
	m := coll.Maps[name]
	if m == nil {
		t.Fatalf("%s map not loaded", name)
	}
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("update %s: %v", name, err)
	}
}

func runUserspaceXDPTestPacket(t *testing.T, coll *ebpf.Collection, packet []byte) uint32 {
	t.Helper()
	prog := coll.Programs[userspaceXDPEntryProg]
	if prog == nil {
		t.Fatalf("%s program not loaded", userspaceXDPEntryProg)
	}
	ret, _, err := prog.Test(packet)
	if err != nil {
		t.Fatalf("run %s: %v", userspaceXDPEntryProg, err)
	}
	return ret
}

func assertUserspaceXDPFallbackStat(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := userspaceXDPFallbackStat(t, coll, name); got == 0 {
		t.Fatalf("fallback stat %q = 0, want incremented", name)
	}
}

func assertUserspaceXDPFallbackStatAbsent(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := userspaceXDPFallbackStat(t, coll, name); got != 0 {
		t.Fatalf("fallback stat %q = %d, want 0", name, got)
	}
}

func userspaceXDPFallbackStat(t *testing.T, coll *ebpf.Collection, name string) uint64 {
	t.Helper()
	stats := coll.Maps["userspace_fallback_stats"]
	if stats == nil {
		t.Fatal("userspace_fallback_stats map not loaded")
	}
	idx := fallbackReasonIndex(t, name)
	var got uint64
	if err := stats.Lookup(idx, &got); err != nil {
		t.Fatalf("lookup userspace_fallback_stats[%d] (%s): %v", idx, name, err)
	}
	return got
}

func fallbackReasonIndex(t *testing.T, name string) uint32 {
	t.Helper()
	for idx, candidate := range fallbackReasonNames {
		if candidate == name {
			return uint32(idx)
		}
	}
	t.Fatalf("fallback reason %q not found", name)
	return 0
}

func udpIPv4TestPacket(src [4]byte, dst [4]byte) []byte {
	return ipv4TestPacket(src, dst, 17, 8)
}

func espIPv4TestPacket(src [4]byte, dst [4]byte) []byte {
	return ipv4TestPacket(src, dst, 50, 8)
}

func ipv4TestPacket(src [4]byte, dst [4]byte, protocol byte, payloadLen int) []byte {
	packet := make([]byte, 14+20+8)
	if payloadLen > 8 {
		packet = make([]byte, 14+20+payloadLen)
	}
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)

	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+payloadLen))
	ip[8] = 64
	ip[9] = protocol
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])

	if protocol == 17 {
		udp := packet[34:]
		binary.BigEndian.PutUint16(udp[0:2], 12345)
		binary.BigEndian.PutUint16(udp[2:4], 443)
		binary.BigEndian.PutUint16(udp[4:6], uint16(payloadLen))
	}
	return packet
}

func icmpv6TestPacket(src [16]byte, dst [16]byte, icmpType byte) []byte {
	packet := make([]byte, 14+40+8)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)

	ip := packet[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8)
	ip[6] = 58
	ip[7] = 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])

	icmp := packet[54:]
	icmp[0] = icmpType
	return packet
}

func arpTestPacket() []byte {
	packet := make([]byte, 14+28)
	copy(packet[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	return packet
}
