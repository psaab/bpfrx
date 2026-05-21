package userspace

import (
	"reflect"
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
