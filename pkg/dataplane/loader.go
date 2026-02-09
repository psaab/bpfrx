package dataplane

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// go:generate directives -- run "make generate" with clang + libbpf-dev installed.
// These produce the *_bpfel.go files with embedded ELF objects.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpMain ../../bpf/xdp/xdp_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpScreen ../../bpf/xdp/xdp_screen.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpZone ../../bpf/xdp/xdp_zone.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpConntrack ../../bpf/xdp/xdp_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpPolicy ../../bpf/xdp/xdp_policy.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpNat ../../bpf/xdp/xdp_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpForward ../../bpf/xdp/xdp_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcMain ../../bpf/tc/tc_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcConntrack ../../bpf/tc/tc_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcNat ../../bpf/tc/tc_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcScreenEgress ../../bpf/tc/tc_screen_egress.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcForward ../../bpf/tc/tc_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu

// Manager manages the eBPF dataplane: programs, maps, and attachments.
type Manager struct {
	loaded      bool
	programs    map[string]*ebpf.Program
	maps        map[string]*ebpf.Map
	colls       []*ebpf.Collection
	xdpLinks    map[int]link.Link
	tcLinks     map[int]link.Link
	lastCompile *CompileResult
}

// New creates a new dataplane Manager.
func New() *Manager {
	return &Manager{
		programs: make(map[string]*ebpf.Program),
		maps:     make(map[string]*ebpf.Map),
		xdpLinks: make(map[int]link.Link),
		tcLinks:  make(map[int]link.Link),
	}
}

// Load loads all eBPF programs and maps. Returns an error if eBPF
// programs have not been generated yet (run "make generate" first).
func (m *Manager) Load() error {
	slog.Info("loading eBPF programs")

	// loadAllObjects is implemented in loader_ebpf.go (generated build)
	// or returns an error in loader_stub.go (no generated files).
	if err := m.loadAllObjects(); err != nil {
		return err
	}

	m.loaded = true
	slog.Info("eBPF programs loaded successfully")
	return nil
}

// IsLoaded returns true if eBPF programs are loaded.
func (m *Manager) IsLoaded() bool {
	return m.loaded
}

// AttachXDP attaches the XDP main program to the given interface.
func (m *Manager) AttachXDP(ifindex int) error {
	if !m.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	prog, ok := m.programs["xdp_main_prog"]
	if !ok {
		return fmt.Errorf("xdp_main_prog not found")
	}

	if _, exists := m.xdpLinks[ifindex]; exists {
		return fmt.Errorf("XDP already attached to ifindex %d", ifindex)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err != nil {
		return fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	m.xdpLinks[ifindex] = l
	slog.Info("attached XDP program", "ifindex", ifindex)
	return nil
}

// DetachXDP detaches the XDP program from the given interface.
func (m *Manager) DetachXDP(ifindex int) error {
	l, exists := m.xdpLinks[ifindex]
	if !exists {
		return nil
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("detach XDP from ifindex %d: %w", ifindex, err)
	}
	delete(m.xdpLinks, ifindex)
	slog.Info("detached XDP program", "ifindex", ifindex)
	return nil
}

// SetZone maps an interface to a security zone in the BPF map.
func (m *Manager) SetZone(ifindex int, zoneID uint16) error {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return fmt.Errorf("iface_zone_map not found")
	}
	return zm.Update(uint32(ifindex), zoneID, ebpf.UpdateAny)
}

// AddTxPort adds an interface to the devmap for XDP_REDIRECT.
func (m *Manager) AddTxPort(ifindex int) error {
	tm, ok := m.maps["tx_ports"]
	if !ok {
		return fmt.Errorf("tx_ports not found")
	}
	val := struct{ Ifindex uint32 }{Ifindex: uint32(ifindex)}
	return tm.Update(uint32(ifindex), val, ebpf.UpdateAny)
}

// AttachTC attaches the TC main program to the egress path of the given interface.
func (m *Manager) AttachTC(ifindex int) error {
	if !m.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	prog, ok := m.programs["tc_main_prog"]
	if !ok {
		return fmt.Errorf("tc_main_prog not found")
	}

	if _, exists := m.tcLinks[ifindex]; exists {
		return fmt.Errorf("TC already attached to ifindex %d", ifindex)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifindex,
	})
	if err != nil {
		return fmt.Errorf("attach TC to ifindex %d: %w", ifindex, err)
	}

	m.tcLinks[ifindex] = l
	slog.Info("attached TC egress program", "ifindex", ifindex)
	return nil
}

// DetachTC detaches the TC program from the given interface.
func (m *Manager) DetachTC(ifindex int) error {
	l, exists := m.tcLinks[ifindex]
	if !exists {
		return nil
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("detach TC from ifindex %d: %w", ifindex, err)
	}
	delete(m.tcLinks, ifindex)
	slog.Info("detached TC egress program", "ifindex", ifindex)
	return nil
}

// Map returns a named eBPF map, or nil if not found.
func (m *Manager) Map(name string) *ebpf.Map {
	return m.maps[name]
}

// LastCompileResult returns the result from the most recent Compile call.
func (m *Manager) LastCompileResult() *CompileResult {
	return m.lastCompile
}

// Close releases all eBPF resources.
func (m *Manager) Close() error {
	for ifindex, l := range m.xdpLinks {
		if err := l.Close(); err != nil {
			slog.Error("failed to detach XDP", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex, l := range m.tcLinks {
		if err := l.Close(); err != nil {
			slog.Error("failed to detach TC", "ifindex", ifindex, "err", err)
		}
	}
	for _, coll := range m.colls {
		coll.Close()
	}
	m.loaded = false
	return nil
}
