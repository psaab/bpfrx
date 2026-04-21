package dataplane

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// TestMaxInterfacesConstants is a sanity check that the Go-visible
// mirrors in constants.go match the values this PR baked in. If someone
// bumps MaxInterfaces without bumping bpf/headers/xpf_common.h (or vice
// versa), the load-time MaxEntries assertion in loader_ebpf.go will
// still fire — but this test catches the drift at build time.
func TestMaxInterfacesConstants(t *testing.T) {
	if MaxInterfaces != 65536 {
		t.Fatalf("MaxInterfaces = %d, want 65536", MaxInterfaces)
	}
	if BindingQueuesPerIface != 16 {
		t.Fatalf("BindingQueuesPerIface = %d, want 16", BindingQueuesPerIface)
	}
	if BindingArrayMaxEntries != MaxInterfaces*BindingQueuesPerIface {
		t.Fatalf("BindingArrayMaxEntries = %d, want %d",
			BindingArrayMaxEntries, MaxInterfaces*BindingQueuesPerIface)
	}
}

// fakeLinkLister is a test helper that swaps out netlink.LinkList.
func withFakeLinkLister(t *testing.T, links []netlink.Link, err error) {
	t.Helper()
	prev := linkLister
	linkLister = func() ([]netlink.Link, error) { return links, err }
	t.Cleanup(func() { linkLister = prev })
}

// fakeLink implements netlink.Link with a settable Index + Name.
type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "fake" }

func makeFakeLink(name string, ifindex int) netlink.Link {
	return &fakeLink{attrs: netlink.LinkAttrs{Name: name, Index: ifindex}}
}

func TestPreflightCheckIfindexCaps_WithinCap(t *testing.T) {
	withFakeLinkLister(t, []netlink.Link{
		makeFakeLink("lo", 1),
		makeFakeLink("eth0", 2),
		makeFakeLink("fab0", int(MaxInterfaces-1)),
	}, nil)
	m := &Manager{}
	if err := m.preflightCheckIfindexCaps(); err != nil {
		t.Fatalf("preflightCheckIfindexCaps returned %v, want nil", err)
	}
}

func TestPreflightCheckIfindexCaps_OverCap(t *testing.T) {
	over := int(MaxInterfaces) + 10
	withFakeLinkLister(t, []netlink.Link{
		makeFakeLink("lo", 1),
		makeFakeLink("fab0", over),
	}, nil)
	m := &Manager{}
	err := m.preflightCheckIfindexCaps()
	if err == nil {
		t.Fatal("preflightCheckIfindexCaps returned nil, want error")
	}
	if !strings.Contains(err.Error(), "fab0") {
		t.Fatalf("error missing offending interface name: %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_INTERFACES") {
		t.Fatalf("error missing remediation pointer: %v", err)
	}
}

func TestPreflightCheckIfindexCaps_AtCapFails(t *testing.T) {
	// ifindex == MaxInterfaces is out of range for a dense array
	// indexed [0, MaxInterfaces). Must fail, not pass.
	withFakeLinkLister(t, []netlink.Link{
		makeFakeLink("fab0", int(MaxInterfaces)),
	}, nil)
	m := &Manager{}
	if err := m.preflightCheckIfindexCaps(); err == nil {
		t.Fatal("preflightCheckIfindexCaps at cap returned nil, want error")
	}
}

func TestPreflightCheckIfindexCaps_NetlinkErrorIsNonFatal(t *testing.T) {
	withFakeLinkLister(t, nil, errors.New("netlink temporary failure"))
	m := &Manager{}
	// The preflight must NOT abort compile on a transient netlink error
	// — the call-site cap checks remain the real guardrail.
	if err := m.preflightCheckIfindexCaps(); err != nil {
		t.Fatalf("preflightCheckIfindexCaps on netlink error returned %v, want nil", err)
	}
}

// TestAddTxPort_IfindexAtCapRejected verifies the cap check fires
// before any BPF map touch. We deliberately do NOT inject a real
// tx_ports DEVMAP here — the cap guard must reject ifindex before the
// map-existence check so it's usable in environments without
// CAP_SYS_RESOURCE / memlock headroom.
func TestAddTxPort_IfindexAtCapRejected(t *testing.T) {
	m := &Manager{maps: map[string]*ebpf.Map{}}
	err := m.AddTxPort(int(MaxInterfaces))
	if err == nil {
		t.Fatal("AddTxPort at cap returned nil, want error")
	}
	if !strings.Contains(err.Error(), "exceeds tx_ports cap") {
		t.Fatalf("error missing cap-check message: %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_INTERFACES") {
		t.Fatalf("error missing remediation pointer: %v", err)
	}
}

func TestAddTxPort_IfindexOverCapRejected(t *testing.T) {
	m := &Manager{maps: map[string]*ebpf.Map{}}
	err := m.AddTxPort(int(MaxInterfaces) + 1234)
	if err == nil {
		t.Fatal("AddTxPort over cap returned nil, want error")
	}
	if !strings.Contains(err.Error(), "exceeds tx_ports cap") {
		t.Fatalf("error missing cap-check message: %v", err)
	}
}

func TestAddTxPort_NegativeIfindexRejected(t *testing.T) {
	m := &Manager{maps: map[string]*ebpf.Map{}}
	if err := m.AddTxPort(-1); err == nil {
		t.Fatal("AddTxPort(-1) returned nil, want error")
	}
}

// TestMaxInterfacesMatchesCHeader parses bpf/headers/xpf_common.h and
// fails if the C-side MAX_INTERFACES definition drifts from the Go
// MaxInterfaces mirror in constants.go. Addresses the "hand-mirrored
// constants with no enforcement" review finding — build-time drift
// detection without waiting for load-time to fire.
func TestMaxInterfacesMatchesCHeader(t *testing.T) {
	data, err := os.ReadFile("../../bpf/headers/xpf_common.h")
	if err != nil {
		t.Skipf("cannot read bpf/headers/xpf_common.h: %v", err)
	}
	re := regexp.MustCompile(`(?m)^#define\s+MAX_INTERFACES\s+(\d+)`)
	m := re.FindStringSubmatch(string(data))
	if len(m) < 2 {
		t.Fatal("MAX_INTERFACES define not found in bpf/headers/xpf_common.h")
	}
	got, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse MAX_INTERFACES %q: %v", m[1], err)
	}
	if uint32(got) != MaxInterfaces {
		t.Fatalf("C-side MAX_INTERFACES=%d drift from Go MaxInterfaces=%d — update one of them", got, MaxInterfaces)
	}
}
