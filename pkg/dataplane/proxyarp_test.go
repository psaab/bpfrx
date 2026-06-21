package dataplane

import (
	"errors"
	"net"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sysctlWrite records a single (iface, family) proxy-responder sysctl write
// captured through the proxyARPSysctlSeam test hook.
type sysctlWrite struct {
	iface  string
	family int
}

// captureProxySysctl installs a fake proxyARPSysctlSeam that records every
// write and restores the production writer on cleanup. Returns a pointer to
// the captured slice.
func captureProxySysctl(t *testing.T, fail bool) *[]sysctlWrite {
	t.Helper()
	prev := proxyARPSysctlSeam
	var writes []sysctlWrite
	proxyARPSysctlSeam = func(iface string, family int) error {
		writes = append(writes, sysctlWrite{iface, family})
		if fail {
			return errors.New("simulated procfs failure")
		}
		return nil
	}
	t.Cleanup(func() { proxyARPSysctlSeam = prev })
	return &writes
}

// TestEnableProxyResponders_IPv4 is the core #2160 regression: a static-NAT
// (or any) proxy-ARP'd IPv4 external address on an interface must enable the
// per-interface net.ipv4.conf.<if>.proxy_arp sysctl. Before the fix the
// reconcile installed the NTF_PROXY neighbor entry but never enabled the
// sysctl, so the kernel ignored the entry and never answered ARP. This test
// fails on pre-fix code (no write is performed).
func TestEnableProxyResponders_IPv4(t *testing.T) {
	writes := captureProxySysctl(t, false)

	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}},
	})

	if n != 1 {
		t.Fatalf("enabled count = %d, want 1", n)
	}
	if len(*writes) != 1 {
		t.Fatalf("got %d sysctl writes, want 1: %+v", len(*writes), *writes)
	}
	w := (*writes)[0]
	if w.iface != "ge-0-0-1" || w.family != unix.AF_INET {
		t.Fatalf("write = %+v, want {ge-0-0-1, AF_INET}", w)
	}
}

// TestEnableProxyResponders_IPv6 verifies an IPv6 proxy entry enables the
// proxy_ndp sysctl (the v6 equivalent the kernel requires to answer NDP).
func TestEnableProxyResponders_IPv6(t *testing.T) {
	writes := captureProxySysctl(t, false)

	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET6: {}},
	})

	if n != 1 {
		t.Fatalf("enabled count = %d, want 1", n)
	}
	if len(*writes) != 1 {
		t.Fatalf("got %d sysctl writes, want 1", len(*writes))
	}
	w := (*writes)[0]
	if w.iface != "ge-0-0-1" || w.family != unix.AF_INET6 {
		t.Fatalf("write = %+v, want {ge-0-0-1, AF_INET6}", w)
	}
}

// TestEnableProxyResponders_DualStack verifies an interface carrying both an
// IPv4 and an IPv6 proxy entry enables BOTH proxy_arp and proxy_ndp, in a
// deterministic order (AF_INET before AF_INET6).
func TestEnableProxyResponders_DualStack(t *testing.T) {
	writes := captureProxySysctl(t, false)

	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}, unix.AF_INET6: {}},
	})

	if n != 2 {
		t.Fatalf("enabled count = %d, want 2", n)
	}
	if len(*writes) != 2 {
		t.Fatalf("got %d sysctl writes, want 2: %+v", len(*writes), *writes)
	}
	if (*writes)[0].family != unix.AF_INET || (*writes)[1].family != unix.AF_INET6 {
		t.Fatalf("families not deterministic v4-then-v6: %+v", *writes)
	}
}

// TestEnableProxyResponders_MultiInterface verifies each interface with a
// desired proxy entry gets its own sysctl, sorted deterministically by name.
func TestEnableProxyResponders_MultiInterface(t *testing.T) {
	writes := captureProxySysctl(t, false)

	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-2": {unix.AF_INET: {}},
		"ge-0-0-1": {unix.AF_INET: {}},
	})

	if n != 2 {
		t.Fatalf("enabled count = %d, want 2", n)
	}
	var ifaces []string
	for _, w := range *writes {
		ifaces = append(ifaces, w.iface)
	}
	if !sort.StringsAreSorted(ifaces) {
		t.Fatalf("interface writes not sorted: %v", ifaces)
	}
}

// TestEnableProxyResponders_FailureNonFatal verifies a procfs write failure
// is best-effort: it is counted out of the success total but does not panic
// or abort the remaining writes (matching the reconcile's never-fatal posture).
func TestEnableProxyResponders_FailureNonFatal(t *testing.T) {
	writes := captureProxySysctl(t, true)

	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}},
		"ge-0-0-2": {unix.AF_INET: {}},
	})

	if n != 0 {
		t.Fatalf("enabled count = %d, want 0 (all writes failed)", n)
	}
	// Both writes were still attempted despite the first failing.
	if len(*writes) != 2 {
		t.Fatalf("got %d attempted writes, want 2 (failure must not abort the loop)", len(*writes))
	}
}

// TestEnableProxyResponders_Empty verifies no writes happen when no proxy
// entries are configured.
func TestEnableProxyResponders_Empty(t *testing.T) {
	writes := captureProxySysctl(t, false)
	if n := enableProxyResponders(nil); n != 0 {
		t.Fatalf("enabled count = %d, want 0", n)
	}
	if len(*writes) != 0 {
		t.Fatalf("got %d writes for empty input, want 0", len(*writes))
	}
}

// TestWriteProxyResponderSysctl_UnsupportedFamily verifies the production
// writer rejects a family it has no procfs path for, rather than writing to a
// bogus path.
func TestWriteProxyResponderSysctl_UnsupportedFamily(t *testing.T) {
	err := writeProxyResponderSysctl("ge-0-0-1", unix.AF_PACKET)
	if err == nil {
		t.Fatal("expected error for unsupported family, got nil")
	}
}

// TestReconcileProxyARP_EnablesSysctl drives the full ReconcileProxyARP path
// against the loopback interface and asserts that a configured proxy-ARP IPv4
// address results in the per-interface proxy_arp sysctl being enabled on the
// resolved interface name. This is the end-to-end #2160 regression: before
// the fix the reconcile installed the NTF_PROXY neighbor entry but issued no
// sysctl write, so this assertion (>=1 write for the lo interface) fails on
// pre-fix code. Loopback is used because it always exists and the NTF_PROXY
// install is harmless on it (cleaned up by the stale-removal pass / test
// teardown is unnecessary — lo proxy neighbors are not consulted for routing).
func TestReconcileProxyARP_EnablesSysctl(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	writes := captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "lo", Addresses: []string{"10.0.2.50/32"}},
	}
	ifaceMap := map[string]int{"lo": lo.Index}

	// NeighSet on lo may require privileges; tolerate a failure there since
	// the sysctl-enable step (the thing under test) runs after the neighbor
	// install inside ReconcileProxyARP, so if the install errors we cannot
	// reach the sysctl step — skip rather than false-fail in an unprivileged
	// sandbox.
	if _, err := ReconcileProxyARP(cfg, ifaceMap); err != nil {
		t.Skipf("ReconcileProxyARP needs privileges in this env: %v", err)
	}
	// Clean up the NTF_PROXY neighbor entry this test installed on lo so the
	// privileged test runner's host state is left untouched.
	t.Cleanup(func() {
		_ = netlink.NeighDel(&netlink.Neigh{
			LinkIndex: lo.Index,
			IP:        net.ParseIP("10.0.2.50").To4(),
			Flags:     unix.NTF_PROXY,
			Family:    unix.AF_INET,
		})
	})

	found := false
	for _, w := range *writes {
		if w.iface == "lo" && w.family == unix.AF_INET {
			found = true
		}
	}
	if !found {
		t.Fatalf("no proxy_arp sysctl enable for lo; writes=%+v "+
			"(pre-#2160 behavior — neighbor installed but sysctl left 0)", *writes)
	}
}
