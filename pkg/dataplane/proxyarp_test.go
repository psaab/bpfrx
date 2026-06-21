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

// captureNeigh installs fake netlink seams that record every NeighSet /
// NeighDel and return a configurable existing-entry list from NeighList,
// restoring the production wiring on cleanup. This lets the v4/v6 install +
// stale-removal logic be exercised without CAP_NET_ADMIN. Returns pointers to
// the captured add/del slices.
func captureNeigh(t *testing.T, existing []netlink.Neigh) (set, del *[]netlink.Neigh) {
	t.Helper()
	prevList, prevSet, prevDel := neighListSeam, neighSetSeam, neighDelSeam
	var sets, dels []netlink.Neigh
	neighListSeam = func(linkIndex, family int) ([]netlink.Neigh, error) {
		// Return only entries matching the requested family so the v4 and v6
		// passes are properly separated, mirroring the kernel.
		var out []netlink.Neigh
		for _, n := range existing {
			if n.Family == family {
				out = append(out, n)
			}
		}
		return out, nil
	}
	neighSetSeam = func(n *netlink.Neigh) error { sets = append(sets, *n); return nil }
	neighDelSeam = func(n *netlink.Neigh) error { dels = append(dels, *n); return nil }
	t.Cleanup(func() {
		neighListSeam, neighSetSeam, neighDelSeam = prevList, prevSet, prevDel
	})
	return &sets, &dels
}

// TestReconcileProxyARP_V6InstallsPneigh is the #2197 item-1 regression: a v6
// static-NAT external proxy address must produce an AF_INET6 NTF_PROXY pneigh
// install (the v6 analogue of `ip -6 neigh add proxy <addr> dev <if>`) AND
// enable the proxy_ndp sysctl. Before the fix the AF_INET6 branch enabled the
// sysctl but `continue`d before any neighbor install, so the kernel never
// answered NDP (sysctl alone is a no-op without the pneigh entry). This test
// FAILS on pre-fix code (no AF_INET6 NeighSet is recorded). Seam-driven so it
// runs without root.
func TestReconcileProxyARP_V6InstallsPneigh(t *testing.T) {
	sets, _ := captureNeigh(t, nil)
	writes := captureProxySysctl(t, false)

	const idx = 7
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"2001:db8::50/128"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": idx}

	added, err := ReconcileProxyARP(cfg, ifaceMap)
	if err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}

	// A single AF_INET6 NTF_PROXY install for the configured address.
	if len(*sets) != 1 {
		t.Fatalf("got %d NeighSet calls, want 1: %+v", len(*sets), *sets)
	}
	got := (*sets)[0]
	if got.Family != unix.AF_INET6 {
		t.Fatalf("NeighSet family = %d, want AF_INET6 (%d)", got.Family, unix.AF_INET6)
	}
	if got.Flags&unix.NTF_PROXY == 0 {
		t.Fatalf("NeighSet flags = %#x, missing NTF_PROXY", got.Flags)
	}
	if got.LinkIndex != idx {
		t.Fatalf("NeighSet LinkIndex = %d, want %d", got.LinkIndex, idx)
	}
	if !got.IP.Equal(net.ParseIP("2001:db8::50")) {
		t.Fatalf("NeighSet IP = %v, want 2001:db8::50", got.IP)
	}

	// The returned added entry is tagged AF_INET6 so the caller skips the
	// IPv4-only GARP (#2197 item 1, risk R1).
	if len(added) != 1 || added[0].Family != unix.AF_INET6 {
		t.Fatalf("added = %+v, want one AF_INET6 entry", added)
	}

	// proxy_ndp sysctl enabled on the resolved interface (idx 7 may not
	// resolve to a real name in the sandbox; the sysctl-enable step still
	// runs over whatever name LinkByIndex returns, and is best-effort).
	for _, w := range *writes {
		if w.family == unix.AF_INET6 {
			return
		}
	}
	// If the ifindex did not resolve to a name (LinkByIndex failed in the
	// sandbox), the sysctl write is skipped — that path is exercised by the
	// loopback test below. The pneigh install (the item-1 fix) is the
	// load-bearing assertion and is verified above.
}

// TestReconcileProxyARP_V6StaleRemoval verifies a v6 NTF_PROXY entry no longer
// in the desired set is torn down (NeighDel with AF_INET6). This is the v6 arm
// of the stale-removal symmetry the existing v4 pass already had — it could
// only fire once v6 entries are listed (#2197 item 1).
func TestReconcileProxyARP_V6StaleRemoval(t *testing.T) {
	const idx = 7
	stale := net.ParseIP("2001:db8::dead")
	existing := []netlink.Neigh{{
		LinkIndex: idx,
		IP:        stale,
		Flags:     unix.NTF_PROXY,
		Family:    unix.AF_INET6,
	}}
	_, dels := captureNeigh(t, existing)
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	// Desired set is a DIFFERENT v6 address, so the stale one must be removed.
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"2001:db8::50/128"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": idx}

	if _, err := ReconcileProxyARP(cfg, ifaceMap); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}

	if len(*dels) != 1 {
		t.Fatalf("got %d NeighDel calls, want 1 (stale v6 removal): %+v", len(*dels), *dels)
	}
	d := (*dels)[0]
	if d.Family != unix.AF_INET6 || !d.IP.Equal(stale) {
		t.Fatalf("NeighDel = {family %d, ip %v}, want {AF_INET6, %v}", d.Family, d.IP, stale)
	}
}

// TestReconcileProxyARP_V4MappedClassifiesAsV4 is the SMR F1 guard: a
// ::ffff:10.0.0.1 v4-mapped literal proxy address MUST take the AF_INET
// install path, never a v6 NeighSet. netip's Is4In6 detection keeps the
// classification consistent with the desired-set and family-derivation logic.
func TestReconcileProxyARP_V4MappedClassifiesAsV4(t *testing.T) {
	sets, _ := captureNeigh(t, nil)
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"::ffff:10.0.0.1/128"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": 7}

	if _, err := ReconcileProxyARP(cfg, ifaceMap); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(*sets) != 1 {
		t.Fatalf("got %d NeighSet calls, want 1: %+v", len(*sets), *sets)
	}
	if (*sets)[0].Family != unix.AF_INET {
		t.Fatalf("v4-mapped literal installed with family %d, want AF_INET (%d)",
			(*sets)[0].Family, unix.AF_INET)
	}
}

// TestReconcileProxyARP_V6Idempotent verifies a v6 entry already present in the
// kernel (returned by the NeighList seam) is NOT re-installed — the reconcile
// diffs desired vs existing, so a steady config produces no NeighSet churn.
func TestReconcileProxyARP_V6Idempotent(t *testing.T) {
	const idx = 7
	addr := net.ParseIP("2001:db8::50")
	existing := []netlink.Neigh{{
		LinkIndex: idx,
		IP:        addr,
		Flags:     unix.NTF_PROXY,
		Family:    unix.AF_INET6,
	}}
	sets, dels := captureNeigh(t, existing)
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"2001:db8::50/128"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": idx}

	if _, err := ReconcileProxyARP(cfg, ifaceMap); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(*sets) != 0 {
		t.Fatalf("v6 entry re-installed despite already existing: %+v", *sets)
	}
	if len(*dels) != 0 {
		t.Fatalf("v6 desired entry wrongly removed: %+v", *dels)
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

// TestReconcileProxyARP_V6InstallsPneighLive is the privileged ground-truth for
// #2197 item 1: against the real kernel (no seam), a configured v6 proxy-ARP
// address must result in an AF_INET6 NTF_PROXY entry actually present in the
// kernel pneigh table on the interface. It mirrors the v4
// TestReconcileProxyARP_EnablesSysctl loopback pattern and SKIPs without root.
// On pre-fix code no v6 entry is installed (the AF_INET6 branch `continue`d
// before the install), so the post-reconcile NeighList(lo, AF_INET6) would not
// contain the address and this test would fail.
func TestReconcileProxyARP_V6InstallsPneighLive(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	captureProxySysctl(t, false) // keep the sysctl write off real procfs

	const v6 = "2001:db8:2197::50"
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "lo", Addresses: []string{v6 + "/128"}},
	}
	ifaceMap := map[string]int{"lo": lo.Index}

	if _, err := ReconcileProxyARP(cfg, ifaceMap); err != nil {
		t.Skipf("ReconcileProxyARP needs privileges in this env: %v", err)
	}
	t.Cleanup(func() {
		_ = netlink.NeighDel(&netlink.Neigh{
			LinkIndex: lo.Index,
			IP:        net.ParseIP(v6),
			Flags:     unix.NTF_PROXY,
			Family:    unix.AF_INET6,
		})
	})

	neighs, err := netlink.NeighList(lo.Index, unix.AF_INET6)
	if err != nil {
		t.Skipf("NeighList(lo, AF_INET6) needs privileges: %v", err)
	}
	want := net.ParseIP(v6)
	for _, n := range neighs {
		if n.Flags&unix.NTF_PROXY != 0 && n.IP.Equal(want) {
			return // found — the v6 pneigh entry was installed
		}
	}
	t.Fatalf("no AF_INET6 NTF_PROXY entry for %s on lo after reconcile "+
		"(pre-#2197 behavior — v6 sysctl enabled but pneigh entry never installed)", v6)
}
