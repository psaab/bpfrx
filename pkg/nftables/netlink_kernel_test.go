package nftables

import (
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

// netlink_kernel_test.go exercises the netlink installer against the REAL kernel
// nf_tables subsystem in a private network namespace (no `nft` binary needed —
// google/nftables talks netlink directly). It proves:
//   - every construct in the §5.1 matrix LOADS (the kernel validates each expr
//     on Flush; a malformed offset/mask/set is rejected), including the
//     no-prior-table cold-boot install (§12.2) and the day-2 atomic replace;
//   - the named CounterObjs read back UNCHANGED through the existing
//     pkg/nftables counter readers (the observability contract, §4).
//
// These tests need CAP_NET_ADMIN to create a netns; they SKIP with an explicit
// reason otherwise (memory rule: no silent caps). Run locally with
//   unshare -rn env GOFLAGS=-mod=mod go test ./pkg/nftables/...
// and in CI as root; the parent runs the `nft`-text parity T1 where `nft` exists.

// enterPrivateNetns locks the goroutine to its OS thread and moves it into a
// fresh network namespace so the default-netns installer + counter readers all
// operate on an isolated, empty ruleset. It SKIPs when netns creation is denied.
func enterPrivateNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn` or as root): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// TestNetlinkInstallLoadsInKernel installs every ruleset variant and asserts the
// kernel accepts each Flush (validating all exprs), covering the no-prior-table
// cold-boot install and the day-2 atomic replace.
func TestNetlinkInstallLoadsInKernel(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()

	// Cold-boot: no table exists yet — the fence install must NOT abort (§12.2).
	if err := in.InstallColdBootFence(fenceScenario()); err != nil {
		t.Fatalf("cold-boot fence install (no prior table) failed: %v", err)
	}
	// Day-2 atomic replace: the real host-inbound table over the fence.
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install (atomic replace) failed: %v", err)
	}
	// Re-install (idempotent replace) must also succeed.
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound re-install failed: %v", err)
	}
	if err := in.InstallGapFence(gapFenceScenario()); err != nil {
		t.Fatalf("gap fence install failed: %v", err)
	}
	if err := in.InstallLo0(lo0Scenario()); err != nil {
		t.Fatalf("lo0 install failed: %v", err)
	}

	// Every expected table is present with a non-empty input chain.
	assertChainNonEmpty(t, HostInboundTableName)
	assertChainNonEmpty(t, HostInboundGapTableName)
	assertChainNonEmpty(t, Lo0TableName)

	// Teardown: delete is idempotent (present -> removed, absent -> nil).
	for _, name := range []string{HostInboundTableName, HostInboundGapTableName, Lo0TableName} {
		if err := in.DeleteTable(name); err != nil {
			t.Fatalf("DeleteTable(%s) failed: %v", name, err)
		}
		if err := in.DeleteTable(name); err != nil {
			t.Fatalf("DeleteTable(%s) second call (absent) should be nil: %v", name, err)
		}
	}
}

// TestCounterReadbackThroughExistingReaders installs the host-inbound table and
// verifies the named CounterObjs round-trip through the EXISTING pkg/nftables
// readers unchanged (deny, accept, and junos-host deny counters).
func TestCounterReadbackThroughExistingReaders(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install failed: %v", err)
	}

	// Coarse per-zone/family deny counters.
	deny, err := ReadHostInboundDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundDenyCounters: %v", err)
	}
	denySet := map[string]bool{}
	for _, d := range deny {
		denySet[d.Zone+"/"+d.Family] = true
	}
	for _, want := range []string{"trust/ip", "trust/ip6", "core/ip", "edge/ip", "quarantine/ip", "quarantine/ip6", "junos-host/ip", "junos-host/ip6"} {
		if !denySet[want] {
			t.Errorf("deny counter %q not read back; got %v", want, denySet)
		}
	}
	if denySet["mgmt/ip"] {
		t.Errorf("mgmt zone (system-services all) must NOT have a deny counter")
	}

	// Global ICMP-accept counters (aggregate).
	acc, err := ReadHostInboundAcceptCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundAcceptCounters: %v", err)
	}
	accSet := map[string]bool{}
	for _, a := range acc {
		accSet[a.Type] = true
	}
	for _, want := range HostInboundAcceptCounterTypes {
		if !accSet[want] {
			t.Errorf("accept counter %q not read back; got %v", want, accSet)
		}
	}

	// junos-host DENY counters.
	jh, err := ReadHostInboundJunosHostDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundJunosHostDenyCounters: %v", err)
	}
	jhSet := map[string]bool{}
	for _, j := range jh {
		jhSet[j.Scope+"/"+j.Family] = true
	}
	for _, want := range []string{"untrust/ip", "untrust/ip6"} {
		if !jhSet[want] {
			t.Errorf("junos-host deny counter %q not read back; got %v", want, jhSet)
		}
	}
}

// TestLo0CounterReadback installs the lo0 filter and verifies the `then count`
// counters read back through ReadLo0Counters unchanged.
func TestLo0CounterReadback(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if err := in.InstallLo0(lo0Scenario()); err != nil {
		t.Fatalf("lo0 install failed: %v", err)
	}
	counts, err := ReadLo0Counters()
	if err != nil {
		t.Fatalf("ReadLo0Counters: %v", err)
	}
	got := map[string]bool{}
	for _, c := range counts {
		got[c.Counter] = true
	}
	for _, want := range []string{"ssh_hits", "audit"} {
		if !got[want] {
			t.Errorf("lo0 counter %q not read back; got %v", want, got)
		}
	}
}

// assertChainNonEmpty checks the inet table's `input` chain has >= 1 rule.
func assertChainNonEmpty(t *testing.T, table string) {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	rules, err := c.GetRules(
		&nftables.Table{Family: nftables.TableFamilyINet, Name: table},
		&nftables.Chain{Name: "input"},
	)
	if err != nil {
		t.Fatalf("GetRules(%s): %v", table, err)
	}
	if len(rules) == 0 {
		t.Errorf("table %s input chain has no rules", table)
	}
}
