package daemon

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #9138: mergeDNSInput walked every lease the manager held with no interface,
// zone, VRF or trust filter, so a DHCP-learned nameserver from ANY segment —
// including one an operator deliberately isolated in a routing instance —
// was written into /etc/resolv.conf, which is the whole resolver for this host
// (systemd-resolved is masked).
//
// Its sibling lease consumer collectDHCPRoutes already filters. The module
// header and docs/dns-ownership.md described the merge policy in detail and
// mentioned no VRF scoping at all, so this dimension was UNCONSIDERED, not
// rejected.
//
// The certain consequence is not the interesting one: the host resolves from
// the DEFAULT context, so a tenant-VRF nameserver is a dead entry costing a
// full resolver timeout. The reason it is a filter and not a note is that DHCP
// is the only path by which an untrusted network writes into the firewall's own
// host configuration, and what the host resolves — NTP peers, syslog and
// archival-transfer destinations, DDNS servers, the IPsec dynamic-hostname
// family hint — is bounded but not nothing.
func TestDNSMergeScopesByRoutingInstance9138(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		// SUBJECT: a tenant DHCP client, member named in the canonical Junos
		// SLASH spelling. The lease is keyed `ge-0-0-1`, so this cell is also
		// the proof that the filter inherits the #9135 key-shape rule: keyed on
		// the raw config token it would be inert here, exactly as #8963 was.
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
		// CONTROL 1: a default-context WAN DHCP client. Still contributes —
		// that is the supported CPE deployment and matches Junos, where
		// DHCP-learned DNS is global. A fix that dropped this would break every
		// standalone box.
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		// CONTROL 2: fxp0. Management interfaces live in the SYNTHESIZED mgmt
		// VRF, which is NOT a routing instance. A naive "exclude anything in a
		// VRF" predicate would take bootstrap DNS with it.
		"set interfaces fxp0 unit 0 family inet dhcp",
		// CONTROL 3: static name-server is authoritative and unconditional.
		"set system name-server 1.1.1.1",
	})
	cfg := store.ActiveConfig()

	mk := func(iface, dns string) *dhcp.Lease {
		return &dhcp.Lease{
			Interface: iface,
			Family:    dhcp.AFInet,
			DNS:       []netip.Addr{netip.MustParseAddr(dns)},
		}
	}
	in := mergeDNSInput(cfg, []*dhcp.Lease{
		mk("ge-0-0-1", "10.20.0.53"), // tenant-a — must NOT contribute
		mk("ge-0-0-2", "9.9.9.9"),    // default context — must contribute
		mk("fxp0", "192.168.1.1"),    // mgmt — must contribute
	})

	// NON-VACUITY: if the merge produced nothing, the absence assertion below
	// would pass for the wrong reason.
	if len(in.NameServers) == 0 {
		t.Fatal("NON-VACUITY: the merge produced no nameservers at all, so the " +
			"exclusion assertion cannot distinguish a working filter from a " +
			"broken merge")
	}

	for _, tc := range []struct {
		server string
		want   bool
		why    string
	}{
		{"10.20.0.53", false,
			"SUBJECT: a nameserver learned inside routing instance `tenant-a`. " +
				"The host resolver runs in the DEFAULT context, so it is at best a " +
				"dead entry costing a full timeout — and at worst an untrusted " +
				"tenant segment writing into the firewall's own host configuration."},
		{"9.9.9.9", true,
			"CONTROL: a default-context WAN lease must still contribute. This is " +
				"the supported CPE deployment; dropping it would break every " +
				"standalone box and diverge from Junos."},
		{"192.168.1.1", true,
			"CONTROL: fxp0 lives in the synthesized mgmt VRF, which is NOT a " +
				"routing instance. Excluding by VRF membership rather than by " +
				"routing-instance membership would brick bootstrap DNS."},
		{"1.1.1.1", true,
			"CONTROL: a static `system name-server` is authoritative and is never " +
				"filtered."},
	} {
		got := slices.Contains(in.NameServers, tc.server)
		if got != tc.want {
			verb := "must NOT appear"
			if tc.want {
				verb = "must appear"
			}
			t.Errorf("#9138 %s\n  %s in the merged resolver but the merge is %v",
				tc.why, tc.server+" "+verb, in.NameServers)
		}
	}
}

// The static entries stay FIRST and the surviving DHCP entries keep their
// documented order. The filter must remove entries, never reorder the rest —
// glibc consults `nameserver` lines in order, so a reorder is a silent
// priority change.
func TestDNSMergeFilterPreservesOrder9138(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system name-server 1.1.1.1",
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		"set interfaces ge-0/0/3 unit 0 family inet6 dhcpv6",
	})
	in := mergeDNSInput(store.ActiveConfig(), []*dhcp.Lease{
		{Interface: "ge-0-0-2", Family: dhcp.AFInet, DNS: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
		{Interface: "ge-0-0-1", Family: dhcp.AFInet, DNS: []netip.Addr{netip.MustParseAddr("10.20.0.53")}},
		{Interface: "ge-0-0-3", Family: dhcp.AFInet6, DNS: []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}},
	})
	want := []string{"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"}
	if !slices.Equal(in.NameServers, want) {
		t.Errorf("#9138: the filter must remove the tenant entry and leave the "+
			"documented order intact (static, then DHCPv4, then DHCPv6).\n"+
			"  got  %v\n  want %v", in.NameServers, want)
	}
}

// WIRING BIND. The cells above call mergeDNSInput directly, which says nothing
// about whether the DHCP manager's leases ever reach it. Measured while fixing
// #9138: severing the `d.dhcp.Leases()` read in the reconcile path killed ZERO
// tests in this package — DHCP-learned DNS could stop reaching
// /etc/resolv.conf entirely and the Go suite stayed green.
//
// It asserts the SET, not a count: a fix that turned "the tenant entry is
// filtered" into "no lease reaches the merge" would satisfy any length check
// while inverting the failure from detectable to plausible.
func TestDNSInputLockedJoinsLeasesAndConfig9138(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system name-server 1.1.1.1",
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
	})
	mgr := dhcp.NewManagerForTesting(nil)
	seed := func(iface, dns string) {
		mgr.SeedLeaseForTesting(iface, dhcp.AFInet, &dhcp.Lease{
			Interface: iface, Family: dhcp.AFInet,
			DNS: []netip.Addr{netip.MustParseAddr(dns)},
		})
	}
	seed("ge-0-0-1", "10.20.0.53") // tenant-a
	seed("ge-0-0-2", "9.9.9.9")    // default context

	d := &Daemon{store: store, dhcp: mgr}
	in := d.dnsInputLocked(store.ActiveConfig())
	want := []string{"1.1.1.1", "9.9.9.9"}
	if !slices.Equal(in.NameServers, want) {
		t.Errorf("#9138 wiring: the reconcile input must join the committed static "+
			"name-servers with the manager's CURRENT leases, minus the "+
			"routing-instance ones.\n  got  %v\n  want %v\n"+
			"  An empty or static-only result means the lease read is severed and "+
			"nothing the daemon learns by DHCP reaches the resolver at all.",
			in.NameServers, want)
	}
}

// END-TO-END BIND. The cell above proves the input is right; this proves the
// input reaches the FILE. reconcileDNSLocked is what the apply path and the
// DHCP callback both call, and its handoff to the reconciler was the last
// unbound edge: severing it left the whole Go suite green, because the merge
// policy is covered against mergeDNSInput and the filesystem behaviour against
// a hand-built dnsReconciler (#6792), with nothing joining the two.
func TestReconcileDNSLockedWritesInstanceScopedResolvConf9138(t *testing.T) {
	rec, _ := newTestReconciler(t, t.TempDir())
	prev := newDNSReconcilerFn
	newDNSReconcilerFn = func() *dnsReconciler { return rec }
	t.Cleanup(func() { newDNSReconcilerFn = prev })

	store := testStoreWithSetConfig(t, []string{
		"set system name-server 1.1.1.1",
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
	})
	mgr := dhcp.NewManagerForTesting(nil)
	for iface, dns := range map[string]string{"ge-0-0-1": "10.20.0.53", "ge-0-0-2": "9.9.9.9"} {
		mgr.SeedLeaseForTesting(iface, dhcp.AFInet, &dhcp.Lease{
			Interface: iface, Family: dhcp.AFInet,
			DNS: []netip.Addr{netip.MustParseAddr(dns)},
		})
	}
	d := &Daemon{store: store, dhcp: mgr}
	if err := d.reconcileDNSLocked(store.ActiveConfig(), false); err != nil {
		t.Fatalf("reconcileDNSLocked: %v", err)
	}
	got := readFile(t, rec.resolvConfPath)

	// POSITIVE CONTROL FIRST. "the tenant nameserver is absent" is also true of
	// a file that was never written, of an empty file, and of a reconcile that
	// silently did nothing — three failures that read exactly like success.
	for _, want := range []string{"nameserver 1.1.1.1", "nameserver 9.9.9.9"} {
		if !strings.Contains(got, want) {
			t.Fatalf("POSITIVE CONTROL FAILED: %q missing from the written "+
				"resolv.conf, so the absence assertion below cannot distinguish "+
				"a scoped resolver from a resolver that was never written.\n%s",
				want, got)
		}
	}
	if strings.Contains(got, "10.20.0.53") {
		t.Errorf("#9138: a nameserver learned inside routing instance `tenant-a` "+
			"reached the host's only resolver. The host resolves from the DEFAULT "+
			"context, so at best this is a dead entry costing a full timeout; at "+
			"worst it is an isolated tenant segment writing into the firewall's "+
			"own host configuration.\n%s", got)
	}
}
