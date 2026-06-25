package daemon

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
)

// #2691 P2 daemon-level Surface A tests: scope construction from the committed
// per-interface bindings + provider catalog (with RG attribution), and the
// per-RG HA gate. Fail-on-revert: prove a binding resolves to a scoped publish
// record and that an HA-owned (reth) interface scope is keyed on its RG.

func TestBuildSurfaceAScopesFromConfig(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set system services dynamic-dns forced-refresh 24h",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0/0/2 unit 50 family inet dynamic-dns address-source dhcp",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns provider corp-2136",
		"set interfaces ge-0/0/2 unit 50 family inet6 dynamic-dns hostname wan6.example.net",
		// A binding whose provider is undefined must be skipped.
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns provider ghost",
		"set interfaces ge-0/0/3 unit 0 family inet dynamic-dns hostname ghost.example.net",
	})
	d := &Daemon{store: store}
	cfg := d.store.ActiveConfig()
	scopes := d.buildSurfaceAScopes(cfg)

	byFQDN := map[string]ddns.SurfaceAScope{}
	for _, s := range scopes {
		byFQDN[s.FQDN] = s
	}
	if _, ok := byFQDN["ghost.example.net"]; ok {
		t.Fatal("a binding referencing an undefined provider must be skipped")
	}
	v4, ok := byFQDN["wan.example.net"]
	if !ok {
		t.Fatalf("inet binding scope missing; got %d scopes", len(scopes))
	}
	if v4.Key.Family != ddns.FamilyV4 || v4.Key.Interface != "ge-0/0/2" || v4.Key.Unit != 50 {
		t.Fatalf("inet scope key mismatch: %+v", v4.Key)
	}
	if v4.Source != ddns.AddressSourceDHCP {
		t.Fatalf("inet scope source = %q, want dhcp", v4.Source)
	}
	if v4.Provider == nil || v4.Provider.UpdateServer != "192.0.2.53" {
		t.Fatalf("inet scope provider not resolved: %+v", v4.Provider)
	}
	if v4.ForcedRefresh.Hours() != 24 {
		t.Fatalf("forced-refresh not threaded into the scope: %v", v4.ForcedRefresh)
	}
	v6, ok := byFQDN["wan6.example.net"]
	if !ok {
		t.Fatal("inet6 binding scope missing")
	}
	if v6.Key.Family != ddns.FamilyV6 {
		t.Fatalf("inet6 scope family mismatch: %+v", v6.Key)
	}
	if v4.Source == ddns.AddressSourceInterface {
		t.Fatal("inet scope should be dhcp, not interface default")
	}
}

func TestBuildSurfaceAScopesAttributesRG(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set interfaces reth0 unit 80 family inet dynamic-dns provider corp-2136",
		"set interfaces reth0 unit 80 family inet dynamic-dns hostname vip.example.net",
	})
	d := &Daemon{store: store, cluster: cluster.NewManager(0, 1)}
	cfg := d.store.ActiveConfig()
	scopes := d.buildSurfaceAScopes(cfg)
	if len(scopes) != 1 {
		t.Fatalf("expected one reth scope, got %d", len(scopes))
	}
	if scopes[0].Key.RGOwner != 1 {
		t.Fatalf("a reth0 (RG1) binding must attribute RGOwner=1, got %d", scopes[0].Key.RGOwner)
	}
}

func TestSurfaceAGatePerRG(t *testing.T) {
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
	}
	// No RG is master yet → an RG1 scope is gated CLOSED; an RG0 (non-HA)
	// scope is always admitted.
	gate := d.surfaceAGate()
	if gate == nil {
		t.Fatal("cluster daemon must produce a per-RG gate")
	}
	if gate(ddns.ScopeKey{RGOwner: 1}) {
		t.Fatal("RG1 scope must be gated closed when not master for RG1")
	}
	if !gate(ddns.ScopeKey{RGOwner: 0}) {
		t.Fatal("RG0 (non-HA) scope must be admitted")
	}
}

func TestSurfaceAStandaloneGateNil(t *testing.T) {
	d := &Daemon{} // no cluster
	if d.surfaceAGate() != nil {
		t.Fatal("standalone daemon must return a nil gate (every scope writable)")
	}
}

func TestStaticUnitAddr(t *testing.T) {
	// Genuinely globally-routable unicast addresses are accepted.
	unit := &config.InterfaceUnit{Addresses: []string{"198.51.99.5/24", "2606:4700:4700::1111/64"}}
	a4, ok := staticUnitAddr(unit, true)
	if !ok || a4 != netip.MustParseAddr("198.51.99.5") {
		t.Fatalf("v4 static addr = %v ok=%v", a4, ok)
	}
	a6, ok := staticUnitAddr(unit, false)
	if !ok || a6 != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("v6 static addr = %v ok=%v", a6, ok)
	}
	// Link-local / loopback are skipped.
	llUnit := &config.InterfaceUnit{Addresses: []string{"fe80::1/64"}}
	if _, ok := staticUnitAddr(llUnit, false); ok {
		t.Fatal("link-local must not be selected as a Surface A address")
	}
}

// TestStaticUnitAddrPublicGate is the #2776 fail-on-revert gate for the
// Surface A static-address fallback. A configured static address that is NOT
// globally-routable unicast (multicast, reserved, ULA, CGNAT, documentation,
// IANA special-purpose) must be SKIPPED — never published as the router's
// A/AAAA record — and a genuine public static address must be selected. This
// goes RED if the ddns.IsPublicAddr gate is removed from staticUnitAddr: each
// rejected entry below would then be returned ok=true.
func TestStaticUnitAddrPublicGate(t *testing.T) {
	rejectV4 := []string{
		"224.0.0.1/24",       // 224/4 multicast
		"240.0.0.1/24",       // 240/4 reserved-for-future-use
		"10.1.2.3/24",        // 10/8 private
		"100.64.0.1/24",      // 100.64/10 CGNAT
		"192.0.2.5/24",       // 192.0.2/24 TEST-NET-1 documentation
		"203.0.113.5/24",     // 203.0.113/24 TEST-NET-3 documentation
		"198.18.0.1/24",      // 198.18/15 benchmarking
		"255.255.255.255/32", // limited broadcast
	}
	for _, cidr := range rejectV4 {
		u := &config.InterfaceUnit{Addresses: []string{cidr}}
		if a, ok := staticUnitAddr(u, true); ok {
			t.Errorf("staticUnitAddr(%s) = %v ok=true, want skipped (non-public)", cidr, a)
		}
	}
	rejectV6 := []string{
		"ff02::1/64",     // ff00::/8 multicast
		"fc00::1/64",     // fc00::/7 ULA
		"fd00::1/64",     // fc00::/7 ULA
		"2001:db8::1/64", // 2001:db8::/32 documentation
		"64:ff9b::1/96",  // 64:ff9b::/96 NAT64 well-known
	}
	for _, cidr := range rejectV6 {
		u := &config.InterfaceUnit{Addresses: []string{cidr}}
		if a, ok := staticUnitAddr(u, false); ok {
			t.Errorf("staticUnitAddr(%s) = %v ok=true, want skipped (non-public)", cidr, a)
		}
	}
	// A genuine public static address IS selected, even when listed after a
	// rejected one (the gate skips, it does not abort the scan).
	mixed := &config.InterfaceUnit{Addresses: []string{"224.0.0.1/24", "8.8.4.4/24"}}
	a, ok := staticUnitAddr(mixed, true)
	if !ok || a != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("public addr after a rejected one = %v ok=%v, want 8.8.4.4 ok=true", a, ok)
	}
}

// mkAddr builds a synthetic netlink.Addr with the given CIDR and IFA_F_* flags
// for selectInterfaceAddr table tests (no kernel interface required).
func mkAddr(cidr string, flags int) netlink.Addr {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, Flags: flags}
}

// TestSelectInterfaceAddrLifetime is the #2775 fail-on-revert gate for IPv6
// address-lifetime-aware selection. observeInterfaceAddr (via this pure helper)
// must honor RFC 4862 address state:
//
//   - PREFER a `preferred` address over a `deprecated` one. Goes RED if the
//     lifetime-preference logic is reverted (a deprecated address wrongly
//     selected over a preferred one).
//   - fall back to `deprecated` only when no preferred exists (never blackhole).
//   - NEVER select tentative / dadfailed / optimistic (DAD not succeeded).
//   - the selected address STILL passes ddns.IsPublicAddr (composes with #2776):
//     a preferred-but-ULA address is rejected.
func TestSelectInterfaceAddrLifetime(t *testing.T) {
	pref6 := netip.MustParseAddr("2606:4700:4700::1111")
	dep6 := netip.MustParseAddr("2606:4700:4700::2222")
	pref4 := netip.MustParseAddr("198.51.99.5")

	tests := []struct {
		name  string
		addrs []netlink.Addr
		af4   bool
		want  netip.Addr
		ok    bool
	}{
		{
			// Core fail-on-revert: preferred wins over deprecated even though the
			// deprecated address is listed FIRST (netlink order must not decide).
			name: "prefer preferred over deprecated (deprecated listed first)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// Only deprecated available → use it (never blackhole).
			name: "deprecated only falls back, no blackhole",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// tentative / dadfailed / optimistic are never publishable, even if
			// they are the only globally-routable addresses present.
			name: "tentative never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_TENTATIVE),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			name: "dadfailed never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_DADFAILED),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			name: "optimistic never selected",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_OPTIMISTIC),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// Composition with #2776: a preferred ULA is still rejected; the
			// preferred GUA listed after it is selected.
			name: "preferred-but-ULA rejected, GUA selected",
			addrs: []netlink.Addr{
				mkAddr("fd00::1/64", 0),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// A tentative preferred + a deprecated valid → deprecated wins (the
			// tentative is skipped, the deprecated is the only usable address).
			name: "tentative preferred skipped, deprecated used",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", unix.IFA_F_TENTATIVE),
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// #2975 fail-on-revert: a SLAAC privacy/temporary preferred address
			// listed FIRST must NOT be selected when a stable permanent preferred
			// address exists. Goes RED if IFA_F_TEMPORARY is dropped from the skip
			// mask (the temporary 0xdead address would win on netlink order).
			name: "temporary skipped, permanent preferred selected (temporary first)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
				mkAddr("2606:4700:4700::1111/64", 0),
			},
			af4:  false,
			want: pref6,
			ok:   true,
		},
		{
			// A temporary address as the ONLY candidate is rejected outright — a
			// rotating privacy identifier must never be published, even at the
			// cost of no answer (it would blackhole on the next rotation anyway).
			name: "temporary only is rejected (never publish privacy identifier)",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// Composition: a temporary preferred + a deprecated permanent → the
			// temporary is skipped and the deprecated permanent is the only usable
			// answer (never blackhole). Confirms the temporary skip does not
			// accidentally promote a temporary into the deprecated fallback slot.
			name: "temporary preferred skipped, deprecated permanent used",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY),
				mkAddr("2606:4700:4700::2222/64", unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: dep6,
			ok:   true,
		},
		{
			// A deprecated temporary address (privacy address mid-rotation) is
			// skipped twice over — neither TEMPORARY nor DEPRECATED may publish.
			name: "deprecated temporary never used as fallback",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::dead/64", unix.IFA_F_TEMPORARY|unix.IFA_F_DEPRECATED),
			},
			af4:  false,
			want: netip.Addr{},
			ok:   false,
		},
		{
			// IPv4 family filter + preferred selection.
			name: "v4 preferred selected, v6 ignored",
			addrs: []netlink.Addr{
				mkAddr("2606:4700:4700::1111/64", 0),
				mkAddr("198.51.99.5/24", 0),
			},
			af4:  true,
			want: pref4,
			ok:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectInterfaceAddr(tc.addrs, tc.af4)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("selectInterfaceAddr() = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestObserveInterfaceAddrTransientVsDefinitive is the #2840 fail-on-revert gate
// for the transient-vs-definitive contract of observeInterfaceAddr. The netlink
// reads are injected via the netlinkLinkByName / netlinkAddrList seams so no
// real kernel interface is required.
//
// The load-bearing distinction:
//
//   - A LinkByName ERROR or an AddrList ERROR is a TRANSIENT read failure →
//     (zero, false): the engine leaves the scope untouched (no publish, no
//     withdraw). It MUST NOT fall back to the configured static — publishing a
//     "configured" address that we could not confirm is "active" points DNS at a
//     possibly-stale address during a transient link outage. This case goes RED
//     if reverted to returning (static, true) on a link-read error (the #2840
//     bug).
//   - An interface that reads SUCCESSFULLY but yields no usable dynamic address
//     IS the legitimate static-use case → the static fallback applies
//     (present-but-addressless), and a present-but-addressless interface with NO
//     usable static is (zero, true) = definitively-none → the engine withdraws.
//   - A normal dynamic address is returned as-is.
func TestObserveInterfaceAddrTransientVsDefinitive(t *testing.T) {
	staticV4 := netip.MustParseAddr("198.51.99.7")
	dynV4 := netip.MustParseAddr("198.51.99.9")
	unitWithStatic := &config.InterfaceUnit{Addresses: []string{"198.51.99.7/24"}}

	// Save and restore the netlink seams.
	origLink := netlinkLinkByName
	origAddr := netlinkAddrList
	t.Cleanup(func() {
		netlinkLinkByName = origLink
		netlinkAddrList = origAddr
	})

	// fakeLink is a minimal netlink.Link for the AddrList seam to consume.
	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2"}}

	d := &Daemon{}

	t.Run("LinkByName error is transient (no static publish)", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			t.Fatal("AddrList must not be called after a LinkByName error")
			return nil, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		// FAIL-ON-REVERT: if observeInterfaceAddr is reverted to returning the
		// static on a LinkByName error, ok becomes true (and got == staticV4)
		// and this assertion fails.
		if ok || got.IsValid() {
			t.Fatalf("LinkByName error: got (%v, %v); want (zero, false) transient (static must NOT be published)", got, ok)
		}
	})

	t.Run("AddrList error is transient (no static publish)", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, errors.New("netlink hiccup")
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if ok || got.IsValid() {
			t.Fatalf("AddrList error: got (%v, %v); want (zero, false) transient (static must NOT be published)", got, ok)
		}
	})

	t.Run("present-but-addressless falls back to static", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, nil // successful read, no addresses
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if !ok || got != staticV4 {
			t.Fatalf("present-but-addressless: got (%v, %v); want (%v, true) static fallback", got, ok, staticV4)
		}
	})

	t.Run("present-but-addressless with no static is definitively-none", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return nil, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, &config.InterfaceUnit{})
		if !ok || got.IsValid() {
			t.Fatalf("addressless, no static: got (%v, %v); want (zero, true) definitively-none", got, ok)
		}
	})

	t.Run("normal dynamic address is returned", func(t *testing.T) {
		netlinkLinkByName = func(string) (netlink.Link, error) {
			return fakeLink, nil
		}
		netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
			return []netlink.Addr{mkAddr("198.51.99.9/24", 0)}, nil
		}
		got, ok := d.observeInterfaceAddr("ge-0-0-2", true, unitWithStatic)
		if !ok || got != dynV4 {
			t.Fatalf("dynamic address: got (%v, %v); want (%v, true)", got, ok, dynV4)
		}
	})
}
