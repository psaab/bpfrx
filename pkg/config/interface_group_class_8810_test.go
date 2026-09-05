package config

import (
	"sort"
	"testing"
)

// TestProxyARPAndRAGroupsCreateEveryInterface8810 completes the `interface`
// container class: all five namedInstances enumeration sites now fan out a
// bracketed group.
//
// #8810 fixed `chassis device-map` and `ospf area … interface` and deliberately
// left these two, named with UNMEASURED severity rather than fixed blind. This
// measures them and they are the OSPF case, not the device-map case.
//
// THE DISCRIMINATOR, MEASURED RATHER THAN REASONED. A grouped statement shares
// ONE body, so whether fanning out is correct depends on whether that body can
// legitimately be shared:
//
//	device-map   body carries `pci` — a per-NIC identity. Two NICs cannot share
//	             one, so the grouped form is REJECTED (and must be).
//	proxy-arp    body carries `address`. Measured: writing the SAME address on
//	             two interfaces LONGHAND is ACCEPTED, so it is shareable and
//	             fanning out produces valid config.
//	RA           body carries advertisement parameters, shareable by nature.
//
// The proxy-arp control is the load-bearing one: if a shared proxy-ARP address
// were forbidden, the longhand-same-address case would have been rejected and
// this container would have inverted to the device-map remedy. It was not.
func TestProxyARPAndRAGroupsCreateEveryInterface8810(t *testing.T) {
	const ifaces = `interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } ` +
		`ge-0/0/2 { unit 0 { family inet { address 10.0.2.1/24; } } } } `

	proxyNames := func(t *testing.T, label, text string) []string {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", label, perrs)
		}
		cfg, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("%s: strict compile: %v", label, err)
		}
		var out []string
		for _, p := range cfg.Security.NAT.ProxyARP {
			out = append(out, p.Interface)
		}
		sort.Strings(out)
		return out
	}
	raNames := func(t *testing.T, label, text string) []string {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", label, perrs)
		}
		cfg, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("%s: strict compile: %v", label, err)
		}
		var out []string
		for _, r := range cfg.Protocols.RouterAdvertisement {
			out = append(out, r.Interface)
		}
		sort.Strings(out)
		return out
	}
	want := []string{"ge-0/0/1.0", "ge-0/0/2.0"}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	t.Run("proxy-arp grouped", func(t *testing.T) {
		got := proxyNames(t, "proxy-arp grouped", ifaces+
			`security { nat { proxy-arp { interface [ ge-0/0/1.0 ge-0/0/2.0 ] { address 10.0.1.50/32; } } } }`)
		if !eq(got, want) {
			t.Errorf("proxy-arp entries %v, want %v. An interface the operator listed does "+
				"not answer ARP for the address, so traffic to it is not drawn to this box "+
				"(#8810)", got, want)
		}
	})
	// THE CONTROL THAT DECIDED THE REMEDY. A shared proxy-ARP address written
	// longhand is accepted, so the body IS shareable and create-N is correct.
	// If this ever starts rejecting, the grouped form must be rejected too and
	// the cell above is asserting the wrong outcome.
	t.Run("control: shared address longhand is legal", func(t *testing.T) {
		got := proxyNames(t, "shared addr longhand", ifaces+
			`security { nat { proxy-arp { interface ge-0/0/1.0 { address 10.0.1.50/32; } interface ge-0/0/2.0 { address 10.0.1.50/32; } } } }`)
		if !eq(got, want) {
			t.Errorf("two interfaces sharing one proxy-ARP address were not both compiled "+
				"(%v). If that is now forbidden, proxy-arp is the device-map case and a "+
				"grouped form must be REJECTED rather than fanned out (#8810)", got)
		}
	})
	t.Run("router-advertisement grouped", func(t *testing.T) {
		got := raNames(t, "RA grouped",
			`protocols { router-advertisement { interface [ ge-0/0/1.0 ge-0/0/2.0 ] { max-advertisement-interval 600; } } }`)
		if !eq(got, want) {
			t.Errorf("RA interfaces %v, want %v. An interface the operator listed sends no "+
				"router advertisements, so hosts on that link get no default route (#8810)",
				got, want)
		}
	})
	t.Run("control: RA longhand", func(t *testing.T) {
		got := raNames(t, "RA longhand",
			`protocols { router-advertisement { interface ge-0/0/1.0 { max-advertisement-interval 600; } interface ge-0/0/2.0 { max-advertisement-interval 600; } } }`)
		if !eq(got, want) {
			t.Errorf("RA longhand %v, want %v — the spelling that always worked regressed", got, want)
		}
	})
}
