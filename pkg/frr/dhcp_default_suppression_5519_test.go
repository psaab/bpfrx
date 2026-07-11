package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// renderDHCP5519 runs renderDHCPDefaults over fc and returns the rendered
// text so a test can assert whether the DHCP-learned default survived or was
// suppressed by a static default.
func renderDHCP5519(fc *FullConfig) string {
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	return b.String()
}

// #5519 (availability / remote lockout): renderDHCPDefaults suppressed the
// DHCP-learned default for ANY static 0.0.0.0/0 (or ::/0) stanza, but
// generateStaticRoute emits NOTHING for a zero-next-hop, non-discard default
// (#3872). Deleting the last ECMP next-hop of a static default therefore left a
// 0.0.0.0/0 object that rendered no FIB entry AND still masked the DHCP
// fallback → no default route at all → WAN / management lockout. Suppression
// must be derived from the static default's ACTUAL renderability
// (staticRouteRendersFIB), not the mere presence of the stanza.
//
// RED-on-revert: restore the old `sr.Destination == "0.0.0.0/0"` /
// `sr.Destination == "::/0"` suppression (drop the staticRouteRendersFIB
// guard) and the zero-next-hop cases below fail — the DHCP default vanishes.

// (a) A zero-next-hop, non-discard static default must NOT suppress the
// DHCP-learned v4 default: the DHCP default survives in the rendered output.
func TestZeroNextHopStaticDefaultKeepsDHCPDefault_v4_5519(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{Destination: "0.0.0.0/0"}}, // no next-hops
		DHCPRoutes:   []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
	}
	got := renderDHCP5519(fc)
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 200") {
		t.Fatalf("zero-next-hop static default suppressed the DHCP v4 default (remote lockout); rendered:\n%s", got)
	}
}

// (b) A static default WITH next-hops renders a FIB entry, so it DOES suppress
// the DHCP-learned v4 default (unchanged pre-#5519 behavior).
func TestNextHopStaticDefaultSuppressesDHCPDefault_v4_5519(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{
			Destination: "0.0.0.0/0",
			NextHops:    []config.NextHopEntry{{Address: "10.0.2.254"}},
		}},
		DHCPRoutes: []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
	}
	if got := renderDHCP5519(fc); strings.Contains(got, "0.0.0.0/0") {
		t.Fatalf("next-hop static default did not suppress the DHCP v4 default; rendered:\n%s", got)
	}
}

// (c) A discard or reject static default renders a negative FIB entry, so it
// DOES suppress the DHCP-learned v4 default.
func TestDiscardRejectStaticDefaultSuppressesDHCPDefault_v4_5519(t *testing.T) {
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
	}{
		{"discard", &config.StaticRoute{Destination: "0.0.0.0/0", Discard: true}},
		{"reject", &config.StaticRoute{Destination: "0.0.0.0/0", Reject: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				StaticRoutes: []*config.StaticRoute{tc.sr},
				DHCPRoutes:   []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
			}
			if got := renderDHCP5519(fc); strings.Contains(got, "0.0.0.0/0") {
				t.Fatalf("%s static default did not suppress the DHCP v4 default; rendered:\n%s", tc.name, got)
			}
		})
	}
}

// (d) Same matrix for the IPv6 ::/0 default.
func TestZeroNextHopStaticDefaultKeepsDHCPDefault_v6_5519(t *testing.T) {
	fc := &FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0"}}, // no next-hops
		DHCPRoutes:        []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
	}
	got := renderDHCP5519(fc)
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 ge-0-0-2 200") {
		t.Fatalf("zero-next-hop static ::/0 default suppressed the DHCP v6 default (remote lockout); rendered:\n%s", got)
	}
}

func TestNextHopStaticDefaultSuppressesDHCPDefault_v6_5519(t *testing.T) {
	fc := &FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{{
			Destination: "::/0",
			NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
		}},
		DHCPRoutes: []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
	}
	if got := renderDHCP5519(fc); strings.Contains(got, "::/0") {
		t.Fatalf("next-hop static ::/0 default did not suppress the DHCP v6 default; rendered:\n%s", got)
	}
}

func TestDiscardRejectStaticDefaultSuppressesDHCPDefault_v6_5519(t *testing.T) {
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
	}{
		{"discard", &config.StaticRoute{Destination: "::/0", Discard: true}},
		{"reject", &config.StaticRoute{Destination: "::/0", Reject: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				Inet6StaticRoutes: []*config.StaticRoute{tc.sr},
				DHCPRoutes:        []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
			}
			if got := renderDHCP5519(fc); strings.Contains(got, "::/0") {
				t.Fatalf("%s static ::/0 default did not suppress the DHCP v6 default; rendered:\n%s", tc.name, got)
			}
		})
	}
}

// staticRouteRendersFIB is the shared predicate; pin its truth table so the
// emit test in generateStaticRouteInTable and the suppression test in
// renderDHCPDefaults cannot silently drift.
func TestStaticRouteRendersFIB_5519(t *testing.T) {
	cases := []struct {
		name string
		sr   *config.StaticRoute
		want bool
	}{
		{"zero-next-hop", &config.StaticRoute{Destination: "0.0.0.0/0"}, false},
		{"next-hop", &config.StaticRoute{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}}, true},
		{"discard", &config.StaticRoute{Destination: "0.0.0.0/0", Discard: true}, true},
		{"reject", &config.StaticRoute{Destination: "0.0.0.0/0", Reject: true}, true},
		{"next-table", &config.StaticRoute{Destination: "0.0.0.0/0", NextTable: "Comcast"}, false},
	}
	for _, tc := range cases {
		if got := staticRouteRendersFIB(tc.sr); got != tc.want {
			t.Errorf("staticRouteRendersFIB(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
