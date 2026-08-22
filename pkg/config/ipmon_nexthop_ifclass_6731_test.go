package config

import (
	"strings"
	"testing"
)

// #6731 — the ip-monitoring interface next-hop validator rejected any interface
// whose NAME merely began with a tunnel/loopback prefix.
//
// Interface names are wildcard-authorable with no reservation on those prefixes,
// so `strings.HasPrefix(name, "lo")` also matched `login0`, `"st"` matched
// `start0`, `"fti"` matched `ftime0` and `"gr-"` matched `gr-eenwich`. Each is
// an ordinary data interface an operator may legitimately name and run a DHCP
// client on, and the commit was refused with a message telling them they had
// named a tunnel.
//
// The fix LOOSENS a validator, so the dangerous direction is over-loosening.
// Every cell below therefore comes in a pair: the look-alike must compile AND
// the genuine tunnel/loopback name in the same namespace must still be refused.
// A test that only asserted the look-alikes would pass just as well against
// `return false`.

// ipmonNextHopLines builds a config whose ip-monitoring preferred route names
// <ifd>.0 as its interface-typed next-hop, with a DHCP client on that unit.
func ipmonNextHopLines(ifd string) []string {
	return []string{
		"set services rpm probe WAN test wan-a probe-type icmp-ping",
		"set services rpm probe WAN test wan-a target address 1.1.1.1",
		"set services rpm probe WAN test wan-a destination-interface " + ifd + ".0",
		"set services rpm probe WAN test wan-a next-hop 172.16.50.1",
		"set interfaces " + ifd + " unit 0 family inet dhcp",
		"set services ip-monitoring policy p match rpm-probe WAN",
		"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop " + ifd + ".0",
	}
}

// compileIPMonNextHop6731 compiles a config naming ifd as the next-hop and
// returns the tunnel/loopback rejection message, or "" when it compiled.
func compileIPMonNextHop6731(t *testing.T, ifd string) string {
	t.Helper()
	tree := buildTree(t, ipmonNextHopLines(ifd))
	_, err := CompileConfig(tree)
	if err == nil {
		return ""
	}
	if !strings.Contains(err.Error(), "names a tunnel or loopback interface") {
		t.Fatalf("%s: compile failed for an unrelated reason, so this cell is not testing the "+
			"interface-class validator: %v", ifd, err)
	}
	return err.Error()
}

// TestIPMonNextHopAcceptsTunnelLookalikeNames6731 is the reported defect.
func TestIPMonNextHopAcceptsTunnelLookalikeNames6731(t *testing.T) {
	for _, tc := range []struct{ ifd, why string }{
		{"start0", "begins with `st` but is not a secure tunnel — XFRMIfNameAndID builds no xfrmi for it"},
		{"login0", "begins with `lo` but is not a loopback"},
		{"ftime0", "begins with `fti` but is not a flexible-tunnel interface"},
		{"st65536", "an `st` name OUTSIDE the if_id range, so it can never be an xfrmi"},
		{"gr-eenwich", "begins with `gr-` but is not a Junos GRE port path"},
		{"ip-sec0", "begins with `ip-` but is not a Junos IP-IP port path"},
	} {
		if msg := compileIPMonNextHop6731(t, tc.ifd); msg != "" {
			t.Errorf("%s must be usable as a DHCP-tracked next-hop — it %s. Got: %s",
				tc.ifd, tc.why, msg)
		}
	}
}

// TestIPMonNextHopStillRejectsRealTunnels6731 is the over-loosening guard, and
// it is the half that makes the test above mean anything. Neutralising
// IsTunnelOrLoopbackIfName (or reverting it to `return false`) reds here while
// every look-alike cell above stays green.
func TestIPMonNextHopStillRejectsRealTunnels6731(t *testing.T) {
	for _, tc := range []struct{ ifd, why string }{
		{"lo0", "loopback"},
		{"st0", "secure tunnel (in the if_id range)"},
		{"fti0", "flexible tunnel interface"},
		{"gr-0/0/0", "GRE, a Junos port path"},
		{"ip-0/0/0", "IP-IP, a Junos port path"},
	} {
		if msg := compileIPMonNextHop6731(t, tc.ifd); msg == "" {
			t.Errorf("%s is a %s and can never acquire a DHCP lease, so it must still be "+
				"refused as an ip-monitoring next-hop — accepting it manufactures a "+
				"permanently-unresolvable route", tc.ifd, tc.why)
		}
	}
}

// TestTunnelOrLoopbackIfNameBoundaries6731 pins the predicate directly, at the
// boundaries the compile-level cells cannot reach cheaply.
func TestTunnelOrLoopbackIfNameBoundaries6731(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		// Genuine members of each namespace.
		{"lo0", true}, {"lo1", true}, {"fti0", true}, {"fti12", true},
		{"st0", true}, {"st1", true}, {"st65535", true},
		{"gr-0/0/0", true}, {"ip-0/0/0", true},
		// The kernel spelling LinuxIfName produces.
		{"gr-0-0-0", true}, {"ip-0-0-0", true},
		// Look-alikes: the reported defect.
		{"login0", false}, {"lo", false}, {"loop", false},
		{"start0", false}, {"st", false}, {"stuff", false},
		{"ftime0", false}, {"fti", false},
		{"gr-eenwich", false}, {"ip-sec0", false}, {"gr-", false}, {"ip-", false},
		// st65536 is outside the XFRM if_id range, so no xfrmi is ever built
		// for it — the range rule is shared with XFRMIfNameAndID rather than
		// restated here.
		{"st65536", false},
		// Ordinary data interfaces.
		{"ge-0/0/0", false}, {"reth0", false}, {"", false},
	} {
		if got := IsTunnelOrLoopbackIfName(tc.name); got != tc.want {
			t.Errorf("IsTunnelOrLoopbackIfName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
