package config

import (
	"reflect"
	"testing"
)

// #5634 — the predefined `junos-sip` application shipped UDP-only
// ({Protocol:"udp", DestinationPort:"5060"}), so a policy referencing
// `match application junos-sip` matched only UDP/5060 and silently dropped
// TCP/5060 SIP. Real Junos junos-sip matches BOTH UDP/5060 AND TCP/5060 (SIP
// signals over both transports; TCP added in 12.3X48-D25 / 17.3R1). The fix
// models junos-sip as a PredefinedApplicationSet over two single-protocol
// members (junos-sip-udp = udp/5060, junos-sip-tcp = tcp/5060), mirroring the
// #4102 junos-ms-rpc / junos-sun-rpc TCP+UDP split.
//
// Fail-on-revert: restoring the UDP-only `"junos-sip"` application entry (and
// deleting the set) makes resolveUserspaceApplicationNames resolve junos-sip as
// an application FIRST — the TCP member never resolves and this test goes RED
// (ExpandApplicationSet no longer returns the tcp/5060 member).

// TestPredefinedSipSetResolves_5634 pins junos-sip as a UDP+TCP/5060 bundle and
// proves both members resolve as predefined applications with NO user config.
func TestPredefinedSipSetResolves_5634(t *testing.T) {
	empty := &ApplicationsConfig{}

	// junos-sip resolves as an application-SET, not a bare application. It MUST
	// NOT be a plain predefined application — an application hit would shadow the
	// set (app-first precedence) and re-drop TCP/5060.
	if _, ok := ResolveApplication("junos-sip", nil); ok {
		t.Fatalf("junos-sip still resolves as a predefined APPLICATION; it must be a set only (app-first precedence would re-drop TCP/5060)")
	}
	if _, ok := ResolveApplicationSet("junos-sip", nil); !ok {
		t.Fatalf("ResolveApplicationSet(junos-sip, nil) = false, want true (predefined set)")
	}

	got, err := ExpandApplicationSet("junos-sip", empty)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(junos-sip): %v", err)
	}
	want := []string{"junos-sip-udp", "junos-sip-tcp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandApplicationSet(junos-sip) = %v, want %v (UDP-first config order)", got, want)
	}

	// Both members must resolve as predefined applications with the exact
	// protocol/port. The tcp/5060 member is the #5634 parity fix; the udp/5060
	// member preserves the historical match.
	for _, tc := range []struct {
		name, proto, dport string
	}{
		{"junos-sip-udp", "udp", "5060"},
		{"junos-sip-tcp", "tcp", "5060"},
	} {
		app, ok := ResolveApplication(tc.name, nil)
		if !ok {
			t.Fatalf("member %q does not resolve as a predefined application", tc.name)
		}
		if app.Protocol != tc.proto || app.DestinationPort != tc.dport {
			t.Fatalf("member %q = proto %q dport %q, want proto %q dport %q",
				tc.name, app.Protocol, app.DestinationPort, tc.proto, tc.dport)
		}
	}
}

// TestPredefinedSipPolicyCommits_5634 proves a stock policy that references
// `match application junos-sip` commits cleanly under the STRICT path — the
// bundle must be recognized by the commit gate exactly like any predefined app.
func TestPredefinedSipPolicyCommits_5634(t *testing.T) {
	cmds := append(append([]string{}, zoneBoilerplate...),
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-sip",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	tree := buildAppMatchTree(t, cmds...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: predefined junos-sip should commit clean, got %v", err)
	}
}
