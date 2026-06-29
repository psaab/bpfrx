package config

import (
	"strings"
	"testing"
)

// Test_3362_PerInterfaceHostInboundParses asserts the per-zone-interface
// `host-inbound-traffic` override (#3362) parses (flat-set form) into
// ZoneConfig.InterfaceHostInbound and compiles cleanly alongside (or without) a
// zone-level stanza. Fail-on-revert: drop the `interfaces <if> host-inbound-traffic`
// schema/compiler wiring and either ParseSetCommand/SetPath rejects the path or
// InterfaceHostInbound stays nil — both fail this test.
func Test_3362_PerInterfaceHostInboundParses(t *testing.T) {
	tree := buildTree(t, []string{
		// zone-level: nothing on the zone, ssh only on the uplink interface.
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf",
		// a second interface in the same zone with NO override.
		"set security zones security-zone wan interfaces ge-0/0/1.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	zone := cfg.Security.Zones["wan"]
	if zone == nil {
		t.Fatal("wan zone missing")
	}
	if len(zone.Interfaces) != 2 {
		t.Errorf("wan interfaces = %v, want 2 entries", zone.Interfaces)
	}
	ovr := zone.InterfaceHostInbound["ge-0/0/0.0"]
	if ovr == nil {
		t.Fatal("interface override for ge-0/0/0.0 missing — per-interface host-inbound not parsed")
	}
	if len(ovr.SystemServices) != 1 || ovr.SystemServices[0] != "ssh" {
		t.Errorf("override system-services = %v, want [ssh]", ovr.SystemServices)
	}
	if len(ovr.Protocols) != 1 || ovr.Protocols[0] != "ospf" {
		t.Errorf("override protocols = %v, want [ospf]", ovr.Protocols)
	}
	if _, ok := zone.InterfaceHostInbound["ge-0/0/1.0"]; ok {
		t.Error("ge-0/0/1.0 has no host-inbound body — must not appear in InterfaceHostInbound")
	}
}

// Test_3362_PerInterfaceUnknownTokenFailsCommit asserts an unknown / typo'd
// token on an INTERFACE-level host-inbound stanza is hard-rejected at commit,
// exactly like the zone-level gate (#3200/#3362). Without the interface-level
// branch in validateHostInboundTokensStrict the typo would commit and the two
// enforcement surfaces (kernel nft vs Rust classifier) would disagree.
func Test_3362_PerInterfaceUnknownTokenFailsCommit(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string
	}{
		{
			name: "unknown interface system-service",
			cmds: []string{
				"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services sssh",
			},
			wantSub: `system-services "sssh"`,
		},
		{
			name: "unknown interface protocol",
			cmds: []string{
				"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic protocols ospff",
			},
			wantSub: `protocols "ospff"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("expected commit to reject an unknown interface-level host-inbound token")
			} else if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name the bad token (want %q)", err.Error(), tc.wantSub)
			} else if !strings.Contains(err.Error(), "interfaces") {
				t.Fatalf("error %q does not name the interface scope", err.Error())
			}
		})
	}
}

// Test_3362_PerInterfaceKnownTokenCommits is the anti-over-reject guard: a valid
// interface-level token (mixed with a zone-level stanza) must commit.
func Test_3362_PerInterfaceKnownTokenCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone wan host-inbound-traffic system-services ping",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone wan interfaces ge-0/0/0.0 host-inbound-traffic protocols all",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a legitimate interface-level host-inbound token: %v", err)
	}
}
