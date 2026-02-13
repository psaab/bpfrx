package config

import (
	"strings"
	"testing"
)

func TestLexer(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
    }
}`
	lex := NewLexer(input)
	expected := []struct {
		typ TokenType
		val string
	}{
		{TokenIdentifier, "security"},
		{TokenLBrace, "{"},
		{TokenIdentifier, "zones"},
		{TokenLBrace, "{"},
		{TokenIdentifier, "security-zone"},
		{TokenIdentifier, "trust"},
		{TokenLBrace, "{"},
		{TokenIdentifier, "interfaces"},
		{TokenLBrace, "{"},
		{TokenIdentifier, "eth0.0"},
		{TokenSemicolon, ";"},
		{TokenRBrace, "}"},
		{TokenRBrace, "}"},
		{TokenRBrace, "}"},
		{TokenRBrace, "}"},
		{TokenEOF, ""},
	}

	for i, exp := range expected {
		tok := lex.Next()
		if tok.Type != exp.typ {
			t.Errorf("token %d: expected type %s, got %s (value=%q)", i, exp.typ, tok.Type, tok.Value)
		}
		if exp.val != "" && tok.Value != exp.val {
			t.Errorf("token %d: expected value %q, got %q", i, exp.val, tok.Value)
		}
	}
}

func TestLexerComments(t *testing.T) {
	input := `# this is a comment
security {
    /* block comment */
    zones {
        // line comment
        security-zone trust;
    }
}`
	lex := NewLexer(input)
	tok := lex.Next()
	if tok.Type != TokenIdentifier || tok.Value != "security" {
		t.Errorf("expected 'security', got %s %q", tok.Type, tok.Value)
	}
}

func TestBracketList(t *testing.T) {
	input := `security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address [ server1 server2 server3 ];
                    application [ junos-http junos-https ];
                }
                then {
                    permit;
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Security.Policies) == 0 {
		t.Fatal("no policies compiled")
	}
	pol := cfg.Security.Policies[0]
	if len(pol.Policies) == 0 {
		t.Fatal("no policies compiled")
	}
	rule := pol.Policies[0]
	if len(rule.Match.DestinationAddresses) != 3 {
		t.Errorf("expected 3 dst addresses, got %d: %v", len(rule.Match.DestinationAddresses), rule.Match.DestinationAddresses)
	}
	if len(rule.Match.Applications) != 2 {
		t.Errorf("expected 2 applications, got %d: %v", len(rule.Match.Applications), rule.Match.Applications)
	}
}

func TestParseHierarchical(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                    log {
                        session-init;
                    }
                }
            }
        }
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	// Verify structure
	secNode := tree.FindChild("security")
	if secNode == nil {
		t.Fatal("missing 'security' node")
	}

	zonesNode := secNode.FindChild("zones")
	if zonesNode == nil {
		t.Fatal("missing 'zones' node")
	}

	trustZones := zonesNode.FindChildren("security-zone")
	if len(trustZones) != 2 {
		t.Fatalf("expected 2 security-zone nodes, got %d", len(trustZones))
	}

	if trustZones[0].Keys[1] != "trust" {
		t.Errorf("expected first zone 'trust', got %q", trustZones[0].Keys[1])
	}
	if trustZones[1].Keys[1] != "untrust" {
		t.Errorf("expected second zone 'untrust', got %q", trustZones[1].Keys[1])
	}

	// Verify interfaces
	ifacesNode := trustZones[0].FindChild("interfaces")
	if ifacesNode == nil || len(ifacesNode.Children) != 1 {
		t.Fatal("trust zone missing interfaces")
	}
	if ifacesNode.Children[0].Keys[0] != "eth0.0" {
		t.Errorf("expected interface 'eth0.0', got %q", ifacesNode.Children[0].Keys[0])
	}

	// Verify policy
	polNode := secNode.FindChild("policies")
	if polNode == nil {
		t.Fatal("missing 'policies' node")
	}

	zpNode := polNode.FindChild("from-zone")
	if zpNode == nil {
		t.Fatal("missing 'from-zone' node")
	}
	if zpNode.Keys[1] != "trust" || zpNode.Keys[3] != "untrust" {
		t.Errorf("expected from-zone trust to-zone untrust, got %v", zpNode.Keys)
	}
}

func TestCompileConfig(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                }
            }
        }
    }
    address-book {
        global {
            address web-server 10.0.1.100/32;
        }
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify zones
	if len(cfg.Security.Zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("missing trust zone")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}

	// Verify policies
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "allow-web" {
		t.Errorf("policy name: %s", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("policy action: %d", pol.Action)
	}
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "junos-http" {
		t.Errorf("policy applications: %v", pol.Match.Applications)
	}

	// Verify address book
	if cfg.Security.AddressBook == nil {
		t.Fatal("missing address book")
	}
	addr := cfg.Security.AddressBook.Addresses["web-server"]
	if addr == nil {
		t.Fatal("missing web-server address")
	}
	if addr.Value != "10.0.1.100/32" {
		t.Errorf("address value: %s", addr.Value)
	}
}

func TestSetCommand(t *testing.T) {
	path, err := ParseSetCommand("set security zones security-zone trust interfaces eth0.0")
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"security", "zones", "security-zone", "trust", "interfaces", "eth0.0"}
	if len(path) != len(expected) {
		t.Fatalf("expected %d parts, got %d: %v", len(expected), len(path), path)
	}
	for i := range expected {
		if path[i] != expected[i] {
			t.Errorf("part %d: expected %q, got %q", i, expected[i], path[i])
		}
	}
}

func TestFormatRoundTrip(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	output := tree.Format()
	// Normalize whitespace for comparison
	inputNorm := strings.TrimSpace(input)
	outputNorm := strings.TrimSpace(output)

	if inputNorm != outputNorm {
		t.Errorf("format round-trip mismatch:\n--- input ---\n%s\n--- output ---\n%s", inputNorm, outputNorm)
	}
}

func TestSetPathSchema(t *testing.T) {
	// Build a tree from set commands and verify it compiles correctly.
	tree := &ConfigTree{}

	setCommands := []string{
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust screen untrust-screen",
		"set security zones security-zone untrust interfaces eth1.0",
		"set security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match application junos-http",
		"set security policies from-zone trust to-zone untrust policy allow-web then permit",
		"set security policies from-zone trust to-zone untrust policy allow-web then log session-init",
		"set security policies from-zone trust to-zone untrust policy allow-web then count",
		"set security screen ids-option myscreen tcp land",
		"set security screen ids-option myscreen icmp ping-death",
		"set security address-book global address srv1 10.0.1.10/32",
		"set security address-book global address-set servers address srv1",
		"set interfaces eth0 unit 0 family inet address 10.0.1.1/24",
		"set applications application my-app protocol tcp",
		"set applications application my-app destination-port 8080",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	// Verify the tree formats correctly.
	output := tree.Format()
	t.Logf("Formatted tree:\n%s", output)

	// The tree should compile without errors.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}

	// Verify zones.
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("missing trust zone")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
	if trustZone.ScreenProfile != "untrust-screen" {
		t.Errorf("trust zone screen profile: %q", trustZone.ScreenProfile)
	}
	if trustZone.HostInboundTraffic == nil {
		t.Fatal("trust zone missing host-inbound-traffic")
	}
	if len(trustZone.HostInboundTraffic.SystemServices) != 2 {
		t.Errorf("expected 2 system-services, got %d", len(trustZone.HostInboundTraffic.SystemServices))
	}

	// Verify policies.
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	pol := zpp.Policies[0]
	if pol.Action != PolicyPermit {
		t.Errorf("policy action: %d", pol.Action)
	}
	if pol.Log == nil || !pol.Log.SessionInit {
		t.Error("policy should have log session-init")
	}
	if !pol.Count {
		t.Error("policy should have count")
	}

	// Verify screen.
	screen := cfg.Security.Screen["myscreen"]
	if screen == nil {
		t.Fatal("missing screen profile myscreen")
	}
	if !screen.TCP.Land {
		t.Error("screen should have tcp land")
	}
	if !screen.ICMP.PingDeath {
		t.Error("screen should have icmp ping-death")
	}

	// Verify address book.
	if cfg.Security.AddressBook == nil {
		t.Fatal("missing address book")
	}
	addr := cfg.Security.AddressBook.Addresses["srv1"]
	if addr == nil || addr.Value != "10.0.1.10/32" {
		t.Errorf("address srv1: %+v", addr)
	}
	addrSet := cfg.Security.AddressBook.AddressSets["servers"]
	if addrSet == nil || len(addrSet.Addresses) != 1 {
		t.Errorf("address-set servers: %+v", addrSet)
	}

	// Verify interfaces.
	ifc := cfg.Interfaces.Interfaces["eth0"]
	if ifc == nil {
		t.Fatal("missing interface eth0")
	}
	unit := ifc.Units[0]
	if unit == nil || len(unit.Addresses) != 1 || unit.Addresses[0] != "10.0.1.1/24" {
		t.Errorf("interface eth0 unit 0: %+v", unit)
	}

	// Verify applications.
	app := cfg.Applications.Applications["my-app"]
	if app == nil {
		t.Fatal("missing application my-app")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" {
		t.Errorf("application my-app: proto=%s port=%s", app.Protocol, app.DestinationPort)
	}

	// Verify round-trip: Format -> Parse -> Compile should produce same result.
	parser2 := NewParser(output)
	tree2, errs := parser2.Parse()
	if len(errs) > 0 {
		t.Fatalf("re-parse errors: %v", errs)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("re-compile failed: %v", err)
	}
	if len(cfg2.Security.Zones) != len(cfg.Security.Zones) {
		t.Error("round-trip zone count mismatch")
	}
}

func TestDeletePath(t *testing.T) {
	// Build a tree via set commands.
	tree := &ConfigTree{}
	setCommands := []string{
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone trust interfaces eth2.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone untrust interfaces eth1.0",
		"set security address-book global address srv1 10.0.1.10/32",
		"set security address-book global address srv2 10.0.2.10/32",
		"set security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match application junos-http",
		"set security policies from-zone trust to-zone untrust policy allow-web then permit",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	// Test 1: Delete a leaf (single interface from a zone).
	path, _ := ParseSetCommand("delete security zones security-zone trust interfaces eth2.0")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete interface leaf: %v", err)
	}
	// Verify eth2.0 is gone but eth0.0 remains.
	setOut := tree.FormatSet()
	if strings.Contains(setOut, "eth2.0") {
		t.Error("eth2.0 should have been deleted")
	}
	if !strings.Contains(setOut, "eth0.0") {
		t.Error("eth0.0 should still exist")
	}

	// Test 2: Delete address by name prefix (without CIDR value).
	path, _ = ParseSetCommand("delete security address-book global address srv1")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete address by prefix: %v", err)
	}
	setOut = tree.FormatSet()
	if strings.Contains(setOut, "srv1") {
		t.Error("srv1 should have been deleted")
	}
	if !strings.Contains(setOut, "srv2") {
		t.Error("srv2 should still exist")
	}

	// Test 3: Delete a container (entire zone).
	path, _ = ParseSetCommand("delete security zones security-zone untrust")
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("delete container: %v", err)
	}
	setOut = tree.FormatSet()
	if strings.Contains(setOut, "security-zone untrust") {
		t.Error("untrust zone should have been deleted")
	}
	if !strings.Contains(setOut, "security-zone trust") {
		t.Error("trust zone should still exist")
	}

	// Test 4: Delete nonexistent path returns error.
	path, _ = ParseSetCommand("delete security zones security-zone nonexistent")
	if err := tree.DeletePath(path); err == nil {
		t.Error("deleting nonexistent path should return error")
	}

	// Test 5: Remaining config compiles successfully.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after deletions: %v", err)
	}
	if len(cfg.Security.Zones) != 1 {
		t.Errorf("expected 1 zone after deletions, got %d", len(cfg.Security.Zones))
	}
	if cfg.Security.Zones["trust"] == nil {
		t.Error("trust zone should remain after deletions")
	}
	if len(cfg.Security.Zones["trust"].Interfaces) != 1 {
		t.Errorf("trust zone should have 1 interface, got %d",
			len(cfg.Security.Zones["trust"].Interfaces))
	}
}

func TestApplicationSet(t *testing.T) {
	// Test hierarchical syntax
	input := `applications {
    application my-app {
        protocol tcp;
        destination-port 8080;
    }
    application-set web-apps {
        application junos-http;
        application junos-https;
        application my-app;
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
        security-zone untrust {
            interfaces {
                eth1.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application web-apps;
                }
                then {
                    permit;
                }
            }
        }
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify application-set
	if len(cfg.Applications.ApplicationSets) != 1 {
		t.Fatalf("expected 1 application-set, got %d", len(cfg.Applications.ApplicationSets))
	}
	as := cfg.Applications.ApplicationSets["web-apps"]
	if as == nil {
		t.Fatal("missing application-set web-apps")
	}
	if len(as.Applications) != 3 {
		t.Errorf("expected 3 members, got %d: %v", len(as.Applications), as.Applications)
	}

	// Verify expansion
	expanded, err := ExpandApplicationSet("web-apps", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Errorf("expected 3 expanded apps, got %d: %v", len(expanded), expanded)
	}

	// Policy should reference web-apps
	pol := cfg.Security.Policies[0].Policies[0]
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "web-apps" {
		t.Errorf("policy apps: %v", pol.Match.Applications)
	}

	// Test set syntax round-trip
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set applications application-set web-apps application junos-http",
		"set applications application-set web-apps application junos-https",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile set syntax: %v", err)
	}
	as2 := cfg2.Applications.ApplicationSets["web-apps"]
	if as2 == nil {
		t.Fatal("missing application-set from set syntax")
	}
	if len(as2.Applications) != 2 {
		t.Errorf("expected 2 members from set syntax, got %d", len(as2.Applications))
	}
}

func TestRoutingConfigParsing(t *testing.T) {
	tree := &ConfigTree{}

	setCommands := []string{
		// Static routes
		"set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1",
		"set routing-options static route 10.10.0.0/16 next-hop 10.0.0.2",
		"set routing-options static route 192.168.99.0/24 discard",
		"set routing-options static route 172.16.0.0/12 next-hop 10.0.0.3",
		"set routing-options static route 172.16.0.0/12 preference 100",
		// OSPF
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface eth1",
		"set protocols ospf area 0.0.0.0 interface gre0",
		"set protocols ospf area 0.0.0.0 interface eth2 passive",
		// BGP
		"set protocols bgp local-as 65001",
		"set protocols bgp router-id 10.0.0.1",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp neighbor 10.1.0.1",
		// GRE tunnel interface
		"set interfaces gre0 tunnel source 10.0.0.1",
		"set interfaces gre0 tunnel destination 10.1.0.1",
		"set interfaces gre0 unit 0 family inet address 172.16.0.1/30",
		// IPsec
		"set security ipsec proposal aes256 protocol esp",
		"set security ipsec proposal aes256 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal aes256 authentication-algorithm hmac-sha-256",
		"set security ipsec proposal aes256 dh-group 14",
		"set security ipsec proposal aes256 lifetime-seconds 3600",
		"set security ipsec vpn site-a gateway 10.1.0.1",
		"set security ipsec vpn site-a local-address 10.0.0.1",
		"set security ipsec vpn site-a ipsec-policy aes256",
		"set security ipsec vpn site-a local-identity 10.0.0.0/24",
		"set security ipsec vpn site-a remote-identity 10.1.0.0/24",
		`set security ipsec vpn site-a pre-shared-key "secret123"`,
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	// Format and log for debugging
	output := tree.Format()
	t.Logf("Formatted tree:\n%s", output)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}

	// --- Static Routes ---
	if len(cfg.RoutingOptions.StaticRoutes) != 4 {
		t.Fatalf("expected 4 static routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
	}

	// Default route
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "0.0.0.0/0" || len(r0.NextHops) != 1 || r0.NextHops[0].Address != "192.168.1.1" {
		t.Errorf("route 0: dest=%s nhs=%v", r0.Destination, r0.NextHops)
	}
	if r0.Preference != 5 {
		t.Errorf("route 0: expected default preference 5, got %d", r0.Preference)
	}

	// Discard route
	r2 := cfg.RoutingOptions.StaticRoutes[2]
	if r2.Destination != "192.168.99.0/24" || !r2.Discard {
		t.Errorf("route 2: dest=%s discard=%v", r2.Destination, r2.Discard)
	}

	// Route with custom preference (merged from separate set lines)
	r3 := cfg.RoutingOptions.StaticRoutes[3]
	if r3.Destination != "172.16.0.0/12" || len(r3.NextHops) != 1 || r3.NextHops[0].Address != "10.0.0.3" {
		t.Errorf("route 3: dest=%s nhs=%v", r3.Destination, r3.NextHops)
	}
	if r3.Preference != 100 {
		t.Errorf("route 3: expected preference 100, got %d", r3.Preference)
	}

	// --- OSPF ---
	if cfg.Protocols.OSPF == nil {
		t.Fatal("OSPF config is nil")
	}
	if cfg.Protocols.OSPF.RouterID != "10.0.0.1" {
		t.Errorf("OSPF router-id: %s", cfg.Protocols.OSPF.RouterID)
	}
	if len(cfg.Protocols.OSPF.Areas) != 1 {
		t.Fatalf("expected 1 OSPF area, got %d", len(cfg.Protocols.OSPF.Areas))
	}
	area := cfg.Protocols.OSPF.Areas[0]
	if area.ID != "0.0.0.0" {
		t.Errorf("OSPF area ID: %s", area.ID)
	}
	if len(area.Interfaces) != 3 {
		t.Fatalf("expected 3 OSPF interfaces, got %d", len(area.Interfaces))
	}
	if area.Interfaces[0].Name != "eth1" || area.Interfaces[0].Passive {
		t.Errorf("OSPF iface 0: name=%s passive=%v", area.Interfaces[0].Name, area.Interfaces[0].Passive)
	}
	if area.Interfaces[2].Name != "eth2" || !area.Interfaces[2].Passive {
		t.Errorf("OSPF iface 2: name=%s passive=%v", area.Interfaces[2].Name, area.Interfaces[2].Passive)
	}

	// --- BGP ---
	if cfg.Protocols.BGP == nil {
		t.Fatal("BGP config is nil")
	}
	if cfg.Protocols.BGP.LocalAS != 65001 {
		t.Errorf("BGP local-as: %d", cfg.Protocols.BGP.LocalAS)
	}
	if cfg.Protocols.BGP.RouterID != "10.0.0.1" {
		t.Errorf("BGP router-id: %s", cfg.Protocols.BGP.RouterID)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected 1 BGP neighbor, got %d", len(cfg.Protocols.BGP.Neighbors))
	}
	nbr := cfg.Protocols.BGP.Neighbors[0]
	if nbr.Address != "10.1.0.1" || nbr.PeerAS != 65002 {
		t.Errorf("BGP neighbor: addr=%s peer-as=%d", nbr.Address, nbr.PeerAS)
	}

	// --- GRE Tunnel ---
	ifc := cfg.Interfaces.Interfaces["gre0"]
	if ifc == nil {
		t.Fatal("missing interface gre0")
	}
	if ifc.Tunnel == nil {
		t.Fatal("gre0 missing tunnel config")
	}
	if ifc.Tunnel.Source != "10.0.0.1" || ifc.Tunnel.Destination != "10.1.0.1" {
		t.Errorf("tunnel: src=%s dst=%s", ifc.Tunnel.Source, ifc.Tunnel.Destination)
	}
	if len(ifc.Tunnel.Addresses) != 1 || ifc.Tunnel.Addresses[0] != "172.16.0.1/30" {
		t.Errorf("tunnel addresses: %v", ifc.Tunnel.Addresses)
	}

	// --- IPsec ---
	prop := cfg.Security.IPsec.Proposals["aes256"]
	if prop == nil {
		t.Fatal("missing IPsec proposal aes256")
	}
	if prop.Protocol != "esp" {
		t.Errorf("proposal protocol: %s", prop.Protocol)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("proposal encryption: %s", prop.EncryptionAlg)
	}
	if prop.AuthAlg != "hmac-sha-256" {
		t.Errorf("proposal auth: %s", prop.AuthAlg)
	}
	if prop.DHGroup != 14 {
		t.Errorf("proposal dh-group: %d", prop.DHGroup)
	}
	if prop.LifetimeSeconds != 3600 {
		t.Errorf("proposal lifetime: %d", prop.LifetimeSeconds)
	}

	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing IPsec VPN site-a")
	}
	if vpn.Gateway != "10.1.0.1" {
		t.Errorf("vpn gateway: %s", vpn.Gateway)
	}
	if vpn.LocalAddr != "10.0.0.1" {
		t.Errorf("vpn local-address: %s", vpn.LocalAddr)
	}
	if vpn.IPsecPolicy != "aes256" {
		t.Errorf("vpn ipsec-policy: %s", vpn.IPsecPolicy)
	}
	if vpn.LocalID != "10.0.0.0/24" {
		t.Errorf("vpn local-identity: %s", vpn.LocalID)
	}
	if vpn.RemoteID != "10.1.0.0/24" {
		t.Errorf("vpn remote-identity: %s", vpn.RemoteID)
	}
	if vpn.PSK != "secret123" {
		t.Errorf("vpn psk: %s", vpn.PSK)
	}

	// --- Round-trip test ---
	parser2 := NewParser(output)
	tree2, errs := parser2.Parse()
	if len(errs) > 0 {
		t.Fatalf("re-parse errors: %v", errs)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("re-compile failed: %v", err)
	}
	if len(cfg2.RoutingOptions.StaticRoutes) != len(cfg.RoutingOptions.StaticRoutes) {
		t.Error("round-trip static route count mismatch")
	}
	if cfg2.Protocols.OSPF == nil || cfg2.Protocols.OSPF.RouterID != cfg.Protocols.OSPF.RouterID {
		t.Error("round-trip OSPF mismatch")
	}
	if cfg2.Protocols.BGP == nil || cfg2.Protocols.BGP.LocalAS != cfg.Protocols.BGP.LocalAS {
		t.Error("round-trip BGP mismatch")
	}
}

func TestECMPStaticRoutes(t *testing.T) {
	// Test flat set syntax with multiple next-hops for same destination
	tree := &ConfigTree{}
	setCommands := []string{
		"set routing-options static route 10.0.0.0/8 next-hop 10.0.1.1",
		"set routing-options static route 10.0.0.0/8 next-hop 10.0.2.1",
		"set routing-options static route 192.168.0.0/16 next-hop 10.0.1.1",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.RoutingOptions.StaticRoutes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
	}

	// ECMP route should have 2 next-hops
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "10.0.0.0/8" {
		t.Errorf("route 0 dest: %s", r0.Destination)
	}
	if len(r0.NextHops) != 2 {
		t.Fatalf("route 0: expected 2 next-hops, got %d", len(r0.NextHops))
	}
	if r0.NextHops[0].Address != "10.0.1.1" || r0.NextHops[1].Address != "10.0.2.1" {
		t.Errorf("route 0 next-hops: %v", r0.NextHops)
	}

	// Single next-hop route
	r1 := cfg.RoutingOptions.StaticRoutes[1]
	if r1.Destination != "192.168.0.0/16" || len(r1.NextHops) != 1 {
		t.Errorf("route 1: dest=%s nhs=%v", r1.Destination, r1.NextHops)
	}

	// Test hierarchical syntax with multiple next-hops
	hierInput := `routing-options {
    static {
        route 10.0.0.0/8 {
            next-hop 10.0.1.1;
            next-hop 10.0.2.1;
            next-hop 10.0.3.1;
        }
    }
}`
	parser := NewParser(hierInput)
	hierTree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(hierCfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
	}
	hr := hierCfg.RoutingOptions.StaticRoutes[0]
	if len(hr.NextHops) != 3 {
		t.Fatalf("expected 3 next-hops, got %d", len(hr.NextHops))
	}
	if hr.NextHops[0].Address != "10.0.1.1" || hr.NextHops[1].Address != "10.0.2.1" || hr.NextHops[2].Address != "10.0.3.1" {
		t.Errorf("hierarchical next-hops: %v", hr.NextHops)
	}
}

func TestSyslogSeverityParsing(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set security log stream security-events host 192.0.2.1",
		"set security log stream security-events severity warning",
		"set security log stream all-events host 192.0.2.2",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Security.Log.Streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(cfg.Security.Log.Streams))
	}

	secEvts := cfg.Security.Log.Streams["security-events"]
	if secEvts == nil {
		t.Fatal("missing security-events stream")
	}
	if secEvts.Host != "192.0.2.1" {
		t.Errorf("security-events host: %s", secEvts.Host)
	}
	if secEvts.Severity != "warning" {
		t.Errorf("security-events severity: %s", secEvts.Severity)
	}

	allEvts := cfg.Security.Log.Streams["all-events"]
	if allEvts == nil {
		t.Fatal("missing all-events stream")
	}
	if allEvts.Severity != "" {
		t.Errorf("all-events severity should be empty, got %q", allEvts.Severity)
	}
}

func TestSyslogFacilityParsing(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set security log stream auth-events host 10.0.0.1",
		"set security log stream auth-events severity error",
		"set security log stream auth-events facility local3",
		"set security log stream default-events host 10.0.0.2",
	}
	for _, cmd := range setCommands {
		fields := strings.Fields(cmd)
		if err := tree.SetPath(fields[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Security.Log.Streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(cfg.Security.Log.Streams))
	}

	authEvts := cfg.Security.Log.Streams["auth-events"]
	if authEvts == nil {
		t.Fatal("missing auth-events stream")
	}
	if authEvts.Facility != "local3" {
		t.Errorf("auth-events facility: got %q, want %q", authEvts.Facility, "local3")
	}
	if authEvts.Severity != "error" {
		t.Errorf("auth-events severity: got %q, want %q", authEvts.Severity, "error")
	}

	defEvts := cfg.Security.Log.Streams["default-events"]
	if defEvts == nil {
		t.Fatal("missing default-events stream")
	}
	if defEvts.Facility != "" {
		t.Errorf("default-events facility should be empty, got %q", defEvts.Facility)
	}
}

func TestNestedAddressSets(t *testing.T) {
	// Test hierarchical syntax with nested address-sets
	input := `security {
    address-book {
        global {
            address srv1 10.0.1.10/32;
            address srv2 10.0.1.20/32;
            address srv3 10.0.2.10/32;
            address-set servers {
                address srv1;
                address srv2;
            }
            address-set all-servers {
                address srv3;
                address-set servers;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	ab := cfg.Security.AddressBook
	if ab == nil {
		t.Fatal("missing address book")
	}

	// Verify individual addresses
	if len(ab.Addresses) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(ab.Addresses))
	}

	// Verify "servers" set has 2 direct address members
	servers := ab.AddressSets["servers"]
	if servers == nil {
		t.Fatal("missing address-set servers")
	}
	if len(servers.Addresses) != 2 {
		t.Errorf("servers: expected 2 address members, got %d", len(servers.Addresses))
	}
	if len(servers.AddressSets) != 0 {
		t.Errorf("servers: expected 0 address-set members, got %d", len(servers.AddressSets))
	}

	// Verify "all-servers" set has 1 address + 1 nested set
	allServers := ab.AddressSets["all-servers"]
	if allServers == nil {
		t.Fatal("missing address-set all-servers")
	}
	if len(allServers.Addresses) != 1 {
		t.Errorf("all-servers: expected 1 address member, got %d", len(allServers.Addresses))
	}
	if len(allServers.AddressSets) != 1 {
		t.Errorf("all-servers: expected 1 address-set member, got %d", len(allServers.AddressSets))
	}
	if len(allServers.AddressSets) > 0 && allServers.AddressSets[0] != "servers" {
		t.Errorf("all-servers nested set: expected 'servers', got %q", allServers.AddressSets[0])
	}

	// Verify recursive expansion
	expanded, err := ExpandAddressSet("all-servers", ab)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Errorf("expected 3 expanded addresses, got %d: %v", len(expanded), expanded)
	}
	// Should contain srv3 (direct), srv1, srv2 (from nested "servers")
	expandedMap := make(map[string]bool)
	for _, a := range expanded {
		expandedMap[a] = true
	}
	for _, expected := range []string{"srv1", "srv2", "srv3"} {
		if !expandedMap[expected] {
			t.Errorf("expanded set missing %q", expected)
		}
	}

	// Test set-command syntax for nested address-sets
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set security address-book global address srv1 10.0.1.10/32",
		"set security address-book global address srv2 10.0.1.20/32",
		"set security address-book global address srv3 10.0.2.10/32",
		"set security address-book global address-set servers address srv1",
		"set security address-book global address-set servers address srv2",
		"set security address-book global address-set all-servers address srv3",
		"set security address-book global address-set all-servers address-set servers",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile set syntax: %v", err)
	}

	allServers2 := cfg2.Security.AddressBook.AddressSets["all-servers"]
	if allServers2 == nil {
		t.Fatal("missing all-servers from set syntax")
	}
	if len(allServers2.Addresses) != 1 || len(allServers2.AddressSets) != 1 {
		t.Errorf("all-servers from set syntax: addresses=%d sets=%d",
			len(allServers2.Addresses), len(allServers2.AddressSets))
	}

	expanded2, err := ExpandAddressSet("all-servers", cfg2.Security.AddressBook)
	if err != nil {
		t.Fatalf("expand set syntax error: %v", err)
	}
	if len(expanded2) != 3 {
		t.Errorf("expected 3 expanded from set syntax, got %d: %v", len(expanded2), expanded2)
	}
}

func TestNestedAddressSetCycleDetection(t *testing.T) {
	ab := &AddressBook{
		Addresses: map[string]*Address{
			"a1": {Name: "a1", Value: "10.0.0.1/32"},
		},
		AddressSets: map[string]*AddressSet{
			"set-a": {Name: "set-a", Addresses: []string{"a1"}, AddressSets: []string{"set-b"}},
			"set-b": {Name: "set-b", AddressSets: []string{"set-a"}},
		},
	}

	_, err := ExpandAddressSet("set-a", ab)
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected cycle error, got: %v", err)
	}
}

func TestRoutingInstances(t *testing.T) {
	// Test set-command syntax for routing instances
	tree := &ConfigTree{}
	setCommands := []string{
		"set routing-instances Comcast-GigabitPro instance-type virtual-router",
		"set routing-instances Comcast-GigabitPro interface enp7s0.100",
		"set routing-instances Comcast-GigabitPro interface enp7s0.200",
		"set routing-instances Comcast-GigabitPro routing-options static route 0.0.0.0/0 next-hop 74.93.96.1",
		"set routing-instances Comcast-GigabitPro routing-options static route 0.0.0.0/0 preference 10",
		"set routing-instances ATT instance-type virtual-router",
		"set routing-instances ATT interface enp8s0",
		"set routing-instances ATT routing-options static route 0.0.0.0/0 next-hop 192.168.1.254",
		"set routing-instances ATT protocols bgp local-as 65001",
		"set routing-instances ATT protocols bgp group upstream peer-as 7018",
		"set routing-instances ATT protocols bgp group upstream neighbor 192.168.1.254",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	output := tree.Format()
	t.Logf("Formatted tree:\n%s", output)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}

	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}

	// Find the two instances (order not guaranteed)
	var comcast, att *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		switch ri.Name {
		case "Comcast-GigabitPro":
			comcast = ri
		case "ATT":
			att = ri
		}
	}

	if comcast == nil {
		t.Fatal("missing routing instance Comcast-GigabitPro")
	}
	if comcast.InstanceType != "virtual-router" {
		t.Errorf("Comcast instance-type: %s", comcast.InstanceType)
	}
	if len(comcast.Interfaces) != 2 {
		t.Errorf("Comcast interfaces: expected 2, got %d", len(comcast.Interfaces))
	}
	if len(comcast.StaticRoutes) != 1 {
		t.Fatalf("Comcast static routes: expected 1, got %d", len(comcast.StaticRoutes))
	}
	if len(comcast.StaticRoutes[0].NextHops) != 1 || comcast.StaticRoutes[0].NextHops[0].Address != "74.93.96.1" {
		t.Errorf("Comcast route next-hops: %v", comcast.StaticRoutes[0].NextHops)
	}
	if comcast.StaticRoutes[0].Preference != 10 {
		t.Errorf("Comcast route preference: %d", comcast.StaticRoutes[0].Preference)
	}
	if comcast.TableID < 100 {
		t.Errorf("Comcast table ID should be >= 100, got %d", comcast.TableID)
	}

	if att == nil {
		t.Fatal("missing routing instance ATT")
	}
	if len(att.Interfaces) != 1 || att.Interfaces[0] != "enp8s0" {
		t.Errorf("ATT interfaces: %v", att.Interfaces)
	}
	if len(att.StaticRoutes) != 1 {
		t.Fatalf("ATT static routes: expected 1, got %d", len(att.StaticRoutes))
	}
	if att.BGP == nil {
		t.Fatal("ATT BGP config is nil")
	}
	if att.BGP.LocalAS != 65001 {
		t.Errorf("ATT BGP local-as: %d", att.BGP.LocalAS)
	}
	if len(att.BGP.Neighbors) != 1 {
		t.Fatalf("ATT BGP neighbors: expected 1, got %d", len(att.BGP.Neighbors))
	}
	if att.BGP.Neighbors[0].Address != "192.168.1.254" || att.BGP.Neighbors[0].PeerAS != 7018 {
		t.Errorf("ATT BGP neighbor: addr=%s as=%d",
			att.BGP.Neighbors[0].Address, att.BGP.Neighbors[0].PeerAS)
	}

	// Test hierarchical syntax
	hierInput := `routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
        interface enp7s0.100;
        routing-options {
            static {
                route 0.0.0.0/0 {
                    next-hop 74.93.96.1;
                }
            }
        }
    }
}`
	parser := NewParser(hierInput)
	hierTree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("hierarchical parse errors: %v", errs)
	}
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("hierarchical compile error: %v", err)
	}
	if len(hierCfg.RoutingInstances) != 1 {
		t.Fatalf("hierarchical: expected 1 instance, got %d", len(hierCfg.RoutingInstances))
	}
	if hierCfg.RoutingInstances[0].Name != "Comcast-GigabitPro" {
		t.Errorf("hierarchical instance name: %s", hierCfg.RoutingInstances[0].Name)
	}
}

func TestRouterAdvertisement(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set protocols router-advertisement interface vlan100 managed-configuration",
		"set protocols router-advertisement interface vlan100 other-stateful-configuration",
		"set protocols router-advertisement interface vlan100 default-lifetime 1800",
		"set protocols router-advertisement interface vlan100 max-advertisement-interval 600",
		"set protocols router-advertisement interface vlan100 link-mtu 1500",
		"set protocols router-advertisement interface vlan100 prefix 2001:db8:1::/64 on-link",
		"set protocols router-advertisement interface vlan100 prefix 2001:db8:1::/64 autonomous",
		"set protocols router-advertisement interface vlan100 dns-server-address 2001:db8::53",
		"set protocols router-advertisement interface vlan100 dns-server-address 2001:db8::54",
		"set protocols router-advertisement interface vlan100 nat64prefix 64:ff9b::/96",
		"set protocols router-advertisement interface vlan200 prefix 2001:db8:2::/64",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}

	if len(cfg.Protocols.RouterAdvertisement) != 2 {
		t.Fatalf("expected 2 RA interfaces, got %d", len(cfg.Protocols.RouterAdvertisement))
	}

	// Find vlan100 config
	var ra100 *RAInterfaceConfig
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra.Interface == "vlan100" {
			ra100 = ra
		}
	}
	if ra100 == nil {
		t.Fatal("missing RA config for vlan100")
	}
	if !ra100.ManagedConfig {
		t.Error("vlan100: managed-configuration should be true")
	}
	if !ra100.OtherStateful {
		t.Error("vlan100: other-stateful should be true")
	}
	if ra100.DefaultLifetime != 1800 {
		t.Errorf("vlan100: default-lifetime = %d", ra100.DefaultLifetime)
	}
	if ra100.LinkMTU != 1500 {
		t.Errorf("vlan100: link-mtu = %d", ra100.LinkMTU)
	}
	if len(ra100.Prefixes) != 1 || ra100.Prefixes[0].Prefix != "2001:db8:1::/64" {
		t.Errorf("vlan100: prefixes = %+v", ra100.Prefixes)
	}
	if !ra100.Prefixes[0].OnLink || !ra100.Prefixes[0].Autonomous {
		t.Error("vlan100: prefix flags should default to on-link+autonomous")
	}
	if len(ra100.DNSServers) != 2 {
		t.Errorf("vlan100: dns-servers = %v", ra100.DNSServers)
	}
	if ra100.NAT64Prefix != "64:ff9b::/96" {
		t.Errorf("vlan100: nat64prefix = %s", ra100.NAT64Prefix)
	}
}

func TestNAT64(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		// Define a source NAT pool for NAT64 translated packets
		"set security nat source pool nat64-pool address 203.0.113.0/24",
		// Define NAT64 rule-set
		"set security nat nat64 rule-set v6-to-v4 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set v6-to-v4 source-pool nat64-pool",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}

	// Verify NAT64 rule-set
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("expected 1 NAT64 rule-set, got %d", len(cfg.Security.NAT.NAT64))
	}

	rs := cfg.Security.NAT.NAT64[0]
	if rs.Name != "v6-to-v4" {
		t.Errorf("rule-set name = %q, want %q", rs.Name, "v6-to-v4")
	}
	if rs.Prefix != "64:ff9b::/96" {
		t.Errorf("prefix = %q, want %q", rs.Prefix, "64:ff9b::/96")
	}
	if rs.SourcePool != "nat64-pool" {
		t.Errorf("source-pool = %q, want %q", rs.SourcePool, "nat64-pool")
	}

	// Also test hierarchical syntax
	hierInput := `security {
    nat {
        nat64 {
            rule-set wkp {
                prefix 64:ff9b::/96;
                source-pool pool1;
            }
        }
    }
}`
	parser := NewParser(hierInput)
	tree2, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse hierarchical: %v", errs)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig hierarchical: %v", err)
	}
	if len(cfg2.Security.NAT.NAT64) != 1 {
		t.Fatalf("hierarchical: expected 1 NAT64 rule-set, got %d", len(cfg2.Security.NAT.NAT64))
	}
	rs2 := cfg2.Security.NAT.NAT64[0]
	if rs2.Name != "wkp" || rs2.Prefix != "64:ff9b::/96" || rs2.SourcePool != "pool1" {
		t.Errorf("hierarchical: got %+v", rs2)
	}
}

func TestFormatSet(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces {
                eth0.0;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, _ := parser.Parse()
	setOutput := tree.FormatSet()

	if !strings.Contains(setOutput, "set security zones security-zone trust interfaces eth0.0") {
		t.Errorf("set format missing expected line:\n%s", setOutput)
	}
}

func TestFirewallFilter(t *testing.T) {
	// Test hierarchical syntax
	input := `firewall {
    family inet {
        filter inet-source-dscp {
            term dscp-to-gigabitpro {
                from {
                    dscp ef;
                }
                then {
                    routing-instance Comcast-GigabitPro;
                }
            }
            term ip-to-atherton-fiber {
                from {
                    source-address {
                        172.16.80.198/32;
                        176.124.71.0/24;
                    }
                }
                then {
                    routing-instance Atherton-Fiber;
                }
            }
            term default {
                then accept;
            }
        }
        filter filter-management {
            term block_unauthorised {
                from {
                    source-address {
                        0.0.0.0/0;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then {
                    log;
                    syslog;
                    reject;
                }
            }
            term accept_default {
                then accept;
            }
        }
    }
    family inet6 {
        filter block-ra-adv {
            term t1 {
                from {
                    icmp-type 134;
                    icmp-code 0;
                }
                then discard;
            }
            term t2 {
                then accept;
            }
        }
    }
}
routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
    }
    Atherton-Fiber {
        instance-type virtual-router;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Check inet filters
	if cfg.Firewall.FiltersInet == nil {
		t.Fatal("expected FiltersInet to be non-nil")
	}
	dscpFilter, ok := cfg.Firewall.FiltersInet["inet-source-dscp"]
	if !ok {
		t.Fatal("expected inet-source-dscp filter")
	}
	if len(dscpFilter.Terms) != 3 {
		t.Errorf("expected 3 terms, got %d", len(dscpFilter.Terms))
	}
	if dscpFilter.Terms[0].DSCP != "ef" {
		t.Errorf("expected dscp ef, got %q", dscpFilter.Terms[0].DSCP)
	}
	if dscpFilter.Terms[0].RoutingInstance != "Comcast-GigabitPro" {
		t.Errorf("expected routing-instance Comcast-GigabitPro, got %q",
			dscpFilter.Terms[0].RoutingInstance)
	}
	if len(dscpFilter.Terms[1].SourceAddresses) != 2 {
		t.Errorf("expected 2 source addresses, got %d",
			len(dscpFilter.Terms[1].SourceAddresses))
	}

	mgmtFilter, ok := cfg.Firewall.FiltersInet["filter-management"]
	if !ok {
		t.Fatal("expected filter-management filter")
	}
	if len(mgmtFilter.Terms) != 2 {
		t.Errorf("expected 2 terms, got %d", len(mgmtFilter.Terms))
	}
	if mgmtFilter.Terms[0].Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %q", mgmtFilter.Terms[0].Protocol)
	}
	if mgmtFilter.Terms[0].Action != "reject" {
		t.Errorf("expected action reject, got %q", mgmtFilter.Terms[0].Action)
	}
	if len(mgmtFilter.Terms[0].DestinationPorts) != 1 {
		t.Errorf("expected 1 destination port, got %d",
			len(mgmtFilter.Terms[0].DestinationPorts))
	}

	// Check inet6 filters
	if cfg.Firewall.FiltersInet6 == nil {
		t.Fatal("expected FiltersInet6 to be non-nil")
	}
	raFilter, ok := cfg.Firewall.FiltersInet6["block-ra-adv"]
	if !ok {
		t.Fatal("expected block-ra-adv filter")
	}
	if len(raFilter.Terms) != 2 {
		t.Errorf("expected 2 terms, got %d", len(raFilter.Terms))
	}
	if raFilter.Terms[0].ICMPType != 134 {
		t.Errorf("expected icmp-type 134, got %d", raFilter.Terms[0].ICMPType)
	}
	if raFilter.Terms[0].Action != "discard" {
		t.Errorf("expected action discard, got %q", raFilter.Terms[0].Action)
	}

	// Check routing instances were compiled
	if len(cfg.RoutingInstances) != 2 {
		t.Errorf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}

	// Test set-command format
	setCommands := []string{
		"set firewall family inet filter test-filter term t1 from dscp af43",
		"set firewall family inet filter test-filter term t1 then routing-instance ATT",
		"set firewall family inet filter test-filter term default then accept",
	}
	tree2 := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	tf, ok := cfg2.Firewall.FiltersInet["test-filter"]
	if !ok {
		t.Fatal("expected test-filter from set commands")
	}
	if len(tf.Terms) != 2 {
		t.Errorf("expected 2 terms from set commands, got %d", len(tf.Terms))
	}
	if tf.Terms[0].DSCP != "af43" {
		t.Errorf("expected dscp af43, got %q", tf.Terms[0].DSCP)
	}
}

func TestFirewallPrefixList(t *testing.T) {
	input := `policy-options {
    prefix-list management-hosts {
        10.0.0.0/8;
        172.16.0.0/12;
    }
}
firewall {
    family inet {
        filter filter-mgmt {
            term block_unauthorised {
                from {
                    source-address {
                        0.0.0.0/0;
                    }
                    source-prefix-list {
                        management-hosts except;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then {
                    log;
                    syslog;
                    count block-counter;
                    reject;
                }
            }
            term accept_default {
                then accept;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Check prefix-list was compiled
	pl := cfg.PolicyOptions.PrefixLists["management-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list management-hosts")
	}
	if len(pl.Prefixes) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}

	// Check firewall filter
	f := cfg.Firewall.FiltersInet["filter-mgmt"]
	if f == nil {
		t.Fatal("missing filter filter-mgmt")
	}
	term := f.Terms[0]
	if len(term.SourcePrefixLists) != 1 {
		t.Fatalf("expected 1 source-prefix-list, got %d", len(term.SourcePrefixLists))
	}
	if term.SourcePrefixLists[0].Name != "management-hosts" {
		t.Errorf("prefix-list name = %q", term.SourcePrefixLists[0].Name)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("prefix-list should have except modifier")
	}
	if len(term.DestinationPorts) != 1 {
		t.Errorf("expected 1 destination port, got %d", len(term.DestinationPorts))
	}
	if term.Count != "block-counter" {
		t.Errorf("count = %q, want block-counter", term.Count)
	}
	if !term.Log {
		t.Error("log should be set")
	}
}

func TestFlowMonitoringConfig(t *testing.T) {
	// Test hierarchical syntax
	input := `services {
    flow-monitoring {
        version9 {
            template v9-tmpl {
                flow-active-timeout 60;
                flow-inactive-timeout 15;
                template-refresh-rate {
                    seconds 30;
                }
            }
        }
    }
}
forwarding-options {
    sampling {
        instance sample-1 {
            input {
                rate 1;
            }
            family inet {
                output {
                    flow-server 192.168.99.104 {
                        port 4739;
                        version9-template v9-tmpl;
                        source-address 192.168.99.1;
                    }
                    inline-jflow;
                }
            }
            family inet6 {
                output {
                    flow-server 192.168.99.104 {
                        port 4739;
                        version9-template v9-tmpl;
                    }
                    inline-jflow;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify services/flow-monitoring
	if cfg.Services.FlowMonitoring == nil {
		t.Fatal("expected FlowMonitoring to be non-nil")
	}
	v9 := cfg.Services.FlowMonitoring.Version9
	if v9 == nil {
		t.Fatal("expected Version9 to be non-nil")
	}
	if len(v9.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(v9.Templates))
	}
	tmpl := v9.Templates["v9-tmpl"]
	if tmpl == nil {
		t.Fatal("expected template v9-tmpl")
	}
	if tmpl.FlowActiveTimeout != 60 {
		t.Errorf("active timeout: got %d, want 60", tmpl.FlowActiveTimeout)
	}
	if tmpl.FlowInactiveTimeout != 15 {
		t.Errorf("inactive timeout: got %d, want 15", tmpl.FlowInactiveTimeout)
	}
	if tmpl.TemplateRefreshRate != 30 {
		t.Errorf("refresh rate: got %d, want 30", tmpl.TemplateRefreshRate)
	}

	// Verify forwarding-options/sampling
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("expected Sampling to be non-nil")
	}
	if len(cfg.ForwardingOptions.Sampling.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cfg.ForwardingOptions.Sampling.Instances))
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["sample-1"]
	if inst == nil {
		t.Fatal("expected instance sample-1")
	}
	if inst.InputRate != 1 {
		t.Errorf("input rate: got %d, want 1", inst.InputRate)
	}

	// Family inet
	if inst.FamilyInet == nil {
		t.Fatal("expected FamilyInet")
	}
	if !inst.FamilyInet.InlineJflow {
		t.Error("expected inline-jflow for inet")
	}
	if inst.FamilyInet.SourceAddress != "192.168.99.1" {
		t.Errorf("source-address: got %q, want 192.168.99.1", inst.FamilyInet.SourceAddress)
	}
	if len(inst.FamilyInet.FlowServers) != 1 {
		t.Fatalf("expected 1 flow server for inet, got %d", len(inst.FamilyInet.FlowServers))
	}
	fs := inst.FamilyInet.FlowServers[0]
	if fs.Address != "192.168.99.104" {
		t.Errorf("flow-server address: got %q", fs.Address)
	}
	if fs.Port != 4739 {
		t.Errorf("flow-server port: got %d", fs.Port)
	}
	if fs.Version9Template != "v9-tmpl" {
		t.Errorf("flow-server template: got %q", fs.Version9Template)
	}

	// Family inet6
	if inst.FamilyInet6 == nil {
		t.Fatal("expected FamilyInet6")
	}
	if !inst.FamilyInet6.InlineJflow {
		t.Error("expected inline-jflow for inet6")
	}
	if len(inst.FamilyInet6.FlowServers) != 1 {
		t.Fatalf("expected 1 flow server for inet6, got %d", len(inst.FamilyInet6.FlowServers))
	}

	// Test set-command syntax
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set services flow-monitoring version9 template v9-set flow-active-timeout 120",
		"set services flow-monitoring version9 template v9-set flow-inactive-timeout 30",
		"set services flow-monitoring version9 template v9-set template-refresh-rate seconds 45",
		"set forwarding-options sampling instance jf-inst input rate 100",
		"set forwarding-options sampling instance jf-inst family inet output flow-server 10.0.0.1 port 2055",
		"set forwarding-options sampling instance jf-inst family inet output flow-server 10.0.0.1 version9-template v9-set",
		"set forwarding-options sampling instance jf-inst family inet output inline-jflow",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}

	if cfg2.Services.FlowMonitoring == nil {
		t.Fatal("set syntax: expected FlowMonitoring")
	}
	tmpl2 := cfg2.Services.FlowMonitoring.Version9.Templates["v9-set"]
	if tmpl2 == nil {
		t.Fatal("set syntax: expected template v9-set")
	}
	if tmpl2.FlowActiveTimeout != 120 {
		t.Errorf("set syntax active timeout: got %d, want 120", tmpl2.FlowActiveTimeout)
	}
	if tmpl2.FlowInactiveTimeout != 30 {
		t.Errorf("set syntax inactive timeout: got %d, want 30", tmpl2.FlowInactiveTimeout)
	}
	if tmpl2.TemplateRefreshRate != 45 {
		t.Errorf("set syntax refresh rate: got %d, want 45", tmpl2.TemplateRefreshRate)
	}

	inst2 := cfg2.ForwardingOptions.Sampling.Instances["jf-inst"]
	if inst2 == nil {
		t.Fatal("set syntax: expected instance jf-inst")
	}
	if inst2.InputRate != 100 {
		t.Errorf("set syntax input rate: got %d, want 100", inst2.InputRate)
	}
	if inst2.FamilyInet == nil {
		t.Fatal("set syntax: expected FamilyInet")
	}
	if !inst2.FamilyInet.InlineJflow {
		t.Error("set syntax: expected inline-jflow")
	}
	if len(inst2.FamilyInet.FlowServers) != 1 {
		t.Fatalf("set syntax: expected 1 flow server, got %d", len(inst2.FamilyInet.FlowServers))
	}
	fs2 := inst2.FamilyInet.FlowServers[0]
	if fs2.Address != "10.0.0.1" || fs2.Port != 2055 {
		t.Errorf("set syntax flow-server: addr=%s port=%d", fs2.Address, fs2.Port)
	}
	if fs2.Version9Template != "v9-set" {
		t.Errorf("set syntax flow-server template: %q", fs2.Version9Template)
	}
}

func TestALGAndFlowOptions(t *testing.T) {
	input := `security {
    flow {
        tcp-mss {
            ipsec-vpn 1350;
            gre-in 1400;
        }
        allow-dns-reply;
        allow-embedded-icmp;
    }
    alg {
        dns { disable; }
        ftp { disable; }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if cfg.Security.Flow.TCPMSSIPsecVPN != 1350 {
		t.Errorf("tcp-mss ipsec-vpn: got %d, want 1350", cfg.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg.Security.Flow.TCPMSSGre != 1400 {
		t.Errorf("tcp-mss gre: got %d, want 1400", cfg.Security.Flow.TCPMSSGre)
	}
	if !cfg.Security.Flow.AllowDNSReply {
		t.Error("expected allow-dns-reply to be true")
	}
	if !cfg.Security.Flow.AllowEmbeddedICMP {
		t.Error("expected allow-embedded-icmp to be true")
	}
	if !cfg.Security.ALG.DNSDisable {
		t.Error("expected ALG DNS disable")
	}
	if !cfg.Security.ALG.FTPDisable {
		t.Error("expected ALG FTP disable")
	}

	// Test set-command syntax
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set security flow tcp-mss ipsec-vpn 1350",
		"set security flow tcp-mss gre-in 1400",
		"set security flow allow-dns-reply",
		"set security flow allow-embedded-icmp",
		"set security alg dns disable",
		"set security alg ftp disable",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}

	if cfg2.Security.Flow.TCPMSSIPsecVPN != 1350 {
		t.Errorf("set syntax: tcp-mss ipsec-vpn: got %d, want 1350", cfg2.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg2.Security.Flow.TCPMSSGre != 1400 {
		t.Errorf("set syntax: tcp-mss gre: got %d, want 1400", cfg2.Security.Flow.TCPMSSGre)
	}
	if !cfg2.Security.Flow.AllowDNSReply {
		t.Error("set syntax: expected allow-dns-reply")
	}
	if !cfg2.Security.ALG.DNSDisable {
		t.Error("set syntax: expected ALG DNS disable")
	}
	if !cfg2.Security.ALG.FTPDisable {
		t.Error("set syntax: expected ALG FTP disable")
	}
}

func TestRPMConfig(t *testing.T) {
	// Test hierarchical syntax
	input := `services {
    rpm {
        probe isp-comcast {
            test icmp-check {
                probe-type icmp-ping;
                target 1.1.1.1;
                probe-interval 5;
                probe-count 3;
                test-interval 30;
                thresholds {
                    successive-loss 3;
                }
            }
            test http-check {
                probe-type http-get;
                target http://1.1.1.1;
                test-interval 60;
            }
        }
        probe isp-att {
            test tcp-check {
                probe-type tcp-ping;
                target 8.8.8.8;
                destination-port 443;
                source-address 10.0.1.1;
                routing-instance att-vr;
                thresholds {
                    successive-loss 5;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if cfg.Services.RPM == nil {
		t.Fatal("expected RPM to be non-nil")
	}
	if len(cfg.Services.RPM.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(cfg.Services.RPM.Probes))
	}

	// Check isp-comcast probe
	comcast := cfg.Services.RPM.Probes["isp-comcast"]
	if comcast == nil {
		t.Fatal("expected probe isp-comcast")
	}
	if len(comcast.Tests) != 2 {
		t.Fatalf("expected 2 tests, got %d", len(comcast.Tests))
	}

	icmpTest := comcast.Tests["icmp-check"]
	if icmpTest == nil {
		t.Fatal("expected test icmp-check")
	}
	if icmpTest.ProbeType != "icmp-ping" {
		t.Errorf("probe type: got %q, want icmp-ping", icmpTest.ProbeType)
	}
	if icmpTest.Target != "1.1.1.1" {
		t.Errorf("target: got %q, want 1.1.1.1", icmpTest.Target)
	}
	if icmpTest.ProbeInterval != 5 {
		t.Errorf("probe-interval: got %d, want 5", icmpTest.ProbeInterval)
	}
	if icmpTest.ProbeCount != 3 {
		t.Errorf("probe-count: got %d, want 3", icmpTest.ProbeCount)
	}
	if icmpTest.TestInterval != 30 {
		t.Errorf("test-interval: got %d, want 30", icmpTest.TestInterval)
	}
	if icmpTest.ThresholdSuccessive != 3 {
		t.Errorf("successive-loss: got %d, want 3", icmpTest.ThresholdSuccessive)
	}

	httpTest := comcast.Tests["http-check"]
	if httpTest == nil {
		t.Fatal("expected test http-check")
	}
	if httpTest.ProbeType != "http-get" {
		t.Errorf("probe type: got %q, want http-get", httpTest.ProbeType)
	}

	// Check isp-att probe
	att := cfg.Services.RPM.Probes["isp-att"]
	if att == nil {
		t.Fatal("expected probe isp-att")
	}
	tcpTest := att.Tests["tcp-check"]
	if tcpTest == nil {
		t.Fatal("expected test tcp-check")
	}
	if tcpTest.ProbeType != "tcp-ping" {
		t.Errorf("probe type: got %q, want tcp-ping", tcpTest.ProbeType)
	}
	if tcpTest.Target != "8.8.8.8" {
		t.Errorf("target: got %q, want 8.8.8.8", tcpTest.Target)
	}
	if tcpTest.DestPort != 443 {
		t.Errorf("dest port: got %d, want 443", tcpTest.DestPort)
	}
	if tcpTest.SourceAddress != "10.0.1.1" {
		t.Errorf("source-address: got %q, want 10.0.1.1", tcpTest.SourceAddress)
	}
	if tcpTest.RoutingInstance != "att-vr" {
		t.Errorf("routing-instance: got %q, want att-vr", tcpTest.RoutingInstance)
	}
	if tcpTest.ThresholdSuccessive != 5 {
		t.Errorf("successive-loss: got %d, want 5", tcpTest.ThresholdSuccessive)
	}

	// Test set-command syntax
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set services rpm probe monitor test ping-test probe-type icmp-ping",
		"set services rpm probe monitor test ping-test target 8.8.4.4",
		"set services rpm probe monitor test ping-test probe-interval 10",
		"set services rpm probe monitor test ping-test test-interval 60",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}

	if cfg2.Services.RPM == nil {
		t.Fatal("set syntax: expected RPM")
	}
	monitor := cfg2.Services.RPM.Probes["monitor"]
	if monitor == nil {
		t.Fatal("set syntax: expected probe monitor")
	}
	pingTest := monitor.Tests["ping-test"]
	if pingTest == nil {
		t.Fatal("set syntax: expected test ping-test")
	}
	if pingTest.ProbeType != "icmp-ping" {
		t.Errorf("set syntax probe type: got %q, want icmp-ping", pingTest.ProbeType)
	}
	if pingTest.Target != "8.8.4.4" {
		t.Errorf("set syntax target: got %q, want 8.8.4.4", pingTest.Target)
	}
	if pingTest.ProbeInterval != 10 {
		t.Errorf("set syntax probe-interval: got %d, want 10", pingTest.ProbeInterval)
	}
	if pingTest.TestInterval != 60 {
		t.Errorf("set syntax test-interval: got %d, want 60", pingTest.TestInterval)
	}
}

func TestSystemConfig(t *testing.T) {
	input := `system {
    host-name bpfrx-fw;
    time-zone America/Los_Angeles;
    no-redirects;
    name-server {
        2606:4700:4700::1111;
        2606:4700:4700::1001;
    }
    ntp {
        server 2001:559:8585:ffff::4;
        server 192.168.99.4;
    }
    login {
        user admin {
            uid 2000;
            class super-user;
            authentication {
                ssh-ed25519 "ssh-ed25519 AAAA...";
            }
        }
        user readonly {
            uid 2001;
            class read-only;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if cfg.System.HostName != "bpfrx-fw" {
		t.Errorf("hostname = %q", cfg.System.HostName)
	}
	if cfg.System.TimeZone != "America/Los_Angeles" {
		t.Errorf("timezone = %q", cfg.System.TimeZone)
	}
	if !cfg.System.NoRedirects {
		t.Error("no-redirects not set")
	}
	if len(cfg.System.NameServers) != 2 {
		t.Errorf("expected 2 name-servers, got %d", len(cfg.System.NameServers))
	}
	if len(cfg.System.NTPServers) != 2 {
		t.Errorf("expected 2 NTP servers, got %d", len(cfg.System.NTPServers))
	}
	if cfg.System.Login == nil {
		t.Fatal("login config missing")
	}
	if len(cfg.System.Login.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.System.Login.Users))
	}
	if cfg.System.Login.Users[0].Name != "admin" {
		t.Errorf("user[0] name = %q", cfg.System.Login.Users[0].Name)
	}
	if cfg.System.Login.Users[0].UID != 2000 {
		t.Errorf("user[0] uid = %d", cfg.System.Login.Users[0].UID)
	}
	if cfg.System.Login.Users[0].Class != "super-user" {
		t.Errorf("user[0] class = %q", cfg.System.Login.Users[0].Class)
	}
	if len(cfg.System.Login.Users[0].SSHKeys) != 1 {
		t.Errorf("expected 1 SSH key for admin, got %d", len(cfg.System.Login.Users[0].SSHKeys))
	}
}

func TestDHCPServerConfig(t *testing.T) {
	// Test hierarchical syntax
	input := `system {
    services {
        dhcp-local-server {
            group lan-pool {
                interface eth0.0;
                interface eth1.0;
                pool office-pool {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.200;
                    router 10.0.1.1;
                    dns-server 8.8.8.8;
                    dns-server 8.8.4.4;
                    lease-time 3600;
                    domain-name example.local;
                }
            }
            group guest-pool {
                interface eth2.0;
                pool guest {
                    subnet 10.0.2.0/24;
                    address-range low 10.0.2.50 high 10.0.2.150;
                    router 10.0.2.1;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	dhcp := cfg.System.DHCPServer.DHCPLocalServer
	if dhcp == nil {
		t.Fatal("expected DHCPLocalServer to be non-nil")
	}
	if len(dhcp.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(dhcp.Groups))
	}

	lanGroup := dhcp.Groups["lan-pool"]
	if lanGroup == nil {
		t.Fatal("expected group lan-pool")
	}
	if len(lanGroup.Interfaces) != 2 {
		t.Errorf("lan-pool interfaces: expected 2, got %d", len(lanGroup.Interfaces))
	}
	if len(lanGroup.Pools) != 1 {
		t.Fatalf("lan-pool pools: expected 1, got %d", len(lanGroup.Pools))
	}

	pool := lanGroup.Pools[0]
	if pool.Name != "office-pool" {
		t.Errorf("pool name: got %q, want office-pool", pool.Name)
	}
	if pool.Subnet != "10.0.1.0/24" {
		t.Errorf("pool subnet: got %q", pool.Subnet)
	}
	if pool.RangeLow != "10.0.1.100" || pool.RangeHigh != "10.0.1.200" {
		t.Errorf("pool range: %s - %s", pool.RangeLow, pool.RangeHigh)
	}
	if pool.Router != "10.0.1.1" {
		t.Errorf("pool router: got %q", pool.Router)
	}
	if len(pool.DNSServers) != 2 {
		t.Errorf("pool dns: expected 2, got %d", len(pool.DNSServers))
	}
	if pool.LeaseTime != 3600 {
		t.Errorf("pool lease-time: got %d, want 3600", pool.LeaseTime)
	}
	if pool.Domain != "example.local" {
		t.Errorf("pool domain: got %q", pool.Domain)
	}

	// Test set-command syntax
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set system services dhcp-local-server group test interface eth3.0",
		"set system services dhcp-local-server group test pool p1 subnet 172.16.0.0/24",
		"set system services dhcp-local-server group test pool p1 address-range low 172.16.0.10 high 172.16.0.50",
		"set system services dhcp-local-server group test pool p1 router 172.16.0.1",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	if cfg2.System.DHCPServer.DHCPLocalServer == nil {
		t.Fatal("set syntax: DHCP server is nil")
	}
	testGroup := cfg2.System.DHCPServer.DHCPLocalServer.Groups["test"]
	if testGroup == nil {
		t.Fatal("set syntax: missing group test")
	}
	if len(testGroup.Pools) != 1 {
		t.Fatalf("set syntax: expected 1 pool, got %d", len(testGroup.Pools))
	}
	if testGroup.Pools[0].Subnet != "172.16.0.0/24" {
		t.Errorf("set syntax pool subnet: %q", testGroup.Pools[0].Subnet)
	}
}

func TestDynamicAddressFeed(t *testing.T) {
	// Test hierarchical syntax
	input := `security {
    dynamic-address {
        feed-server threat-feed {
            url "https://feeds.example.com/threats.txt";
            update-interval 1800;
            hold-interval 3600;
            feed-name malware-ips;
        }
        feed-server geo-feed {
            url "https://feeds.example.com/geo.txt";
            update-interval 7200;
            feed-name geo-block;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	da := cfg.Security.DynamicAddress
	if da.FeedServers == nil || len(da.FeedServers) != 2 {
		t.Fatalf("expected 2 feed servers, got %v", da.FeedServers)
	}

	tf := da.FeedServers["threat-feed"]
	if tf == nil {
		t.Fatal("expected threat-feed server")
	}
	if tf.URL != "https://feeds.example.com/threats.txt" {
		t.Errorf("url: got %q", tf.URL)
	}
	if tf.UpdateInterval != 1800 {
		t.Errorf("update-interval: got %d, want 1800", tf.UpdateInterval)
	}
	if tf.HoldInterval != 3600 {
		t.Errorf("hold-interval: got %d, want 3600", tf.HoldInterval)
	}
	if tf.FeedName != "malware-ips" {
		t.Errorf("feed-name: got %q", tf.FeedName)
	}
}

func TestMultipleSNATRules(t *testing.T) {
	input := `security {
    zones {
        security-zone trust {
            interfaces { eth0.0; }
        }
        security-zone untrust {
            interfaces { eth1.0; }
        }
    }
    nat {
        source {
            pool wan-pool {
                address 203.0.113.1/32;
            }
            pool backup-pool {
                address 203.0.113.2/32;
            }
            rule-set trust-to-untrust {
                from zone trust;
                to zone untrust;
                rule web-traffic {
                    match {
                        source-address 10.0.1.0/24;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            pool wan-pool;
                        }
                    }
                }
                rule backup-traffic {
                    match {
                        source-address 10.0.2.0/24;
                    }
                    then {
                        source-nat {
                            pool backup-pool;
                        }
                    }
                }
                rule default-snat {
                    match {
                        source-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("expected 1 source rule-set, got %d", len(cfg.Security.NAT.Source))
	}

	rs := cfg.Security.NAT.Source[0]
	if rs.FromZone != "trust" || rs.ToZone != "untrust" {
		t.Errorf("rule-set zones: from=%s to=%s", rs.FromZone, rs.ToZone)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rs.Rules))
	}

	// Verify first rule uses pool
	r1 := rs.Rules[0]
	if r1.Name != "web-traffic" {
		t.Errorf("rule 1 name: %s", r1.Name)
	}
	if r1.Match.SourceAddress != "10.0.1.0/24" {
		t.Errorf("rule 1 src: %s", r1.Match.SourceAddress)
	}
	if r1.Then.PoolName != "wan-pool" {
		t.Errorf("rule 1 pool: %s", r1.Then.PoolName)
	}

	// Verify third rule uses interface
	r3 := rs.Rules[2]
	if r3.Name != "default-snat" {
		t.Errorf("rule 3 name: %s", r3.Name)
	}
	if !r3.Then.Interface {
		t.Error("rule 3 should use interface SNAT")
	}

	// Verify pools
	if cfg.Security.NAT.SourcePools == nil {
		t.Fatal("source pools nil")
	}
	if len(cfg.Security.NAT.SourcePools) != 2 {
		t.Errorf("expected 2 source pools, got %d", len(cfg.Security.NAT.SourcePools))
	}
}

func TestDNATWithProtocol(t *testing.T) {
	input := `security {
    zones {
        security-zone untrust {
            interfaces { eth1.0; }
        }
        security-zone dmz {
            interfaces { eth2.0; }
        }
    }
    nat {
        destination {
            pool web-server {
                address 10.0.30.100;
            }
            rule-set untrust-to-dmz {
                from zone untrust;
                rule http-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 80;
                        protocol tcp;
                    }
                    then {
                        destination-nat {
                            pool web-server;
                        }
                    }
                }
                rule https-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 443;
                        protocol tcp;
                    }
                    then {
                        destination-nat {
                            pool web-server;
                        }
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	if len(dnat.RuleSets) != 1 {
		t.Fatalf("expected 1 DNAT rule-set, got %d", len(dnat.RuleSets))
	}

	rs := dnat.RuleSets[0]
	if len(rs.Rules) != 2 {
		t.Fatalf("expected 2 DNAT rules, got %d", len(rs.Rules))
	}

	r1 := rs.Rules[0]
	if r1.Name != "http-dnat" {
		t.Errorf("rule 1 name: %s", r1.Name)
	}
	if r1.Match.Protocol != "tcp" {
		t.Errorf("rule 1 protocol: %s", r1.Match.Protocol)
	}
	if r1.Match.DestinationPort != 80 {
		t.Errorf("rule 1 port: %d", r1.Match.DestinationPort)
	}
	if r1.Match.DestinationAddress != "203.0.113.10/32" {
		t.Errorf("rule 1 dst: %s", r1.Match.DestinationAddress)
	}
	if r1.Then.PoolName != "web-server" {
		t.Errorf("rule 1 pool: %s", r1.Then.PoolName)
	}
}

func TestVLANInterfaceCompilation(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set interfaces enp7s0 vlan-tagging",
		"set interfaces enp7s0 unit 100 vlan-id 100",
		"set interfaces enp7s0 unit 100 family inet address 10.0.100.1/24",
		"set interfaces enp7s0 unit 200 vlan-id 200",
		"set interfaces enp7s0 unit 200 family inet address 10.0.200.1/24",
		"set interfaces enp7s0 unit 200 family inet6 address fd00:200::1/64",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	ifc := cfg.Interfaces.Interfaces["enp7s0"]
	if ifc == nil {
		t.Fatal("missing interface enp7s0")
	}
	if !ifc.VlanTagging {
		t.Error("expected vlan-tagging to be true")
	}
	if len(ifc.Units) != 2 {
		t.Fatalf("expected 2 units, got %d", len(ifc.Units))
	}

	unit100 := ifc.Units[100]
	if unit100 == nil {
		t.Fatal("missing unit 100")
	}
	if unit100.VlanID != 100 {
		t.Errorf("unit 100 vlan-id: got %d", unit100.VlanID)
	}
	if len(unit100.Addresses) != 1 || unit100.Addresses[0] != "10.0.100.1/24" {
		t.Errorf("unit 100 addresses: %v", unit100.Addresses)
	}

	unit200 := ifc.Units[200]
	if unit200 == nil {
		t.Fatal("missing unit 200")
	}
	if unit200.VlanID != 200 {
		t.Errorf("unit 200 vlan-id: got %d", unit200.VlanID)
	}
	if len(unit200.Addresses) != 2 {
		t.Errorf("unit 200 addresses: expected 2, got %v", unit200.Addresses)
	}
}

func TestEdgeCases(t *testing.T) {
	// Empty block
	input := `security {
    zones {
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("empty block parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("empty block compile error: %v", err)
	}
	if len(cfg.Security.Zones) != 0 {
		t.Errorf("expected 0 zones from empty block, got %d", len(cfg.Security.Zones))
	}

	// Trailing semicolon after block content
	input2 := `security {
    zones {
        security-zone test {
            interfaces {
                eth0.0;
            }
        }
    }
}
`
	parser2 := NewParser(input2)
	tree2, errs2 := parser2.Parse()
	if len(errs2) > 0 {
		t.Fatalf("trailing semicolon parse errors: %v", errs2)
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("trailing semicolon compile error: %v", err)
	}
	if len(cfg2.Security.Zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(cfg2.Security.Zones))
	}

	// Deeply nested config (>10 levels via routing-instances)
	tree3 := &ConfigTree{}
	deepCommands := []string{
		"set routing-instances deep-vr instance-type virtual-router",
		"set routing-instances deep-vr routing-options static route 10.0.0.0/8 next-hop 192.168.1.1",
		"set routing-instances deep-vr protocols ospf area 0.0.0.0 interface eth0",
		"set routing-instances deep-vr protocols bgp local-as 65001",
		"set routing-instances deep-vr protocols bgp group peer peer-as 65002",
		"set routing-instances deep-vr protocols bgp group peer neighbor 10.1.0.1",
	}
	for _, cmd := range deepCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree3.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg3, err := CompileConfig(tree3)
	if err != nil {
		t.Fatalf("deep config compile error: %v", err)
	}
	if len(cfg3.RoutingInstances) != 1 {
		t.Errorf("expected 1 routing instance, got %d", len(cfg3.RoutingInstances))
	}
	ri := cfg3.RoutingInstances[0]
	if ri.BGP == nil || ri.BGP.LocalAS != 65001 {
		t.Error("deep config: BGP not compiled correctly")
	}
}

func TestScreenCompilation(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set security screen ids-option wan-screen tcp syn-flood alarm-threshold 1000",
		"set security screen ids-option wan-screen tcp syn-flood attack-threshold 2000",
		"set security screen ids-option wan-screen tcp land",
		"set security screen ids-option wan-screen tcp syn-fin",
		"set security screen ids-option wan-screen tcp no-flag",
		"set security screen ids-option wan-screen tcp winnuke",
		"set security screen ids-option wan-screen tcp fin-no-ack",
		"set security screen ids-option wan-screen icmp ping-death",
		"set security screen ids-option wan-screen icmp flood threshold 500",
		"set security screen ids-option wan-screen ip source-route-option",
		"set security screen ids-option wan-screen ip tear-drop",
		"set security screen ids-option wan-screen udp flood threshold 1000",
	}

	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	screen := cfg.Security.Screen["wan-screen"]
	if screen == nil {
		t.Fatal("missing screen profile wan-screen")
	}

	// TCP checks
	if !screen.TCP.Land {
		t.Error("expected tcp land")
	}
	if !screen.TCP.SynFin {
		t.Error("expected tcp syn-fin")
	}
	if !screen.TCP.NoFlag {
		t.Error("expected tcp tcp-no-flag")
	}
	if !screen.TCP.WinNuke {
		t.Error("expected tcp winnuke")
	}
	if !screen.TCP.FinNoAck {
		t.Error("expected tcp fin-no-ack")
	}
	if screen.TCP.SynFlood == nil {
		t.Fatal("expected syn-flood config")
	}

	// ICMP checks
	if !screen.ICMP.PingDeath {
		t.Error("expected icmp ping-death")
	}
	if screen.ICMP.FloodThreshold != 500 {
		t.Errorf("icmp flood threshold: got %d, want 500", screen.ICMP.FloodThreshold)
	}

	// IP checks
	if !screen.IP.SourceRouteOption {
		t.Error("expected ip source-route-option")
	}
	if !screen.IP.TearDrop {
		t.Error("expected ip tear-drop")
	}

	// UDP checks
	if screen.UDP.FloodThreshold != 1000 {
		t.Errorf("udp flood threshold: got %d, want 1000", screen.UDP.FloodThreshold)
	}
}

func TestInterfaceFilterAssignment(t *testing.T) {
	input := `interfaces {
    enp6s0 {
        unit 0 {
            family inet {
                filter {
                    input inet-source-dscp;
                }
                address 192.168.0.1/24;
            }
            family inet6 {
                filter {
                    input inet6-source-dscp;
                }
                address fd35::1/64;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	ifc, ok := cfg.Interfaces.Interfaces["enp6s0"]
	if !ok {
		t.Fatal("expected enp6s0 interface")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("expected unit 0")
	}
	if unit.FilterInputV4 != "inet-source-dscp" {
		t.Errorf("expected FilterInputV4=inet-source-dscp, got %q", unit.FilterInputV4)
	}
	if unit.FilterInputV6 != "inet6-source-dscp" {
		t.Errorf("expected FilterInputV6=inet6-source-dscp, got %q", unit.FilterInputV6)
	}
}

func TestIPsecBindInterface(t *testing.T) {
	input := `security {
    ipsec {
        proposal aes256gcm {
            protocol esp;
            encryption-algorithm aes-256-gcm;
            dh-group 14;
            lifetime-seconds 3600;
        }
        vpn site-a {
            bind-interface st0.0;
            gateway 203.0.113.1;
            local-address 198.51.100.1;
            ipsec-policy aes256gcm;
            local-identity 10.0.0.0/24;
            remote-identity 10.1.0.0/24;
            pre-shared-key "secret123";
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("expected BindInterface=st0.0, got %q", vpn.BindInterface)
	}
	if vpn.Gateway != "203.0.113.1" {
		t.Errorf("expected Gateway=203.0.113.1, got %q", vpn.Gateway)
	}
	if vpn.LocalAddr != "198.51.100.1" {
		t.Errorf("expected LocalAddr=198.51.100.1, got %q", vpn.LocalAddr)
	}
	if vpn.IPsecPolicy != "aes256gcm" {
		t.Errorf("expected IPsecPolicy=aes256gcm, got %q", vpn.IPsecPolicy)
	}

	prop := cfg.Security.IPsec.Proposals["aes256gcm"]
	if prop == nil {
		t.Fatal("missing proposal aes256gcm")
	}
	if prop.EncryptionAlg != "aes-256-gcm" {
		t.Errorf("expected EncryptionAlg=aes-256-gcm, got %q", prop.EncryptionAlg)
	}
}

func TestIPsecBindInterfaceSetSyntax(t *testing.T) {
	setCommands := []string{
		`set security ipsec proposal aes256gcm protocol esp`,
		`set security ipsec proposal aes256gcm encryption-algorithm aes-256-gcm`,
		`set security ipsec proposal aes256gcm dh-group 14`,
		`set security ipsec vpn site-b bind-interface st1.0`,
		`set security ipsec vpn site-b gateway 10.2.0.1`,
		`set security ipsec vpn site-b ipsec-policy aes256gcm`,
		`set security ipsec vpn site-b local-identity 10.0.0.0/24`,
		`set security ipsec vpn site-b remote-identity 10.2.0.0/24`,
		`set security ipsec vpn site-b pre-shared-key "vpnkey"`,
	}

	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	vpn := cfg.Security.IPsec.VPNs["site-b"]
	if vpn == nil {
		t.Fatal("missing VPN site-b")
	}
	if vpn.BindInterface != "st1.0" {
		t.Errorf("expected BindInterface=st1.0, got %q", vpn.BindInterface)
	}
	if vpn.Gateway != "10.2.0.1" {
		t.Errorf("expected Gateway=10.2.0.1, got %q", vpn.Gateway)
	}
}

func TestIPsecGateway(t *testing.T) {
	input := `security {
    ipsec {
        proposal ike-strong {
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha256-128;
            dh-group 14;
        }
        proposal esp-strong {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha256-128;
            dh-group 14;
        }
        gateway remote-gw {
            address 203.0.113.1;
            local-address 198.51.100.1;
            ike-policy ike-strong;
            external-interface untrust0;
        }
        vpn site-a {
            gateway remote-gw;
            ipsec-policy esp-strong;
            bind-interface st0.0;
            local-identity 10.0.0.0/24;
            remote-identity 10.1.0.0/24;
            pre-shared-key "secret123";
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify gateway is compiled
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q, want 203.0.113.1", gw.Address)
	}
	if gw.LocalAddress != "198.51.100.1" {
		t.Errorf("gateway local-address = %q, want 198.51.100.1", gw.LocalAddress)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("gateway ike-policy = %q, want ike-strong", gw.IKEPolicy)
	}
	if gw.ExternalIface != "untrust0" {
		t.Errorf("gateway external-interface = %q, want untrust0", gw.ExternalIface)
	}

	// Verify VPN references gateway by name
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q, want remote-gw", vpn.Gateway)
	}
}

func TestIPsecGatewaySetSyntax(t *testing.T) {
	setCommands := []string{
		`set security ipsec gateway remote-gw address 203.0.113.1`,
		`set security ipsec gateway remote-gw local-address 198.51.100.1`,
		`set security ipsec gateway remote-gw ike-policy ike-strong`,
		`set security ipsec gateway remote-gw external-interface untrust0`,
		`set security ipsec vpn site-a gateway remote-gw`,
		`set security ipsec vpn site-a bind-interface st0.0`,
	}

	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q", gw.Address)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("gateway ike-policy = %q", gw.IKEPolicy)
	}

	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q", vpn.Gateway)
	}
}

func TestIKEAdvancedFeatures(t *testing.T) {
	input := `security {
    ike {
        proposal ike-phase1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
            lifetime-seconds 28800;
        }
        policy ike-pol {
            mode main;
            proposals ike-phase1;
            pre-shared-key ascii-text "secret123";
        }
        gateway remote-gw {
            ike-policy ike-pol;
            address 203.0.113.1;
            dead-peer-detection always-send;
            no-nat-traversal;
            local-identity hostname vpn.example.com;
            remote-identity inet 203.0.113.1;
            external-interface wan0;
            local-address 198.51.100.1;
            version v2-only;
        }
        gateway dynamic-gw {
            ike-policy ike-pol;
            dynamic hostname peer.example.com;
            local-identity hostname vpn.example.com;
            external-interface wan0;
            version v2-only;
        }
    }
    ipsec {
        proposal esp-phase2 {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha-256-128;
            lifetime-seconds 3600;
        }
        policy ipsec-pol {
            perfect-forward-secrecy {
                keys group14;
            }
            proposals esp-phase2;
        }
        vpn site-a {
            bind-interface st0.0;
            df-bit copy;
            ike {
                gateway remote-gw;
                ipsec-policy ipsec-pol;
            }
            establish-tunnels immediately;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// IKE proposal
	ikeProp := cfg.Security.IPsec.IKEProposals["ike-phase1"]
	if ikeProp == nil {
		t.Fatal("missing IKE proposal ike-phase1")
	}
	if ikeProp.AuthMethod != "pre-shared-keys" {
		t.Errorf("IKE proposal auth-method = %q", ikeProp.AuthMethod)
	}
	if ikeProp.DHGroup != 14 {
		t.Errorf("IKE proposal dh-group = %d, want 14", ikeProp.DHGroup)
	}
	if ikeProp.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("IKE proposal enc = %q", ikeProp.EncryptionAlg)
	}
	if ikeProp.LifetimeSeconds != 28800 {
		t.Errorf("IKE proposal lifetime = %d", ikeProp.LifetimeSeconds)
	}

	// IKE policy
	ikePol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if ikePol == nil {
		t.Fatal("missing IKE policy ike-pol")
	}
	if ikePol.Mode != "main" {
		t.Errorf("IKE policy mode = %q", ikePol.Mode)
	}
	if ikePol.Proposals != "ike-phase1" {
		t.Errorf("IKE policy proposals = %q", ikePol.Proposals)
	}
	if ikePol.PSK != "secret123" {
		t.Errorf("IKE policy PSK = %q", ikePol.PSK)
	}

	// Gateway with static address
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("gateway address = %q", gw.Address)
	}
	if gw.Version != "v2-only" {
		t.Errorf("gateway version = %q", gw.Version)
	}
	if !gw.NoNATTraversal {
		t.Error("gateway no-nat-traversal not set")
	}
	if gw.DeadPeerDetect != "always-send" {
		t.Errorf("gateway dpd = %q", gw.DeadPeerDetect)
	}
	if gw.LocalIDType != "hostname" || gw.LocalIDValue != "vpn.example.com" {
		t.Errorf("gateway local-identity = %q %q", gw.LocalIDType, gw.LocalIDValue)
	}
	if gw.RemoteIDType != "inet" || gw.RemoteIDValue != "203.0.113.1" {
		t.Errorf("gateway remote-identity = %q %q", gw.RemoteIDType, gw.RemoteIDValue)
	}

	// Gateway with dynamic hostname
	dynGw := cfg.Security.IPsec.Gateways["dynamic-gw"]
	if dynGw == nil {
		t.Fatal("missing gateway dynamic-gw")
	}
	if dynGw.DynamicHostname != "peer.example.com" {
		t.Errorf("dynamic gateway hostname = %q", dynGw.DynamicHostname)
	}

	// IPsec policy (PFS)
	ipsecPol := cfg.Security.IPsec.Policies["ipsec-pol"]
	if ipsecPol == nil {
		t.Fatal("missing IPsec policy ipsec-pol")
	}
	if ipsecPol.PFSGroup != 14 {
		t.Errorf("IPsec policy PFS group = %d, want 14", ipsecPol.PFSGroup)
	}
	if ipsecPol.Proposals != "esp-phase2" {
		t.Errorf("IPsec policy proposals = %q", ipsecPol.Proposals)
	}

	// VPN with nested ike {} block
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("missing VPN site-a")
	}
	if vpn.Gateway != "remote-gw" {
		t.Errorf("vpn gateway = %q", vpn.Gateway)
	}
	if vpn.IPsecPolicy != "ipsec-pol" {
		t.Errorf("vpn ipsec-policy = %q", vpn.IPsecPolicy)
	}
	if vpn.DFBit != "copy" {
		t.Errorf("vpn df-bit = %q", vpn.DFBit)
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("vpn establish-tunnels = %q", vpn.EstablishTunnels)
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("vpn bind-interface = %q", vpn.BindInterface)
	}
}

func TestIKEAdvancedSetSyntax(t *testing.T) {
	setCommands := []string{
		`set security ike proposal ike-p1 authentication-method pre-shared-keys`,
		`set security ike proposal ike-p1 dh-group group14`,
		`set security ike proposal ike-p1 encryption-algorithm aes-256-cbc`,
		`set security ike policy pol1 mode main`,
		`set security ike policy pol1 proposals ike-p1`,
		`set security ike policy pol1 pre-shared-key ascii-text mysecret`,
		`set security ike gateway gw1 ike-policy pol1`,
		`set security ike gateway gw1 address 10.0.0.1`,
		`set security ike gateway gw1 version v2-only`,
		`set security ike gateway gw1 no-nat-traversal`,
		`set security ike gateway gw1 dead-peer-detection always-send`,
		`set security ike gateway gw1 local-identity hostname vpn.test.com`,
		`set security ike gateway gw1 remote-identity inet 10.0.0.1`,
		`set security ipsec policy ipsec-pol perfect-forward-secrecy keys group5`,
		`set security ipsec policy ipsec-pol proposals esp-p2`,
		`set security ipsec vpn tun1 bind-interface st0.0`,
		`set security ipsec vpn tun1 df-bit copy`,
		`set security ipsec vpn tun1 establish-tunnels immediately`,
		`set security ipsec vpn tun1 ike gateway gw1`,
		`set security ipsec vpn tun1 ike ipsec-policy ipsec-pol`,
	}

	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// IKE proposal
	ikeProp := cfg.Security.IPsec.IKEProposals["ike-p1"]
	if ikeProp == nil {
		t.Fatal("missing IKE proposal")
	}
	if ikeProp.DHGroup != 14 {
		t.Errorf("dh-group = %d, want 14", ikeProp.DHGroup)
	}

	// IKE policy
	ikePol := cfg.Security.IPsec.IKEPolicies["pol1"]
	if ikePol == nil {
		t.Fatal("missing IKE policy")
	}
	if ikePol.PSK != "mysecret" {
		t.Errorf("PSK = %q", ikePol.PSK)
	}

	// Gateway
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("missing gateway")
	}
	if gw.Version != "v2-only" {
		t.Errorf("version = %q", gw.Version)
	}
	if !gw.NoNATTraversal {
		t.Error("no-nat-traversal not set")
	}
	if gw.LocalIDType != "hostname" || gw.LocalIDValue != "vpn.test.com" {
		t.Errorf("local-identity = %q %q", gw.LocalIDType, gw.LocalIDValue)
	}

	// IPsec policy
	ipsecPol := cfg.Security.IPsec.Policies["ipsec-pol"]
	if ipsecPol == nil {
		t.Fatal("missing IPsec policy")
	}
	if ipsecPol.PFSGroup != 5 {
		t.Errorf("PFS group = %d, want 5", ipsecPol.PFSGroup)
	}

	// VPN
	vpn := cfg.Security.IPsec.VPNs["tun1"]
	if vpn == nil {
		t.Fatal("missing VPN")
	}
	if vpn.DFBit != "copy" {
		t.Errorf("df-bit = %q", vpn.DFBit)
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("establish-tunnels = %q", vpn.EstablishTunnels)
	}
	if vpn.Gateway != "gw1" {
		t.Errorf("gateway = %q", vpn.Gateway)
	}
	if vpn.IPsecPolicy != "ipsec-pol" {
		t.Errorf("ipsec-policy = %q", vpn.IPsecPolicy)
	}
}

func TestHostInboundIPsec(t *testing.T) {
	input := `security {
    zones {
        security-zone vpn {
            interfaces { st0; }
            host-inbound-traffic {
                system-services {
                    ping;
                    ipsec;
                    ike;
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	zone := cfg.Security.Zones["vpn"]
	if zone == nil {
		t.Fatal("missing vpn zone")
	}
	if zone.HostInboundTraffic == nil {
		t.Fatal("missing host-inbound-traffic")
	}

	services := zone.HostInboundTraffic.SystemServices
	expected := map[string]bool{"ping": false, "ipsec": false, "ike": false}
	for _, svc := range services {
		if _, ok := expected[svc]; ok {
			expected[svc] = true
		}
	}
	for svc, found := range expected {
		if !found {
			t.Errorf("expected system-service %q not found in %v", svc, services)
		}
	}
}

func TestPolicyReject(t *testing.T) {
	input := `security {
    zones {
        security-zone trust { interfaces { eth0; } }
        security-zone untrust { interfaces { eth1; } }
    }
    policies {
        from-zone untrust to-zone trust {
            policy block-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { reject; }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "untrust" || zpp.ToZone != "trust" {
		t.Errorf("zone pair: from=%s to=%s", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "block-all" {
		t.Errorf("policy name: %s", pol.Name)
	}
	if pol.Action != PolicyReject {
		t.Errorf("expected PolicyReject (%d), got %d", PolicyReject, pol.Action)
	}

	// Also test set-command syntax
	tree2 := &ConfigTree{}
	setCommands := []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security policies from-zone untrust to-zone trust policy block-all match source-address any",
		"set security policies from-zone untrust to-zone trust policy block-all match destination-address any",
		"set security policies from-zone untrust to-zone trust policy block-all match application any",
		"set security policies from-zone untrust to-zone trust policy block-all then reject",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}

	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("set-command compile error: %v", err)
	}
	if len(cfg2.Security.Policies) != 1 {
		t.Fatalf("set: expected 1 zone-pair, got %d", len(cfg2.Security.Policies))
	}
	if cfg2.Security.Policies[0].Policies[0].Action != PolicyReject {
		t.Errorf("set: expected PolicyReject, got %d",
			cfg2.Security.Policies[0].Policies[0].Action)
	}
}

func TestPolicyDenyAll(t *testing.T) {
	input := `security {
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then { permit; }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Errorf("expected DefaultPolicy=PolicyDeny (%d), got %d",
			PolicyDeny, cfg.Security.DefaultPolicy)
	}
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("expected 1 zone-pair policy, got %d", len(cfg.Security.Policies))
	}
	pol := cfg.Security.Policies[0].Policies[0]
	if pol.Action != PolicyPermit {
		t.Errorf("expected PolicyPermit, got %d", pol.Action)
	}
}

func TestRoutingInstanceWithZone(t *testing.T) {
	input := `
routing-instances {
    isp-a {
        instance-type virtual-router;
        interface enp7s0;
        routing-options {
            static {
                route 0.0.0.0/0 {
                    next-hop 10.0.2.1;
                }
            }
        }
    }
}
security {
    zones {
        security-zone untrust {
            interfaces {
                enp7s0;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// Verify routing instance
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("expected 1 routing instance, got %d", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if ri.Name != "isp-a" {
		t.Errorf("instance name: got %q, want %q", ri.Name, "isp-a")
	}
	if len(ri.Interfaces) != 1 || ri.Interfaces[0] != "enp7s0" {
		t.Errorf("instance interfaces: got %v, want [enp7s0]", ri.Interfaces)
	}
	if ri.TableID != 100 {
		t.Errorf("table ID: got %d, want 100", ri.TableID)
	}
	if len(ri.StaticRoutes) != 1 {
		t.Fatalf("expected 1 static route, got %d", len(ri.StaticRoutes))
	}
	if len(ri.StaticRoutes[0].NextHops) != 1 || ri.StaticRoutes[0].NextHops[0].Address != "10.0.2.1" {
		t.Errorf("next-hops: got %v, want [{10.0.2.1 }]", ri.StaticRoutes[0].NextHops)
	}

	// Verify zone references the same interface
	zone, ok := cfg.Security.Zones["untrust"]
	if !ok {
		t.Fatal("missing untrust zone")
	}
	if len(zone.Interfaces) != 1 || zone.Interfaces[0] != "enp7s0" {
		t.Errorf("zone interfaces: got %v, want [enp7s0]", zone.Interfaces)
	}
}

func TestOSPFExportAndCost(t *testing.T) {
	input := `
protocols {
    ospf {
        router-id 10.0.0.1;
        export connected;
        export static;
        area 0.0.0.0 {
            interface trust0 {
                cost 100;
                passive;
            }
            interface dmz0;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if ospf.RouterID != "10.0.0.1" {
		t.Errorf("router-id: got %q, want %q", ospf.RouterID, "10.0.0.1")
	}
	if len(ospf.Export) != 2 {
		t.Fatalf("export count: got %d, want 2", len(ospf.Export))
	}
	if ospf.Export[0] != "connected" || ospf.Export[1] != "static" {
		t.Errorf("exports: got %v, want [connected static]", ospf.Export)
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("area count: got %d, want 1", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.Interfaces) != 2 {
		t.Fatalf("interface count: got %d, want 2", len(area.Interfaces))
	}
	if area.Interfaces[0].Cost != 100 {
		t.Errorf("trust0 cost: got %d, want 100", area.Interfaces[0].Cost)
	}
	if !area.Interfaces[0].Passive {
		t.Error("trust0 should be passive")
	}
}

func TestOSPFExportSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf export connected",
		"set protocols ospf area 0.0.0.0 interface trust0 cost 100",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ospf := cfg.Protocols.OSPF
	if ospf == nil {
		t.Fatal("OSPF config is nil")
	}
	if ospf.RouterID != "10.0.0.1" {
		t.Errorf("router-id: got %q, want %q", ospf.RouterID, "10.0.0.1")
	}
	if len(ospf.Export) != 1 || ospf.Export[0] != "connected" {
		t.Errorf("exports: got %v, want [connected]", ospf.Export)
	}
}

func TestBGPExportAndNeighborDetails(t *testing.T) {
	input := `protocols {
    bgp {
        local-as 65001;
        router-id 1.1.1.1;
        export connected;
        export static;
        group external {
            peer-as 65002;
            description upstream-peers;
            multihop 3;
            neighbor 10.0.2.1 {
                description specific-peer;
            }
            neighbor 10.0.3.1;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.LocalAS != 65001 {
		t.Errorf("local-as: got %d, want 65001", bgp.LocalAS)
	}
	if len(bgp.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", bgp.Export)
	}
	if bgp.Export[0] != "connected" || bgp.Export[1] != "static" {
		t.Errorf("exports: got %v, want [connected static]", bgp.Export)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	// First neighbor should have per-neighbor description override
	n0 := bgp.Neighbors[0]
	if n0.Address != "10.0.2.1" {
		t.Errorf("neighbor[0] address: got %q", n0.Address)
	}
	if n0.Description != "specific-peer" {
		t.Errorf("neighbor[0] description: got %q, want %q", n0.Description, "specific-peer")
	}
	if n0.MultihopTTL != 3 {
		t.Errorf("neighbor[0] multihop: got %d, want 3", n0.MultihopTTL)
	}
	// Second neighbor inherits group defaults
	n1 := bgp.Neighbors[1]
	if n1.Address != "10.0.3.1" {
		t.Errorf("neighbor[1] address: got %q", n1.Address)
	}
	if n1.Description != "upstream-peers" {
		t.Errorf("neighbor[1] description: got %q, want %q", n1.Description, "upstream-peers")
	}
	if n1.MultihopTTL != 3 {
		t.Errorf("neighbor[1] multihop: got %d, want 3", n1.MultihopTTL)
	}
}

func TestBGPExportSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp export connected",
		"set protocols bgp export static",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.2.1",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if len(bgp.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", bgp.Export)
	}
	if len(bgp.Neighbors) != 1 || bgp.Neighbors[0].Address != "10.0.2.1" {
		t.Errorf("neighbors: got %v", bgp.Neighbors)
	}
}

func TestISISExport(t *testing.T) {
	input := `protocols {
    isis {
        net 49.0001.1921.6800.1001.00;
        level level-1-2;
        export connected;
        export static;
        interface trust0;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if len(isis.Export) != 2 {
		t.Fatalf("exports: got %v, want [connected static]", isis.Export)
	}
	if isis.Export[0] != "connected" || isis.Export[1] != "static" {
		t.Errorf("exports: got %v", isis.Export)
	}
}

func TestConfigValidation(t *testing.T) {
	input := `
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
        }
    }
    policies {
        from-zone trust to-zone nonexistent {
            policy test {
                match {
                    source-address any;
                    destination-address bad-addr;
                    application bad-app;
                }
                then { permit; }
            }
        }
    }
    screen {
        ids-option myscreen {
            tcp { land; }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// Should have warnings for: nonexistent zone, bad-addr, bad-app
	if len(cfg.Warnings) == 0 {
		t.Fatal("expected validation warnings, got none")
	}

	var foundZone, foundAddr, foundApp bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nonexistent") && strings.Contains(w, "zone") {
			foundZone = true
		}
		if strings.Contains(w, "bad-addr") {
			foundAddr = true
		}
		if strings.Contains(w, "bad-app") {
			foundApp = true
		}
	}
	if !foundZone {
		t.Error("missing warning for nonexistent zone")
	}
	if !foundAddr {
		t.Error("missing warning for bad-addr")
	}
	if !foundApp {
		t.Error("missing warning for bad-app")
	}
}

func TestConfigValidationClean(t *testing.T) {
	// A valid config should have no warnings
	input := `
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
            screen myscreen;
        }
        security-zone untrust {
            interfaces { eth1; }
        }
    }
    screen {
        ids-option myscreen {
            tcp { land; }
        }
    }
    address-book {
        global {
            address srv1 10.0.1.10/32;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow {
                match {
                    source-address any;
                    destination-address srv1;
                    application junos-http;
                }
                then { permit; }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Warnings) > 0 {
		t.Errorf("expected no warnings, got: %v", cfg.Warnings)
	}
}

func TestMultiTermApplication(t *testing.T) {
	input := `applications {
    application ssh-long {
        description "Long SSH sessions";
        term 22 alg ssh protocol tcp destination-port 22 inactivity-timeout 86400;
        term 2222 alg ssh protocol tcp destination-port 2222 inactivity-timeout 86400;
    }
    application FaceTime {
        term 41642_65535 protocol udp source-port 41642-65535 destination-port 3478-3497;
        term 0_41640 protocol udp source-port 0-41640 destination-port 3478-3497;
    }
    application simple-app {
        protocol tcp;
        destination-port 8080;
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// ssh-long should become an implicit application-set with 2 term apps
	as, ok := cfg.Applications.ApplicationSets["ssh-long"]
	if !ok {
		t.Fatal("multi-term app 'ssh-long' should create an implicit application-set")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("ssh-long set: expected 2 members, got %d", len(as.Applications))
	}

	// Check individual term apps
	term22 := cfg.Applications.Applications["ssh-long-22"]
	if term22 == nil {
		t.Fatal("missing term app ssh-long-22")
	}
	if term22.Protocol != "tcp" {
		t.Errorf("ssh-long-22 protocol: got %q, want tcp", term22.Protocol)
	}
	if term22.DestinationPort != "22" {
		t.Errorf("ssh-long-22 dest-port: got %q, want 22", term22.DestinationPort)
	}
	if term22.ALG != "ssh" {
		t.Errorf("ssh-long-22 ALG: got %q, want ssh", term22.ALG)
	}
	if term22.InactivityTimeout != 86400 {
		t.Errorf("ssh-long-22 timeout: got %d, want 86400", term22.InactivityTimeout)
	}

	// Check FaceTime source-port
	ft := cfg.Applications.Applications["FaceTime-41642_65535"]
	if ft == nil {
		t.Fatal("missing term app FaceTime-41642_65535")
	}
	if ft.SourcePort != "41642-65535" {
		t.Errorf("FaceTime source-port: got %q, want 41642-65535", ft.SourcePort)
	}
	if ft.DestinationPort != "3478-3497" {
		t.Errorf("FaceTime dest-port: got %q, want 3478-3497", ft.DestinationPort)
	}

	// simple-app should remain a plain Application (not an app-set)
	if _, isSet := cfg.Applications.ApplicationSets["simple-app"]; isSet {
		t.Error("simple-app should NOT be an application-set")
	}
	simpleApp := cfg.Applications.Applications["simple-app"]
	if simpleApp == nil {
		t.Fatal("missing simple-app")
	}
	if simpleApp.Protocol != "tcp" || simpleApp.DestinationPort != "8080" {
		t.Errorf("simple-app: got proto=%q port=%q", simpleApp.Protocol, simpleApp.DestinationPort)
	}
}

func TestMultiTermApplicationSetSyntax(t *testing.T) {
	// Test flat set syntax for multi-term apps
	tree := &ConfigTree{}
	setCommands := []string{
		"set applications application plex term 32400 protocol tcp destination-port 32400 inactivity-timeout 1800",
		"set applications application plex term 32480 protocol tcp destination-port 32480",
		"set applications application plex term 5001-udp protocol udp destination-port 5001",
	}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// plex should become an implicit application-set
	as, ok := cfg.Applications.ApplicationSets["plex"]
	if !ok {
		t.Fatal("multi-term 'plex' should create an implicit application-set")
	}
	if len(as.Applications) != 3 {
		t.Fatalf("plex set: expected 3 members, got %d", len(as.Applications))
	}

	// Check a term
	term := cfg.Applications.Applications["plex-32400"]
	if term == nil {
		t.Fatal("missing plex-32400")
	}
	if term.InactivityTimeout != 1800 {
		t.Errorf("plex-32400 timeout: got %d, want 1800", term.InactivityTimeout)
	}
}

func TestFormatPath(t *testing.T) {
	input := `interfaces {
    wan0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    trust0 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                trust0.0;
            }
        }
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	// Show just interfaces section
	out := tree.FormatPath([]string{"interfaces"})
	if !strings.Contains(out, "wan0") || !strings.Contains(out, "trust0") {
		t.Errorf("FormatPath(interfaces) should contain both interfaces, got:\n%s", out)
	}
	if strings.Contains(out, "security") {
		t.Error("FormatPath(interfaces) should not contain security section")
	}

	// Show specific interface
	out = tree.FormatPath([]string{"interfaces", "wan0"})
	if !strings.Contains(out, "10.0.1.1/24") {
		t.Errorf("FormatPath(interfaces, wan0) should contain wan0 address, got:\n%s", out)
	}
	if strings.Contains(out, "trust0") {
		t.Error("FormatPath(interfaces, wan0) should not contain trust0")
	}

	// Non-existent path
	out = tree.FormatPath([]string{"interfaces", "nonexistent"})
	if out != "" {
		t.Errorf("FormatPath for non-existent should return empty, got:\n%s", out)
	}

	// Empty path = full config
	out = tree.FormatPath(nil)
	if !strings.Contains(out, "interfaces") || !strings.Contains(out, "security") {
		t.Error("FormatPath(nil) should return full config")
	}
}

func TestPolicyOptions(t *testing.T) {
	input := `policy-options {
    prefix-list management-hosts {
        10.9.9.0/24;
        172.16.50.0/24;
        2001:559:8585:100::d/128;
    }
    policy-statement to_BV-FIREHOUSE {
        term default_v4 {
            from {
                protocol direct;
                route-filter 192.168.50.0/24 exact;
                route-filter 192.168.99.0/24 exact;
            }
            then accept;
        }
        then reject;
    }
}`

	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Check prefix-list
	pl := cfg.PolicyOptions.PrefixLists["management-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list management-hosts")
	}
	if len(pl.Prefixes) != 3 {
		t.Fatalf("management-hosts: expected 3 prefixes, got %d", len(pl.Prefixes))
	}
	if pl.Prefixes[0] != "10.9.9.0/24" {
		t.Errorf("first prefix: got %q, want 10.9.9.0/24", pl.Prefixes[0])
	}

	// Check policy-statement
	ps := cfg.PolicyOptions.PolicyStatements["to_BV-FIREHOUSE"]
	if ps == nil {
		t.Fatal("missing policy-statement to_BV-FIREHOUSE")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(ps.Terms))
	}
	term := ps.Terms[0]
	if term.Name != "default_v4" {
		t.Errorf("term name: got %q, want default_v4", term.Name)
	}
	if term.FromProtocol != "direct" {
		t.Errorf("from protocol: got %q, want direct", term.FromProtocol)
	}
	if len(term.RouteFilters) != 2 {
		t.Fatalf("expected 2 route-filters, got %d", len(term.RouteFilters))
	}
	if term.RouteFilters[0].Prefix != "192.168.50.0/24" {
		t.Errorf("route-filter 0: got %q", term.RouteFilters[0].Prefix)
	}
	if term.RouteFilters[0].MatchType != "exact" {
		t.Errorf("match-type: got %q, want exact", term.RouteFilters[0].MatchType)
	}
	if term.Action != "accept" {
		t.Errorf("action: got %q, want accept", term.Action)
	}
	if ps.DefaultAction != "reject" {
		t.Errorf("default action: got %q, want reject", ps.DefaultAction)
	}
}

func TestPolicyOptionsSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set policy-options prefix-list mgmt 172.16.0.0/12",
		"set policy-options policy-statement export-policy term t1 from protocol direct",
		"set policy-options policy-statement export-policy term t1 from route-filter 10.0.0.0/8 exact",
		"set policy-options policy-statement export-policy term t1 then accept",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	pl := cfg.PolicyOptions.PrefixLists["mgmt"]
	if pl == nil {
		t.Fatal("missing prefix-list mgmt")
	}
	if len(pl.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}

	ps := cfg.PolicyOptions.PolicyStatements["export-policy"]
	if ps == nil {
		t.Fatal("missing policy-statement export-policy")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(ps.Terms))
	}
}

func TestIKEProposalSetSyntax(t *testing.T) {
	setCommands := []string{
		`set security ike proposal ike-aes256 authentication-method pre-shared-keys`,
		`set security ike proposal ike-aes256 encryption-algorithm aes-256-cbc`,
		`set security ike proposal ike-aes256 authentication-algorithm sha-256`,
		`set security ike proposal ike-aes256 dh-group group14`,
		`set security ike proposal ike-aes256 lifetime-seconds 28800`,
		`set security ike policy ike-strong mode main`,
		`set security ike policy ike-strong proposals ike-aes256`,
		`set security ike gateway remote-gw address 203.0.113.1`,
		`set security ike gateway remote-gw ike-policy ike-strong`,
		`set security ike gateway remote-gw external-interface untrust0`,
	}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify IKE proposal
	prop := cfg.Security.IPsec.IKEProposals["ike-aes256"]
	if prop == nil {
		t.Fatal("missing IKE proposal ike-aes256")
	}
	if prop.AuthMethod != "pre-shared-keys" {
		t.Errorf("auth-method = %q, want pre-shared-keys", prop.AuthMethod)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("encryption = %q, want aes-256-cbc", prop.EncryptionAlg)
	}
	if prop.DHGroup != 14 {
		t.Errorf("dh-group = %d, want 14", prop.DHGroup)
	}
	if prop.LifetimeSeconds != 28800 {
		t.Errorf("lifetime = %d, want 28800", prop.LifetimeSeconds)
	}

	// Verify IKE policy
	pol := cfg.Security.IPsec.IKEPolicies["ike-strong"]
	if pol == nil {
		t.Fatal("missing IKE policy ike-strong")
	}
	if pol.Mode != "main" {
		t.Errorf("mode = %q, want main", pol.Mode)
	}
	if pol.Proposals != "ike-aes256" {
		t.Errorf("proposals = %q, want ike-aes256", pol.Proposals)
	}

	// Verify IKE gateway
	gw := cfg.Security.IPsec.Gateways["remote-gw"]
	if gw == nil {
		t.Fatal("missing gateway remote-gw")
	}
	if gw.Address != "203.0.113.1" {
		t.Errorf("address = %q, want 203.0.113.1", gw.Address)
	}
	if gw.IKEPolicy != "ike-strong" {
		t.Errorf("ike-policy = %q, want ike-strong", gw.IKEPolicy)
	}
}

func TestIPsecProposalSetSyntax(t *testing.T) {
	setCommands := []string{
		`set security ipsec proposal esp-aes256 protocol esp`,
		`set security ipsec proposal esp-aes256 encryption-algorithm aes-256-cbc`,
		`set security ipsec proposal esp-aes256 authentication-algorithm hmac-sha-256-128`,
		`set security ipsec proposal esp-aes256 lifetime-seconds 3600`,
		`set security ipsec policy ipsec-strong proposals esp-aes256`,
	}
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Verify IPsec proposal
	prop := cfg.Security.IPsec.Proposals["esp-aes256"]
	if prop == nil {
		t.Fatal("missing IPsec proposal esp-aes256")
	}
	if prop.Protocol != "esp" {
		t.Errorf("protocol = %q, want esp", prop.Protocol)
	}
	if prop.EncryptionAlg != "aes-256-cbc" {
		t.Errorf("encryption = %q, want aes-256-cbc", prop.EncryptionAlg)
	}
	if prop.AuthAlg != "hmac-sha-256-128" {
		t.Errorf("auth-alg = %q, want hmac-sha-256-128", prop.AuthAlg)
	}
	if prop.LifetimeSeconds != 3600 {
		t.Errorf("lifetime = %d, want 3600", prop.LifetimeSeconds)
	}

	// Verify IPsec policy
	pol := cfg.Security.IPsec.Policies["ipsec-strong"]
	if pol == nil {
		t.Fatal("missing IPsec policy ipsec-strong")
	}
	if pol.Proposals != "esp-aes256" {
		t.Errorf("proposals = %q, want esp-aes256", pol.Proposals)
	}
}

func TestBGPGroupExportFamily(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set protocols bgp local-as 64701",
		"set protocols bgp group ebgp-peer family inet unicast",
		"set protocols bgp group ebgp-peer family inet6 unicast",
		"set protocols bgp group ebgp-peer export my-export-policy",
		"set protocols bgp group ebgp-peer peer-as 65002",
		"set protocols bgp group ebgp-peer neighbor 10.1.0.1",
		"set protocols bgp group ebgp-peer neighbor 10.2.0.1",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if bgp.LocalAS != 64701 {
		t.Errorf("LocalAS = %d, want 64701", bgp.LocalAS)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if n.Address != "10.1.0.1" {
		t.Errorf("neighbor 0 address = %q, want 10.1.0.1", n.Address)
	}
	if !n.FamilyInet {
		t.Error("neighbor should have FamilyInet=true")
	}
	if !n.FamilyInet6 {
		t.Error("neighbor should have FamilyInet6=true")
	}
	if len(n.Export) != 1 || n.Export[0] != "my-export-policy" {
		t.Errorf("neighbor export = %v, want [my-export-policy]", n.Export)
	}
}

func TestSystemConfigExtended(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set system host-name test-fw",
		"set system backup-router 192.168.50.1 destination 192.168.0.0/16",
		"set system internet-options no-ipv6-reject-zero-hop-limit",
		"set system services ssh root-login allow",
		"set system services web-management http",
		"set system services web-management https",
		"set system syslog host 192.168.99.3 daemon info",
		"set system syslog file messages any any",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	sys := cfg.System
	if sys.HostName != "test-fw" {
		t.Errorf("HostName = %q, want test-fw", sys.HostName)
	}
	if sys.BackupRouter != "192.168.50.1" {
		t.Errorf("BackupRouter = %q, want 192.168.50.1", sys.BackupRouter)
	}
	if sys.BackupRouterDst != "192.168.0.0/16" {
		t.Errorf("BackupRouterDst = %q, want 192.168.0.0/16", sys.BackupRouterDst)
	}
	if sys.InternetOptions == nil {
		t.Fatal("InternetOptions is nil")
	}
	if !sys.InternetOptions.NoIPv6RejectZeroHopLimit {
		t.Error("NoIPv6RejectZeroHopLimit should be true")
	}
	if sys.Services == nil {
		t.Fatal("Services is nil")
	}
	if sys.Services.SSH == nil || sys.Services.SSH.RootLogin != "allow" {
		t.Errorf("SSH root-login = %v, want allow", sys.Services.SSH)
	}
	if sys.Services.WebManagement == nil {
		t.Fatal("WebManagement is nil")
	}
	if !sys.Services.WebManagement.HTTP {
		t.Error("HTTP should be true")
	}
	if !sys.Services.WebManagement.HTTPS {
		t.Error("HTTPS should be true")
	}
	if sys.Syslog == nil {
		t.Fatal("Syslog is nil")
	}
	if len(sys.Syslog.Hosts) != 1 {
		t.Fatalf("got %d syslog hosts, want 1", len(sys.Syslog.Hosts))
	}
	if sys.Syslog.Hosts[0].Address != "192.168.99.3" {
		t.Errorf("syslog host = %q, want 192.168.99.3", sys.Syslog.Hosts[0].Address)
	}
	if len(sys.Syslog.Files) != 1 {
		t.Fatalf("got %d syslog files, want 1", len(sys.Syslog.Files))
	}
	if sys.Syslog.Files[0].Name != "messages" {
		t.Errorf("syslog file = %q, want messages", sys.Syslog.Files[0].Name)
	}
}

func TestTCPMSSHierarchical(t *testing.T) {
	input := `
security {
    flow {
        tcp-mss {
            ipsec-vpn {
                mss 1360;
            }
            gre-in {
                mss 1360;
            }
            gre-out {
                mss 1360;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Security.Flow.TCPMSSIPsecVPN != 1360 {
		t.Errorf("TCPMSSIPsecVPN = %d, want 1360", cfg.Security.Flow.TCPMSSIPsecVPN)
	}
	if cfg.Security.Flow.TCPMSSGre != 1360 {
		t.Errorf("TCPMSSGre = %d, want 1360", cfg.Security.Flow.TCPMSSGre)
	}
}

func TestZoneSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust interfaces trust0",
		"set security zones security-zone trust interfaces trust1",
		"set security zones security-zone trust screen untrust-screen",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic protocols ospf",
		"set security zones security-zone untrust interfaces untrust0",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone not found")
	}
	if len(trust.Interfaces) != 2 {
		t.Fatalf("trust interfaces = %v, want 2", trust.Interfaces)
	}
	if trust.ScreenProfile != "untrust-screen" {
		t.Errorf("trust screen = %q, want untrust-screen", trust.ScreenProfile)
	}
	if trust.HostInboundTraffic == nil {
		t.Fatal("trust host-inbound-traffic is nil")
	}
	if len(trust.HostInboundTraffic.SystemServices) != 2 {
		t.Errorf("system-services = %v, want [ping ssh]", trust.HostInboundTraffic.SystemServices)
	}
	if len(trust.HostInboundTraffic.Protocols) != 1 || trust.HostInboundTraffic.Protocols[0] != "ospf" {
		t.Errorf("protocols = %v, want [ospf]", trust.HostInboundTraffic.Protocols)
	}

	untrust := cfg.Security.Zones["untrust"]
	if untrust == nil {
		t.Fatal("untrust zone not found")
	}
	if len(untrust.Interfaces) != 1 || untrust.Interfaces[0] != "untrust0" {
		t.Errorf("untrust interfaces = %v, want [untrust0]", untrust.Interfaces)
	}
}

func TestScreenSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security screen ids-option untrust-screen icmp ping-death",
		"set security screen ids-option untrust-screen tcp land",
		"set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000",
		"set security screen ids-option untrust-screen tcp syn-flood attack-threshold 500",
		"set security screen ids-option untrust-screen ip source-route-option",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	profile := cfg.Security.Screen["untrust-screen"]
	if profile == nil {
		t.Fatal("screen profile not found")
	}
	if !profile.ICMP.PingDeath {
		t.Error("PingDeath should be true")
	}
	if !profile.TCP.Land {
		t.Error("Land should be true")
	}
	if profile.TCP.SynFlood == nil {
		t.Fatal("SynFlood is nil")
	}
	if profile.TCP.SynFlood.AlarmThreshold != 1000 {
		t.Errorf("AlarmThreshold = %d, want 1000", profile.TCP.SynFlood.AlarmThreshold)
	}
	if profile.TCP.SynFlood.AttackThreshold != 500 {
		t.Errorf("AttackThreshold = %d, want 500", profile.TCP.SynFlood.AttackThreshold)
	}
	if !profile.IP.SourceRouteOption {
		t.Error("SourceRouteOption should be true")
	}
}

func TestNATSourceSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security nat source pool snat-pool address 203.0.113.0/24",
		"set security nat source rule-set trust-to-untrust from zone trust",
		"set security nat source rule-set trust-to-untrust to zone untrust",
		"set security nat source rule-set trust-to-untrust rule snat-rule match source-address 10.0.0.0/8",
		"set security nat source rule-set trust-to-untrust rule snat-rule then source-nat interface",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	pool := cfg.Security.NAT.SourcePools["snat-pool"]
	if pool == nil {
		t.Fatal("source pool not found")
	}
	if len(pool.Addresses) != 1 || pool.Addresses[0] != "203.0.113.0/24" {
		t.Errorf("pool addresses = %v, want [203.0.113.0/24]", pool.Addresses)
	}

	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.Name != "trust-to-untrust" {
		t.Errorf("rule-set name = %q, want trust-to-untrust", rs.Name)
	}
	if rs.FromZone != "trust" {
		t.Errorf("from zone = %q, want trust", rs.FromZone)
	}
	if rs.ToZone != "untrust" {
		t.Errorf("to zone = %q, want untrust", rs.ToZone)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if rule.Name != "snat-rule" {
		t.Errorf("rule name = %q, want snat-rule", rule.Name)
	}
	if rule.Match.SourceAddress != "10.0.0.0/8" {
		t.Errorf("match source = %q, want 10.0.0.0/8", rule.Match.SourceAddress)
	}
	if !rule.Then.Interface {
		t.Error("then should be source-nat interface")
	}
}

func TestPolicySetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy allow-all match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-all match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow-all match application any",
		"set security policies from-zone trust to-zone untrust policy allow-all then permit",
		"set security policies from-zone trust to-zone untrust policy allow-all then log session-init",
		"set security policies from-zone trust to-zone untrust policy allow-all then count",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("got %d zone-pair policies, want 1", len(cfg.Security.Policies))
	}
	zpp := cfg.Security.Policies[0]
	if zpp.FromZone != "trust" || zpp.ToZone != "untrust" {
		t.Errorf("zones = %s->%s, want trust->untrust", zpp.FromZone, zpp.ToZone)
	}
	if len(zpp.Policies) != 1 {
		t.Fatalf("got %d policies, want 1", len(zpp.Policies))
	}
	pol := zpp.Policies[0]
	if pol.Name != "allow-all" {
		t.Errorf("policy name = %q, want allow-all", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("action = %d, want permit", pol.Action)
	}
	if pol.Log == nil || !pol.Log.SessionInit {
		t.Error("log session-init should be true")
	}
	if !pol.Count {
		t.Error("count should be true")
	}
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "any" {
		t.Errorf("source-address = %v, want [any]", pol.Match.SourceAddresses)
	}
}

func TestApplicationSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application my-http protocol tcp",
		"set applications application my-http destination-port 8080",
		"set applications application-set web-apps application my-http",
		"set applications application-set web-apps application junos-https",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	app := cfg.Applications.Applications["my-http"]
	if app == nil {
		t.Fatal("application my-http not found")
	}
	if app.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", app.Protocol)
	}
	if app.DestinationPort != "8080" {
		t.Errorf("destination-port = %q, want 8080", app.DestinationPort)
	}

	as := cfg.Applications.ApplicationSets["web-apps"]
	if as == nil {
		t.Fatal("application-set web-apps not found")
	}
	if len(as.Applications) != 2 {
		t.Fatalf("got %d apps in set, want 2", len(as.Applications))
	}
}

func TestSecurityLogEnhancements(t *testing.T) {
	input := `
security {
    log {
        mode stream;
        format sd-syslog;
        source-interface reth1.100;
        stream syslog-container {
            format sd-syslog;
            category all;
            host {
                192.168.99.3;
            }
            source-address 172.16.100.1;
        }
        stream filebeat-syslog {
            host {
                192.168.99.106;
                port 9006;
            }
            source-address 192.168.99.1;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	log := cfg.Security.Log
	if log.Mode != "stream" {
		t.Errorf("Mode = %q, want stream", log.Mode)
	}
	if log.Format != "sd-syslog" {
		t.Errorf("Format = %q, want sd-syslog", log.Format)
	}
	if log.SourceInterface != "reth1.100" {
		t.Errorf("SourceInterface = %q, want reth1.100", log.SourceInterface)
	}
	if len(log.Streams) != 2 {
		t.Fatalf("got %d streams, want 2", len(log.Streams))
	}

	s1 := log.Streams["syslog-container"]
	if s1 == nil {
		t.Fatal("missing stream syslog-container")
	}
	if s1.Host != "192.168.99.3" {
		t.Errorf("syslog-container host = %q, want 192.168.99.3", s1.Host)
	}
	if s1.Format != "sd-syslog" {
		t.Errorf("syslog-container format = %q, want sd-syslog", s1.Format)
	}
	if s1.Category != "all" {
		t.Errorf("syslog-container category = %q, want all", s1.Category)
	}
	if s1.SourceAddress != "172.16.100.1" {
		t.Errorf("syslog-container source-address = %q, want 172.16.100.1", s1.SourceAddress)
	}

	s2 := log.Streams["filebeat-syslog"]
	if s2 == nil {
		t.Fatal("missing stream filebeat-syslog")
	}
	if s2.Host != "192.168.99.106" {
		t.Errorf("filebeat-syslog host = %q, want 192.168.99.106", s2.Host)
	}
	if s2.Port != 9006 {
		t.Errorf("filebeat-syslog port = %d, want 9006", s2.Port)
	}
	if s2.SourceAddress != "192.168.99.1" {
		t.Errorf("filebeat-syslog source-address = %q, want 192.168.99.1", s2.SourceAddress)
	}
}

func TestNATMultiZoneBracketList(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set multi-zone-snat {
                from zone [ guest lan dmz ];
                to zone [ Internet-ATT Internet-BCI ];
                rule catch-all {
                    match {
                        source-address 0.0.0.0/0;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
        destination {
            pool web-server {
                address 10.0.1.100/32 port 80;
            }
            rule-set multi-zone-dnat {
                from zone [ Internet-ATT Internet-BCI ];
                rule http-in {
                    match {
                        destination-address 1.2.3.4/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat {
                            pool {
                                web-server;
                            }
                        }
                    }
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Source NAT: 3 from-zones × 2 to-zones = 6 expanded rule-sets
	if len(cfg.Security.NAT.Source) != 6 {
		t.Fatalf("got %d source rule-sets, want 6 (3×2 Cartesian)", len(cfg.Security.NAT.Source))
	}

	// Verify all zone combinations are present
	zonePairs := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		zonePairs[rs.FromZone+"->"+rs.ToZone] = true
		if len(rs.Rules) != 1 || rs.Rules[0].Name != "catch-all" {
			t.Errorf("rule-set %s->%s: expected 1 rule 'catch-all', got %d",
				rs.FromZone, rs.ToZone, len(rs.Rules))
		}
	}
	for _, pair := range []string{
		"guest->Internet-ATT", "guest->Internet-BCI",
		"lan->Internet-ATT", "lan->Internet-BCI",
		"dmz->Internet-ATT", "dmz->Internet-BCI",
	} {
		if !zonePairs[pair] {
			t.Errorf("missing zone pair: %s", pair)
		}
	}

	// Destination NAT: 2 from-zones × 1 to-zone (empty) = 2 expanded rule-sets
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("no destination NAT config")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 2 {
		t.Fatalf("got %d DNAT rule-sets, want 2", len(cfg.Security.NAT.Destination.RuleSets))
	}
	dnatZones := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		dnatZones[rs.FromZone] = true
	}
	if !dnatZones["Internet-ATT"] || !dnatZones["Internet-BCI"] {
		t.Errorf("DNAT from zones = %v, want Internet-ATT + Internet-BCI", dnatZones)
	}
}

func TestNATMultiZoneSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security nat source rule-set internal-to-internet from zone [ guest lan ]",
		"set security nat source rule-set internal-to-internet to zone Internet-ATT",
		"set security nat source rule-set internal-to-internet rule catch-all match source-address 0.0.0.0/0",
		"set security nat source rule-set internal-to-internet rule catch-all then source-nat interface",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// 2 from-zones × 1 to-zone = 2 expanded rule-sets
	if len(cfg.Security.NAT.Source) != 2 {
		t.Fatalf("got %d source rule-sets, want 2", len(cfg.Security.NAT.Source))
	}
	zones := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		zones[rs.FromZone] = true
		if rs.ToZone != "Internet-ATT" {
			t.Errorf("to-zone = %q, want Internet-ATT", rs.ToZone)
		}
	}
	if !zones["guest"] || !zones["lan"] {
		t.Errorf("from zones = %v, want guest + lan", zones)
	}
}

func TestNATSourceOff(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set exempt {
                from zone internal;
                to zone Internet;
                rule no-nat {
                    match {
                        source-address 192.203.228.0/24;
                        destination-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            off;
                        }
                    }
                }
                rule catch-all {
                    match {
                        source-address 0.0.0.0/0;
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if len(rs.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs.Rules))
	}

	// First rule: source-nat off
	r0 := rs.Rules[0]
	if r0.Name != "no-nat" {
		t.Errorf("rule[0] name = %q, want no-nat", r0.Name)
	}
	if !r0.Then.Off {
		t.Error("rule[0] should have Then.Off = true")
	}
	if r0.Then.Interface {
		t.Error("rule[0] should NOT have Then.Interface")
	}

	// Second rule: source-nat interface
	r1 := rs.Rules[1]
	if !r1.Then.Interface {
		t.Error("rule[1] should have Then.Interface = true")
	}
	if r1.Then.Off {
		t.Error("rule[1] should NOT have Then.Off")
	}
}

func TestNATSourceOffSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security nat source rule-set exempt from zone internal",
		"set security nat source rule-set exempt to zone Internet",
		"set security nat source rule-set exempt rule no-nat match source-address 192.203.228.0/24",
		"set security nat source rule-set exempt rule no-nat then source-nat off",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
	}
	if len(cfg.Security.NAT.Source[0].Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Security.NAT.Source[0].Rules))
	}
	r := cfg.Security.NAT.Source[0].Rules[0]
	if !r.Then.Off {
		t.Error("Then.Off should be true")
	}
	if r.Match.SourceAddress != "192.203.228.0/24" {
		t.Errorf("source address = %q, want 192.203.228.0/24", r.Match.SourceAddress)
	}
}

func TestDNATApplicationMatch(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool web-server {
                address 192.168.1.100/32;
            }
            rule-set internet-dnat {
                from zone untrust;
                rule app-match {
                    match {
                        destination-address 1.2.3.4/32;
                        application junos-http;
                    }
                    then {
                        destination-nat {
                            pool {
                                web-server;
                            }
                        }
                    }
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("no destination NAT config")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("got %d DNAT rule-sets, want 1", len(cfg.Security.NAT.Destination.RuleSets))
	}
	r := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if r.Match.Application != "junos-http" {
		t.Errorf("application = %q, want junos-http", r.Match.Application)
	}
	if r.Then.PoolName != "web-server" {
		t.Errorf("pool = %q, want web-server", r.Then.PoolName)
	}
}

func TestInterfaceDescriptionAndRedundantParent(t *testing.T) {
	input := `interfaces {
    ge-0/0/0 {
        description "Uplink to core";
        gigether-options {
            redundant-parent reth0;
        }
    }
    reth0 {
        description "Redundant Ethernet 0";
        unit 0 {
            description "Management VLAN";
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ge := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	if ge.Description != "Uplink to core" {
		t.Errorf("ge description = %q, want %q", ge.Description, "Uplink to core")
	}
	if ge.RedundantParent != "reth0" {
		t.Errorf("redundant-parent = %q, want reth0", ge.RedundantParent)
	}

	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil {
		t.Fatal("reth0 not found")
	}
	if reth.Description != "Redundant Ethernet 0" {
		t.Errorf("reth description = %q, want %q", reth.Description, "Redundant Ethernet 0")
	}
	unit0 := reth.Units[0]
	if unit0 == nil {
		t.Fatal("reth0 unit 0 not found")
	}
	if unit0.Description != "Management VLAN" {
		t.Errorf("unit description = %q, want %q", unit0.Description, "Management VLAN")
	}
}

func TestInterfacePointToPointAndMTU(t *testing.T) {
	input := `interfaces {
    gr-0/0/0 {
        unit 0 {
            point-to-point;
            tunnel {
                source 10.0.0.1;
                destination 10.0.0.2;
                routing-instance {
                    destination my-vrf;
                }
            }
            family inet {
                mtu 1456;
                address 10.255.0.1/30;
            }
            family inet6 {
                mtu 1436;
                address fe80::1/64;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	gr := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if gr == nil {
		t.Fatal("gr-0/0/0 not found")
	}
	unit0 := gr.Units[0]
	if unit0 == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit0.PointToPoint {
		t.Error("point-to-point should be true")
	}
	// MTU: inet has 1456, inet6 has 1436 — takes the smaller
	if unit0.MTU != 1436 {
		t.Errorf("MTU = %d, want 1436", unit0.MTU)
	}
	if gr.Tunnel == nil {
		t.Fatal("tunnel not set")
	}
	if gr.Tunnel.Source != "10.0.0.1" {
		t.Errorf("tunnel source = %q, want 10.0.0.1", gr.Tunnel.Source)
	}
	if gr.Tunnel.Destination != "10.0.0.2" {
		t.Errorf("tunnel destination = %q, want 10.0.0.2", gr.Tunnel.Destination)
	}
	if gr.Tunnel.RoutingInstance != "my-vrf" {
		t.Errorf("tunnel routing-instance = %q, want my-vrf", gr.Tunnel.RoutingInstance)
	}
}

func TestRoutingOptionsExtended(t *testing.T) {
	input := `routing-options {
    autonomous-system 64701;
    rib inet6.0 {
        static {
            route ::/0 next-hop 2001:db8::1;
        }
    }
    static {
        route 0.0.0.0/0 next-hop 10.0.0.1;
        route 10.1.0.0/16 next-hop 10.0.1.1;
    }
    forwarding-table {
        export load-balancing-policy;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ro := cfg.RoutingOptions
	if ro.AutonomousSystem != 64701 {
		t.Errorf("AS = %d, want 64701", ro.AutonomousSystem)
	}
	if ro.ForwardingTableExport != "load-balancing-policy" {
		t.Errorf("forwarding-table export = %q, want load-balancing-policy", ro.ForwardingTableExport)
	}
	if len(ro.StaticRoutes) != 2 {
		t.Fatalf("got %d static routes, want 2", len(ro.StaticRoutes))
	}
	if len(ro.Inet6StaticRoutes) != 1 {
		t.Fatalf("got %d inet6 static routes, want 1", len(ro.Inet6StaticRoutes))
	}
	v6 := ro.Inet6StaticRoutes[0]
	if v6.Destination != "::/0" {
		t.Errorf("inet6 route dest = %q, want ::/0", v6.Destination)
	}
	if len(v6.NextHops) != 1 || v6.NextHops[0].Address != "2001:db8::1" {
		t.Errorf("inet6 route next-hop = %v, want 2001:db8::1", v6.NextHops)
	}
}

func TestPolicyStatementNextHopAndLoadBalance(t *testing.T) {
	input := `policy-options {
    policy-statement load-balancing-policy {
        then {
            load-balance consistent-hash;
        }
    }
    policy-statement to-peer {
        term send-routes {
            from {
                protocol direct;
                prefix-list management-hosts;
                route-filter 10.0.0.0/8 exact;
            }
            then {
                next-hop peer-address;
                accept;
            }
        }
        then reject;
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lb := cfg.PolicyOptions.PolicyStatements["load-balancing-policy"]
	if lb == nil {
		t.Fatal("load-balancing-policy not found")
	}

	peer := cfg.PolicyOptions.PolicyStatements["to-peer"]
	if peer == nil {
		t.Fatal("to-peer not found")
	}
	if len(peer.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(peer.Terms))
	}
	term := peer.Terms[0]
	if term.FromProtocol != "direct" {
		t.Errorf("from protocol = %q, want direct", term.FromProtocol)
	}
	if term.PrefixList != "management-hosts" {
		t.Errorf("prefix-list = %q, want management-hosts", term.PrefixList)
	}
	if term.NextHop != "peer-address" {
		t.Errorf("next-hop = %q, want peer-address", term.NextHop)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
	}
	if len(term.RouteFilters) != 1 {
		t.Fatalf("got %d route-filters, want 1", len(term.RouteFilters))
	}
	if peer.DefaultAction != "reject" {
		t.Errorf("default action = %q, want reject", peer.DefaultAction)
	}
}

func TestPolicyStatementSetSyntax(t *testing.T) {
	cmds := []string{
		"set policy-options policy-statement lb then load-balance consistent-hash",
		"set policy-options policy-statement to-peer term t1 from protocol direct",
		"set policy-options policy-statement to-peer term t1 from prefix-list mgmt",
		"set policy-options policy-statement to-peer term t1 then next-hop peer-address",
		"set policy-options policy-statement to-peer term t1 then accept",
		"set policy-options policy-statement to-peer then reject",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	peer := cfg.PolicyOptions.PolicyStatements["to-peer"]
	if peer == nil {
		t.Fatal("to-peer not found")
	}
	if len(peer.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(peer.Terms))
	}
	term := peer.Terms[0]
	if term.PrefixList != "mgmt" {
		t.Errorf("prefix-list = %q, want mgmt", term.PrefixList)
	}
	if term.NextHop != "peer-address" {
		t.Errorf("next-hop = %q, want peer-address", term.NextHop)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
	}

	lb := cfg.PolicyOptions.PolicyStatements["lb"]
	if lb == nil {
		t.Fatal("lb not found")
	}
}

func TestInterfaceDescriptionSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces ge-0/0/0 description \"Uplink to core\"",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces gr-0/0/0 unit 0 point-to-point",
		"set interfaces gr-0/0/0 unit 0 description \"Tunnel unit\"",
		"set interfaces gr-0/0/0 unit 0 family inet mtu 1420",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	ge := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	if ge.Description != "Uplink to core" {
		t.Errorf("ge description = %q, want %q", ge.Description, "Uplink to core")
	}
	if ge.RedundantParent != "reth0" {
		t.Errorf("redundant-parent = %q, want reth0", ge.RedundantParent)
	}

	gr := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if gr == nil {
		t.Fatal("gr-0/0/0 not found")
	}
	unit0 := gr.Units[0]
	if unit0 == nil {
		t.Fatal("gr unit 0 not found")
	}
	if !unit0.PointToPoint {
		t.Error("point-to-point should be true")
	}
	if unit0.Description != "Tunnel unit" {
		t.Errorf("unit description = %q, want %q", unit0.Description, "Tunnel unit")
	}
	if unit0.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", unit0.MTU)
	}
}

func TestSystemConfigRootAuthAndArchival(t *testing.T) {
	input := `
system {
    root-authentication {
        encrypted-password "$6$abc123";
        ssh-ed25519 "ssh-ed25519 AAAA... user@host";
        ssh-rsa "ssh-rsa AAAA... user@host";
    }
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                "scp://backup@10.0.0.1:/configs";
            }
        }
    }
    master-password {
        pseudorandom-function juniper-prf1;
    }
    license {
        autoupdate {
            url https://ae1.juniper.net/junos/key_retrieval;
        }
    }
    processes {
        utmd disable;
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// root-authentication
	ra := cfg.System.RootAuthentication
	if ra == nil {
		t.Fatal("root-authentication is nil")
	}
	if ra.EncryptedPassword != "$6$abc123" {
		t.Errorf("encrypted-password = %q, want %q", ra.EncryptedPassword, "$6$abc123")
	}
	if len(ra.SSHKeys) != 2 {
		t.Fatalf("ssh keys count = %d, want 2", len(ra.SSHKeys))
	}

	// archival
	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if len(arch.ArchiveSites) != 1 {
		t.Fatalf("archive-sites count = %d, want 1", len(arch.ArchiveSites))
	}
	if arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
		t.Errorf("archive-site = %q", arch.ArchiveSites[0])
	}

	// master-password
	if cfg.System.MasterPassword != "juniper-prf1" {
		t.Errorf("master-password = %q, want %q", cfg.System.MasterPassword, "juniper-prf1")
	}

	// license
	if cfg.System.LicenseAutoUpdate != "https://ae1.juniper.net/junos/key_retrieval" {
		t.Errorf("license autoupdate url = %q", cfg.System.LicenseAutoUpdate)
	}

	// processes
	if len(cfg.System.DisabledProcesses) != 1 || cfg.System.DisabledProcesses[0] != "utmd" {
		t.Errorf("disabled processes = %v, want [utmd]", cfg.System.DisabledProcesses)
	}
}

func TestSystemConfigWebManagementEnhanced(t *testing.T) {
	input := `
system {
    services {
        web-management {
            http {
                interface fxp0.0;
            }
            https {
                system-generated-certificate;
                interface fxp0.0;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management is nil")
	}
	if !wm.HTTP {
		t.Error("HTTP should be true")
	}
	if !wm.HTTPS {
		t.Error("HTTPS should be true")
	}
	if wm.HTTPInterface != "fxp0.0" {
		t.Errorf("HTTP interface = %q, want fxp0.0", wm.HTTPInterface)
	}
	if wm.HTTPSInterface != "fxp0.0" {
		t.Errorf("HTTPS interface = %q, want fxp0.0", wm.HTTPSInterface)
	}
	if !wm.SystemGeneratedCert {
		t.Error("system-generated-certificate should be true")
	}
}

func TestSyslogMultiFacilityAndUser(t *testing.T) {
	input := `
system {
    syslog {
        user * {
            any emergency;
        }
        host 192.168.1.1 {
            any any;
            daemon info;
            change-log info;
            allow-duplicates;
        }
        file messages {
            any notice;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	sl := cfg.System.Syslog
	if sl == nil {
		t.Fatal("syslog is nil")
	}

	// user destination
	if len(sl.Users) != 1 {
		t.Fatalf("users count = %d, want 1", len(sl.Users))
	}
	if sl.Users[0].User != "*" {
		t.Errorf("user = %q, want *", sl.Users[0].User)
	}
	if sl.Users[0].Facility != "any" || sl.Users[0].Severity != "emergency" {
		t.Errorf("user facility/severity = %q/%q, want any/emergency",
			sl.Users[0].Facility, sl.Users[0].Severity)
	}

	// host with multiple facilities
	if len(sl.Hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(sl.Hosts))
	}
	host := sl.Hosts[0]
	if host.Address != "192.168.1.1" {
		t.Errorf("host address = %q", host.Address)
	}
	if !host.AllowDuplicates {
		t.Error("allow-duplicates should be true")
	}
	if len(host.Facilities) != 3 {
		t.Fatalf("host facilities count = %d, want 3", len(host.Facilities))
	}
	// Check each facility
	expected := []SyslogFacility{
		{Facility: "any", Severity: "any"},
		{Facility: "daemon", Severity: "info"},
		{Facility: "change-log", Severity: "info"},
	}
	for i, exp := range expected {
		if host.Facilities[i] != exp {
			t.Errorf("facility[%d] = %+v, want %+v", i, host.Facilities[i], exp)
		}
	}
}

func TestSystemConfigSetSyntax(t *testing.T) {
	cmds := []string{
		"set system root-authentication encrypted-password \"$6$abc\"",
		"set system root-authentication ssh-ed25519 \"ssh-ed25519 AAAA\"",
		"set system master-password pseudorandom-function juniper-prf1",
		"set system license autoupdate url https://example.com/keys",
		"set system processes utmd disable",
		"set system services web-management https system-generated-certificate",
		"set system services web-management https interface fxp0.0",
		"set system syslog user * any emergency",
		"set system syslog host 10.0.0.1 any any",
		"set system syslog host 10.0.0.1 daemon info",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if cfg.System.RootAuthentication == nil {
		t.Fatal("root-authentication is nil")
	}
	if cfg.System.RootAuthentication.EncryptedPassword != "$6$abc" {
		t.Errorf("encrypted-password = %q", cfg.System.RootAuthentication.EncryptedPassword)
	}
	if len(cfg.System.RootAuthentication.SSHKeys) != 1 {
		t.Errorf("ssh keys = %d, want 1", len(cfg.System.RootAuthentication.SSHKeys))
	}
	if cfg.System.MasterPassword != "juniper-prf1" {
		t.Errorf("master-password = %q", cfg.System.MasterPassword)
	}
	if cfg.System.LicenseAutoUpdate != "https://example.com/keys" {
		t.Errorf("license url = %q", cfg.System.LicenseAutoUpdate)
	}
	if len(cfg.System.DisabledProcesses) != 1 || cfg.System.DisabledProcesses[0] != "utmd" {
		t.Errorf("disabled processes = %v", cfg.System.DisabledProcesses)
	}

	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management nil")
	}
	if !wm.HTTPS {
		t.Error("HTTPS should be true")
	}
	if !wm.SystemGeneratedCert {
		t.Error("system-generated-certificate should be true")
	}
	if wm.HTTPSInterface != "fxp0.0" {
		t.Errorf("HTTPS interface = %q", wm.HTTPSInterface)
	}

	// Syslog user
	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Users) != 1 {
		t.Fatal("syslog user not parsed")
	}
	if cfg.System.Syslog.Users[0].User != "*" {
		t.Errorf("syslog user = %q", cfg.System.Syslog.Users[0].User)
	}

	// Syslog host with multiple facilities
	if len(cfg.System.Syslog.Hosts) != 1 {
		t.Fatalf("syslog hosts = %d", len(cfg.System.Syslog.Hosts))
	}
	if len(cfg.System.Syslog.Hosts[0].Facilities) != 2 {
		t.Errorf("syslog host facilities = %d, want 2", len(cfg.System.Syslog.Hosts[0].Facilities))
	}
}

