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
	if r0.Destination != "0.0.0.0/0" || r0.NextHop != "192.168.1.1" {
		t.Errorf("route 0: dest=%s nh=%s", r0.Destination, r0.NextHop)
	}
	if r0.Preference != 5 {
		t.Errorf("route 0: expected default preference 5, got %d", r0.Preference)
	}

	// Discard route
	r2 := cfg.RoutingOptions.StaticRoutes[2]
	if r2.Destination != "192.168.99.0/24" || !r2.Discard {
		t.Errorf("route 2: dest=%s discard=%v", r2.Destination, r2.Discard)
	}

	// Route with custom preference
	r3 := cfg.RoutingOptions.StaticRoutes[3]
	if r3.Destination != "172.16.0.0/12" || r3.NextHop != "10.0.0.3" {
		t.Errorf("route 3: dest=%s nh=%s", r3.Destination, r3.NextHop)
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
	if comcast.StaticRoutes[0].NextHop != "74.93.96.1" {
		t.Errorf("Comcast route next-hop: %s", comcast.StaticRoutes[0].NextHop)
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
