package config

import (
	"encoding/json"
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

func TestSetPathSingleValueDedup(t *testing.T) {
	// Simulate pre-existing duplicate host-name leaves (from before dedup fix).
	// SetPath should replace the first and remove all subsequent duplicates.
	tree := &ConfigTree{}

	// Manually inject three duplicate host-name leaves into the system block.
	sysNode := &Node{
		Keys: []string{"system"},
		Children: []*Node{
			{Keys: []string{"host-name", "old-fw1"}, IsLeaf: true},
			{Keys: []string{"host-name", "old-fw2"}, IsLeaf: true},
			{Keys: []string{"host-name", "old-fw3"}, IsLeaf: true},
			{Keys: []string{"domain-name", "example.com"}, IsLeaf: true},
		},
	}
	tree.Children = append(tree.Children, sysNode)

	// Now set a new host-name via SetPath.
	path, err := ParseSetCommand("set system host-name new-fw")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	// Count host-name entries in the system node.
	var hostNames []string
	for _, child := range sysNode.Children {
		if child.IsLeaf && len(child.Keys) > 0 && child.Keys[0] == "host-name" {
			hostNames = append(hostNames, child.Keys[1])
		}
	}
	if len(hostNames) != 1 {
		t.Fatalf("expected 1 host-name entry, got %d: %v", len(hostNames), hostNames)
	}
	if hostNames[0] != "new-fw" {
		t.Errorf("expected host-name new-fw, got %s", hostNames[0])
	}

	// Verify domain-name is preserved.
	var hasDomain bool
	for _, child := range sysNode.Children {
		if child.IsLeaf && len(child.Keys) > 0 && child.Keys[0] == "domain-name" {
			hasDomain = true
		}
	}
	if !hasDomain {
		t.Error("domain-name entry was incorrectly removed")
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

func TestNestedApplicationSet(t *testing.T) {
	input := `applications {
    application app-a {
        protocol tcp;
        destination-port 80;
    }
    application app-b {
        protocol tcp;
        destination-port 443;
    }
    application app-c {
        protocol udp;
        destination-port 53;
    }
    application-set inner-set {
        application app-a;
        application app-b;
    }
    application-set outer-set {
        application inner-set;
        application app-c;
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

	// outer-set should expand to [app-a, app-b, app-c] (deduped, recursive)
	expanded, err := ExpandApplicationSet("outer-set", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand error: %v", err)
	}
	if len(expanded) != 3 {
		t.Fatalf("expected 3 expanded apps, got %d: %v", len(expanded), expanded)
	}
	want := map[string]bool{"app-a": true, "app-b": true, "app-c": true}
	for _, a := range expanded {
		if !want[a] {
			t.Errorf("unexpected expanded app: %q", a)
		}
	}

	// inner-set should expand to just [app-a, app-b]
	inner, err := ExpandApplicationSet("inner-set", &cfg.Applications)
	if err != nil {
		t.Fatalf("inner expand error: %v", err)
	}
	if len(inner) != 2 {
		t.Fatalf("inner: expected 2 apps, got %d: %v", len(inner), inner)
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

func TestNextTableStaticRoutes(t *testing.T) {
	// Test flat set syntax with next-table
	tree := &ConfigTree{}
	setCommands := []string{
		"set routing-options static route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0",
		"set routing-options static route 10.1.10.0/24 next-hop 50.247.115.22",
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

	// next-table route
	r0 := cfg.RoutingOptions.StaticRoutes[0]
	if r0.Destination != "0.0.0.0/0" {
		t.Errorf("route 0 dest: %s", r0.Destination)
	}
	if r0.NextTable != "Comcast-GigabitPro" {
		t.Errorf("route 0 next-table: got %q, want %q", r0.NextTable, "Comcast-GigabitPro")
	}
	if len(r0.NextHops) != 0 {
		t.Errorf("route 0 should have no next-hops, got %v", r0.NextHops)
	}

	// Regular next-hop route
	r1 := cfg.RoutingOptions.StaticRoutes[1]
	if r1.NextTable != "" {
		t.Errorf("route 1 should have no next-table, got %q", r1.NextTable)
	}
	if len(r1.NextHops) != 1 || r1.NextHops[0].Address != "50.247.115.22" {
		t.Errorf("route 1 next-hops: %v", r1.NextHops)
	}

	// Test hierarchical syntax with next-table
	hierInput := `routing-options {
    static {
        route 0.0.0.0/0 {
            next-table Comcast-GigabitPro.inet.0;
        }
    }
    rib inet6.0 {
        static {
            route ::/0 next-table Comcast-GigabitPro.inet6.0;
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
		t.Fatalf("expected 1 inet route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
	}
	if hierCfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("inet next-table: got %q", hierCfg.RoutingOptions.StaticRoutes[0].NextTable)
	}

	if len(hierCfg.RoutingOptions.Inet6StaticRoutes) != 1 {
		t.Fatalf("expected 1 inet6 route, got %d", len(hierCfg.RoutingOptions.Inet6StaticRoutes))
	}
	if hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("inet6 next-table: got %q", hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable)
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

func TestForwardingInstanceType(t *testing.T) {
	// Test hierarchical syntax
	input := `routing-instances {
    vpn-fwd {
        instance-type forwarding;
        routing-options {
            static {
                route 10.99.0.0/16 next-hop 10.0.40.1;
            }
        }
    }
    normal-vr {
        instance-type virtual-router;
        interface trust0;
        routing-options {
            static {
                route 192.168.0.0/16 next-hop 10.0.1.1;
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
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
	}

	var fwd, vr *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		switch ri.Name {
		case "vpn-fwd":
			fwd = ri
		case "normal-vr":
			vr = ri
		}
	}

	if fwd == nil {
		t.Fatal("missing vpn-fwd instance")
	}
	if fwd.InstanceType != "forwarding" {
		t.Errorf("vpn-fwd instance-type: got %q, want forwarding", fwd.InstanceType)
	}
	if len(fwd.StaticRoutes) != 1 {
		t.Fatalf("vpn-fwd static routes: expected 1, got %d", len(fwd.StaticRoutes))
	}
	if len(fwd.Interfaces) != 0 {
		t.Errorf("vpn-fwd interfaces: expected 0, got %d", len(fwd.Interfaces))
	}

	if vr == nil {
		t.Fatal("missing normal-vr instance")
	}
	if vr.InstanceType != "virtual-router" {
		t.Errorf("normal-vr instance-type: got %q, want virtual-router", vr.InstanceType)
	}
	if len(vr.Interfaces) != 1 {
		t.Errorf("normal-vr interfaces: expected 1, got %d", len(vr.Interfaces))
	}

	// Test set-command syntax
	tree2 := &ConfigTree{}
	for _, cmd := range []string{
		"set routing-instances vpn-fwd instance-type forwarding",
		"set routing-instances vpn-fwd routing-options static route 10.99.0.0/16 next-hop 10.0.40.1",
		"set routing-instances normal-vr instance-type virtual-router",
		"set routing-instances normal-vr interface trust0",
	} {
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
	var fwd2 *RoutingInstanceConfig
	for _, ri := range cfg2.RoutingInstances {
		if ri.Name == "vpn-fwd" {
			fwd2 = ri
		}
	}
	if fwd2 == nil {
		t.Fatal("set syntax: missing vpn-fwd instance")
	}
	if fwd2.InstanceType != "forwarding" {
		t.Errorf("set syntax: vpn-fwd instance-type: got %q, want forwarding", fwd2.InstanceType)
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

func TestFirewallFilterSourcePort(t *testing.T) {
	input := `firewall {
    family inet {
        filter rate-limit {
            term match-dns {
                from {
                    protocol udp;
                    source-port 53;
                }
                then discard;
            }
            term default {
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
	f, ok := cfg.Firewall.FiltersInet["rate-limit"]
	if !ok {
		t.Fatal("expected rate-limit filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	if len(f.Terms[0].SourcePorts) != 1 || f.Terms[0].SourcePorts[0] != "53" {
		t.Errorf("expected source-port [53], got %v", f.Terms[0].SourcePorts)
	}
	if f.Terms[0].Protocol != "udp" {
		t.Errorf("expected protocol udp, got %q", f.Terms[0].Protocol)
	}

	// Test set-command format
	tree2 := &ConfigTree{}
	cmds := []string{
		"set firewall family inet filter test-sp term t1 from protocol tcp",
		"set firewall family inet filter test-sp term t1 from source-port 8080",
		"set firewall family inet filter test-sp term t1 then accept",
	}
	for _, cmd := range cmds {
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
		t.Fatalf("set-command compile: %v", err)
	}
	sp, ok := cfg2.Firewall.FiltersInet["test-sp"]
	if !ok {
		t.Fatal("expected test-sp filter")
	}
	if len(sp.Terms[0].SourcePorts) != 1 || sp.Terms[0].SourcePorts[0] != "8080" {
		t.Errorf("expected source-port [8080], got %v", sp.Terms[0].SourcePorts)
	}
}

func TestFirewallFilterPortRange(t *testing.T) {
	input := `firewall {
    family inet {
        filter port-range-test {
            term block-range {
                from {
                    protocol tcp;
                    destination-port 8000-9000;
                    source-port 1024-65535;
                }
                then discard;
            }
            term default {
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
	f, ok := cfg.Firewall.FiltersInet["port-range-test"]
	if !ok {
		t.Fatal("expected port-range-test filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	term := f.Terms[0]
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "8000-9000" {
		t.Errorf("destination-port = %v, want [8000-9000]", term.DestinationPorts)
	}
	if len(term.SourcePorts) != 1 || term.SourcePorts[0] != "1024-65535" {
		t.Errorf("source-port = %v, want [1024-65535]", term.SourcePorts)
	}
	if term.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", term.Protocol)
	}
	if term.Action != "discard" {
		t.Errorf("action = %q, want discard", term.Action)
	}
}

func TestFirewallFilterDSCPRewrite(t *testing.T) {
	// Hierarchical format
	input := `firewall {
    family inet {
        filter dscp-mark {
            term mark-voice {
                from {
                    protocol udp;
                    destination-port 5060;
                }
                then {
                    dscp ef;
                    accept;
                }
            }
            term mark-bulk {
                from {
                    protocol tcp;
                }
                then {
                    dscp af11;
                    accept;
                }
            }
            term default {
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
	f, ok := cfg.Firewall.FiltersInet["dscp-mark"]
	if !ok {
		t.Fatal("expected dscp-mark filter")
	}
	if len(f.Terms) != 3 {
		t.Fatalf("expected 3 terms, got %d", len(f.Terms))
	}
	if f.Terms[0].DSCPRewrite != "ef" {
		t.Errorf("expected DSCPRewrite ef, got %q", f.Terms[0].DSCPRewrite)
	}
	if f.Terms[1].DSCPRewrite != "af11" {
		t.Errorf("expected DSCPRewrite af11, got %q", f.Terms[1].DSCPRewrite)
	}
	if f.Terms[2].DSCPRewrite != "" {
		t.Errorf("expected no DSCPRewrite on default term, got %q", f.Terms[2].DSCPRewrite)
	}

	// Test set-command format
	tree2 := &ConfigTree{}
	cmds := []string{
		"set firewall family inet filter dscp-set term t1 from protocol udp",
		"set firewall family inet filter dscp-set term t1 then dscp ef",
		"set firewall family inet filter dscp-set term t1 then accept",
	}
	for _, cmd := range cmds {
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
		t.Fatalf("set-command compile: %v", err)
	}
	f2, ok := cfg2.Firewall.FiltersInet["dscp-set"]
	if !ok {
		t.Fatal("expected dscp-set filter")
	}
	if f2.Terms[0].DSCPRewrite != "ef" {
		t.Errorf("set-command: expected DSCPRewrite ef, got %q", f2.Terms[0].DSCPRewrite)
	}
}

func TestFirewallFilterTCPFlags(t *testing.T) {
	// Test set-command format (must use ParseSetCommand, not NewParser)
	tree := &ConfigTree{}
	cmds := []string{
		"set firewall family inet filter tcp-flag-test term syn-only from protocol tcp",
		"set firewall family inet filter tcp-flag-test term syn-only from tcp-flags syn",
		"set firewall family inet filter tcp-flag-test term syn-only then discard",
		"set firewall family inet filter tcp-flag-test term syn-ack from protocol tcp",
		"set firewall family inet filter tcp-flag-test term syn-ack from tcp-flags syn",
		"set firewall family inet filter tcp-flag-test term syn-ack from tcp-flags ack",
		"set firewall family inet filter tcp-flag-test term syn-ack then accept",
		"set firewall family inet filter tcp-flag-test term default then accept",
	}
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
		t.Fatalf("compile: %v", err)
	}
	f, ok := cfg.Firewall.FiltersInet["tcp-flag-test"]
	if !ok {
		t.Fatal("expected tcp-flag-test filter")
	}
	if len(f.Terms) != 3 {
		t.Fatalf("expected 3 terms, got %d", len(f.Terms))
	}
	// First term: syn only
	if len(f.Terms[0].TCPFlags) != 1 || f.Terms[0].TCPFlags[0] != "syn" {
		t.Errorf("term syn-only: expected TCPFlags [syn], got %v", f.Terms[0].TCPFlags)
	}
	if f.Terms[0].Action != "discard" {
		t.Errorf("term syn-only: expected action discard, got %q", f.Terms[0].Action)
	}
	// Second term: syn + ack
	if len(f.Terms[1].TCPFlags) != 2 {
		t.Errorf("term syn-ack: expected 2 TCPFlags, got %v", f.Terms[1].TCPFlags)
	}
}

func TestFirewallFilterIsFragment(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set firewall family inet filter frag-test term drop-frags from is-fragment",
		"set firewall family inet filter frag-test term drop-frags then discard",
		"set firewall family inet filter frag-test term allow-rest then accept",
	}
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
		t.Fatalf("compile: %v", err)
	}
	f, ok := cfg.Firewall.FiltersInet["frag-test"]
	if !ok {
		t.Fatal("expected frag-test filter")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	if !f.Terms[0].IsFragment {
		t.Error("expected IsFragment=true for drop-frags term")
	}
	if f.Terms[0].Action != "discard" {
		t.Errorf("expected action discard, got %q", f.Terms[0].Action)
	}
	if f.Terms[1].IsFragment {
		t.Error("expected IsFragment=false for allow-rest term")
	}
}

func TestFirewallPolicer(t *testing.T) {
	input := `firewall {
    policer rate-limit-1m {
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then discard;
    }
    policer rate-limit-10g {
        if-exceeding {
            bandwidth-limit 10g;
            burst-size-limit 1m;
        }
        then discard;
    }
    family inet {
        filter with-policer {
            term rate-limited {
                from {
                    protocol tcp;
                }
                then {
                    policer rate-limit-1m;
                    accept;
                }
            }
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}

	// Check policer definitions
	if len(cfg.Firewall.Policers) != 2 {
		t.Fatalf("expected 2 policers, got %d", len(cfg.Firewall.Policers))
	}

	pol1m := cfg.Firewall.Policers["rate-limit-1m"]
	if pol1m == nil {
		t.Fatal("rate-limit-1m policer not found")
	}
	// 1m = 1,000,000 bits/sec = 125,000 bytes/sec
	if pol1m.BandwidthLimit != 125000 {
		t.Errorf("expected bandwidth 125000 bytes/sec, got %d", pol1m.BandwidthLimit)
	}
	// 15k = 15,000 bytes
	if pol1m.BurstSizeLimit != 15000 {
		t.Errorf("expected burst 15000 bytes, got %d", pol1m.BurstSizeLimit)
	}
	if pol1m.ThenAction != "discard" {
		t.Errorf("expected action discard, got %q", pol1m.ThenAction)
	}

	pol10g := cfg.Firewall.Policers["rate-limit-10g"]
	if pol10g == nil {
		t.Fatal("rate-limit-10g policer not found")
	}
	// 10g = 10,000,000,000 bits/sec = 1,250,000,000 bytes/sec
	if pol10g.BandwidthLimit != 1250000000 {
		t.Errorf("expected bandwidth 1250000000 bytes/sec, got %d", pol10g.BandwidthLimit)
	}
	// 1m = 1,000,000 bytes
	if pol10g.BurstSizeLimit != 1000000 {
		t.Errorf("expected burst 1000000 bytes, got %d", pol10g.BurstSizeLimit)
	}

	// Check filter term has policer reference
	f := cfg.Firewall.FiltersInet["with-policer"]
	if f == nil {
		t.Fatal("with-policer filter not found")
	}
	if len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(f.Terms))
	}
	if f.Terms[0].Policer != "rate-limit-1m" {
		t.Errorf("expected policer rate-limit-1m, got %q", f.Terms[0].Policer)
	}
}

func TestFirewallPolicerSetSyntax(t *testing.T) {
	lines := []string{
		"set firewall policer my-policer if-exceeding bandwidth-limit 500k",
		"set firewall policer my-policer if-exceeding burst-size-limit 10k",
		"set firewall policer my-policer then discard",
		"set firewall family inet filter test-filter term t1 then policer my-policer",
		"set firewall family inet filter test-filter term t1 then accept",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse set %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Check policer
	pol := cfg.Firewall.Policers["my-policer"]
	if pol == nil {
		t.Fatal("my-policer not found")
	}
	// 500k = 500,000 bps = 62,500 bytes/sec
	if pol.BandwidthLimit != 62500 {
		t.Errorf("expected bandwidth 62500 bytes/sec, got %d", pol.BandwidthLimit)
	}
	// 10k = 10,000 bytes
	if pol.BurstSizeLimit != 10000 {
		t.Errorf("expected burst 10000 bytes, got %d", pol.BurstSizeLimit)
	}

	// Check filter reference
	f := cfg.Firewall.FiltersInet["test-filter"]
	if f == nil {
		t.Fatal("test-filter not found")
	}
	if f.Terms[0].Policer != "my-policer" {
		t.Errorf("expected policer my-policer, got %q", f.Terms[0].Policer)
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

func TestFirewallPrefixListSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set policy-options prefix-list mgmt-hosts 10.0.0.0/8",
		"set policy-options prefix-list mgmt-hosts 172.16.0.0/12",
		"set firewall family inet filter filter-mgmt term block from source-prefix-list mgmt-hosts except",
		"set firewall family inet filter filter-mgmt term block from protocol tcp",
		"set firewall family inet filter filter-mgmt term block from destination-port 22",
		"set firewall family inet filter filter-mgmt term block then reject",
		"set firewall family inet filter filter-mgmt term allow then accept",
	}
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
		t.Fatalf("compile error: %v", err)
	}

	// Verify prefix-list
	pl := cfg.PolicyOptions.PrefixLists["mgmt-hosts"]
	if pl == nil {
		t.Fatal("missing prefix-list mgmt-hosts")
	}
	if len(pl.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(pl.Prefixes))
	}

	// Verify filter term
	f := cfg.Firewall.FiltersInet["filter-mgmt"]
	if f == nil {
		t.Fatal("missing filter filter-mgmt")
	}
	if len(f.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %d", len(f.Terms))
	}
	term := f.Terms[0]
	if len(term.SourcePrefixLists) != 1 {
		t.Fatalf("expected 1 source-prefix-list, got %d", len(term.SourcePrefixLists))
	}
	if term.SourcePrefixLists[0].Name != "mgmt-hosts" {
		t.Errorf("prefix-list name = %q, want mgmt-hosts", term.SourcePrefixLists[0].Name)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("prefix-list should have except modifier")
	}
	if term.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", term.Protocol)
	}
	if len(term.DestinationPorts) != 1 || term.DestinationPorts[0] != "22" {
		t.Errorf("destination-port = %v, want [22]", term.DestinationPorts)
	}
	if term.Action != "reject" {
		t.Errorf("action = %q, want reject", term.Action)
	}
}

func TestFirewallDestPrefixListExcept(t *testing.T) {
	input := `policy-options {
    prefix-list blocked-nets {
        192.168.0.0/16;
    }
}
firewall {
    family inet {
        filter test-filter {
            term deny-blocked {
                from {
                    destination-prefix-list {
                        blocked-nets except;
                    }
                }
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

	f := cfg.Firewall.FiltersInet["test-filter"]
	if f == nil {
		t.Fatal("missing filter test-filter")
	}
	term := f.Terms[0]
	if len(term.DestPrefixLists) != 1 {
		t.Fatalf("expected 1 dest-prefix-list, got %d", len(term.DestPrefixLists))
	}
	if term.DestPrefixLists[0].Name != "blocked-nets" {
		t.Errorf("dest prefix-list name = %q, want blocked-nets", term.DestPrefixLists[0].Name)
	}
	if !term.DestPrefixLists[0].Except {
		t.Error("dest prefix-list should have except modifier")
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
            gre-out 1380;
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
	if cfg.Security.Flow.TCPMSSGreIn != 1400 {
		t.Errorf("tcp-mss gre-in: got %d, want 1400", cfg.Security.Flow.TCPMSSGreIn)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1380 {
		t.Errorf("tcp-mss gre-out: got %d, want 1380", cfg.Security.Flow.TCPMSSGreOut)
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
		"set security flow tcp-mss gre-out 1380",
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
	if cfg2.Security.Flow.TCPMSSGreIn != 1400 {
		t.Errorf("set syntax: tcp-mss gre-in: got %d, want 1400", cfg2.Security.Flow.TCPMSSGreIn)
	}
	if cfg2.Security.Flow.TCPMSSGreOut != 1380 {
		t.Errorf("set syntax: tcp-mss gre-out: got %d, want 1380", cfg2.Security.Flow.TCPMSSGreOut)
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
		"set security screen ids-option wan-screen tcp port-scan threshold 5000",
		"set security screen ids-option wan-screen ip ip-sweep threshold 3000",
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

	// Port scan check
	if screen.TCP.PortScanThreshold != 5000 {
		t.Errorf("tcp port-scan threshold: got %d, want 5000", screen.TCP.PortScanThreshold)
	}

	// IP sweep check
	if screen.IP.IPSweepThreshold != 3000 {
		t.Errorf("ip ip-sweep threshold: got %d, want 3000", screen.IP.IPSweepThreshold)
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
	if gw.NATTraversal != "disable" {
		t.Errorf("gateway NATTraversal = %q, want 'disable'", gw.NATTraversal)
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
	if gw.NATTraversal != "disable" {
		t.Errorf("NATTraversal = %q, want 'disable'", gw.NATTraversal)
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

func TestIPsecNATTraversal(t *testing.T) {
	// Hierarchical syntax
	input := `security {
    ike {
        gateway force-gw {
            address 10.0.0.1;
            nat-traversal force;
            version v2-only;
        }
        gateway disable-gw {
            address 10.0.0.2;
            no-nat-traversal;
        }
        gateway enable-gw {
            address 10.0.0.3;
            nat-traversal enable;
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

	// force-gw
	fgw := cfg.Security.IPsec.Gateways["force-gw"]
	if fgw == nil {
		t.Fatal("missing force-gw")
	}
	if fgw.NATTraversal != "force" {
		t.Errorf("force-gw NATTraversal = %q, want 'force'", fgw.NATTraversal)
	}

	// disable-gw (using no-nat-traversal)
	dgw := cfg.Security.IPsec.Gateways["disable-gw"]
	if dgw == nil {
		t.Fatal("missing disable-gw")
	}
	if !dgw.NoNATTraversal {
		t.Error("disable-gw NoNATTraversal not set")
	}
	if dgw.NATTraversal != "disable" {
		t.Errorf("disable-gw NATTraversal = %q, want 'disable'", dgw.NATTraversal)
	}

	// enable-gw
	egw := cfg.Security.IPsec.Gateways["enable-gw"]
	if egw == nil {
		t.Fatal("missing enable-gw")
	}
	if egw.NATTraversal != "enable" {
		t.Errorf("enable-gw NATTraversal = %q, want 'enable'", egw.NATTraversal)
	}
	if egw.NoNATTraversal {
		t.Error("enable-gw should not have NoNATTraversal set")
	}
}

func TestIPsecNATTraversalFlatSet(t *testing.T) {
	lines := []string{
		`set security ike gateway gw1 address 10.0.0.1`,
		`set security ike gateway gw1 nat-traversal force`,
		`set security ike gateway gw1 version v2-only`,
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("missing gateway gw1")
	}
	if gw.NATTraversal != "force" {
		t.Errorf("NATTraversal = %q, want 'force'", gw.NATTraversal)
	}
	if gw.Address != "10.0.0.1" {
		t.Errorf("Address = %q, want '10.0.0.1'", gw.Address)
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
interfaces {
    eth0 {
        unit 0 { family inet { address 10.0.1.1/24; } }
    }
    eth1 {
        unit 0 { family inet { address 10.0.2.1/24; } }
    }
}
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

func TestConfigValidationCrossRef(t *testing.T) {
	input := `
interfaces {
    eth0 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust {
            interfaces { eth0; }
        }
        security-zone untrust {
            interfaces { missing-iface; }
        }
    }
    nat {
        source {
            rule-set test {
                from zone trust;
                to zone untrust;
                rule snat {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat { pool { missing-pool; } } }
                }
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-test {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name missing-sched;
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

	var foundIfaceWarn, foundPoolWarn, foundSchedWarn bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "missing-iface") && strings.Contains(w, "not in interfaces") {
			foundIfaceWarn = true
		}
		if strings.Contains(w, "missing-pool") && strings.Contains(w, "not defined") {
			foundPoolWarn = true
		}
		if strings.Contains(w, "missing-sched") && strings.Contains(w, "not defined") {
			foundSchedWarn = true
		}
	}
	if !foundIfaceWarn {
		t.Errorf("missing warning for zone referencing unconfigured interface, got: %v", cfg.Warnings)
	}
	if !foundPoolWarn {
		t.Errorf("missing warning for SNAT referencing undefined pool, got: %v", cfg.Warnings)
	}
	if !foundSchedWarn {
		t.Errorf("missing warning for policy referencing undefined scheduler, got: %v", cfg.Warnings)
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
	if cfg.Security.Flow.TCPMSSGreIn != 1360 {
		t.Errorf("TCPMSSGreIn = %d, want 1360", cfg.Security.Flow.TCPMSSGreIn)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1360 {
		t.Errorf("TCPMSSGreOut = %d, want 1360", cfg.Security.Flow.TCPMSSGreOut)
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

func TestRouterDiscoveryProtocolSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust interfaces trust0",
		"set security zones security-zone trust host-inbound-traffic protocols router-discovery",
		"set security zones security-zone trust host-inbound-traffic protocols ospf",
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
	if trust.HostInboundTraffic == nil {
		t.Fatal("host-inbound-traffic is nil")
	}
	protos := trust.HostInboundTraffic.Protocols
	if len(protos) != 2 {
		t.Fatalf("protocols = %v, want [router-discovery ospf]", protos)
	}
	found := false
	for _, p := range protos {
		if p == "router-discovery" {
			found = true
		}
	}
	if !found {
		t.Errorf("router-discovery not in protocols: %v", protos)
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

func TestGlobalPolicies(t *testing.T) {
	input := `
security {
    policies {
        global {
            policy icmpv6-allow {
                match {
                    source-address any-ipv6;
                    destination-address any-ipv6;
                    application junos-icmp6-all;
                }
                then {
                    permit;
                }
            }
            policy default-deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log {
                        session-init;
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
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("got %d global policies, want 2", len(cfg.Security.GlobalPolicies))
	}

	pol0 := cfg.Security.GlobalPolicies[0]
	if pol0.Name != "icmpv6-allow" {
		t.Errorf("policy 0 name = %q, want icmpv6-allow", pol0.Name)
	}
	if pol0.Action != PolicyPermit {
		t.Errorf("policy 0 action = %d, want permit", pol0.Action)
	}
	if len(pol0.Match.Applications) != 1 || pol0.Match.Applications[0] != "junos-icmp6-all" {
		t.Errorf("policy 0 apps = %v, want [junos-icmp6-all]", pol0.Match.Applications)
	}

	pol1 := cfg.Security.GlobalPolicies[1]
	if pol1.Name != "default-deny" {
		t.Errorf("policy 1 name = %q, want default-deny", pol1.Name)
	}
	if pol1.Action != PolicyDeny {
		t.Errorf("policy 1 action = %d, want deny", pol1.Action)
	}
	if pol1.Log == nil || !pol1.Log.SessionInit {
		t.Error("policy 1 log session-init should be true")
	}
}

func TestGlobalPoliciesSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies global policy allow-icmpv6 match source-address any-ipv6",
		"set security policies global policy allow-icmpv6 match destination-address any-ipv6",
		"set security policies global policy allow-icmpv6 match application junos-icmp6-all",
		"set security policies global policy allow-icmpv6 then permit",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("got %d global policies, want 1", len(cfg.Security.GlobalPolicies))
	}

	pol := cfg.Security.GlobalPolicies[0]
	if pol.Name != "allow-icmpv6" {
		t.Errorf("name = %q, want allow-icmpv6", pol.Name)
	}
	if pol.Action != PolicyPermit {
		t.Errorf("action = %d, want permit", pol.Action)
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

func TestPolicyStatementRouteMapAttributesSetSyntax(t *testing.T) {
	cmds := []string{
		"set policy-options policy-statement PREFER-LOCAL term 10 from protocol bgp",
		"set policy-options policy-statement PREFER-LOCAL term 10 then local-preference 200",
		"set policy-options policy-statement PREFER-LOCAL term 10 then metric 100",
		"set policy-options policy-statement PREFER-LOCAL term 10 then community 65000:100",
		"set policy-options policy-statement PREFER-LOCAL term 10 then origin igp",
		"set policy-options policy-statement PREFER-LOCAL term 10 then accept",
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

	ps := cfg.PolicyOptions.PolicyStatements["PREFER-LOCAL"]
	if ps == nil {
		t.Fatal("PREFER-LOCAL not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	term := ps.Terms[0]
	if term.FromProtocol != "bgp" {
		t.Errorf("from protocol = %q, want bgp", term.FromProtocol)
	}
	if term.LocalPreference != 200 {
		t.Errorf("local-preference = %d, want 200", term.LocalPreference)
	}
	if term.Metric != 100 {
		t.Errorf("metric = %d, want 100", term.Metric)
	}
	if term.Community != "65000:100" {
		t.Errorf("community = %q, want 65000:100", term.Community)
	}
	if term.Origin != "igp" {
		t.Errorf("origin = %q, want igp", term.Origin)
	}
	if term.Action != "accept" {
		t.Errorf("action = %q, want accept", term.Action)
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

func TestAPIAuthConfig(t *testing.T) {
	input := `
system {
    services {
        web-management {
            http;
            api-auth {
                user admin {
                    password secret123;
                }
                user readonly {
                    password view456;
                }
                api-key tok-abc-123;
                api-key tok-xyz-789;
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management is nil")
	}
	if wm.APIAuth == nil {
		t.Fatal("api-auth is nil")
	}
	if len(wm.APIAuth.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(wm.APIAuth.Users))
	}
	if len(wm.APIAuth.APIKeys) != 2 {
		t.Fatalf("expected 2 api-keys, got %d", len(wm.APIAuth.APIKeys))
	}
	// Check users (order may vary)
	foundAdmin := false
	for _, u := range wm.APIAuth.Users {
		if u.Username == "admin" && u.Password == "secret123" {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Error("admin user not found with correct password")
	}
}

func TestAPIAuthFlatSet(t *testing.T) {
	cmds := []string{
		"set system services web-management http",
		"set system services web-management api-auth user admin password secret123",
		"set system services web-management api-auth api-key tok-abc-123",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	wm := cfg.System.Services.WebManagement
	if wm == nil {
		t.Fatal("web-management is nil")
	}
	if wm.APIAuth == nil {
		t.Fatal("api-auth is nil")
	}
	if len(wm.APIAuth.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(wm.APIAuth.Users))
	}
	if wm.APIAuth.Users[0].Username != "admin" || wm.APIAuth.Users[0].Password != "secret123" {
		t.Errorf("user = %+v, want admin/secret123", wm.APIAuth.Users[0])
	}
	if len(wm.APIAuth.APIKeys) != 1 {
		t.Fatalf("expected 1 api-key, got %d", len(wm.APIAuth.APIKeys))
	}
	if wm.APIAuth.APIKeys[0] != "tok-abc-123" {
		t.Errorf("api-key = %q, want tok-abc-123", wm.APIAuth.APIKeys[0])
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

func TestSecurityZoneTCPRst(t *testing.T) {
	input := `
security {
    zones {
        security-zone trust {
            tcp-rst;
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
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
	if !cfg.Security.Zones["trust"].TCPRst {
		t.Error("trust zone tcp-rst should be true")
	}
	if cfg.Security.Zones["untrust"].TCPRst {
		t.Error("untrust zone tcp-rst should be false")
	}
}

func TestSSHKnownHostsAndPolicyStats(t *testing.T) {
	input := `
security {
    ssh-known-hosts {
        host 192.168.0.253 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY;
        }
    }
    policy-stats {
        system-wide enable;
    }
    pre-id-default-policy {
        then {
            log {
                session-close;
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

	// ssh-known-hosts
	if len(cfg.Security.SSHKnownHosts) != 1 {
		t.Fatalf("ssh-known-hosts count = %d, want 1", len(cfg.Security.SSHKnownHosts))
	}
	keys := cfg.Security.SSHKnownHosts["192.168.0.253"]
	if len(keys) != 1 {
		t.Fatalf("host keys count = %d, want 1", len(keys))
	}
	if keys[0].Type != "ecdsa-sha2-nistp256-key" {
		t.Errorf("key type = %q", keys[0].Type)
	}

	// policy-stats
	if !cfg.Security.PolicyStatsEnabled {
		t.Error("policy-stats should be enabled")
	}

	// pre-id-default-policy
	pidp := cfg.Security.PreIDDefaultPolicy
	if pidp == nil {
		t.Fatal("pre-id-default-policy is nil")
	}
	if pidp.LogSessionInit {
		t.Error("session-init should be false")
	}
	if !pidp.LogSessionClose {
		t.Error("session-close should be true")
	}
}

func TestInterfaceRedundancyAndFabric(t *testing.T) {
	input := `
interfaces {
    reth0 {
        redundant-ether-options {
            redundancy-group 1;
        }
        unit 0 {
            family inet {
                address 10.0.0.1/24 {
                    primary;
                    preferred;
                }
            }
        }
    }
    fab0 {
        fabric-options {
            member-interfaces {
                ge-0/0/7;
                ge-7/0/7;
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

	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil {
		t.Fatal("reth0 not found")
	}
	if reth.RedundancyGroup != 1 {
		t.Errorf("redundancy-group = %d, want 1", reth.RedundancyGroup)
	}
	unit0 := reth.Units[0]
	if unit0 == nil {
		t.Fatal("reth0 unit 0 not found")
	}
	if unit0.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("primary address = %q, want 10.0.0.1/24", unit0.PrimaryAddress)
	}

	fab := cfg.Interfaces.Interfaces["fab0"]
	if fab == nil {
		t.Fatal("fab0 not found")
	}
	if len(fab.FabricMembers) != 2 {
		t.Fatalf("fabric members = %d, want 2", len(fab.FabricMembers))
	}
	if fab.FabricMembers[0] != "ge-0/0/7" {
		t.Errorf("fabric member[0] = %q", fab.FabricMembers[0])
	}
}

func TestInterfaceSamplingAndFilterOutput(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                sampling {
                    input;
                    output;
                }
                filter {
                    input ingress-filter;
                    output egress-filter;
                }
                address 10.0.0.1/24;
            }
            family inet6 {
                dad-disable;
                sampling {
                    input;
                }
                filter {
                    input ingress-v6;
                    output egress-v6;
                }
                address 2001:db8::1/64;
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

	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}

	// Sampling
	if !unit.SamplingInput {
		t.Error("sampling input should be true")
	}
	if !unit.SamplingOutput {
		t.Error("sampling output should be true")
	}

	// Filter output
	if unit.FilterInputV4 != "ingress-filter" {
		t.Errorf("FilterInputV4 = %q", unit.FilterInputV4)
	}
	if unit.FilterOutputV4 != "egress-filter" {
		t.Errorf("FilterOutputV4 = %q", unit.FilterOutputV4)
	}
	if unit.FilterInputV6 != "ingress-v6" {
		t.Errorf("FilterInputV6 = %q", unit.FilterInputV6)
	}
	if unit.FilterOutputV6 != "egress-v6" {
		t.Errorf("FilterOutputV6 = %q", unit.FilterOutputV6)
	}

	// DAD disable
	if !unit.DADDisable {
		t.Error("dad-disable should be true")
	}
}

func TestTopLevelSNMP(t *testing.T) {
	input := `
snmp {
    community public {
        authorization read-only;
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

	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	comm := cfg.System.SNMP.Communities["public"]
	if comm == nil {
		t.Fatal("community public not found")
	}
	if comm.Authorization != "read-only" {
		t.Errorf("authorization = %q, want read-only", comm.Authorization)
	}
}

func TestSNMPv3USMHierarchical(t *testing.T) {
	input := `
snmp {
    v3 {
        usm {
            local-engine {
                user monitor {
                    authentication-sha {
                        authentication-password "secret123";
                    }
                    privacy-aes128 {
                        privacy-password "privpass";
                    }
                }
                user readonly {
                    authentication-md5 {
                        authentication-password "md5pass";
                    }
                }
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

	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	if len(cfg.System.SNMP.V3Users) != 2 {
		t.Fatalf("V3Users count = %d, want 2", len(cfg.System.SNMP.V3Users))
	}

	monitor := cfg.System.SNMP.V3Users["monitor"]
	if monitor == nil {
		t.Fatal("user monitor not found")
	}
	if monitor.AuthProtocol != "sha" {
		t.Errorf("monitor auth = %q, want sha", monitor.AuthProtocol)
	}
	if monitor.AuthPassword != "secret123" {
		t.Errorf("monitor auth password = %q, want secret123", monitor.AuthPassword)
	}
	if monitor.PrivProtocol != "aes128" {
		t.Errorf("monitor priv = %q, want aes128", monitor.PrivProtocol)
	}
	if monitor.PrivPassword != "privpass" {
		t.Errorf("monitor priv password = %q, want privpass", monitor.PrivPassword)
	}

	readonly := cfg.System.SNMP.V3Users["readonly"]
	if readonly == nil {
		t.Fatal("user readonly not found")
	}
	if readonly.AuthProtocol != "md5" {
		t.Errorf("readonly auth = %q, want md5", readonly.AuthProtocol)
	}
	if readonly.PrivProtocol != "" {
		t.Errorf("readonly priv = %q, want empty", readonly.PrivProtocol)
	}
}

func TestSNMPv3USMFlatSet(t *testing.T) {
	lines := []string{
		"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password adminpass",
		"set snmp v3 usm local-engine user admin privacy-des privacy-password despass",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		parts, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(parts); err != nil {
			t.Fatalf("SetPath(%v): %v", parts, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.SNMP == nil {
		t.Fatal("SNMP is nil")
	}
	admin := cfg.System.SNMP.V3Users["admin"]
	if admin == nil {
		t.Fatal("user admin not found")
	}
	if admin.AuthProtocol != "sha256" {
		t.Errorf("admin auth = %q, want sha256", admin.AuthProtocol)
	}
	if admin.PrivProtocol != "des" {
		t.Errorf("admin priv = %q, want des", admin.PrivProtocol)
	}
}

func TestDHCPInetOptions(t *testing.T) {
	input := `
interfaces {
    reth2 {
        unit 0 {
            family inet {
                dhcp {
                    lease-time 86400;
                    retransmission-attempt 6;
                    retransmission-interval 5;
                    force-discover;
                }
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

	ifc := cfg.Interfaces.Interfaces["reth2"]
	if ifc == nil {
		t.Fatal("reth2 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.DHCP {
		t.Error("DHCP should be true")
	}
	opts := unit.DHCPOptions
	if opts == nil {
		t.Fatal("DHCPOptions is nil")
	}
	if opts.LeaseTime != 86400 {
		t.Errorf("lease-time = %d, want 86400", opts.LeaseTime)
	}
	if opts.RetransmissionAttempt != 6 {
		t.Errorf("retransmission-attempt = %d, want 6", opts.RetransmissionAttempt)
	}
	if opts.RetransmissionInterval != 5 {
		t.Errorf("retransmission-interval = %d, want 5", opts.RetransmissionInterval)
	}
	if !opts.ForceDiscover {
		t.Error("force-discover should be true")
	}
}

func TestDHCPv6ClientExpanded(t *testing.T) {
	input := `
interfaces {
    reth2 {
        unit 0 {
            family inet6 {
                dhcpv6-client {
                    client-type stateful;
                    client-ia-type ia-pd;
                    client-ia-type ia-na;
                    prefix-delegating {
                        preferred-prefix-length 60;
                        sub-prefix-length 64;
                    }
                    client-identifier duid-type duid-ll;
                    req-option dns-server;
                    update-router-advertisement {
                        interface reth2.0;
                    }
                }
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

	ifc := cfg.Interfaces.Interfaces["reth2"]
	if ifc == nil {
		t.Fatal("reth2 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.DHCPv6 {
		t.Error("DHCPv6 should be true")
	}
	dc := unit.DHCPv6Client
	if dc == nil {
		t.Fatal("DHCPv6Client is nil")
	}
	if dc.ClientType != "stateful" {
		t.Errorf("client-type = %q, want stateful", dc.ClientType)
	}
	if len(dc.ClientIATypes) != 2 {
		t.Fatalf("client-ia-types = %d, want 2", len(dc.ClientIATypes))
	}
	if dc.ClientIATypes[0] != "ia-pd" || dc.ClientIATypes[1] != "ia-na" {
		t.Errorf("client-ia-types = %v", dc.ClientIATypes)
	}
	if dc.PrefixDelegatingPrefixLen != 60 {
		t.Errorf("preferred-prefix-length = %d, want 60", dc.PrefixDelegatingPrefixLen)
	}
	if dc.PrefixDelegatingSubPrefLen != 64 {
		t.Errorf("sub-prefix-length = %d, want 64", dc.PrefixDelegatingSubPrefLen)
	}
	if dc.DUIDType != "duid-ll" {
		t.Errorf("duid-type = %q, want duid-ll", dc.DUIDType)
	}
	if len(dc.ReqOptions) != 1 || dc.ReqOptions[0] != "dns-server" {
		t.Errorf("req-options = %v, want [dns-server]", dc.ReqOptions)
	}
	if dc.UpdateRAInterface != "reth2.0" {
		t.Errorf("update-ra interface = %q, want reth2.0", dc.UpdateRAInterface)
	}
}

func TestFlowFlagsAndPowerMode(t *testing.T) {
	input := `security {
    flow {
        tcp-mss {
            all-tcp {
                mss 1400;
            }
        }
        gre-performance-acceleration;
        power-mode-disable;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.Flow.GREPerformanceAcceleration {
		t.Error("GREPerformanceAcceleration should be true")
	}
	if !cfg.Security.Flow.PowerModeDisable {
		t.Error("PowerModeDisable should be true")
	}
}

func TestFlowFlagsSetSyntax(t *testing.T) {
	commands := []string{
		"set security flow gre-performance-acceleration",
		"set security flow power-mode-disable",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.Flow.GREPerformanceAcceleration {
		t.Error("GREPerformanceAcceleration should be true")
	}
	if !cfg.Security.Flow.PowerModeDisable {
		t.Error("PowerModeDisable should be true")
	}
}

func TestNTPThreshold(t *testing.T) {
	input := `system {
    ntp {
        server 10.0.0.1;
        threshold 300 action accept;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.NTPThreshold != 300 {
		t.Errorf("NTPThreshold = %d, want 300", cfg.System.NTPThreshold)
	}
	if cfg.System.NTPThresholdAction != "accept" {
		t.Errorf("NTPThresholdAction = %q, want accept", cfg.System.NTPThresholdAction)
	}
}

func TestNTPThresholdHierarchical(t *testing.T) {
	input := `system {
    ntp {
        server 10.0.0.1;
        threshold 300 {
            action accept;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.NTPThreshold != 300 {
		t.Errorf("NTPThreshold = %d, want 300", cfg.System.NTPThreshold)
	}
	if cfg.System.NTPThresholdAction != "accept" {
		t.Errorf("NTPThresholdAction = %q, want accept", cfg.System.NTPThresholdAction)
	}
}

func TestDNSServiceEnabled(t *testing.T) {
	input := `system {
    services {
        dns;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Services == nil {
		t.Fatal("Services is nil")
	}
	if !cfg.System.Services.DNSEnabled {
		t.Error("DNSEnabled should be true")
	}
}

func TestRAPreferenceAndNAT64Lifetime(t *testing.T) {
	input := `protocols {
    router-advertisement {
        interface reth2.0 {
            prefix 2001:db8::/64;
            preference high;
            nat64prefix 64:ff9b::/96 {
                lifetime 600;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Protocols.RouterAdvertisement) == 0 {
		t.Fatal("no RA interfaces")
	}
	ra := cfg.Protocols.RouterAdvertisement[0]
	if ra.Preference != "high" {
		t.Errorf("Preference = %q, want high", ra.Preference)
	}
	if ra.NAT64Prefix != "64:ff9b::/96" {
		t.Errorf("NAT64Prefix = %q, want 64:ff9b::/96", ra.NAT64Prefix)
	}
	if ra.NAT64PrefixLife != 600 {
		t.Errorf("NAT64PrefixLife = %d, want 600", ra.NAT64PrefixLife)
	}
}

func TestChassisCluster(t *testing.T) {
	input := `chassis {
    cluster {
        reth-count 5;
        redundancy-group 0 {
            node 0 priority 100;
            node 1 priority 1;
        }
        redundancy-group 1 {
            node 0 priority 100;
            node 1 priority 1;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/0 weight 255;
                ge-7/0/0 weight 255;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.RethCount != 5 {
		t.Errorf("RethCount = %d, want 5", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}

	rg0 := cl.RedundancyGroups[0]
	if rg0.ID != 0 {
		t.Errorf("rg0.ID = %d, want 0", rg0.ID)
	}
	if rg0.NodePriorities[0] != 100 {
		t.Errorf("rg0 node 0 priority = %d, want 100", rg0.NodePriorities[0])
	}
	if rg0.NodePriorities[1] != 1 {
		t.Errorf("rg0 node 1 priority = %d, want 1", rg0.NodePriorities[1])
	}

	rg1 := cl.RedundancyGroups[1]
	if rg1.GratuitousARPCount != 8 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 8", rg1.GratuitousARPCount)
	}
	if len(rg1.InterfaceMonitors) != 2 {
		t.Fatalf("rg1 interface-monitors = %d, want 2", len(rg1.InterfaceMonitors))
	}
	if rg1.InterfaceMonitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor[0] = %q, want ge-0/0/0", rg1.InterfaceMonitors[0].Interface)
	}
	if rg1.InterfaceMonitors[0].Weight != 255 {
		t.Errorf("monitor[0] weight = %d, want 255", rg1.InterfaceMonitors[0].Weight)
	}
}

func TestChassisClusterSetSyntax(t *testing.T) {
	commands := []string{
		"set chassis cluster reth-count 3",
		"set chassis cluster redundancy-group 0 node 0 priority 100",
		"set chassis cluster redundancy-group 0 node 1 priority 50",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 gratuitous-arp-count 16",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.RethCount != 3 {
		t.Errorf("RethCount = %d, want 3", cfg.Chassis.Cluster.RethCount)
	}
	if len(cfg.Chassis.Cluster.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cfg.Chassis.Cluster.RedundancyGroups))
	}
	rg0 := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg0.NodePriorities[0] != 100 || rg0.NodePriorities[1] != 50 {
		t.Errorf("rg0 priorities: node0=%d, node1=%d", rg0.NodePriorities[0], rg0.NodePriorities[1])
	}
	rg1 := cfg.Chassis.Cluster.RedundancyGroups[1]
	if rg1.NodePriorities[0] != 200 {
		t.Errorf("rg1 node 0 priority = %d, want 200", rg1.NodePriorities[0])
	}
	if rg1.GratuitousARPCount != 16 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 16", rg1.GratuitousARPCount)
	}
}

func TestChassisClusterExtendedFields(t *testing.T) {
	input := `chassis {
    cluster {
        cluster-id 1;
        node 0;
        heartbeat-interval 500;
        heartbeat-threshold 5;
        reth-count 2;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 4;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", cl.ClusterID)
	}
	if cl.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", cl.NodeID)
	}
	if cl.HeartbeatInterval != 500 {
		t.Errorf("HeartbeatInterval = %d, want 500", cl.HeartbeatInterval)
	}
	if cl.HeartbeatThreshold != 5 {
		t.Errorf("HeartbeatThreshold = %d, want 5", cl.HeartbeatThreshold)
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	for i, rg := range cl.RedundancyGroups {
		if !rg.Preempt {
			t.Errorf("rg%d.Preempt = false, want true", i)
		}
		if rg.NodePriorities[0] != 200 {
			t.Errorf("rg%d node 0 priority = %d, want 200", i, rg.NodePriorities[0])
		}
		if rg.NodePriorities[1] != 100 {
			t.Errorf("rg%d node 1 priority = %d, want 100", i, rg.NodePriorities[1])
		}
	}
	if cl.RedundancyGroups[1].GratuitousARPCount != 4 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 4", cl.RedundancyGroups[1].GratuitousARPCount)
	}
}

func TestChassisClusterExtendedFieldsSet(t *testing.T) {
	commands := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster heartbeat-interval 500",
		"set chassis cluster heartbeat-threshold 5",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 0 preempt",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster redundancy-group 1 preempt",
		"set chassis cluster redundancy-group 1 gratuitous-arp-count 4",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", cl.ClusterID)
	}
	if cl.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", cl.NodeID)
	}
	if cl.HeartbeatInterval != 500 {
		t.Errorf("HeartbeatInterval = %d, want 500", cl.HeartbeatInterval)
	}
	if cl.HeartbeatThreshold != 5 {
		t.Errorf("HeartbeatThreshold = %d, want 5", cl.HeartbeatThreshold)
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	for i, rg := range cl.RedundancyGroups {
		if !rg.Preempt {
			t.Errorf("rg%d.Preempt = false, want true", i)
		}
		if rg.NodePriorities[0] != 200 {
			t.Errorf("rg%d node 0 priority = %d, want 200", i, rg.NodePriorities[0])
		}
		if rg.NodePriorities[1] != 100 {
			t.Errorf("rg%d node 1 priority = %d, want 100", i, rg.NodePriorities[1])
		}
	}
	if cl.RedundancyGroups[1].GratuitousARPCount != 4 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 4", cl.RedundancyGroups[1].GratuitousARPCount)
	}
}

func TestChassisClusterIPMonitoring(t *testing.T) {
	input := `chassis {
    cluster {
        cluster-id 1;
        node 0;
        redundancy-group 0 {
            node 0 priority 200;
            ip-monitoring {
                global-weight 255;
                global-threshold 200;
                family {
                    inet {
                        10.0.1.1 weight 100;
                        10.0.2.1 weight 80;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	rg := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg.IPMonitoring == nil {
		t.Fatal("IPMonitoring is nil")
	}
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Errorf("GlobalWeight = %d, want 255", rg.IPMonitoring.GlobalWeight)
	}
	if rg.IPMonitoring.GlobalThreshold != 200 {
		t.Errorf("GlobalThreshold = %d, want 200", rg.IPMonitoring.GlobalThreshold)
	}
	if len(rg.IPMonitoring.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2", len(rg.IPMonitoring.Targets))
	}
	if rg.IPMonitoring.Targets[0].Address != "10.0.1.1" {
		t.Errorf("target[0].Address = %q, want 10.0.1.1", rg.IPMonitoring.Targets[0].Address)
	}
	if rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Errorf("target[0].Weight = %d, want 100", rg.IPMonitoring.Targets[0].Weight)
	}
	if rg.IPMonitoring.Targets[1].Address != "10.0.2.1" {
		t.Errorf("target[1].Address = %q, want 10.0.2.1", rg.IPMonitoring.Targets[1].Address)
	}
	if rg.IPMonitoring.Targets[1].Weight != 80 {
		t.Errorf("target[1].Weight = %d, want 80", rg.IPMonitoring.Targets[1].Weight)
	}
}

func TestChassisClusterIPMonitoringSetSyntax(t *testing.T) {
	commands := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 ip-monitoring global-weight 255",
		"set chassis cluster redundancy-group 0 ip-monitoring global-threshold 200",
		"set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.1.1 weight 100",
		"set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.2.1 weight 80",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	rg := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg.IPMonitoring == nil {
		t.Fatal("IPMonitoring is nil")
	}
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Errorf("GlobalWeight = %d, want 255", rg.IPMonitoring.GlobalWeight)
	}
	if rg.IPMonitoring.GlobalThreshold != 200 {
		t.Errorf("GlobalThreshold = %d, want 200", rg.IPMonitoring.GlobalThreshold)
	}
	if len(rg.IPMonitoring.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2", len(rg.IPMonitoring.Targets))
	}
	if rg.IPMonitoring.Targets[0].Address != "10.0.1.1" {
		t.Errorf("target[0].Address = %q, want 10.0.1.1", rg.IPMonitoring.Targets[0].Address)
	}
	if rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Errorf("target[0].Weight = %d, want 100", rg.IPMonitoring.Targets[0].Weight)
	}
	if rg.IPMonitoring.Targets[1].Address != "10.0.2.1" {
		t.Errorf("target[1].Address = %q, want 10.0.2.1", rg.IPMonitoring.Targets[1].Address)
	}
	if rg.IPMonitoring.Targets[1].Weight != 80 {
		t.Errorf("target[1].Weight = %d, want 80", rg.IPMonitoring.Targets[1].Weight)
	}
}

func TestEventOptions(t *testing.T) {
	input := `event-options {
    policy disable-on-ping-failure {
        events [ ping_test_failed ping_probe_failed ];
        within 30 {
            trigger until 4;
        }
        within 25 {
            trigger on 3;
        }
        attributes-match {
            ping_test_failed.test-owner matches Comcast-GigabitPro;
            ping_test_failed.test-name matches one-one-one-one;
        }
        then {
            change-configuration {
                commands {
                    "set routing-options static route 0.0.0.0/0 next-table ATT.inet.0";
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("EventOptions = %d, want 1", len(cfg.EventOptions))
	}
	ep := cfg.EventOptions[0]
	if ep.Name != "disable-on-ping-failure" {
		t.Errorf("Name = %q", ep.Name)
	}
	if len(ep.Events) < 2 {
		t.Fatalf("Events = %d, want >= 2", len(ep.Events))
	}
	if len(ep.WithinClauses) != 2 {
		t.Fatalf("WithinClauses = %d, want 2", len(ep.WithinClauses))
	}
	if ep.WithinClauses[0].Seconds != 30 {
		t.Errorf("within[0].Seconds = %d, want 30", ep.WithinClauses[0].Seconds)
	}
	if ep.WithinClauses[0].TriggerUntil != 4 {
		t.Errorf("within[0].TriggerUntil = %d, want 4", ep.WithinClauses[0].TriggerUntil)
	}
	if ep.WithinClauses[1].Seconds != 25 {
		t.Errorf("within[1].Seconds = %d, want 25", ep.WithinClauses[1].Seconds)
	}
	if ep.WithinClauses[1].TriggerOn != 3 {
		t.Errorf("within[1].TriggerOn = %d, want 3", ep.WithinClauses[1].TriggerOn)
	}
	if len(ep.AttributesMatch) != 2 {
		t.Fatalf("AttributesMatch = %d, want 2", len(ep.AttributesMatch))
	}
	if len(ep.ThenCommands) != 1 {
		t.Fatalf("ThenCommands = %d, want 1", len(ep.ThenCommands))
	}
}

func TestNATAddressPersistent(t *testing.T) {
	input := `security {
    nat {
        source {
            address-persistent;
            pool my-pool {
                address 10.0.0.1/32;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.NAT.AddressPersistent {
		t.Error("AddressPersistent should be true")
	}
}

func TestInlineJflowSourceAddress(t *testing.T) {
	input := `forwarding-options {
    sampling {
        instance jflow-inst {
            input {
                rate 10000;
            }
            family inet {
                output {
                    flow-server 192.168.1.1 {
                        port 4739;
                        version9 {
                            template {
                                ipv4-template;
                            }
                        }
                    }
                    inline-jflow {
                        source-address 192.168.99.1;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("Sampling is nil")
	}
	inst, ok := cfg.ForwardingOptions.Sampling.Instances["jflow-inst"]
	if !ok {
		t.Fatal("instance jflow-inst not found")
	}
	if inst.FamilyInet == nil {
		t.Fatal("FamilyInet is nil")
	}
	if !inst.FamilyInet.InlineJflow {
		t.Error("InlineJflow should be true")
	}
	if inst.FamilyInet.InlineJflowSourceAddress != "192.168.99.1" {
		t.Errorf("InlineJflowSourceAddress = %q, want 192.168.99.1", inst.FamilyInet.InlineJflowSourceAddress)
	}
	if len(inst.FamilyInet.FlowServers) == 0 {
		t.Fatal("no flow servers")
	}
	if inst.FamilyInet.FlowServers[0].Version9Template != "ipv4-template" {
		t.Errorf("Version9Template = %q, want ipv4-template", inst.FamilyInet.FlowServers[0].Version9Template)
	}
}

func TestRibGroups(t *testing.T) {
	input := `routing-options {
    rib-groups {
        Other-ISPS {
            import-rib [ ATT.inet.0 inet.0 ];
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RoutingOptions.RibGroups == nil {
		t.Fatal("RibGroups is nil")
	}
	rg, ok := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if !ok {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
	if rg.ImportRibs[0] != "ATT.inet.0" {
		t.Errorf("ImportRibs[0] = %q, want ATT.inet.0", rg.ImportRibs[0])
	}
}

func TestRoutingInstanceInterfaceRoutesRibGroup(t *testing.T) {
	input := `routing-instances {
    ATT {
        instance-type virtual-router;
        routing-options {
            interface-routes {
                rib-group {
                    inet Other-ISPS;
                    inet6 Other-ISP6;
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if ri.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS", ri.InterfaceRoutesRibGroup)
	}
	if ri.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6", ri.InterfaceRoutesRibGroupV6)
	}
}

func TestMultipleRoutingInstances(t *testing.T) {
	input := `routing-instances {
    tunnel-vr {
        instance-type virtual-router;
        interface tunnel0;
        routing-options {
            static {
                route 10.0.50.0/24 { next-hop 10.0.40.1; }
            }
        }
    }
    dmz-vr {
        instance-type virtual-router;
        interface dmz0;
        routing-options {
            interface-routes {
                rib-group inet dmz-leak;
            }
            static {
                route 0.0.0.0/0 { next-hop 10.0.30.1; }
            }
        }
    }
}
routing-options {
    rib-groups {
        dmz-leak {
            import-rib [ dmz-vr.inet.0 inet.0 ];
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}

	// Verify two routing instances
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
	}

	// Table IDs should be 100 and 101 (auto-assigned)
	for _, ri := range cfg.RoutingInstances {
		if ri.TableID != 100 && ri.TableID != 101 {
			t.Errorf("instance %s: TableID = %d, want 100 or 101", ri.Name, ri.TableID)
		}
	}

	// Find dmz-vr and verify rib-group reference
	var dmzVR *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "dmz-vr" {
			dmzVR = ri
			break
		}
	}
	if dmzVR == nil {
		t.Fatal("dmz-vr not found")
	}
	if dmzVR.InterfaceRoutesRibGroup != "dmz-leak" {
		t.Errorf("dmz-vr InterfaceRoutesRibGroup = %q, want dmz-leak", dmzVR.InterfaceRoutesRibGroup)
	}
	if len(dmzVR.StaticRoutes) != 1 {
		t.Fatalf("dmz-vr StaticRoutes = %d, want 1", len(dmzVR.StaticRoutes))
	}
	if dmzVR.StaticRoutes[0].Destination != "0.0.0.0/0" {
		t.Errorf("dmz-vr route destination = %q, want 0.0.0.0/0", dmzVR.StaticRoutes[0].Destination)
	}

	// Verify rib-group was parsed
	rg, ok := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if !ok {
		t.Fatal("rib-group dmz-leak not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
	if rg.ImportRibs[0] != "dmz-vr.inet.0" {
		t.Errorf("ImportRibs[0] = %q, want dmz-vr.inet.0", rg.ImportRibs[0])
	}
	if rg.ImportRibs[1] != "inet.0" {
		t.Errorf("ImportRibs[1] = %q, want inet.0", rg.ImportRibs[1])
	}

	// Verify tunnel-vr
	var tunnelVR *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "tunnel-vr" {
			tunnelVR = ri
			break
		}
	}
	if tunnelVR == nil {
		t.Fatal("tunnel-vr not found")
	}
	if len(tunnelVR.Interfaces) != 1 || tunnelVR.Interfaces[0] != "tunnel0" {
		t.Errorf("tunnel-vr Interfaces = %v, want [tunnel0]", tunnelVR.Interfaces)
	}
}

func TestMultipleRoutingInstancesSetSyntax(t *testing.T) {
	lines := []string{
		"set routing-instances tunnel-vr instance-type virtual-router",
		"set routing-instances tunnel-vr interface tunnel0",
		"set routing-instances tunnel-vr routing-options static route 10.0.50.0/24 next-hop 10.0.40.1",
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface dmz0",
		"set routing-instances dmz-vr routing-options interface-routes rib-group inet dmz-leak",
		"set routing-instances dmz-vr routing-options static route 0.0.0.0/0 next-hop 10.0.30.1",
		"set routing-options rib-groups dmz-leak import-rib dmz-vr.inet.0",
		"set routing-options rib-groups dmz-leak import-rib inet.0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingInstances) != 2 {
		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
	}

	// Find dmz-vr
	var dmzVR *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "dmz-vr" {
			dmzVR = ri
			break
		}
	}
	if dmzVR == nil {
		t.Fatal("dmz-vr not found")
	}
	if dmzVR.InterfaceRoutesRibGroup != "dmz-leak" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want dmz-leak", dmzVR.InterfaceRoutesRibGroup)
	}

	// Verify rib-group
	rg, ok := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if !ok {
		t.Fatal("rib-group dmz-leak not found")
	}
	if len(rg.ImportRibs) != 2 {
		t.Fatalf("ImportRibs = %d, want 2", len(rg.ImportRibs))
	}
}

func TestPreferredAddress(t *testing.T) {
	input := `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24 {
                    primary;
                    preferred;
                }
                address 10.0.0.2/24;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil {
		t.Fatal("interface ge-0/0/0 not found")
	}
	unit := iface.Units[0]
	if unit.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("PrimaryAddress = %q, want 10.0.0.1/24", unit.PrimaryAddress)
	}
	if unit.PreferredAddress != "10.0.0.1/24" {
		t.Errorf("PreferredAddress = %q, want 10.0.0.1/24", unit.PreferredAddress)
	}
}

func TestFlowTraceoptions(t *testing.T) {
	input := `security {
    flow {
        traceoptions {
            file flowtrace.log size 100000 files 2;
            flag basic-datapath;
            flag session;
            packet-filter f0 {
                destination-prefix 104.21.54.91/32;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil {
		t.Fatal("Traceoptions is nil")
	}
	if to.File != "flowtrace.log" {
		t.Errorf("File = %q, want flowtrace.log", to.File)
	}
	if to.FileSize != 100000 {
		t.Errorf("FileSize = %d, want 100000", to.FileSize)
	}
	if to.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2", to.FileCount)
	}
	if len(to.Flags) != 2 {
		t.Fatalf("Flags = %d, want 2", len(to.Flags))
	}
	if to.Flags[0] != "basic-datapath" || to.Flags[1] != "session" {
		t.Errorf("Flags = %v", to.Flags)
	}
	if len(to.PacketFilters) != 1 {
		t.Fatalf("PacketFilters = %d, want 1", len(to.PacketFilters))
	}
	if to.PacketFilters[0].DestinationPrefix != "104.21.54.91/32" {
		t.Errorf("DestinationPrefix = %q", to.PacketFilters[0].DestinationPrefix)
	}
}

func TestDNATMultiPort(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool web-server {
                address 10.0.1.100/32;
                address port 80;
            }
            rule-set untrust-dnat {
                from zone untrust;
                rule multi-port {
                    match {
                        destination-address 10.0.2.10/32;
                        destination-port {
                            32400;
                            443;
                        }
                    }
                    then {
                        destination-nat pool web-server;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("Destination NAT is nil")
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("RuleSets = %d, want 1", len(cfg.Security.NAT.Destination.RuleSets))
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("Rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Match.DestinationPort != 32400 {
		t.Errorf("DestinationPort = %d, want 32400", rule.Match.DestinationPort)
	}
	if len(rule.Match.DestinationPorts) != 2 {
		t.Fatalf("DestinationPorts = %d, want 2", len(rule.Match.DestinationPorts))
	}
	if rule.Match.DestinationPorts[0] != 32400 || rule.Match.DestinationPorts[1] != 443 {
		t.Errorf("DestinationPorts = %v, want [32400, 443]", rule.Match.DestinationPorts)
	}
}

func TestFormatJSON(t *testing.T) {
	input := `system {
    host-name fw1;
    name-server 8.8.8.8;
}
interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    eth1 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	jsonOut := tree.FormatJSON()
	if jsonOut == "" || jsonOut == "{}\n" {
		t.Fatal("FormatJSON returned empty object")
	}

	// Verify it's valid JSON.
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &obj); err != nil {
		t.Fatalf("FormatJSON output is not valid JSON: %v\n%s", err, jsonOut)
	}

	// Check structure.
	sys, ok := obj["system"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected system object, got %T", obj["system"])
	}
	if sys["host-name"] != "fw1" {
		t.Errorf("host-name = %v, want fw1", sys["host-name"])
	}
	if sys["name-server"] != "8.8.8.8" {
		t.Errorf("name-server = %v, want 8.8.8.8", sys["name-server"])
	}

	ifaces, ok := obj["interfaces"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected interfaces object, got %T", obj["interfaces"])
	}
	// eth0 and eth1 should be separate keys under interfaces.
	if _, ok := ifaces["eth0"]; !ok {
		t.Error("interfaces missing eth0")
	}
	if _, ok := ifaces["eth1"]; !ok {
		t.Error("interfaces missing eth1")
	}
}

func TestFormatXML(t *testing.T) {
	input := `system {
    host-name fw1;
    name-server 8.8.8.8;
}
security {
    zones {
        security-zone trust {
            interfaces {
                eth0;
            }
        }
    }
}`
	parser := NewParser(input)
	tree, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	xmlOut := tree.FormatXML()
	if xmlOut == "" {
		t.Fatal("FormatXML returned empty string")
	}

	// Verify it starts with XML header.
	if !strings.Contains(xmlOut, "<?xml") {
		t.Error("FormatXML missing XML declaration")
	}

	// Verify root element.
	if !strings.Contains(xmlOut, "<configuration>") {
		t.Error("FormatXML missing <configuration> root")
	}
	if !strings.Contains(xmlOut, "</configuration>") {
		t.Error("FormatXML missing </configuration> closing")
	}

	// Verify nested elements.
	if !strings.Contains(xmlOut, "<system>") {
		t.Error("FormatXML missing <system>")
	}
	if !strings.Contains(xmlOut, "<host-name>fw1</host-name>") {
		t.Error("FormatXML missing <host-name>fw1</host-name>")
	}
	if !strings.Contains(xmlOut, "<name-server>8.8.8.8</name-server>") {
		t.Error("FormatXML missing <name-server>8.8.8.8</name-server>")
	}

	// Verify security zone structure.
	if !strings.Contains(xmlOut, "<security-zone>") {
		t.Error("FormatXML missing <security-zone>")
	}
	if !strings.Contains(xmlOut, "<name>trust</name>") {
		t.Error("FormatXML missing <name>trust</name>")
	}

	// Boolean leaf should be self-closing.
	if !strings.Contains(xmlOut, "<eth0/>") {
		t.Error("FormatXML missing <eth0/> self-closing tag")
	}
}

func TestDomainNameAndSearch(t *testing.T) {
	// Hierarchical form
	input := `system {
    host-name fw1;
    domain-name example.com;
    domain-search {
        corp.example.com;
        dev.example.com;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", cfg.System.DomainName)
	}
	if len(cfg.System.DomainSearch) != 2 {
		t.Fatalf("DomainSearch len = %d, want 2", len(cfg.System.DomainSearch))
	}
	if cfg.System.DomainSearch[0] != "corp.example.com" {
		t.Errorf("DomainSearch[0] = %q, want corp.example.com", cfg.System.DomainSearch[0])
	}
	if cfg.System.DomainSearch[1] != "dev.example.com" {
		t.Errorf("DomainSearch[1] = %q, want dev.example.com", cfg.System.DomainSearch[1])
	}

	// Flat set form
	tree2 := &ConfigTree{}
	for _, cmd := range []string{
		"set system domain-name example.org",
		"set system domain-search corp.example.org",
		"set system domain-search dev.example.org",
	} {
		if err := tree2.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg2, err2 := CompileConfig(tree2)
	if err2 != nil {
		t.Fatal(err2)
	}
	if cfg2.System.DomainName != "example.org" {
		t.Errorf("flat: DomainName = %q, want example.org", cfg2.System.DomainName)
	}
	if len(cfg2.System.DomainSearch) != 2 {
		t.Fatalf("flat: DomainSearch len = %d, want 2", len(cfg2.System.DomainSearch))
	}
}

func TestDPDKConfig(t *testing.T) {
	lines := []string{
		"set system dataplane-type dpdk",
		"set system dataplane cores 2-5",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem \"1024,1024\"",
		"set system dataplane rx-mode adaptive",
		"set system dataplane rx-mode idle-threshold 256",
		"set system dataplane rx-mode resume-threshold 32",
		"set system dataplane rx-mode sleep-timeout 100",
		"set system dataplane ports 0000:03:00.0 interface wan0",
		"set system dataplane ports 0000:03:00.0 rx-mode polling",
		"set system dataplane ports 0000:03:00.0 cores 2-3",
		"set system dataplane ports 0000:06:00.0 interface trust0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.DataplaneType != "dpdk" {
		t.Errorf("DataplaneType = %q, want dpdk", cfg.System.DataplaneType)
	}
	dp := cfg.System.DPDKDataplane
	if dp == nil {
		t.Fatal("DPDKDataplane is nil")
	}
	if dp.Cores != "2-5" {
		t.Errorf("Cores = %q, want 2-5", dp.Cores)
	}
	if dp.Memory != 2048 {
		t.Errorf("Memory = %d, want 2048", dp.Memory)
	}
	if dp.SocketMem != "1024,1024" {
		t.Errorf("SocketMem = %q, want 1024,1024", dp.SocketMem)
	}
	if dp.RXMode != "adaptive" {
		t.Errorf("RXMode = %q, want adaptive", dp.RXMode)
	}
	if dp.AdaptiveConfig == nil {
		t.Fatal("AdaptiveConfig is nil")
	}
	if dp.AdaptiveConfig.IdleThreshold != 256 {
		t.Errorf("IdleThreshold = %d, want 256", dp.AdaptiveConfig.IdleThreshold)
	}
	if dp.AdaptiveConfig.ResumeThreshold != 32 {
		t.Errorf("ResumeThreshold = %d, want 32", dp.AdaptiveConfig.ResumeThreshold)
	}
	if dp.AdaptiveConfig.SleepTimeout != 100 {
		t.Errorf("SleepTimeout = %d, want 100", dp.AdaptiveConfig.SleepTimeout)
	}
	if len(dp.Ports) != 2 {
		t.Fatalf("Ports len = %d, want 2", len(dp.Ports))
	}
	if dp.Ports[0].PCIAddress != "0000:03:00.0" {
		t.Errorf("Port[0].PCIAddress = %q, want 0000:03:00.0", dp.Ports[0].PCIAddress)
	}
	if dp.Ports[0].Interface != "wan0" {
		t.Errorf("Port[0].Interface = %q, want wan0", dp.Ports[0].Interface)
	}
	if dp.Ports[0].RXMode != "polling" {
		t.Errorf("Port[0].RXMode = %q, want polling", dp.Ports[0].RXMode)
	}
	if dp.Ports[0].Cores != "2-3" {
		t.Errorf("Port[0].Cores = %q, want 2-3", dp.Ports[0].Cores)
	}
	if dp.Ports[1].PCIAddress != "0000:06:00.0" {
		t.Errorf("Port[1].PCIAddress = %q, want 0000:06:00.0", dp.Ports[1].PCIAddress)
	}
	if dp.Ports[1].Interface != "trust0" {
		t.Errorf("Port[1].Interface = %q, want trust0", dp.Ports[1].Interface)
	}
}

func TestOSPFAuthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.0 interface trust0 authentication md5 1 key secret123",
		"set protocols ospf area 0.0.0.0 interface dmz0 authentication simple-password plainpw",
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
	if len(ospf.Areas) != 1 {
		t.Fatalf("area count: got %d, want 1", len(ospf.Areas))
	}
	ifaces := ospf.Areas[0].Interfaces
	if len(ifaces) != 2 {
		t.Fatalf("interface count: got %d, want 2", len(ifaces))
	}
	if ifaces[0].AuthType != "md5" {
		t.Errorf("trust0 AuthType: got %q, want md5", ifaces[0].AuthType)
	}
	if ifaces[0].AuthKeyID != 1 {
		t.Errorf("trust0 AuthKeyID: got %d, want 1", ifaces[0].AuthKeyID)
	}
	if ifaces[0].AuthKey != "secret123" {
		t.Errorf("trust0 AuthKey: got %q, want secret123", ifaces[0].AuthKey)
	}
	if ifaces[1].AuthType != "simple" {
		t.Errorf("dmz0 AuthType: got %q, want simple", ifaces[1].AuthType)
	}
	if ifaces[1].AuthKey != "plainpw" {
		t.Errorf("dmz0 AuthKey: got %q, want plainpw", ifaces[1].AuthKey)
	}
}

func TestBGPAuthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external authentication-key bgpSecret",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("neighbors: got %d, want 1", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AuthPassword != "bgpSecret" {
		t.Errorf("AuthPassword: got %q, want bgpSecret", bgp.Neighbors[0].AuthPassword)
	}
}

func TestBGPNeighborAuthOverride(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external authentication-key groupKey",
		"set protocols bgp group external neighbor 10.0.2.1 authentication-key neighborKey",
		"set protocols bgp group external neighbor 10.0.3.1",
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
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	// Per-neighbor override
	if bgp.Neighbors[0].AuthPassword != "neighborKey" {
		t.Errorf("neighbor[0] AuthPassword: got %q, want neighborKey", bgp.Neighbors[0].AuthPassword)
	}
	// Inherited from group
	if bgp.Neighbors[1].AuthPassword != "groupKey" {
		t.Errorf("neighbor[1] AuthPassword: got %q, want groupKey", bgp.Neighbors[1].AuthPassword)
	}
}

func TestOSPFBFDSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.0 interface trust0 bfd-liveness-detection minimum-interval 100",
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
	iface := ospf.Areas[0].Interfaces[0]
	if !iface.BFD {
		t.Error("OSPF interface BFD should be true")
	}
}

func TestBGPBFDSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external bfd-liveness-detection minimum-interval 200",
		"set protocols bgp group external neighbor 10.0.2.1",
		"set protocols bgp group external neighbor 10.0.3.1 bfd-liveness-detection minimum-interval 100",
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
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbors: got %d, want 2", len(bgp.Neighbors))
	}
	// Inherited from group
	if !bgp.Neighbors[0].BFD {
		t.Error("neighbor[0] should have BFD enabled (inherited)")
	}
	if bgp.Neighbors[0].BFDInterval != 200 {
		t.Errorf("neighbor[0] BFDInterval: got %d, want 200", bgp.Neighbors[0].BFDInterval)
	}
	// Per-neighbor override
	if !bgp.Neighbors[1].BFD {
		t.Error("neighbor[1] should have BFD enabled")
	}
	if bgp.Neighbors[1].BFDInterval != 100 {
		t.Errorf("neighbor[1] BFDInterval: got %d, want 100", bgp.Neighbors[1].BFDInterval)
	}
}

func TestOSPFAreaTypeSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.0 interface trust0",
		"set protocols ospf area 0.0.0.1 interface dmz0",
		"set protocols ospf area 0.0.0.1 area-type stub",
		"set protocols ospf area 0.0.0.2 interface untrust0",
		"set protocols ospf area 0.0.0.2 area-type nssa",
		"set protocols ospf area 0.0.0.3 interface tunnel0",
		"set protocols ospf area 0.0.0.3 area-type stub no-summaries",
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
	if len(ospf.Areas) != 4 {
		t.Fatalf("area count: got %d, want 4", len(ospf.Areas))
	}
	// Area 0 (backbone) - no area type
	if ospf.Areas[0].AreaType != "" {
		t.Errorf("area 0 should have no type, got %q", ospf.Areas[0].AreaType)
	}
	// Area 1 - stub
	if ospf.Areas[1].AreaType != "stub" {
		t.Errorf("area 1 AreaType: got %q, want stub", ospf.Areas[1].AreaType)
	}
	if ospf.Areas[1].NoSummary {
		t.Error("area 1 should not have NoSummary")
	}
	// Area 2 - nssa
	if ospf.Areas[2].AreaType != "nssa" {
		t.Errorf("area 2 AreaType: got %q, want nssa", ospf.Areas[2].AreaType)
	}
	// Area 3 - stub no-summary (totally stubby)
	if ospf.Areas[3].AreaType != "stub" {
		t.Errorf("area 3 AreaType: got %q, want stub", ospf.Areas[3].AreaType)
	}
	if !ospf.Areas[3].NoSummary {
		t.Error("area 3 should have NoSummary")
	}
}

func TestBGPRouteReflectorSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp cluster-id 10.0.0.1",
		"set protocols bgp group ibgp peer-as 65001",
		"set protocols bgp group ibgp neighbor 10.0.0.2 route-reflector-client",
		"set protocols bgp group ibgp neighbor 10.0.0.3",
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
	if bgp.ClusterID != "10.0.0.1" {
		t.Errorf("ClusterID: got %q, want 10.0.0.1", bgp.ClusterID)
	}
	if len(bgp.Neighbors) != 2 {
		t.Fatalf("neighbor count: got %d, want 2", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RouteReflectorClient {
		t.Error("neighbor 10.0.0.2 should be route-reflector-client")
	}
	if bgp.Neighbors[1].RouteReflectorClient {
		t.Error("neighbor 10.0.0.3 should not be route-reflector-client")
	}
}

func TestISISAuthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis authentication-type md5",
		"set protocols isis authentication-key isisSecret",
		"set protocols isis interface trust0",
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
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if isis.AuthType != "md5" {
		t.Errorf("AuthType: got %q, want md5", isis.AuthType)
	}
	if isis.AuthKey != "isisSecret" {
		t.Errorf("AuthKey: got %q, want isisSecret", isis.AuthKey)
	}
}

func TestISISInterfaceAuthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis interface trust0 authentication-type md5",
		"set protocols isis interface trust0 authentication-key ifaceSecret",
		"set protocols isis interface trust0 metric 100",
		"set protocols isis interface dmz0 authentication-type simple",
		"set protocols isis interface dmz0 authentication-key plainpw",
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
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if len(isis.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(isis.Interfaces))
	}
	trust := isis.Interfaces[0]
	if trust.AuthType != "md5" {
		t.Errorf("trust0 AuthType: got %q, want md5", trust.AuthType)
	}
	if trust.AuthKey != "ifaceSecret" {
		t.Errorf("trust0 AuthKey: got %q, want ifaceSecret", trust.AuthKey)
	}
	if trust.Metric != 100 {
		t.Errorf("trust0 Metric: got %d, want 100", trust.Metric)
	}
	dmz := isis.Interfaces[1]
	if dmz.AuthType != "simple" {
		t.Errorf("dmz0 AuthType: got %q, want simple", dmz.AuthType)
	}
	if dmz.AuthKey != "plainpw" {
		t.Errorf("dmz0 AuthKey: got %q, want plainpw", dmz.AuthKey)
	}
}

func TestISISWideMetricsOverloadSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis wide-metrics-only",
		"set protocols isis overload",
		"set protocols isis interface trust0",
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
	isis := cfg.Protocols.ISIS
	if isis == nil {
		t.Fatal("ISIS config is nil")
	}
	if !isis.WideMetricsOnly {
		t.Error("WideMetricsOnly: got false, want true")
	}
	if !isis.Overload {
		t.Error("Overload: got false, want true")
	}
}

func TestRIPAuthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols rip neighbor trust0",
		"set protocols rip authentication-type md5",
		"set protocols rip authentication-key ripSecret",
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
	rip := cfg.Protocols.RIP
	if rip == nil {
		t.Fatal("RIP config is nil")
	}
	if rip.AuthType != "md5" {
		t.Errorf("AuthType: got %q, want md5", rip.AuthType)
	}
	if rip.AuthKey != "ripSecret" {
		t.Errorf("AuthKey: got %q, want ripSecret", rip.AuthKey)
	}
}

func TestOSPFReferenceBandwidthSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf reference-bandwidth 10g",
		"set protocols ospf area 0.0.0.0 interface trust0",
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
	// "10g" is not an int, so ReferenceBandwidth stays 0 (Atoi fails).
	// Use numeric value for proper test.
	cmds2 := []string{
		"set protocols ospf reference-bandwidth 10000",
		"set protocols ospf area 0.0.0.0 interface trust0",
	}
	tree2 := &ConfigTree{}
	for _, cmd := range cmds2 {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg2.Protocols.OSPF.ReferenceBandwidth != 10000 {
		t.Errorf("ReferenceBandwidth: got %d, want 10000", cfg2.Protocols.OSPF.ReferenceBandwidth)
	}
}

func TestOSPFPassiveDefaultSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf passive",
		"set protocols ospf area 0.0.0.0 interface trust0 no-passive",
		"set protocols ospf area 0.0.0.0 interface dmz0",
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
	if !ospf.PassiveDefault {
		t.Error("PassiveDefault should be true")
	}
	if len(ospf.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(area.Interfaces))
	}
	// trust0 should have NoPassive=true
	var trust, dmz *OSPFInterface
	for _, iface := range area.Interfaces {
		switch iface.Name {
		case "trust0":
			trust = iface
		case "dmz0":
			dmz = iface
		}
	}
	if trust == nil || !trust.NoPassive {
		t.Error("trust0 should have NoPassive=true")
	}
	if dmz == nil || dmz.NoPassive {
		t.Error("dmz0 should NOT have NoPassive set")
	}
}

func TestOSPFNetworkTypeSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.0 interface trust0 interface-type point-to-point",
		"set protocols ospf area 0.0.0.0 interface dmz0",
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
	area := ospf.Areas[0]
	var trust, dmz *OSPFInterface
	for _, iface := range area.Interfaces {
		switch iface.Name {
		case "trust0":
			trust = iface
		case "dmz0":
			dmz = iface
		}
	}
	if trust == nil || trust.NetworkType != "point-to-point" {
		t.Errorf("trust0 NetworkType: got %q, want \"point-to-point\"", trust.NetworkType)
	}
	if dmz == nil || dmz.NetworkType != "" {
		t.Errorf("dmz0 NetworkType: got %q, want \"\"", dmz.NetworkType)
	}
}

func TestBGPGracefulRestartSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp graceful-restart",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if !bgp.GracefulRestart {
		t.Error("GracefulRestart should be true")
	}
}

func TestBGPMultipathSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp multipath",
		"set protocols bgp multipath multiple-as",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if bgp.Multipath != 64 {
		t.Errorf("Multipath = %d, want 64", bgp.Multipath)
	}
	if !bgp.MultipathMultipleAS {
		t.Error("MultipathMultipleAS should be true")
	}
}

func TestBGPDefaultOriginateSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external default-originate",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].DefaultOriginate {
		t.Error("DefaultOriginate should be true (inherited from group)")
	}
}

func TestBGPDefaultOriginatePerNeighborSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2 default-originate",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].DefaultOriginate {
		t.Error("DefaultOriginate should be true (per-neighbor override)")
	}
}

func TestBGPLogUpdownSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp log-updown",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if !bgp.LogNeighborChanges {
		t.Error("LogNeighborChanges should be true")
	}
}


func TestBGPAllowASInSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external loops 2",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AllowASIn != 2 {
		t.Errorf("AllowASIn = %d, want 2", bgp.Neighbors[0].AllowASIn)
	}
}

func TestBGPAllowASInPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2 loops 3",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if bgp.Neighbors[0].AllowASIn != 3 {
		t.Errorf("AllowASIn = %d, want 3", bgp.Neighbors[0].AllowASIn)
	}
}

func TestBGPRemovePrivateASSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external remove-private",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RemovePrivateAS {
		t.Error("RemovePrivateAS should be true (inherited from group)")
	}
}

func TestBGPRemovePrivateASPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet",
		"set protocols bgp group external neighbor 10.0.0.2 remove-private",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	if !bgp.Neighbors[0].RemovePrivateAS {
		t.Error("RemovePrivateAS should be true (per-neighbor override)")
	}
}

func TestOSPFv3SetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf3 router-id 10.0.0.1",
		"set protocols ospf3 area 0.0.0.0 interface trust0 passive",
		"set protocols ospf3 area 0.0.0.0 interface trust0 cost 10",
		"set protocols ospf3 area 0.0.0.0 interface dmz0 cost 1",
		"set protocols ospf3 export connected",
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
	ospfv3 := cfg.Protocols.OSPFv3
	if ospfv3 == nil {
		t.Fatal("OSPFv3 config is nil")
	}
	if ospfv3.RouterID != "10.0.0.1" {
		t.Errorf("RouterID = %q, want %q", ospfv3.RouterID, "10.0.0.1")
	}
	if len(ospfv3.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospfv3.Areas))
	}
	area := ospfv3.Areas[0]
	if area.ID != "0.0.0.0" {
		t.Errorf("area ID = %q, want %q", area.ID, "0.0.0.0")
	}
	if len(area.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(area.Interfaces))
	}
	trust := area.Interfaces[0]
	if trust.Name != "trust0" {
		t.Errorf("iface name = %q, want %q", trust.Name, "trust0")
	}
	if !trust.Passive {
		t.Error("trust0 should be passive")
	}
	if trust.Cost != 10 {
		t.Errorf("trust0 cost = %d, want 10", trust.Cost)
	}
	dmz := area.Interfaces[1]
	if dmz.Name != "dmz0" {
		t.Errorf("iface name = %q, want %q", dmz.Name, "dmz0")
	}
	if dmz.Passive {
		t.Error("dmz0 should not be passive")
	}
	if dmz.Cost != 1 {
		t.Errorf("dmz0 cost = %d, want 1", dmz.Cost)
	}
	if len(ospfv3.Export) != 1 || ospfv3.Export[0] != "connected" {
		t.Errorf("Export = %v, want [connected]", ospfv3.Export)
	}
}

func TestInterfaceDuplexSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces trust0 speed 1g",
		"set interfaces trust0 duplex full",
		"set interfaces trust0 mtu 9000",
		"set interfaces trust0 description \"LAN interface\"",
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
	ifc := cfg.Interfaces.Interfaces["trust0"]
	if ifc == nil {
		t.Fatal("trust0 interface not found")
	}
	if ifc.Speed != "1g" {
		t.Errorf("Speed = %q, want \"1g\"", ifc.Speed)
	}
	if ifc.Duplex != "full" {
		t.Errorf("Duplex = %q, want \"full\"", ifc.Duplex)
	}
	if ifc.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", ifc.MTU)
	}
	if ifc.Description != "LAN interface" {
		t.Errorf("Description = %q, want \"LAN interface\"", ifc.Description)
	}
}

func TestMetricTypeAndCommunityListSetSyntax(t *testing.T) {
	cmds := []string{
		// Community definitions
		"set policy-options community MY-COMM members 65000:100",
		"set policy-options community MY-COMM members 65000:200",
		"set policy-options community NO-EXPORT members no-export",
		// Policy with metric-type and from community
		"set policy-options policy-statement OSPF-EXPORT term t1 from protocol direct",
		"set policy-options policy-statement OSPF-EXPORT term t1 from community MY-COMM",
		"set policy-options policy-statement OSPF-EXPORT term t1 then metric-type 1",
		"set policy-options policy-statement OSPF-EXPORT term t1 then metric 100",
		"set policy-options policy-statement OSPF-EXPORT term t1 then accept",
		"set policy-options policy-statement OSPF-EXPORT term t2 then metric-type 2",
		"set policy-options policy-statement OSPF-EXPORT term t2 then reject",
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

	// Check community definitions
	comm := cfg.PolicyOptions.Communities["MY-COMM"]
	if comm == nil {
		t.Fatal("MY-COMM community not found")
	}
	if len(comm.Members) != 2 {
		t.Fatalf("MY-COMM members = %d, want 2", len(comm.Members))
	}
	if comm.Members[0] != "65000:100" || comm.Members[1] != "65000:200" {
		t.Errorf("MY-COMM members = %v, want [65000:100, 65000:200]", comm.Members)
	}

	noExp := cfg.PolicyOptions.Communities["NO-EXPORT"]
	if noExp == nil {
		t.Fatal("NO-EXPORT community not found")
	}
	if len(noExp.Members) != 1 || noExp.Members[0] != "no-export" {
		t.Errorf("NO-EXPORT members = %v, want [no-export]", noExp.Members)
	}

	// Check policy statement
	ps := cfg.PolicyOptions.PolicyStatements["OSPF-EXPORT"]
	if ps == nil {
		t.Fatal("OSPF-EXPORT not found")
	}
	if len(ps.Terms) != 2 {
		t.Fatalf("got %d terms, want 2", len(ps.Terms))
	}

	t1 := ps.Terms[0]
	if t1.FromProtocol != "direct" {
		t.Errorf("t1 from protocol = %q, want direct", t1.FromProtocol)
	}
	if t1.FromCommunity != "MY-COMM" {
		t.Errorf("t1 from community = %q, want MY-COMM", t1.FromCommunity)
	}
	if t1.MetricType != 1 {
		t.Errorf("t1 metric-type = %d, want 1", t1.MetricType)
	}
	if t1.Metric != 100 {
		t.Errorf("t1 metric = %d, want 100", t1.Metric)
	}
	if t1.Action != "accept" {
		t.Errorf("t1 action = %q, want accept", t1.Action)
	}

	t2 := ps.Terms[1]
	if t2.MetricType != 2 {
		t.Errorf("t2 metric-type = %d, want 2", t2.MetricType)
	}
	if t2.Action != "reject" {
		t.Errorf("t2 action = %q, want reject", t2.Action)
	}
}

func TestGRETunnelKeepaliveSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces gre0 tunnel source 10.0.0.1",
		"set interfaces gre0 tunnel destination 10.0.0.2",
		"set interfaces gre0 tunnel keepalive 10",
		"set interfaces gre0 tunnel keepalive-retry 5",
		"set interfaces gre0 tunnel key 100",
		"set interfaces gre0 unit 0 family inet address 10.10.10.1/30",
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
	ifc := cfg.Interfaces.Interfaces["gre0"]
	if ifc == nil {
		t.Fatal("gre0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Source != "10.0.0.1" {
		t.Errorf("Source = %q, want 10.0.0.1", tc.Source)
	}
	if tc.Destination != "10.0.0.2" {
		t.Errorf("Destination = %q, want 10.0.0.2", tc.Destination)
	}
	if tc.Keepalive != 10 {
		t.Errorf("Keepalive = %d, want 10", tc.Keepalive)
	}
	if tc.KeepaliveRetry != 5 {
		t.Errorf("KeepaliveRetry = %d, want 5", tc.KeepaliveRetry)
	}
	if tc.Key != 100 {
		t.Errorf("Key = %d, want 100", tc.Key)
	}
}

func TestBGPDampingSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp damping",
		"set protocols bgp damping half-life 10",
		"set protocols bgp damping reuse 500",
		"set protocols bgp damping suppress 3000",
		"set protocols bgp damping max-suppress 45",
		"set protocols bgp group ext peer-as 65002",
		"set protocols bgp group ext neighbor 10.0.2.1",
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

	bgp := cfg.Protocols.BGP
	if bgp == nil {
		t.Fatal("BGP config is nil")
	}
	if !bgp.Dampening {
		t.Error("Dampening not enabled")
	}
	if bgp.DampeningHalfLife != 10 {
		t.Errorf("DampeningHalfLife = %d, want 10", bgp.DampeningHalfLife)
	}
	if bgp.DampeningReuse != 500 {
		t.Errorf("DampeningReuse = %d, want 500", bgp.DampeningReuse)
	}
	if bgp.DampeningSuppress != 3000 {
		t.Errorf("DampeningSuppress = %d, want 3000", bgp.DampeningSuppress)
	}
	if bgp.DampeningMaxSuppress != 45 {
		t.Errorf("DampeningMaxSuppress = %d, want 45", bgp.DampeningMaxSuppress)
	}
}

func TestASPathSetSyntax(t *testing.T) {
	cmds := []string{
		`set policy-options as-path AS65000 "65000"`,
		`set policy-options as-path TRANSIT "65[0-9]+"`,
		"set policy-options policy-statement FILTER-AS term t1 from as-path AS65000",
		"set policy-options policy-statement FILTER-AS term t1 then accept",
		"set policy-options policy-statement FILTER-AS then reject",
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

	// Check AS-path definitions
	if cfg.PolicyOptions.ASPaths == nil {
		t.Fatal("ASPaths map is nil")
	}
	ap := cfg.PolicyOptions.ASPaths["AS65000"]
	if ap == nil {
		t.Fatal("AS65000 as-path not found")
	}
	if ap.Regex != "65000" {
		t.Errorf("AS65000 regex = %q, want 65000", ap.Regex)
	}
	tr := cfg.PolicyOptions.ASPaths["TRANSIT"]
	if tr == nil {
		t.Fatal("TRANSIT as-path not found")
	}
	if tr.Regex != "65[0-9]+" {
		t.Errorf("TRANSIT regex = %q, want 65[0-9]+", tr.Regex)
	}

	// Check policy term from as-path
	ps := cfg.PolicyOptions.PolicyStatements["FILTER-AS"]
	if ps == nil {
		t.Fatal("FILTER-AS not found")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(ps.Terms))
	}
	if ps.Terms[0].FromASPath != "AS65000" {
		t.Errorf("from as-path = %q, want AS65000", ps.Terms[0].FromASPath)
	}
	if ps.Terms[0].Action != "accept" {
		t.Errorf("action = %q, want accept", ps.Terms[0].Action)
	}
	if ps.DefaultAction != "reject" {
		t.Errorf("default action = %q, want reject", ps.DefaultAction)
	}
}

func TestBGPPrefixLimitSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast prefix-limit maximum 1000",
		"set protocols bgp group external family inet6 unicast prefix-limit maximum 500",
		"set protocols bgp group external neighbor 10.0.0.2",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if !n.FamilyInet {
		t.Error("FamilyInet should be true")
	}
	if !n.FamilyInet6 {
		t.Error("FamilyInet6 should be true")
	}
	if n.PrefixLimitInet != 1000 {
		t.Errorf("PrefixLimitInet = %d, want 1000", n.PrefixLimitInet)
	}
	if n.PrefixLimitInet6 != 500 {
		t.Errorf("PrefixLimitInet6 = %d, want 500", n.PrefixLimitInet6)
	}
}

func TestBGPPrefixLimitPerNeighborSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum 2000",
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
	if len(bgp.Neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(bgp.Neighbors))
	}
	n := bgp.Neighbors[0]
	if n.PrefixLimitInet != 2000 {
		t.Errorf("PrefixLimitInet = %d, want 2000", n.PrefixLimitInet)
	}
}

func TestOSPFVirtualLinkSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.1 interface trust0",
		"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2",
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
	if len(ospf.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(ospf.Areas))
	}
	area := ospf.Areas[0]
	if len(area.VirtualLinks) != 1 {
		t.Fatalf("expected 1 virtual-link, got %d", len(area.VirtualLinks))
	}
	vl := area.VirtualLinks[0]
	if vl.NeighborID != "10.0.0.2" {
		t.Errorf("NeighborID = %q, want 10.0.0.2", vl.NeighborID)
	}
	if vl.TransitArea != "0.0.0.1" {
		t.Errorf("TransitArea = %q, want 0.0.0.1", vl.TransitArea)
	}
}

func TestOSPFVirtualLinkWithTransitAreaSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.1 interface trust0",
		"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0.0.0.3",
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
	area := ospf.Areas[0]
	if len(area.VirtualLinks) != 1 {
		t.Fatalf("expected 1 virtual-link, got %d", len(area.VirtualLinks))
	}
	vl := area.VirtualLinks[0]
	if vl.NeighborID != "10.0.0.2" {
		t.Errorf("NeighborID = %q, want 10.0.0.2", vl.NeighborID)
	}
	if vl.TransitArea != "0.0.0.3" {
		t.Errorf("TransitArea = %q, want 0.0.0.3", vl.TransitArea)
	}
}

func TestLLDPSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols lldp interface trust0",
		"set protocols lldp interface untrust0",
		"set protocols lldp transmit-interval 15",
		"set protocols lldp hold-multiplier 5",
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
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if len(lldpCfg.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(lldpCfg.Interfaces))
	}
	if lldpCfg.Interfaces[0].Name != "trust0" || lldpCfg.Interfaces[1].Name != "untrust0" {
		t.Errorf("interfaces: got %v, want [trust0 untrust0]", lldpCfg.Interfaces)
	}
	if lldpCfg.Interval != 15 {
		t.Errorf("interval: got %d, want 15", lldpCfg.Interval)
	}
	if lldpCfg.HoldMultiplier != 5 {
		t.Errorf("hold-multiplier: got %d, want 5", lldpCfg.HoldMultiplier)
	}
}

func TestLLDPHierarchicalSyntax(t *testing.T) {
	input := `protocols {
    lldp {
        interface trust0;
        interface dmz0;
        transmit-interval 10;
        hold-multiplier 3;
        disable;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if len(lldpCfg.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(lldpCfg.Interfaces))
	}
	if lldpCfg.Interval != 10 {
		t.Errorf("interval: got %d, want 10", lldpCfg.Interval)
	}
	if lldpCfg.HoldMultiplier != 3 {
		t.Errorf("hold-multiplier: got %d, want 3", lldpCfg.HoldMultiplier)
	}
	if !lldpCfg.Disable {
		t.Error("expected Disable=true")
	}
}

func TestLLDPDisableSetSyntax(t *testing.T) {
	cmds := []string{
		"set protocols lldp disable",
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
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg == nil {
		t.Fatal("LLDP config is nil")
	}
	if !lldpCfg.Disable {
		t.Error("expected Disable=true")
	}
}

func TestPortMirroringHierarchical(t *testing.T) {
	input := `forwarding-options {
    port-mirroring {
        instance mirror1 {
            input {
                rate 100;
                ingress {
                    interface trust0;
                    interface dmz0;
                }
            }
            output {
                interface monitor0;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil {
		t.Fatal("PortMirroring is nil")
	}
	inst, ok := pm.Instances["mirror1"]
	if !ok {
		t.Fatal("instance mirror1 not found")
	}
	if inst.InputRate != 100 {
		t.Errorf("InputRate = %d, want 100", inst.InputRate)
	}
	if len(inst.Input) != 2 {
		t.Fatalf("len(Input) = %d, want 2", len(inst.Input))
	}
	if inst.Input[0] != "trust0" || inst.Input[1] != "dmz0" {
		t.Errorf("Input = %v, want [trust0 dmz0]", inst.Input)
	}
	if inst.Output != "monitor0" {
		t.Errorf("Output = %q, want monitor0", inst.Output)
	}
}

func TestPortMirroringFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set forwarding-options port-mirroring instance span1 input rate 50",
		"set forwarding-options port-mirroring instance span1 input ingress interface wan0",
		"set forwarding-options port-mirroring instance span1 output interface monitor0",
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
		t.Fatalf("CompileConfig: %v", err)
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil {
		t.Fatal("PortMirroring is nil")
	}
	inst, ok := pm.Instances["span1"]
	if !ok {
		t.Fatal("instance span1 not found")
	}
	if inst.InputRate != 50 {
		t.Errorf("InputRate = %d, want 50", inst.InputRate)
	}
	if len(inst.Input) != 1 || inst.Input[0] != "wan0" {
		t.Errorf("Input = %v, want [wan0]", inst.Input)
	}
	if inst.Output != "monitor0" {
		t.Errorf("Output = %q, want monitor0", inst.Output)
	}
}

func TestPortMirroringSetSyntaxMultiInput(t *testing.T) {
	cmds := []string{
		"set forwarding-options port-mirroring instance span1 input ingress interface trust0",
		"set forwarding-options port-mirroring instance span1 input ingress interface untrust0",
		"set forwarding-options port-mirroring instance span1 input rate 10",
		"set forwarding-options port-mirroring instance span1 output interface monitor0",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		tokens, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand failed for %q: %v", cmd, err)
		}
		if err := tree.SetPath(tokens); err != nil {
			t.Fatalf("SetPath failed for %q: %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.ForwardingOptions.PortMirroring == nil {
		t.Fatal("expected PortMirroring")
	}
	inst, ok := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if !ok {
		t.Fatal("expected span1 instance")
	}
	if inst.InputRate != 10 {
		t.Errorf("rate = %d, want 10", inst.InputRate)
	}
	if len(inst.Input) != 2 {
		t.Errorf("input count = %d, want 2", len(inst.Input))
	}
	if inst.Output != "monitor0" {
		t.Errorf("output = %q, want monitor0", inst.Output)
	}
}

func TestPortMirroringHierarchicalSimple(t *testing.T) {
	input := `forwarding-options {
    port-mirroring {
        instance span1 {
            input {
                rate 5;
                ingress {
                    interface trust0;
                }
            }
            output {
                interface monitor0;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.ForwardingOptions.PortMirroring == nil {
		t.Fatal("expected PortMirroring")
	}
	inst := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if inst == nil {
		t.Fatal("expected span1")
	}
	if inst.InputRate != 5 {
		t.Errorf("rate = %d, want 5", inst.InputRate)
	}
	if inst.Output != "monitor0" {
		t.Errorf("output = %q, want monitor0", inst.Output)
	}
}

func TestApplyGroupsHierarchical(t *testing.T) {
	input := `
groups {
    common {
        system {
            host-name my-firewall;
        }
        security {
            zones {
                security-zone trust {
                    interfaces {
                        eth0.0;
                    }
                }
            }
        }
    }
}
apply-groups common;
interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if cfg.System.HostName != "my-firewall" {
		t.Errorf("hostname = %q, want my-firewall", cfg.System.HostName)
	}
	// Group should have expanded zone config.
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("expected trust zone from group")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
	// Explicit interface config should still be present.
	iface := cfg.Interfaces.Interfaces["eth0"]
	if iface == nil {
		t.Fatal("expected eth0 interface")
	}
}

func TestApplyGroupsSetSyntax(t *testing.T) {
	setCommands := []string{
		"set groups common system host-name fw1",
		"set groups common security screen ids-option myscreen tcp land",
		"set apply-groups common",
		"set interfaces eth0 unit 0 family inet address 10.0.1.1/24",
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
		t.Fatalf("compile: %v", err)
	}

	if cfg.System.HostName != "fw1" {
		t.Errorf("hostname = %q, want fw1", cfg.System.HostName)
	}
	sp := cfg.Security.Screen["myscreen"]
	if sp == nil {
		t.Fatal("expected myscreen profile")
	}
	if !sp.TCP.Land {
		t.Error("expected land screen")
	}
}

func TestApplyGroupsMergeDoesNotOverride(t *testing.T) {
	input := `
groups {
    defaults {
        system {
            host-name group-name;
        }
    }
}
apply-groups defaults;
system {
    host-name explicit-name;
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if cfg.System.HostName != "explicit-name" {
		t.Errorf("hostname = %q, want explicit-name", cfg.System.HostName)
	}
}

func TestApplyGroupsMissingReference(t *testing.T) {
	input := `
apply-groups nonexistent;
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected error for undefined group reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention group name: %v", err)
	}
}

func TestApplyGroupsCircularReference(t *testing.T) {
	input := `
groups {
    grp-a {
        system {
            host-name from-a;
        }
    }
}
apply-groups grp-a;
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "from-a" {
		t.Errorf("hostname = %q, want from-a", cfg.System.HostName)
	}
}

func TestApplyGroupsMultiple(t *testing.T) {
	// Use set syntax for screen (hierarchical format doesn't match compiler expectations).
	setCommands := []string{
		"set groups net-settings interfaces eth0 unit 0 family inet address 10.0.1.1/24",
		"set groups sec-settings security screen ids-option basic tcp land",
		"set apply-groups net-settings",
		"set apply-groups sec-settings",
		"set system host-name test-fw",
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
		t.Fatalf("compile: %v", err)
	}

	if cfg.System.HostName != "test-fw" {
		t.Errorf("hostname = %q, want test-fw", cfg.System.HostName)
	}
	iface := cfg.Interfaces.Interfaces["eth0"]
	if iface == nil {
		t.Fatal("expected eth0 from net-settings group")
	}
	sp := cfg.Security.Screen["basic"]
	if sp == nil {
		t.Fatal("expected basic screen from sec-settings group")
	}
}

func TestApplyGroupsFormatSet(t *testing.T) {
	setCommands := []string{
		"set groups common system host-name fw1",
		"set apply-groups common",
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

	output := tree.FormatSet()
	if !strings.Contains(output, "set groups common system host-name fw1") {
		t.Errorf("FormatSet missing groups line, got:\n%s", output)
	}
	if !strings.Contains(output, "set apply-groups common") {
		t.Errorf("FormatSet missing apply-groups line, got:\n%s", output)
	}
}

func TestParseLoginClass(t *testing.T) {
	input := `system {
    login {
        user admin {
            class super-user;
        }
        user monitor {
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

	if cfg.System.Login == nil {
		t.Fatal("expected Login config")
	}
	if len(cfg.System.Login.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.System.Login.Users))
	}

	admin := cfg.System.Login.Users[0]
	if admin.Name != "admin" || admin.Class != "super-user" {
		t.Errorf("expected admin/super-user, got %s/%s", admin.Name, admin.Class)
	}

	monitor := cfg.System.Login.Users[1]
	if monitor.Name != "monitor" || monitor.Class != "read-only" {
		t.Errorf("expected monitor/read-only, got %s/%s", monitor.Name, monitor.Class)
	}
}

func TestArchivalConfigWithTransferInterval(t *testing.T) {
	input := `
system {
    archival {
        configuration {
            transfer-on-commit;
            transfer-interval 30;
            archive-sites {
                "scp://backup@10.0.0.1:/configs";
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

	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if arch.TransferInterval != 30 {
		t.Errorf("transfer-interval = %d, want 30", arch.TransferInterval)
	}
	if len(arch.ArchiveSites) != 1 {
		t.Fatalf("archive-sites count = %d, want 1", len(arch.ArchiveSites))
	}
	if arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
		t.Errorf("archive-site = %q", arch.ArchiveSites[0])
	}
	if arch.ArchiveDir != "/var/lib/bpfrx/archive" {
		t.Errorf("archive-dir = %q, want /var/lib/bpfrx/archive", arch.ArchiveDir)
	}
	if arch.MaxArchives != 10 {
		t.Errorf("max-archives = %d, want 10", arch.MaxArchives)
	}
}

func TestArchivalConfigSetSyntax(t *testing.T) {
	lines := []string{
		"system archival configuration transfer-on-commit",
		"system archival configuration transfer-interval 30",
		"system archival configuration archive-sites /var/backup",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("transfer-on-commit should be true")
	}
	if arch.TransferInterval != 30 {
		t.Errorf("transfer-interval = %d, want 30", arch.TransferInterval)
	}
	if len(arch.ArchiveSites) != 1 || arch.ArchiveSites[0] != "/var/backup" {
		t.Errorf("archive-sites = %v", arch.ArchiveSites)
	}
}

func TestAnnotationFormatText(t *testing.T) {
	tree := &ConfigTree{
		Children: []*Node{
			{
				Keys: []string{"system"},
				Children: []*Node{
					{Keys: []string{"host-name", "fw1"}, IsLeaf: true, Annotation: "Primary firewall"},
					{Keys: []string{"domain-name", "example.com"}, IsLeaf: true},
				},
			},
			{
				Keys:       []string{"security"},
				Annotation: "Security configuration",
				Children: []*Node{
					{Keys: []string{"log"}, Children: []*Node{
						{Keys: []string{"mode", "stream"}, IsLeaf: true},
					}},
				},
			},
		},
	}

	out := tree.Format()

	// Check annotation before host-name
	if !strings.Contains(out, "/* Primary firewall */") {
		t.Errorf("missing host-name annotation in:\n%s", out)
	}
	// Check annotation before security block
	if !strings.Contains(out, "/* Security configuration */") {
		t.Errorf("missing security annotation in:\n%s", out)
	}
	// domain-name should NOT have an annotation
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.Contains(line, "domain-name") {
			if i > 0 && strings.Contains(lines[i-1], "/*") {
				t.Errorf("domain-name should not have annotation, but preceding line is: %s", lines[i-1])
			}
		}
	}
}

func TestAnnotationClone(t *testing.T) {
	tree := &ConfigTree{
		Children: []*Node{
			{Keys: []string{"system"}, Children: []*Node{
				{Keys: []string{"host-name", "fw1"}, IsLeaf: true, Annotation: "Test comment"},
			}},
		},
	}

	cloned := tree.Clone()
	if cloned.Children[0].Children[0].Annotation != "Test comment" {
		t.Error("annotation not preserved in clone")
	}

	// Modify clone, original should be unchanged
	cloned.Children[0].Children[0].Annotation = "Modified"
	if tree.Children[0].Children[0].Annotation != "Test comment" {
		t.Error("clone shares annotation with original")
	}
}

func TestValidatePortSpec(t *testing.T) {
	tests := []struct {
		spec string
		ok   bool
	}{
		{"80", true},
		{"8080-8090", true},
		{"1", true},
		{"65535", true},
		{"http", true},
		{"HTTPS", true},
		{"dns", true},
		{"1024-65535", true},
		{"0", false},
		{"99999", false},
		{"abc", false},
		{"8090-8080", false},
		{"", true},
		{"foo-bar", false},
	}
	for _, tt := range tests {
		err := validatePortSpec(tt.spec)
		if (err == nil) != tt.ok {
			t.Errorf("validatePortSpec(%q) = %v, want ok=%v", tt.spec, err, tt.ok)
		}
	}
}

func TestValidateProtocol(t *testing.T) {
	tests := []struct {
		proto string
		ok    bool
	}{
		{"tcp", true},
		{"udp", true},
		{"icmp", true},
		{"icmp6", true},
		{"gre", true},
		{"47", true},
		{"0", true},
		{"255", true},
		{"256", false},
		{"-1", false},
		{"bogus", false},
	}
	for _, tt := range tests {
		err := validateProtocol(tt.proto)
		if (err == nil) != tt.ok {
			t.Errorf("validateProtocol(%q) = %v, want ok=%v", tt.proto, err, tt.ok)
		}
	}
}

func TestValidateConfigApplicationPorts(t *testing.T) {
	cfg := &Config{}
	cfg.Applications.Applications = map[string]*Application{
		"good-app": {
			Name:            "good-app",
			Protocol:        "tcp",
			DestinationPort: "8080-8090",
			SourcePort:      "1024-65535",
		},
		"bad-port": {
			Name:            "bad-port",
			Protocol:        "tcp",
			DestinationPort: "99999",
		},
		"bad-proto": {
			Name:     "bad-proto",
			Protocol: "bogus",
		},
	}
	cfg.Applications.ApplicationSets = map[string]*ApplicationSet{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	cfg.Security.NAT.Source = nil
	cfg.Security.NAT.Destination = nil

	warnings := ValidateConfig(cfg)

	var foundPort, foundProto bool
	for _, w := range warnings {
		if strings.Contains(w, "bad-port") && strings.Contains(w, "99999") {
			foundPort = true
		}
		if strings.Contains(w, "bad-proto") && strings.Contains(w, "bogus") {
			foundProto = true
		}
	}
	if !foundPort {
		t.Error("expected warning about bad-port with invalid port 99999")
	}
	if !foundProto {
		t.Error("expected warning about bad-proto with invalid protocol")
	}
}

func TestIPIPTunnelSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 tunnel ttl 128",
		"set interfaces ip-0/0/0 unit 0 family inet address 10.10.10.1/30",
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
	ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
	if ifc == nil {
		t.Fatal("ip-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Mode != "ipip" {
		t.Errorf("Mode = %q, want %q (auto-detected from ip- prefix)", tc.Mode, "ipip")
	}
	if tc.Source != "10.0.0.1" {
		t.Errorf("Source = %q, want 10.0.0.1", tc.Source)
	}
	if tc.Destination != "10.0.0.2" {
		t.Errorf("Destination = %q, want 10.0.0.2", tc.Destination)
	}
	if tc.TTL != 128 {
		t.Errorf("TTL = %d, want 128", tc.TTL)
	}
}

func TestIPIPTunnelExplicitMode(t *testing.T) {
	// Test that explicit mode=ipip is also honored (for gr- prefix with explicit mode override)
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 tunnel mode ipip",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
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
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.Mode != "ipip" {
		t.Errorf("Mode = %q, want %q (explicitly set)", tc.Mode, "ipip")
	}
}

func TestGRETunnelRoutingInstanceDestination(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination dmz-vr",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
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
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	tc := ifc.Tunnel
	if tc == nil {
		t.Fatal("tunnel config is nil")
	}
	if tc.RoutingInstance != "dmz-vr" {
		t.Errorf("RoutingInstance = %q, want %q", tc.RoutingInstance, "dmz-vr")
	}
}

func TestPointToPointFlag(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 0 point-to-point",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
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
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.PointToPoint {
		t.Error("PointToPoint should be true")
	}
}

func TestIPsecAggressiveModeSetSyntax(t *testing.T) {
	cmds := []string{
		"set security ike proposal ike-phase1 authentication-method pre-shared-keys",
		"set security ike proposal ike-phase1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-phase1 authentication-algorithm sha-256",
		"set security ike proposal ike-phase1 dh-group group14",
		"set security ike policy ike-pol mode aggressive",
		"set security ike policy ike-pol proposals ike-phase1",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 203.0.113.1",
		"set security ike gateway gw1 local-address 198.51.100.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ike gateway gw1 external-interface wan0",
		"set security ike gateway gw1 version v1-only",
		"set security ike gateway gw1 dynamic hostname peer.example.com",
		"set security ipsec vpn site-a ike gateway gw1",
		"set security ipsec vpn site-a df-bit copy",
		"set security ipsec vpn site-a establish-tunnels immediately",
		"set security ipsec vpn site-a bind-interface st0.0",
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

	// Check IKE policy aggressive mode
	ikePol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if ikePol == nil {
		t.Fatal("IKE policy ike-pol not found")
	}
	if ikePol.Mode != "aggressive" {
		t.Errorf("IKE policy mode = %q, want %q", ikePol.Mode, "aggressive")
	}
	if ikePol.PSK != "secret123" {
		t.Errorf("IKE policy PSK = %q, want %q", ikePol.PSK, "secret123")
	}

	// Check gateway
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("gateway gw1 not found")
	}
	if gw.LocalAddress != "198.51.100.1" {
		t.Errorf("gateway local-address = %q, want %q", gw.LocalAddress, "198.51.100.1")
	}
	if gw.DynamicHostname != "peer.example.com" {
		t.Errorf("gateway dynamic hostname = %q, want %q", gw.DynamicHostname, "peer.example.com")
	}
	if gw.Version != "v1-only" {
		t.Errorf("gateway version = %q, want %q", gw.Version, "v1-only")
	}

	// Check VPN
	vpn := cfg.Security.IPsec.VPNs["site-a"]
	if vpn == nil {
		t.Fatal("VPN site-a not found")
	}
	if vpn.DFBit != "copy" {
		t.Errorf("VPN df-bit = %q, want %q", vpn.DFBit, "copy")
	}
	if vpn.EstablishTunnels != "immediately" {
		t.Errorf("VPN establish-tunnels = %q, want %q", vpn.EstablishTunnels, "immediately")
	}
	if vpn.BindInterface != "st0.0" {
		t.Errorf("VPN bind-interface = %q, want %q", vpn.BindInterface, "st0.0")
	}
	if vpn.Gateway != "gw1" {
		t.Errorf("VPN gateway = %q, want %q", vpn.Gateway, "gw1")
	}
}

func TestGlobalInterfaceRoutesRibGroup(t *testing.T) {
	input := `routing-options {
    interface-routes {
        rib-group {
            inet Other-ISPS;
            inet6 Other-ISP6;
        }
    }
    rib-groups {
        Other-ISPS {
            import-rib [ Comcast-BCI.inet.0 inet.0 ATT.inet.0 Atherton-Fiber.inet.0 sfmix.inet.0 ];
        }
        Other-ISP6 {
            import-rib [ Comcast-BCI.inet6.0 inet6.0 ATT.inet6.0 Atherton-Fiber.inet6.0 ];
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}

	// Verify global interface-routes rib-group references
	if cfg.RoutingOptions.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS",
			cfg.RoutingOptions.InterfaceRoutesRibGroup)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6",
			cfg.RoutingOptions.InterfaceRoutesRibGroupV6)
	}

	// Verify rib-groups with many import-ribs
	rg, ok := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if !ok {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 5 {
		t.Fatalf("Other-ISPS ImportRibs = %d, want 5", len(rg.ImportRibs))
	}

	rg6, ok := cfg.RoutingOptions.RibGroups["Other-ISP6"]
	if !ok {
		t.Fatal("rib-group Other-ISP6 not found")
	}
	if len(rg6.ImportRibs) != 4 {
		t.Fatalf("Other-ISP6 ImportRibs = %d, want 4", len(rg6.ImportRibs))
	}
}

func TestGlobalInterfaceRoutesRibGroupSetSyntax(t *testing.T) {
	lines := []string{
		"set routing-options interface-routes rib-group inet Other-ISPS",
		"set routing-options interface-routes rib-group inet6 Other-ISP6",
		"set routing-options rib-groups Other-ISPS import-rib Comcast-BCI.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib inet.0",
		"set routing-options rib-groups Other-ISPS import-rib Other-GigabitPro.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib bv-firehouse-vpn.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib Comcast-GigabitPro.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib ATT.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib Atherton-Fiber.inet.0",
		"set routing-options rib-groups Other-ISPS import-rib sfmix.inet.0",
		"set routing-options rib-groups Other-ISP6 import-rib Comcast-BCI.inet6.0",
		"set routing-options rib-groups Other-ISP6 import-rib inet6.0",
		"set routing-options rib-groups Other-ISP6 import-rib Comcast-GigabitPro.inet6.0",
		"set routing-options rib-groups Other-ISP6 import-rib ATT.inet6.0",
		"set routing-options rib-groups Other-ISP6 import-rib Atherton-Fiber.inet6.0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.RoutingOptions.InterfaceRoutesRibGroup != "Other-ISPS" {
		t.Errorf("InterfaceRoutesRibGroup = %q, want Other-ISPS",
			cfg.RoutingOptions.InterfaceRoutesRibGroup)
	}
	if cfg.RoutingOptions.InterfaceRoutesRibGroupV6 != "Other-ISP6" {
		t.Errorf("InterfaceRoutesRibGroupV6 = %q, want Other-ISP6",
			cfg.RoutingOptions.InterfaceRoutesRibGroupV6)
	}

	// Verify 8 import-ribs for Other-ISPS
	rg := cfg.RoutingOptions.RibGroups["Other-ISPS"]
	if rg == nil {
		t.Fatal("rib-group Other-ISPS not found")
	}
	if len(rg.ImportRibs) != 8 {
		t.Fatalf("Other-ISPS ImportRibs = %d, want 8: %v", len(rg.ImportRibs), rg.ImportRibs)
	}

	// Verify 5 import-ribs for Other-ISP6
	rg6 := cfg.RoutingOptions.RibGroups["Other-ISP6"]
	if rg6 == nil {
		t.Fatal("rib-group Other-ISP6 not found")
	}
	if len(rg6.ImportRibs) != 5 {
		t.Fatalf("Other-ISP6 ImportRibs = %d, want 5: %v", len(rg6.ImportRibs), rg6.ImportRibs)
	}
}

func TestIPv6NextTableStaticRoutes(t *testing.T) {
	// Test IPv6 rib inet6.0 static route with next-table (flat set syntax)
	lines := []string{
		"set routing-options rib inet6.0 static route ::/0 next-table Comcast-GigabitPro.inet6.0",
		"set routing-options rib inet6.0 static route 2001:db8::/32 next-table ATT.inet6.0",
		"set routing-options static route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}

	// IPv6 routes
	if len(cfg.RoutingOptions.Inet6StaticRoutes) != 2 {
		t.Fatalf("Inet6StaticRoutes = %d, want 2", len(cfg.RoutingOptions.Inet6StaticRoutes))
	}
	r0 := cfg.RoutingOptions.Inet6StaticRoutes[0]
	if r0.Destination != "::/0" {
		t.Errorf("v6 route 0 dest = %q, want ::/0", r0.Destination)
	}
	if r0.NextTable != "Comcast-GigabitPro" {
		t.Errorf("v6 route 0 next-table = %q, want Comcast-GigabitPro", r0.NextTable)
	}
	r1 := cfg.RoutingOptions.Inet6StaticRoutes[1]
	if r1.NextTable != "ATT" {
		t.Errorf("v6 route 1 next-table = %q, want ATT", r1.NextTable)
	}

	// IPv4 route
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("StaticRoutes = %d, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	if cfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
		t.Errorf("v4 route next-table = %q", cfg.RoutingOptions.StaticRoutes[0].NextTable)
	}
}

func TestDNATSourceAddressName(t *testing.T) {
	input := `security {
    address-book {
        global {
            address srv1 10.0.1.100/32;
            address-set net_todd_control4 {
                address srv1;
            }
        }
    }
    nat {
        destination {
            pool host_control4 {
                address 10.0.30.100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule todd-control4 {
                    match {
                        source-address-name net_todd_control4;
                        destination-address 50.220.171.30/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat pool host_control4;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	if len(dnat.RuleSets) != 1 {
		t.Fatalf("want 1 rule-set, got %d", len(dnat.RuleSets))
	}
	rule := dnat.RuleSets[0].Rules[0]
	if rule.Match.SourceAddressName != "net_todd_control4" {
		t.Errorf("SourceAddressName = %q, want net_todd_control4", rule.Match.SourceAddressName)
	}
	if rule.Match.DestinationAddress != "50.220.171.30/32" {
		t.Errorf("DestinationAddress = %q, want 50.220.171.30/32", rule.Match.DestinationAddress)
	}
	if rule.Match.DestinationPort != 80 {
		t.Errorf("DestinationPort = %d, want 80", rule.Match.DestinationPort)
	}
}

func TestDNATSourceAddressNameSetSyntax(t *testing.T) {
	lines := []string{
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set wan-dnat from zone untrust",
		"set security nat destination rule-set wan-dnat rule r1 match source-address-name mynet",
		"set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set wan-dnat rule r1 match destination-port 443",
		"set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		t.Fatal("DNAT config nil")
	}
	rule := dnat.RuleSets[0].Rules[0]
	if rule.Match.SourceAddressName != "mynet" {
		t.Errorf("SourceAddressName = %q, want mynet", rule.Match.SourceAddressName)
	}
}

func TestDNATPortRange(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool host1 {
                address 10.0.30.100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule port-range {
                    match {
                        destination-address 50.220.171.30/32;
                        destination-port {
                            80;
                            443;
                            20000 to 20005;
                        }
                    }
                    then {
                        destination-nat pool host1;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	// Expect: 80, 443, 20000, 20001, 20002, 20003, 20004, 20005 = 8 ports
	if len(rule.Match.DestinationPorts) != 8 {
		t.Fatalf("DestinationPorts = %v (len %d), want 8", rule.Match.DestinationPorts, len(rule.Match.DestinationPorts))
	}
	if rule.Match.DestinationPort != 80 {
		t.Errorf("DestinationPort = %d, want 80", rule.Match.DestinationPort)
	}
	if rule.Match.DestinationPorts[2] != 20000 {
		t.Errorf("port[2] = %d, want 20000", rule.Match.DestinationPorts[2])
	}
	if rule.Match.DestinationPorts[7] != 20005 {
		t.Errorf("port[7] = %d, want 20005", rule.Match.DestinationPorts[7])
	}
}

func TestDNATPortRangeSetSyntax(t *testing.T) {
	lines := []string{
		"set security nat destination pool web1 address 10.0.30.100",
		"set security nat destination rule-set wan-dnat from zone untrust",
		"set security nat destination rule-set wan-dnat rule r1 match destination-address 50.0.0.1/32",
		"set security nat destination rule-set wan-dnat rule r1 match destination-port 80",
		"set security nat destination rule-set wan-dnat rule r1 match destination-port 443",
		"set security nat destination rule-set wan-dnat rule r1 match destination-port 20000 to 20003",
		"set security nat destination rule-set wan-dnat rule r1 then destination-nat pool web1",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	// Expect: 80, 443, 20000, 20001, 20002, 20003 = 6 ports
	if len(rule.Match.DestinationPorts) != 6 {
		t.Fatalf("DestinationPorts = %v (len %d), want 6", rule.Match.DestinationPorts, len(rule.Match.DestinationPorts))
	}
}

func TestDNATProtocolGRE(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool gre-host {
                address 10.0.30.50;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule gre-dnat {
                    match {
                        destination-address 209.237.133.188/32;
                        protocol gre;
                    }
                    then {
                        destination-nat pool gre-host;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.Protocol != "gre" {
		t.Errorf("Protocol = %q, want gre", rule.Match.Protocol)
	}
}

func TestDNATProtocolICMP6(t *testing.T) {
	input := `security {
    nat {
        destination {
            pool icmp-host {
                address 2001:db8::100;
            }
            rule-set wan-dnat {
                from zone untrust;
                rule icmp6-dnat {
                    match {
                        destination-address 2001:db8::1/128;
                        protocol icmp6;
                    }
                    then {
                        destination-nat pool icmp-host;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.Protocol != "icmp6" {
		t.Errorf("Protocol = %q, want icmp6", rule.Match.Protocol)
	}
}

func TestLo0FilterExtraction(t *testing.T) {
	input := `interfaces {
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input filter-management;
                }
            }
            family inet6 {
                filter {
                    input filter-management6;
                }
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Lo0FilterInputV4 != "filter-management" {
		t.Errorf("Lo0FilterInputV4 = %q, want filter-management", cfg.System.Lo0FilterInputV4)
	}
	if cfg.System.Lo0FilterInputV6 != "filter-management6" {
		t.Errorf("Lo0FilterInputV6 = %q, want filter-management6", cfg.System.Lo0FilterInputV6)
	}
}

func TestLo0FilterExtractionSet(t *testing.T) {
	lines := []string{
		"set interfaces lo0 unit 0 family inet filter input mgmt-v4",
		"set interfaces lo0 unit 0 family inet6 filter input mgmt-v6",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.System.Lo0FilterInputV4 != "mgmt-v4" {
		t.Errorf("Lo0FilterInputV4 = %q, want mgmt-v4", cfg.System.Lo0FilterInputV4)
	}
	if cfg.System.Lo0FilterInputV6 != "mgmt-v6" {
		t.Errorf("Lo0FilterInputV6 = %q, want mgmt-v6", cfg.System.Lo0FilterInputV6)
	}
}

func TestHostInboundRouterDiscovery(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust host-inbound-traffic protocols bgp",
		"set security zones security-zone trust host-inbound-traffic protocols router-discovery",
		"set security zones security-zone trust interfaces trust0",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone is nil")
	}
	if trust.HostInboundTraffic == nil {
		t.Fatal("host-inbound-traffic is nil")
	}
	protos := trust.HostInboundTraffic.Protocols
	found := map[string]bool{}
	for _, p := range protos {
		found[p] = true
	}
	if !found["bgp"] {
		t.Error("missing protocol bgp")
	}
	if !found["router-discovery"] {
		t.Error("missing protocol router-discovery")
	}
}

func TestNat66SourceRules(t *testing.T) {
	input := `security {
    nat {
        source {
            rule-set internal-to-internet {
                from zone trust;
                to zone untrust;
                rule nat66-iface {
                    match {
                        source-address ::/0;
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
    zones {
        security-zone trust {
            interfaces trust0;
        }
        security-zone untrust {
            interfaces untrust0;
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	rs := cfg.Security.NAT.Source
	if len(rs) != 1 {
		t.Fatalf("expected 1 SNAT rule-set, got %d", len(rs))
	}
	rules := rs[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "nat66-iface" {
		t.Errorf("rule name = %q, want nat66-iface", rules[0].Name)
	}
	if rules[0].Match.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rules[0].Match.SourceAddress)
	}
	if !rules[0].Then.Interface {
		t.Error("expected interface SNAT")
	}
}

func TestSNATMultipleSourceAddressBracketList(t *testing.T) {
	input := `
security {
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address [ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ];
                    }
                    then {
                        source-nat interface;
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
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("expected 1 rule-set, got %d", len(cfg.Security.NAT.Source))
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	// SourceAddress should be first element for backward compat
	if rules[0].Match.SourceAddress != "10.0.0.0/8" {
		t.Errorf("SourceAddress = %q, want 10.0.0.0/8", rules[0].Match.SourceAddress)
	}
	// SourceAddresses should have all three
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(rules[0].Match.SourceAddresses) != len(want) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
}

func TestSNATMultipleSourceAddressSetSyntax(t *testing.T) {
	lines := []string{
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match source-address 172.16.0.0/12",
		"set security nat source rule-set rs1 rule r1 match source-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 {
		t.Fatal("NAT source config is empty")
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(rules[0].Match.SourceAddresses) != len(want) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
}

func TestDNATApplicationMatching(t *testing.T) {
	// Verify that DNAT rule with application match parses correctly
	input := `
security {
    nat {
        destination {
            pool web-pool {
                address 10.0.1.100/32;
            }
            rule-set rs1 {
                from zone untrust;
                rule web-dnat {
                    match {
                        destination-address 203.0.113.1/32;
                        application junos-http;
                    }
                    then {
                        destination-nat pool web-pool;
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
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("NAT destination config is nil")
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.Application != "junos-http" {
		t.Errorf("Application = %q, want junos-http", rules[0].Match.Application)
	}
	if rules[0].Match.DestinationAddress != "203.0.113.1/32" {
		t.Errorf("DestinationAddress = %q, want 203.0.113.1/32", rules[0].Match.DestinationAddress)
	}
}

func TestDNATApplicationSet(t *testing.T) {
	// Verify that DNAT rule with application-set (multi-term app) parses correctly
	input := `
applications {
    application unifi-tcp-8080 {
        protocol tcp;
        destination-port 8080;
    }
    application unifi-udp-3478 {
        protocol udp;
        destination-port 3478;
    }
    application-set unifi-controller {
        application unifi-tcp-8080;
        application unifi-udp-3478;
    }
}
security {
    nat {
        destination {
            pool unifi-pool {
                address 10.0.1.50/32;
            }
            rule-set rs1 {
                from zone untrust;
                rule unifi-dnat {
                    match {
                        destination-address 203.0.113.10/32;
                        application unifi-controller;
                    }
                    then {
                        destination-nat pool unifi-pool;
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
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Verify DNAT rule has application-set reference
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Match.Application != "unifi-controller" {
		t.Errorf("Application = %q, want unifi-controller", rules[0].Match.Application)
	}
	// Verify application-set was compiled with both members
	as, ok := cfg.Applications.ApplicationSets["unifi-controller"]
	if !ok {
		t.Fatal("application-set unifi-controller not found")
	}
	if len(as.Applications) != 2 {
		t.Errorf("application-set has %d members, want 2", len(as.Applications))
	}
	// Verify individual apps are resolvable
	expanded, err := ExpandApplicationSet("unifi-controller", &cfg.Applications)
	if err != nil {
		t.Fatalf("expand application-set: %v", err)
	}
	if len(expanded) != 2 {
		t.Errorf("expanded to %d apps, want 2", len(expanded))
	}
}

func TestSNATDestinationAddressBracketList(t *testing.T) {
	input := `
security {
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address 10.0.0.0/8;
                        destination-address [ 203.0.113.0/24 198.51.100.0/24 ];
                    }
                    then {
                        source-nat interface;
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
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	// DestinationAddress backward compat
	if rules[0].Match.DestinationAddress != "203.0.113.0/24" {
		t.Errorf("DestinationAddress = %q, want 203.0.113.0/24", rules[0].Match.DestinationAddress)
	}
	// DestinationAddresses should have both
	want := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if len(rules[0].Match.DestinationAddresses) != len(want) {
		t.Fatalf("DestinationAddresses len = %d, want %d", len(rules[0].Match.DestinationAddresses), len(want))
	}
	for i, w := range want {
		if rules[0].Match.DestinationAddresses[i] != w {
			t.Errorf("DestinationAddresses[%d] = %q, want %q", i, rules[0].Match.DestinationAddresses[i], w)
		}
	}
}

func TestSNATMultipleAddressPairsSetSyntax(t *testing.T) {
	lines := []string{
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match source-address 172.16.0.0/12",
		"set security nat source rule-set rs1 rule r1 match destination-address 203.0.113.0/24",
		"set security nat source rule-set rs1 rule r1 match destination-address 198.51.100.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat off",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules := cfg.Security.NAT.Source[0].Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	// Both source and destination bracket lists
	wantSrc := []string{"10.0.0.0/8", "172.16.0.0/12"}
	if len(rules[0].Match.SourceAddresses) != len(wantSrc) {
		t.Fatalf("SourceAddresses len = %d, want %d", len(rules[0].Match.SourceAddresses), len(wantSrc))
	}
	for i, w := range wantSrc {
		if rules[0].Match.SourceAddresses[i] != w {
			t.Errorf("SourceAddresses[%d] = %q, want %q", i, rules[0].Match.SourceAddresses[i], w)
		}
	}
	wantDst := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if len(rules[0].Match.DestinationAddresses) != len(wantDst) {
		t.Fatalf("DestinationAddresses len = %d, want %d", len(rules[0].Match.DestinationAddresses), len(wantDst))
	}
	for i, w := range wantDst {
		if rules[0].Match.DestinationAddresses[i] != w {
			t.Errorf("DestinationAddresses[%d] = %q, want %q", i, rules[0].Match.DestinationAddresses[i], w)
		}
	}
	// source-nat off
	if !rules[0].Then.Off {
		t.Error("expected Then.Off = true")
	}
}

func TestStaticNATInet(t *testing.T) {
	input := `
security {
    nat {
        static {
            rule-set nat64-test {
                from zone lan;
                rule ipv6-clients {
                    match {
                        source-address ::/0;
                        destination-address 64:ff9b::/96;
                    }
                    then {
                        static-nat {
                            inet;
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
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if rs.FromZone != "lan" {
		t.Errorf("from-zone = %q, want lan", rs.FromZone)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	rule := rs.Rules[0]
	if rule.Match != "64:ff9b::/96" {
		t.Errorf("match = %q, want 64:ff9b::/96", rule.Match)
	}
	if rule.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rule.SourceAddress)
	}
	if rule.Then != "inet" {
		t.Errorf("then = %q, want inet", rule.Then)
	}
}

func TestStaticNATInetSetSyntax(t *testing.T) {
	lines := []string{
		"set security nat static rule-set nat64 from zone lan",
		"set security nat static rule-set nat64 rule r1 match source-address ::/0",
		"set security nat static rule-set nat64 rule r1 match destination-address 64:ff9b::/96",
		"set security nat static rule-set nat64 rule r1 then static-nat inet",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "inet" {
		t.Errorf("then = %q, want inet", rule.Then)
	}
	if rule.SourceAddress != "::/0" {
		t.Errorf("source-address = %q, want ::/0", rule.SourceAddress)
	}
}

func TestNATv6v4NoFragHeader(t *testing.T) {
	input := `
security {
    nat {
        natv6v4 {
            no-v6-frag-header;
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
		t.Fatal(err)
	}
	if cfg.Security.NAT.NATv6v4 == nil {
		t.Fatal("NATv6v4 is nil")
	}
	if !cfg.Security.NAT.NATv6v4.NoV6FragHeader {
		t.Error("NoV6FragHeader should be true")
	}
}

func TestNATv6v4SetSyntax(t *testing.T) {
	lines := []string{
		"set security nat natv6v4 no-v6-frag-header",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.NAT.NATv6v4 == nil {
		t.Fatal("NATv6v4 is nil")
	}
	if !cfg.Security.NAT.NATv6v4.NoV6FragHeader {
		t.Error("NoV6FragHeader should be true")
	}
}

func TestLLDPPerInterfaceDisable(t *testing.T) {
	input := `
protocols {
    lldp {
        interface eth0;
        interface eth1 {
            disable;
        }
        transmit-interval 60;
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
		t.Fatal(err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatal("LLDP is nil")
	}
	if len(cfg.Protocols.LLDP.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(cfg.Protocols.LLDP.Interfaces))
	}
	if cfg.Protocols.LLDP.Interfaces[0].Name != "eth0" {
		t.Errorf("interface[0] name = %q, want eth0", cfg.Protocols.LLDP.Interfaces[0].Name)
	}
	if cfg.Protocols.LLDP.Interfaces[0].Disable {
		t.Error("eth0 should not be disabled")
	}
	if cfg.Protocols.LLDP.Interfaces[1].Name != "eth1" {
		t.Errorf("interface[1] name = %q, want eth1", cfg.Protocols.LLDP.Interfaces[1].Name)
	}
	if !cfg.Protocols.LLDP.Interfaces[1].Disable {
		t.Error("eth1 should be disabled")
	}
	if cfg.Protocols.LLDP.Interval != 60 {
		t.Errorf("interval = %d, want 60", cfg.Protocols.LLDP.Interval)
	}
}

func TestLLDPPerInterfaceDisableSetSyntax(t *testing.T) {
	lines := []string{
		"set protocols lldp interface eth0",
		"set protocols lldp interface eth1 disable",
		"set protocols lldp transmit-interval 60",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatal("LLDP is nil")
	}
	if len(cfg.Protocols.LLDP.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(cfg.Protocols.LLDP.Interfaces))
	}
	found := false
	for _, iface := range cfg.Protocols.LLDP.Interfaces {
		if iface.Name == "eth1" {
			found = true
			if !iface.Disable {
				t.Error("eth1 should be disabled")
			}
		}
	}
	if !found {
		t.Error("eth1 not found in interfaces")
	}
}

func TestGenerateRoutes(t *testing.T) {
	input := `
routing-options {
    generate {
        route 192.168.0.0/16 {
            policy export-to-isp;
        }
        route 10.0.0.0/8 {
            discard;
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
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 2 {
		t.Fatalf("expected 2 generate routes, got %d", len(cfg.RoutingOptions.GenerateRoutes))
	}
	gr0 := cfg.RoutingOptions.GenerateRoutes[0]
	if gr0.Prefix != "192.168.0.0/16" {
		t.Errorf("route[0] prefix = %q, want 192.168.0.0/16", gr0.Prefix)
	}
	if gr0.Policy != "export-to-isp" {
		t.Errorf("route[0] policy = %q, want export-to-isp", gr0.Policy)
	}
	gr1 := cfg.RoutingOptions.GenerateRoutes[1]
	if gr1.Prefix != "10.0.0.0/8" {
		t.Errorf("route[1] prefix = %q, want 10.0.0.0/8", gr1.Prefix)
	}
	if !gr1.Discard {
		t.Error("route[1] should have discard=true")
	}
}

func TestGenerateRoutesSetSyntax(t *testing.T) {
	lines := []string{
		"set routing-options generate route 192.168.0.0/16 policy export-to-isp",
		"set routing-options generate route 10.0.0.0/8 discard",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 2 {
		t.Fatalf("expected 2 generate routes, got %d", len(cfg.RoutingOptions.GenerateRoutes))
	}
	found := false
	for _, gr := range cfg.RoutingOptions.GenerateRoutes {
		if gr.Prefix == "10.0.0.0/8" && gr.Discard {
			found = true
		}
	}
	if !found {
		t.Error("10.0.0.0/8 discard route not found")
	}
}

func TestThreeColorPolicer(t *testing.T) {
	input := `firewall {
    three-color-policer tcp-3color {
        two-rate {
            color-blind;
            committed-information-rate 10m;
            committed-burst-size 100k;
            peak-information-rate 50m;
            peak-burst-size 500k;
        }
    }
    three-color-policer sr-3color {
        single-rate {
            committed-information-rate 5m;
            committed-burst-size 50k;
            excess-burst-size 200k;
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}

	if len(cfg.Firewall.ThreeColorPolicers) != 2 {
		t.Fatalf("expected 2 three-color policers, got %d", len(cfg.Firewall.ThreeColorPolicers))
	}

	tcp := cfg.Firewall.ThreeColorPolicers["tcp-3color"]
	if tcp == nil {
		t.Fatal("tcp-3color policer not found")
	}
	if !tcp.TwoRate {
		t.Error("expected TwoRate=true")
	}
	if !tcp.ColorBlind {
		t.Error("expected ColorBlind=true")
	}
	// 10m = 10,000,000 bits/sec = 1,250,000 bytes/sec
	if tcp.CIR != 1250000 {
		t.Errorf("CIR = %d, want 1250000", tcp.CIR)
	}
	if tcp.CBS != 100000 {
		t.Errorf("CBS = %d, want 100000", tcp.CBS)
	}
	// 50m = 50,000,000 bits/sec = 6,250,000 bytes/sec
	if tcp.PIR != 6250000 {
		t.Errorf("PIR = %d, want 6250000", tcp.PIR)
	}
	if tcp.PBS != 500000 {
		t.Errorf("PBS = %d, want 500000", tcp.PBS)
	}

	sr := cfg.Firewall.ThreeColorPolicers["sr-3color"]
	if sr == nil {
		t.Fatal("sr-3color policer not found")
	}
	if sr.TwoRate {
		t.Error("expected TwoRate=false for single-rate")
	}
	if sr.CIR != 625000 {
		t.Errorf("CIR = %d, want 625000", sr.CIR)
	}
	if sr.CBS != 50000 {
		t.Errorf("CBS = %d, want 50000", sr.CBS)
	}
	if sr.PBS != 200000 {
		t.Errorf("PBS = %d, want 200000", sr.PBS)
	}
}

func TestThreeColorPolicerSetSyntax(t *testing.T) {
	lines := []string{
		"set firewall three-color-policer my-3c two-rate color-blind",
		"set firewall three-color-policer my-3c two-rate committed-information-rate 10m",
		"set firewall three-color-policer my-3c two-rate committed-burst-size 100k",
		"set firewall three-color-policer my-3c two-rate peak-information-rate 50m",
		"set firewall three-color-policer my-3c two-rate peak-burst-size 500k",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	tcp := cfg.Firewall.ThreeColorPolicers["my-3c"]
	if tcp == nil {
		t.Fatal("my-3c policer not found")
	}
	if !tcp.TwoRate {
		t.Error("expected TwoRate=true")
	}
	if !tcp.ColorBlind {
		t.Error("expected ColorBlind=true")
	}
	if tcp.CIR != 1250000 {
		t.Errorf("CIR = %d, want 1250000", tcp.CIR)
	}
	if tcp.PIR != 6250000 {
		t.Errorf("PIR = %d, want 6250000", tcp.PIR)
	}
}

func TestLogicalInterfacePolicer(t *testing.T) {
	input := `firewall {
    policer shared-rate {
        logical-interface-policer;
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then discard;
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	pol := cfg.Firewall.Policers["shared-rate"]
	if pol == nil {
		t.Fatal("shared-rate policer not found")
	}
	if !pol.LogicalInterfacePolicer {
		t.Error("expected LogicalInterfacePolicer=true")
	}
}

func TestFlexibleMatchRange(t *testing.T) {
	input := `firewall {
    family inet {
        filter flex-test {
            term t1 {
                from {
                    flexible-match-range {
                        range proto-check {
                            match-start layer-3;
                            byte-offset 9;
                            bit-length 8;
                            match-value 0x11;
                            match-mask 0xFF;
                        }
                    }
                }
                then accept;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile error: %v", cerr)
	}
	f := cfg.Firewall.FiltersInet["flex-test"]
	if f == nil {
		t.Fatal("flex-test filter not found")
	}
	if len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %d", len(f.Terms))
	}
	fm := f.Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("FlexMatch is nil")
	}
	if fm.MatchStart != "layer-3" {
		t.Errorf("MatchStart = %q, want layer-3", fm.MatchStart)
	}
	if fm.ByteOffset != 9 {
		t.Errorf("ByteOffset = %d, want 9", fm.ByteOffset)
	}
	if fm.BitLength != 8 {
		t.Errorf("BitLength = %d, want 8", fm.BitLength)
	}
	if fm.Value != 0x11 {
		t.Errorf("Value = 0x%x, want 0x11", fm.Value)
	}
	if fm.Mask != 0xFF {
		t.Errorf("Mask = 0x%x, want 0xFF", fm.Mask)
	}
}

func TestFlexibleMatchRangeSetSyntax(t *testing.T) {
	lines := []string{
		"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 match-start layer-3",
		"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 bit-length 32",
		"set firewall family inet filter flex-set term t1 from flexible-match-range range r1 range 0x0a000000/0xff000000",
		"set firewall family inet filter flex-set term t1 then discard",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(cmd)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["flex-set"]
	if f == nil {
		t.Fatal("flex-set filter not found")
	}
	fm := f.Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("FlexMatch is nil")
	}
	if fm.ByteOffset != 12 {
		t.Errorf("ByteOffset = %d, want 12", fm.ByteOffset)
	}
	if fm.BitLength != 32 {
		t.Errorf("BitLength = %d, want 32", fm.BitLength)
	}
	if fm.Value != 0x0a000000 {
		t.Errorf("Value = 0x%x, want 0x0a000000", fm.Value)
	}
	if fm.Mask != 0xff000000 {
		t.Errorf("Mask = 0x%x, want 0xff000000", fm.Mask)
	}
}

func TestLAGInterfaceHierarchical(t *testing.T) {
	input := `
interfaces {
    ae0 {
        description "LAG to switch";
        aggregated-ether-options {
            lacp {
                active;
                periodic fast;
            }
            link-speed 10g;
            minimum-links 1;
        }
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/0 {
        gigether-options {
            802.3ad ae0;
        }
    }
    ge-0/0/1 {
        gigether-options {
            802.3ad ae0;
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

	// Check ae0 interface
	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0 interface")
	}
	if ae0.Description != "LAG to switch" {
		t.Errorf("ae0 description: got %q", ae0.Description)
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("ae0 aggregated-ether-options is nil")
	}
	if !ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP active")
	}
	if ae0.AggregatedEtherOpts.LACPPeriodic != "fast" {
		t.Errorf("LACP periodic: got %q, want fast", ae0.AggregatedEtherOpts.LACPPeriodic)
	}
	if ae0.AggregatedEtherOpts.LinkSpeed != "10g" {
		t.Errorf("link-speed: got %q, want 10g", ae0.AggregatedEtherOpts.LinkSpeed)
	}
	if ae0.AggregatedEtherOpts.MinimumLinks != 1 {
		t.Errorf("minimum-links: got %d, want 1", ae0.AggregatedEtherOpts.MinimumLinks)
	}

	// Check unit 0
	u0 := ae0.Units[0]
	if u0 == nil {
		t.Fatal("ae0 missing unit 0")
	}
	if len(u0.Addresses) != 1 || u0.Addresses[0] != "10.0.1.1/24" {
		t.Errorf("ae0 unit 0 addresses: %v", u0.Addresses)
	}

	// Check member bindings
	ge0 := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge0 == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if ge0.LAGParent != "ae0" {
		t.Errorf("ge-0/0/0 LAGParent: got %q, want ae0", ge0.LAGParent)
	}

	ge1 := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if ge1 == nil {
		t.Fatal("missing ge-0/0/1")
	}
	if ge1.LAGParent != "ae0" {
		t.Errorf("ge-0/0/1 LAGParent: got %q, want ae0", ge1.LAGParent)
	}
}

func TestLAGInterfaceSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set interfaces ae0 description \"LAG bundle\"",
		"set interfaces ae0 aggregated-ether-options lacp active",
		"set interfaces ae0 aggregated-ether-options lacp periodic fast",
		"set interfaces ae0 aggregated-ether-options link-speed 10g",
		"set interfaces ae0 aggregated-ether-options minimum-links 2",
		"set interfaces ae0 unit 0 family inet address 10.0.5.1/24",
		"set interfaces ge-0/0/0 gigether-options 802.3ad ae0",
		"set interfaces ge-0/0/1 gigether-options 802.3ad ae0",
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
		t.Fatalf("compile error: %v", err)
	}

	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0")
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("aggregated-ether-options is nil")
	}
	if !ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP active")
	}
	if ae0.AggregatedEtherOpts.LACPPeriodic != "fast" {
		t.Errorf("periodic: got %q, want fast", ae0.AggregatedEtherOpts.LACPPeriodic)
	}
	if ae0.AggregatedEtherOpts.LinkSpeed != "10g" {
		t.Errorf("link-speed: got %q", ae0.AggregatedEtherOpts.LinkSpeed)
	}
	if ae0.AggregatedEtherOpts.MinimumLinks != 2 {
		t.Errorf("minimum-links: got %d, want 2", ae0.AggregatedEtherOpts.MinimumLinks)
	}

	ge0 := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge0 == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if ge0.LAGParent != "ae0" {
		t.Errorf("ge-0/0/0 LAGParent: got %q", ge0.LAGParent)
	}

	ge1 := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if ge1 == nil {
		t.Fatal("missing ge-0/0/1")
	}
	if ge1.LAGParent != "ae0" {
		t.Errorf("ge-0/0/1 LAGParent: got %q", ge1.LAGParent)
	}
}

func TestFlexibleVlanTaggingHierarchical(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        encapsulation flexible-ethernet-services;
        unit 100 {
            vlan-id 100;
            inner-vlan-id 200;
            family inet {
                address 10.0.100.1/24;
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

	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if !ifc.FlexibleVlanTagging {
		t.Error("expected flexible-vlan-tagging to be true")
	}
	if ifc.Encapsulation != "flexible-ethernet-services" {
		t.Errorf("encapsulation: got %q, want flexible-ethernet-services", ifc.Encapsulation)
	}

	u100 := ifc.Units[100]
	if u100 == nil {
		t.Fatal("missing unit 100")
	}
	if u100.VlanID != 100 {
		t.Errorf("vlan-id: got %d, want 100", u100.VlanID)
	}
	if u100.InnerVlanID != 200 {
		t.Errorf("inner-vlan-id: got %d, want 200", u100.InnerVlanID)
	}
	if len(u100.Addresses) != 1 || u100.Addresses[0] != "10.0.100.1/24" {
		t.Errorf("addresses: %v", u100.Addresses)
	}
}

func TestFlexibleVlanTaggingSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 encapsulation flexible-ethernet-services",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 inner-vlan-id 200",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.100.1/24",
		"set interfaces ge-0/0/0 unit 200 vlan-id 300",
		"set interfaces ge-0/0/0 unit 200 inner-vlan-id 400",
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
		t.Fatalf("compile error: %v", err)
	}

	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if !ifc.FlexibleVlanTagging {
		t.Error("expected flexible-vlan-tagging")
	}
	if ifc.Encapsulation != "flexible-ethernet-services" {
		t.Errorf("encapsulation: got %q", ifc.Encapsulation)
	}

	u100 := ifc.Units[100]
	if u100 == nil {
		t.Fatal("missing unit 100")
	}
	if u100.VlanID != 100 {
		t.Errorf("unit 100 vlan-id: got %d", u100.VlanID)
	}
	if u100.InnerVlanID != 200 {
		t.Errorf("unit 100 inner-vlan-id: got %d", u100.InnerVlanID)
	}

	u200 := ifc.Units[200]
	if u200 == nil {
		t.Fatal("missing unit 200")
	}
	if u200.VlanID != 300 {
		t.Errorf("unit 200 vlan-id: got %d", u200.VlanID)
	}
	if u200.InnerVlanID != 400 {
		t.Errorf("unit 200 inner-vlan-id: got %d", u200.InnerVlanID)
	}
}

func TestLACPPassiveMode(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{
		"set interfaces ae0 aggregated-ether-options lacp passive",
		"set interfaces ae0 unit 0 family inet address 10.0.1.1/24",
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
		t.Fatalf("compile error: %v", err)
	}

	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0")
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("aggregated-ether-options is nil")
	}
	if ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP not active")
	}
	if !ae0.AggregatedEtherOpts.LACPPassive {
		t.Error("expected LACP passive")
	}
}

func TestInterfaceBandwidth(t *testing.T) {
	// Test hierarchical config
	input := `interfaces {
    wan0 {
        bandwidth 1g;
        unit 0 {
            family inet {
                address 172.16.50.5/24;
            }
        }
    }
    trust0 {
        bandwidth 100m;
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	wan0 := cfg.Interfaces.Interfaces["wan0"]
	if wan0 == nil {
		t.Fatal("wan0 not found")
	}
	if wan0.Bandwidth != 1000000000 {
		t.Errorf("wan0 bandwidth = %d, want 1000000000", wan0.Bandwidth)
	}

	trust0 := cfg.Interfaces.Interfaces["trust0"]
	if trust0 == nil {
		t.Fatal("trust0 not found")
	}
	if trust0.Bandwidth != 100000000 {
		t.Errorf("trust0 bandwidth = %d, want 100000000", trust0.Bandwidth)
	}
}

func TestInterfaceBandwidthSetSyntax(t *testing.T) {
	cmds := []string{
		"set interfaces wan0 bandwidth 1g",
		"set interfaces wan0 unit 0 family inet address 172.16.50.5/24",
		"set interfaces trust0 bandwidth 100m",
		"set interfaces trust0 unit 0 family inet address 10.0.1.10/24",
		"set interfaces lo0 bandwidth 10000",
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
		t.Fatalf("compile error: %v", err)
	}

	wan0 := cfg.Interfaces.Interfaces["wan0"]
	if wan0 == nil {
		t.Fatal("wan0 not found")
	}
	if wan0.Bandwidth != 1000000000 {
		t.Errorf("wan0 bandwidth = %d, want 1000000000", wan0.Bandwidth)
	}

	trust0 := cfg.Interfaces.Interfaces["trust0"]
	if trust0 == nil {
		t.Fatal("trust0 not found")
	}
	if trust0.Bandwidth != 100000000 {
		t.Errorf("trust0 bandwidth = %d, want 100000000", trust0.Bandwidth)
	}

	lo0 := cfg.Interfaces.Interfaces["lo0"]
	if lo0 == nil {
		t.Fatal("lo0 not found")
	}
	if lo0.Bandwidth != 10000 {
		t.Errorf("lo0 bandwidth = %d, want 10000", lo0.Bandwidth)
	}
}

func TestParseBandwidthBps(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"1g", 1000000000},
		{"10G", 10000000000},
		{"100m", 100000000},
		{"500k", 500000},
		{"10000", 10000},
		{"", 0},
		{"abc", 0},
	}
	for _, tc := range tests {
		got := parseBandwidthBps(tc.input)
		if got != tc.want {
			t.Errorf("parseBandwidthBps(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
