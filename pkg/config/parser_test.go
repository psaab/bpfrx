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
