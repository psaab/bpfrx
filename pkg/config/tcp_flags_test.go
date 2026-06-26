package config

import "testing"

func TestParseTCPFlagsExpression(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		required  uint8
		forbidden uint8
		ok        bool
		wantErr   bool
	}{
		{"empty", nil, 0, 0, false, false},
		{"blank", []string{"", "  "}, 0, 0, false, false},
		{"single", []string{"syn"}, 0x02, 0, true, false},
		{"upper", []string{"SYN"}, 0x02, 0, true, false},
		{"list", []string{"syn", "ack"}, 0x12, 0, true, false},
		{"quoted-list", []string{"syn ack"}, 0x12, 0, true, false},
		{"conjunction", []string{"syn & ack"}, 0x12, 0, true, false},
		// The #3076 idiom: match SYN, not ACK.
		{"syn-not-ack", []string{"syn & !ack"}, 0x02, 0x10, true, false},
		{"paren-syn-not-ack", []string{"(syn & !ack)"}, 0x02, 0x10, true, false},
		{"negation-only", []string{"!rst"}, 0, 0x04, true, false},
		{"push-alias", []string{"push"}, 0x08, 0, true, false},
		{"all", []string{"fin", "syn", "rst", "psh", "ack", "urg"}, 0x3f, 0, true, false},
		// Unrepresentable / invalid → error (fail-closed at commit).
		{"disjunction", []string{"ack | rst"}, 0, 0, false, true},
		{"negated-group", []string{"!(syn & ack)"}, 0, 0, false, true},
		{"unknown-flag", []string{"bogus"}, 0, 0, false, true},
		{"unknown-in-list", []string{"syn", "bogus"}, 0, 0, false, true},
		{"contradiction", []string{"syn & !syn"}, 0, 0, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, forb, ok, err := ParseTCPFlagsExpression(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseTCPFlagsExpression(%v): expected error, got req=0x%02x forb=0x%02x ok=%v", c.in, req, forb, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTCPFlagsExpression(%v): unexpected error: %v", c.in, err)
			}
			if ok != c.ok || req != c.required || forb != c.forbidden {
				t.Errorf("ParseTCPFlagsExpression(%v) = (req=0x%02x, forb=0x%02x, ok=%v), want (req=0x%02x, forb=0x%02x, ok=%v)",
					c.in, req, forb, ok, c.required, c.forbidden, c.ok)
			}
		})
	}
}

// TestFirewallFilterTCPFlagsCommitReject is the #3076 commit-layer guard. A
// firewall filter carrying a tcp-flags expression the dataplane cannot enforce
// (here a disjunction) MUST fail to compile rather than commit with the
// constraint silently dropped (fail-open). REVERT (removing the compileFirewall
// validation) makes CompileConfig succeed and this assert FAIL.
func TestFirewallFilterTCPFlagsCommitReject(t *testing.T) {
	build := func(flags string) (*Config, error) {
		tree := &ConfigTree{}
		cmds := []string{
			"set firewall family inet filter f term t from protocol tcp",
			"set firewall family inet filter f term t from tcp-flags \"" + flags + "\"",
			"set firewall family inet filter f term t then discard",
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
		return CompileConfig(tree)
	}

	// A representable expression compiles cleanly.
	if _, err := build("syn & !ack"); err != nil {
		t.Errorf("tcp-flags \"syn & !ack\" should compile, got: %v", err)
	}
	// A disjunction is not representable and must be rejected at commit.
	if _, err := build("ack | rst"); err == nil {
		t.Error("tcp-flags \"ack | rst\" should be rejected at commit (fail-closed), but compiled")
	}
	// An unknown flag is rejected at commit.
	if _, err := build("bogus"); err == nil {
		t.Error("tcp-flags \"bogus\" should be rejected at commit (fail-closed), but compiled")
	}
}
