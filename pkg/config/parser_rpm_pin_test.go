package config

import (
	"strings"
	"testing"
)

// TestRPMPinLeavesHierarchical covers the #1827 PR-1a leaves in the
// hierarchical AST shape: destination-interface, next-hop, and the
// canonical `target address <ip>` form.
func TestRPMPinLeavesHierarchical(t *testing.T) {
	input := `services {
    rpm {
        probe WAN {
            test wan-a {
                probe-type icmp-ping;
                target address 1.1.1.1;
                destination-interface reth0.50;
                next-hop 172.16.50.1;
                thresholds {
                    successive-loss 3;
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
	test := cfg.Services.RPM.Probes["WAN"].Tests["wan-a"]
	if test.Target != "1.1.1.1" {
		t.Fatalf("Target = %q, want 1.1.1.1 (target address form)", test.Target)
	}
	if test.DestinationInterface != "reth0.50" {
		t.Fatalf("DestinationInterface = %q, want reth0.50", test.DestinationInterface)
	}
	if test.NextHop != "172.16.50.1" {
		t.Fatalf("NextHop = %q, want 172.16.50.1", test.NextHop)
	}
}

// TestRPMPinLeavesFlatSet covers the same leaves in flat set syntax
// (ParseSetCommand + SetPath per the project testing rule).
func TestRPMPinLeavesFlatSet(t *testing.T) {
	lines := []string{
		"set services rpm probe WAN test wan-a probe-type icmp-ping",
		"set services rpm probe WAN test wan-a target address 1.1.1.1",
		"set services rpm probe WAN test wan-a destination-interface reth0.50",
		"set services rpm probe WAN test wan-a next-hop 172.16.50.1",
		"set services rpm probe WAN test wan-a thresholds successive-loss 3",
		"set services rpm probe WAN test wan-b target 1.1.1.1",
		"set services rpm probe WAN test wan-b destination-interface reth0.80",
		"set services rpm probe WAN test wan-b next-hop 172.16.80.1",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := cfg.Services.RPM.Probes["WAN"].Tests["wan-a"]
	if a.Target != "1.1.1.1" || a.DestinationInterface != "reth0.50" || a.NextHop != "172.16.50.1" {
		t.Fatalf("wan-a = %+v", a)
	}
	b := cfg.Services.RPM.Probes["WAN"].Tests["wan-b"]
	if b.Target != "1.1.1.1" || b.NextHop != "172.16.80.1" {
		t.Fatalf("wan-b = %+v (same target via second uplink)", b)
	}
}

func TestRPMPinValidation(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name: "next-hop invalid IP",
			lines: []string{
				"set services rpm probe P test t target 1.1.1.1",
				"set services rpm probe P test t destination-interface ge-0/0/1",
				"set services rpm probe P test t next-hop not-an-ip",
			},
			wantErr: "next-hop: invalid IP",
		},
		{
			name: "next-hop without destination-interface",
			lines: []string{
				"set services rpm probe P test t target 1.1.1.1",
				"set services rpm probe P test t next-hop 10.0.0.1",
			},
			wantErr: "requires destination-interface",
		},
		{
			name: "next-hop family mismatch",
			lines: []string{
				"set services rpm probe P test t target 1.1.1.1",
				"set services rpm probe P test t destination-interface ge-0/0/1",
				"set services rpm probe P test t next-hop fe80::1",
			},
			wantErr: "address family does not match",
		},
		{
			name: "next-hop with hostname target",
			lines: []string{
				"set services rpm probe P test t target example.com",
				"set services rpm probe P test t destination-interface ge-0/0/1",
				"set services rpm probe P test t next-hop 10.0.0.1",
			},
			wantErr: "IP-literal target",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestRPMPinBandCapValidation(t *testing.T) {
	var lines []string
	for i := 0; i < ProbeTableCount+1; i++ {
		name := string(rune('a'+i/26)) + string(rune('a'+i%26))
		lines = append(lines,
			"set services rpm probe P test "+name+" target 1.1.1.1",
			"set services rpm probe P test "+name+" destination-interface ge-0/0/1",
			"set services rpm probe P test "+name+" next-hop 10.0.0.1")
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "exceeding the reserved probe table band") {
		t.Fatalf("err = %v, want probe table band cap error", err)
	}
}

func TestRPMPinTableCollisionValidation(t *testing.T) {
	cfg := &Config{}
	cfg.Services.RPM = &RPMConfig{Probes: map[string]*RPMProbe{
		"P": {Name: "P", Tests: map[string]*RPMTest{
			"t": {Name: "t", Target: "1.1.1.1", NextHop: "10.0.0.1", DestinationInterface: "ge-0/0/1"},
		}},
	}}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "clash", TableID: ProbeTableBase + 3},
	}
	err := validateRPMProbePinsStrict(cfg)
	if err == nil || !strings.Contains(err.Error(), "collides with the reserved RPM probe table range") {
		t.Fatalf("err = %v, want collision error", err)
	}

	cfg.RoutingInstances[0].TableID = 100
	if err := validateRPMProbePinsStrict(cfg); err != nil {
		t.Fatalf("unexpected error for non-colliding table: %v", err)
	}
}
