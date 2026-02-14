package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestNftRuleFromTermPrefixListExpansion(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"management-hosts": {
			Name:     "management-hosts",
			Prefixes: []string{"10.0.1.0/24", "10.0.2.0/24", "192.168.1.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:     "allow-ssh",
		Protocol: "tcp",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "management-hosts", Except: false},
		},
		DestinationPorts: []string{"22"},
		Action:           "accept",
		ICMPType:         -1,
		ICMPCode:         -1,
	}

	rule := nftRuleFromTerm(term, "ip", prefixLists)
	// Should contain expanded CIDRs in nft set syntax
	want := "ip saddr { 10.0.1.0/24, 10.0.2.0/24, 192.168.1.0/24 } meta l4proto tcp th dport 22 accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermPrefixListExcept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"allowed": {
			Name:     "allowed",
			Prefixes: []string{"10.0.1.0/24", "10.0.2.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:     "deny-others",
		Protocol: "tcp",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "allowed", Except: true},
		},
		DestinationPorts: []string{"22"},
		Action:           "reject",
		ICMPType:         -1,
		ICMPCode:         -1,
	}

	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "ip saddr != { 10.0.1.0/24, 10.0.2.0/24 } meta l4proto tcp th dport 22 reject"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermRejectVsDiscard(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	tests := []struct {
		action     string
		wantAction string
	}{
		{"accept", "accept"},
		{"reject", "reject"},
		{"discard", "drop"},
		{"", "accept"},
	}

	for _, tt := range tests {
		term := &config.FirewallFilterTerm{
			Name:     "test",
			Action:   tt.action,
			ICMPType: -1,
			ICMPCode: -1,
		}
		rule := nftRuleFromTerm(term, "ip", prefixLists)
		if rule != tt.wantAction {
			t.Errorf("action %q: got %q, want %q", tt.action, rule, tt.wantAction)
		}
	}
}

func TestNftRuleFromTermMultiplePorts(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:             "allow-web",
		Protocol:         "tcp",
		DestinationPorts: []string{"80", "443"},
		Action:           "accept",
		ICMPType:         -1,
		ICMPCode:         -1,
	}

	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "meta l4proto tcp th dport { 80, 443 } accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermSingleSourceAddr(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:            "allow-single",
		SourceAddresses: []string{"10.0.1.0/24"},
		Action:          "accept",
		ICMPType:        -1,
		ICMPCode:        -1,
	}

	rule := nftRuleFromTerm(term, "ip6", prefixLists)
	want := "ip6 saddr 10.0.1.0/24 accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermICMPTypeCode(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// IPv6 block-ra-adv filter: icmp-type 134 icmp-code 0 → discard
	term := &config.FirewallFilterTerm{
		Name:     "block-ra",
		ICMPType: 134,
		ICMPCode: 0,
		Action:   "discard",
	}
	rule := nftRuleFromTerm(term, "ip6", prefixLists)
	want := "icmpv6 type 134 icmpv6 code 0 drop"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}

	// IPv4 ICMP type only (no code)
	term2 := &config.FirewallFilterTerm{
		Name:     "block-redirect",
		ICMPType: 5,
		ICMPCode: -1,
		Action:   "discard",
	}
	rule2 := nftRuleFromTerm(term2, "ip", prefixLists)
	want2 := "icmp type 5 drop"
	if rule2 != want2 {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule2, want2)
	}
}

func TestNftRuleFromTermDSCP(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:     "dscp-match",
		DSCP:     "ef",
		Action:   "accept",
		ICMPType: -1,
		ICMPCode: -1,
	}
	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "ip dscp ef accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}

	// IPv6 traffic-class
	rule6 := nftRuleFromTerm(term, "ip6", prefixLists)
	want6 := "ip6 dscp ef accept"
	if rule6 != want6 {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule6, want6)
	}
}

func TestNftRuleFromTermTCPFlags(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:     "syn-only",
		Protocol: "tcp",
		TCPFlags: []string{"syn"},
		Action:   "discard",
		ICMPType: -1,
		ICMPCode: -1,
	}
	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "meta l4proto tcp tcp flags syn drop"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermFragment(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:       "drop-frags",
		IsFragment: true,
		Action:     "discard",
		ICMPType:   -1,
		ICMPCode:   -1,
	}
	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "ip frag-off & 0x1fff != 0 drop"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}
