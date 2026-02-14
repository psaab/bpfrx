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
			Name:   "test",
			Action: tt.action,
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
	}

	rule := nftRuleFromTerm(term, "ip6", prefixLists)
	want := "ip6 saddr 10.0.1.0/24 accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}
