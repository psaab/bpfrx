package dataplane

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestExpandFilterTermNegateFlags(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"rfc1918": {
			Name:     "rfc1918",
			Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		"bogons": {
			Name:     "bogons",
			Prefixes: []string{"192.168.0.0/16"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "negate-test",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "rfc1918", Except: true},
		},
		DestPrefixLists: []config.PrefixListRef{
			{Name: "bogons", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	// Source: 2 prefixes (except) × Dest: 1 prefix (normal) = 2 rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	for i, r := range rules {
		// Source should have SrcAddr + SrcNegate
		if r.MatchFlags&FilterMatchSrcAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcAddr", i)
		}
		if r.MatchFlags&FilterMatchSrcNegate == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcNegate for except prefix-list", i)
		}
		// Destination should have DstAddr but NOT DstNegate
		if r.MatchFlags&FilterMatchDstAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchDstAddr", i)
		}
		if r.MatchFlags&FilterMatchDstNegate != 0 {
			t.Errorf("rule %d: unexpected FilterMatchDstNegate for non-except prefix-list", i)
		}
	}
}

func TestExpandFilterTermDstNegate(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"private": {
			Name:     "private",
			Prefixes: []string{"10.0.0.0/8"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "dst-negate-test",
		Action: "discard",
		DestPrefixLists: []config.PrefixListRef{
			{Name: "private", Except: true},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchDstAddr == 0 {
		t.Error("missing FilterMatchDstAddr")
	}
	if r.MatchFlags&FilterMatchDstNegate == 0 {
		t.Error("missing FilterMatchDstNegate for except prefix-list")
	}
	if r.MatchFlags&FilterMatchSrcAddr != 0 {
		t.Error("unexpected FilterMatchSrcAddr for term with no source")
	}
	if r.Action != FilterActionDiscard {
		t.Errorf("expected discard action, got %d", r.Action)
	}
}

func TestExpandFilterTermNoNegateWithoutExcept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"allowed": {
			Name:     "allowed",
			Prefixes: []string{"10.0.1.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "no-negate",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "allowed", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchSrcAddr == 0 {
		t.Error("missing FilterMatchSrcAddr")
	}
	if r.MatchFlags&FilterMatchSrcNegate != 0 {
		t.Error("unexpected FilterMatchSrcNegate for non-except prefix-list")
	}
	if r.MatchFlags&FilterMatchDstNegate != 0 {
		t.Error("unexpected FilterMatchDstNegate")
	}
}
