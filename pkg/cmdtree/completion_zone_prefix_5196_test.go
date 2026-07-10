package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5196 (A3-b1-F4): the completion walker resolved unique keyword
// prefixes for traversal but discarded the canonical name, passing the
// raw (possibly abbreviated) words to ContextDynamicFn. The policy-name
// provider under `show security policies from-zone <z> to-zone <z>
// policy` scans the consumed words for the EXACT keywords "from-zone"
// and "to-zone" to recover the zone pair. With an accepted abbreviation
// ("from-z"/"to-z") the scan found neither, both zones came back empty,
// and every policy-name candidate was hidden. The walker now records the
// canonical keyword for each resolved word, so abbreviated and spelled-
// out keyword forms complete identically. Reverting canonWords makes the
// abbreviated form return no policy names (RED on revert).

func zonePolicyTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {},
		"untrust": {},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{
				{Name: "allow-web"},
				{Name: "allow-ssh"},
			},
		},
	}
	return cfg
}

func TestPolicyCompletionRetainsZoneOnAbbreviatedKeywords(t *testing.T) {
	cfg := zonePolicyTestConfig()

	// Exact keywords: baseline, must surface both policy names.
	exact := CompleteFromTree(OperationalTree,
		[]string{"show", "security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"}, "", cfg)
	for _, want := range []string{"allow-web", "allow-ssh"} {
		if !contains(exact, want) {
			t.Fatalf("exact keywords: expected policy %q, got %v", want, exact)
		}
	}

	// Accepted unique-prefix abbreviations for the from-zone/to-zone
	// keywords must produce the SAME policy-name candidates.
	abbrev := CompleteFromTree(OperationalTree,
		[]string{"show", "security", "policies", "from-z", "trust", "to-z", "untrust", "policy"}, "", cfg)
	for _, want := range []string{"allow-web", "allow-ssh"} {
		if !contains(abbrev, want) {
			t.Fatalf("abbreviated keywords: expected policy %q, got %v (zone state lost through prefix completion)", want, abbrev)
		}
	}

	if len(exact) != len(abbrev) {
		t.Fatalf("exact vs abbreviated candidate sets differ: exact=%v abbrev=%v", exact, abbrev)
	}
}

func TestPolicyCompletionAbbreviatedWithPartial(t *testing.T) {
	cfg := zonePolicyTestConfig()
	// Abbreviated keywords + a partial policy name filter.
	cands := CompleteFromTree(OperationalTree,
		[]string{"show", "security", "policies", "from-z", "trust", "to-z", "untrust", "policy"}, "allow-w", cfg)
	if !contains(cands, "allow-web") {
		t.Fatalf("abbreviated keywords + partial: expected allow-web, got %v", cands)
	}
	if contains(cands, "allow-ssh") {
		t.Fatalf("abbreviated keywords + partial: allow-ssh should be filtered by prefix, got %v", cands)
	}
}

func TestPolicyCompletionWithDescAbbreviatedKeywords(t *testing.T) {
	cfg := zonePolicyTestConfig()
	// The description-bearing walker must retain zone state too.
	cands := CompleteFromTreeWithDesc(OperationalTree,
		[]string{"show", "security", "policies", "from-z", "trust", "to-z", "untrust", "policy"}, "", cfg)
	var names []string
	for _, c := range cands {
		names = append(names, c.Name)
	}
	for _, want := range []string{"allow-web", "allow-ssh"} {
		if !contains(names, want) {
			t.Fatalf("abbreviated keywords (desc): expected policy %q, got %v", want, names)
		}
	}
}
