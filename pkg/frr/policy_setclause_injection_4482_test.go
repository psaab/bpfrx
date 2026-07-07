package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_SetClauseAndPrefixListSanitized_4482 is a
// FAIL-ON-REVERT guard for the residual #4097 sanitize-belt bypass on the
// tolerant-load path. #4097 wrapped the `bgp community-list` / `bgp as-path
// access-list` DEFINITIONS in sanitizeFRRValue, but left the route-map `set
// community` / `set as-path prepend` clauses AND the `ip/ipv6 prefix-list`
// entries rendering with a bare %s. A value that carries an embedded newline
// (materialized from a stored `\n` escape by the lexer on a leniently-loaded /
// peer-synced / rolled-back config — the paths the strict #1798 commit gate
// does NOT cover) would then inject a standalone frr.conf command.
//
// The fix routes ALL FRR-rendered free-text through sanitizeFRRValue regardless
// of load path, collapsing the newline to a space so the value stays on its
// single rendered line. Reverting any of the wrapped sites turns this RED: a
// bare `router bgp 65000` / `neighbor` line appears in the managed section.
func TestGeneratePolicyOptions_SetClauseAndPrefixListSanitized_4482(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			// Newline-injecting prefix value.
			"pl-evil": {Name: "pl-evil", Prefixes: []string{"10.0.0.0/8\n router bgp 65000"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{
						Name: "t1",
						// set community (whole-attribute replace) — injection.
						Community: "65000:1\n neighbor 6.6.6.6 remote-as 65000",
						Action:    "accept",
					},
					{
						Name: "t2",
						// set as-path prepend — injection with a legitimate
						// space between ASNs that must survive.
						ASPathPrepend: []string{"65001\n router bgp 65000", "65001"},
						Action:        "accept",
					},
				},
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// No injected top-level command line may appear: every rendered line must
	// be an FRR policy-options directive, never a bare `router bgp` /
	// `neighbor` that an injected newline would have created.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "router bgp") || strings.HasPrefix(trimmed, "neighbor ") {
			t.Fatalf("config injection: rendered a standalone %q line:\n%s", trimmed, got)
		}
	}

	// The payloads survive collapsed onto their single directive lines.
	if !strings.Contains(got, "ip prefix-list pl-evil seq 5 permit 10.0.0.0/8  router bgp 65000\n") {
		t.Errorf("prefix-list entry not sanitized onto one line, got:\n%s", got)
	}
	if !strings.Contains(got, " set community 65000:1  neighbor 6.6.6.6 remote-as 65000\n") {
		t.Errorf("set community not sanitized onto one line, got:\n%s", got)
	}
	if !strings.Contains(got, " set as-path prepend 65001  router bgp 65000 65001\n") {
		t.Errorf("set as-path prepend not sanitized onto one line, got:\n%s", got)
	}
}
