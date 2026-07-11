package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4338: the canonical Junos "match any EXCEPT the listed prefixes" lockdown
// idiom — `from { source-address 0.0.0.0/0; source-prefix-list mgmt except; }` —
// is ACCEPTED by Junos. A match-any positive (0.0.0.0/0 / ::/0) does not
// constrain the positive set, so `any AND NOT X` reduces exactly to the
// sole-`except` representation ("match every address NOT in X"). The runtime
// lowering MUST drop the redundant match-any universe and emit the term as
// except=true over X. Before #4338 it fell through to positive-wins: the
// match-any 0/0 WON, the term matched ALL sources (never excluding X) — a
// fail-OPEN that defeats the lockdown for a discard/reject term.
//
// FAIL-ON-REVERT: remove the addrsAllMatchAny compose in
// ResolveFilterPrefixListAddrs and this returns except=false with 0.0.0.0/0 in
// the positive set (match-all) — the assertions below go RED.
func TestResolvePrefixListAddrsMatchAnyExceptComposes_4338(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt": {Name: "mgmt", Prefixes: []string{"10.1.0.0/16", "10.2.0.0/16"}},
	}

	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"0.0.0.0/0"},
		[]config.PrefixListRef{{Name: "mgmt", Except: true}},
		cfg, "f", "t", "source", "accept",
	)

	if !except {
		t.Fatalf("match-any 0.0.0.0/0 + except must compose to except=true (any NOT in X), got except=false; "+
			"addrs=%v", addrs)
	}
	if !constrained {
		t.Fatalf("an `any except X` term must stay constrained")
	}
	// The redundant match-any universe must be dropped; the matched set is
	// EXACTLY the except prefixes, inverted.
	for _, a := range addrs {
		if a == "0.0.0.0/0" {
			t.Fatalf("match-any 0.0.0.0/0 must be dropped from the compose, got addrs=%v", addrs)
		}
	}
	if len(addrs) != 2 || addrs[0] != "10.1.0.0/16" || addrs[1] != "10.2.0.0/16" {
		t.Fatalf("compose prefixes = %v, want the except set [10.1.0.0/16 10.2.0.0/16]", addrs)
	}
}

// The inet6 ::/0 variant composes identically.
func TestResolvePrefixListAddrsMatchAnyExceptComposesV6_4338(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt6": {Name: "mgmt6", Prefixes: []string{"2001:db8:1::/48"}},
	}
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"::/0"},
		[]config.PrefixListRef{{Name: "mgmt6", Except: true}},
		cfg, "f6", "t", "source", "accept",
	)
	if !except || !constrained {
		t.Fatalf("::/0 + except must compose to except=true, constrained=true; got except=%v constrained=%v addrs=%v",
			except, constrained, addrs)
	}
	if len(addrs) != 1 || addrs[0] != "2001:db8:1::/48" {
		t.Fatalf("compose prefixes = %v, want [2001:db8:1::/48]", addrs)
	}
}

// A SPECIFIC positive literal alongside an except list is NOT the compose case —
// it stays positive-wins (fail-safe), the mixed-shape resolution. This is the
// discriminator: only a match-any positive triggers the #4338 compose.
func TestResolvePrefixListAddrsSpecificPlusExceptStaysPositiveWins_4338(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt": {Name: "mgmt", Prefixes: []string{"10.1.0.0/16"}},
	}
	// A match-any AND a specific literal together: the specific literal makes the
	// positive set constraining, so this is NOT "any except X" — positive-wins.
	addrs, except, _ := resolvePrefixListAddrs(
		[]string{"0.0.0.0/0", "10.0.0.0/8"},
		[]config.PrefixListRef{{Name: "mgmt", Except: true}},
		cfg, "f", "t", "source", "accept",
	)
	if except {
		t.Fatalf("match-any + SPECIFIC positive + except must NOT compose (positive-wins), got except=true addrs=%v", addrs)
	}
}
