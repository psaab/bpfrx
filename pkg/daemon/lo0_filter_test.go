package daemon

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nftRule renders a term to its single nft rule line, asserting the term lowers
// to exactly one rule (the common accept / discard / fall-through-skip case) or
// zero (returns ""). Multi-rule terms — a faithful `reject` (TCP RST + ICMP
// admin-prohibited) and modifier-only fall-through terms (#3445) — are exercised
// against nftRulesFromTerm directly. The single-rule assertion also guards
// against an accidental extra rule slipping into a verdict term.
func nftRule(t *testing.T, term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) string {
	t.Helper()
	rules := nftRulesFromTerm(term, family, prefixLists)
	switch len(rules) {
	case 0:
		return ""
	case 1:
		return rules[0]
	default:
		t.Fatalf("term %q lowered to %d rules, want <=1: %v", term.Name, len(rules), rules)
		return ""
	}
}

// lo0FilterTestConfig returns a config with a representative lo0 input filter
// bound for both families, exercising the same buildLo0FilterPayload path that
// applyLo0Filter uses at commit time.
func lo0FilterTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "mgmt-lockdown"
	cfg.System.Lo0FilterInputV6 = "mgmt-lockdown6"
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"trusted": {Name: "trusted", Prefixes: []string{"10.0.1.0/24", "192.168.1.0/24"}},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"mgmt-lockdown": {
			Name: "mgmt-lockdown",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:              "allow-ssh-trusted",
					Protocols:         []string{"tcp"},
					SourcePrefixLists: []config.PrefixListRef{{Name: "trusted"}},
					DestinationPorts:  []string{"22"},
					Action:            "accept",
				},
				{
					Name:      "deny-rest",
					Protocols: []string{"tcp"},
					Action:    "discard",
				},
			},
		},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"mgmt-lockdown6": {
			Name: "mgmt-lockdown6",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:      "drop-rh0",
					ICMPTypes: []int{134},
					ICMPCodes: []int{0},
					Action:    "discard",
				},
			},
		},
	}
	return cfg
}

// TestLo0FilterPayloadFlushIdiom guards the #2069 fix and the #3445 idiom switch:
// the nft `-f -` payload must NOT use the invalid `flush ruleset <table>` form (a
// parse error that rejected the whole ruleset and made the lo0 filter fail OPEN),
// and must use the atomic add+delete+recreate idiom (`add table; delete table;
// table { ... }`). The pre-#3445 `flush table` idiom is gone because flush does
// not delete named counter objects (#3445 attaches a named counter per `then
// count`), so the delete+recreate idiom is required to redeclare them without a
// "File exists" collision. This test FAILS against the pre-fix payload that began
// `flush ruleset inet xpf_lo0`.
func TestLo0FilterPayloadFlushIdiom(t *testing.T) {
	cfg := lo0FilterTestConfig()
	payload := buildLo0FilterPayload(cfg, cfg.System.Lo0FilterInputV4, cfg.System.Lo0FilterInputV6)

	// The invalid idiom (`flush ruleset` cannot take a table name) must be gone.
	if strings.Contains(payload, "flush ruleset") {
		t.Errorf("payload uses invalid `flush ruleset` idiom (#2069 regression); a table name after `flush ruleset` is an nft parse error that rejects the entire payload:\n%s", payload)
	}

	// The atomic delete+recreate idiom must be present, in order.
	wantLines := []string{
		"add table inet xpf_lo0",
		"delete table inet xpf_lo0",
		"table inet xpf_lo0 {",
	}
	idx := 0
	for _, line := range strings.Split(payload, "\n") {
		if idx < len(wantLines) && strings.TrimSpace(line) == wantLines[idx] {
			idx++
		}
	}
	if idx != len(wantLines) {
		t.Errorf("payload missing the add+delete+recreate idiom (got to line %d/%d):\n%s", idx, len(wantLines), payload)
	}
	// `add` must precede `delete` so the delete always has a target.
	if strings.Index(payload, "add table") > strings.Index(payload, "delete table") {
		t.Errorf("add must precede delete in the lo0 payload:\n%s", payload)
	}

	// The real filter rules must still be present (proves the idiom did not
	// displace the rule body).
	if !strings.Contains(payload, "th dport 22 accept") {
		t.Errorf("payload missing the configured v4 allow-ssh rule:\n%s", payload)
	}
	if !strings.Contains(payload, "icmpv6 type 134") {
		t.Errorf("payload missing the configured v6 rule:\n%s", payload)
	}
}

// TestLo0FilterPayloadNftParses parse-checks the real payload with `nft -c -f -`
// when nft is available. This is the strongest guard: it would FAIL on the
// pre-#2069 payload (nft reports a syntax error on `flush ruleset inet
// xpf_lo0`). A netlink/permission failure (no CAP_NET_ADMIN in the test env)
// occurs AFTER syntax parsing succeeds and is treated as a pass; nft missing
// from PATH skips the test.
func TestLo0FilterPayloadNftParses(t *testing.T) {
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not in PATH; covered by TestLo0FilterPayloadFlushIdiom")
	}

	cfg := lo0FilterTestConfig()
	payload := buildLo0FilterPayload(cfg, cfg.System.Lo0FilterInputV4, cfg.System.Lo0FilterInputV6)

	cmd := exec.Command(nftPath, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return // parsed and (as root) check-applied cleanly
	}

	combined := string(out)
	// A syntax error is the #2069 failure mode and must fail the test.
	if strings.Contains(combined, "syntax error") {
		t.Fatalf("nft -c rejected the lo0 filter payload with a syntax error (#2069):\n%s\npayload:\n%s", combined, payload)
	}
	// Anything else (typically `Operation not permitted` without CAP_NET_ADMIN)
	// means the syntax parsed; that is a pass for this parse-check test.
	t.Logf("nft -c parsed the payload; non-syntax error (expected without CAP_NET_ADMIN): %v\n%s", err, combined)
}

// TestLo0FilterApplyFailureSurfaced is the #3392 fail-on-revert proof for the
// APPLY path: when `nft -f -` fails, applyLo0Filter must return the error (so
// applyConfigLocked fails the commit closed) rather than swallow it at WARN.
// With the pre-fix warn-only code the function returned nothing and this goes
// RED. The nft invocation is replaced by the package-var seam so no real nft is
// run. Mirrors TestHostInboundFilterApplyFailureSurfaced (#3333).
func TestLo0FilterApplyFailureSurfaced(t *testing.T) {
	cfg := lo0FilterTestConfig()

	injected := errors.New("nft: lo0 rule load failed")
	var called bool
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) {
		called = true
		// Sanity: the payload fed to nft must be the lo0 filter ruleset, so a
		// failure here is a real filter-not-installed event.
		if !strings.Contains(payload, "table inet xpf_lo0") {
			t.Errorf("apply seam got unexpected payload:\n%s", payload)
		}
		return []byte("Error: could not process rule\n"), injected
	}
	defer func() { nftApplyPayload = orig }()

	d := &Daemon{}
	err := d.applyLo0Filter(cfg)
	if !called {
		t.Fatal("expected nft apply seam to be invoked for a configured lo0 filter")
	}
	if err == nil {
		t.Fatal("apply failure must be surfaced as an error (fail-closed), got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the nft failure, got %v", err)
	}
}

// TestLo0FilterDeleteFailureSurfaced is the #3392 fail-on-revert proof for the
// TEARDOWN path: when no lo0 filter is configured, the stale table is removed via
// the idempotent add-then-delete payload; a genuine teardown failure (stale lo0
// filter left in the kernel) must surface as an error. The add+delete is
// idempotent for the benign absent-table case, so any error from the seam is a
// real failure. Pre-fix the delete error was discarded entirely (`_, _ =`), so
// this goes RED. Mirrors TestHostInboundFilterDeleteFailureSurfaced (#3333).
func TestLo0FilterDeleteFailureSurfaced(t *testing.T) {
	// A config with NO lo0 filter bound drives the teardown branch.
	cfg := &config.Config{}

	injected := errors.New("nft: device or resource busy")
	var gotFamily, gotName string
	orig := nftDeleteTable
	nftDeleteTable = func(family, name string) ([]byte, error) {
		gotFamily, gotName = family, name
		return []byte("Error: Could not process rule\n"), injected
	}
	defer func() { nftDeleteTable = orig }()

	d := &Daemon{}
	err := d.applyLo0Filter(cfg)
	if gotName != "xpf_lo0" || gotFamily != "inet" {
		t.Errorf("teardown must target inet xpf_lo0, got %s %s", gotFamily, gotName)
	}
	if err == nil {
		t.Fatal("teardown failure must be surfaced as an error (fail-closed), got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the nft teardown failure, got %v", err)
	}
}

// TestLo0FilterApplySuccessNoError verifies the happy paths return nil: a
// successful apply (configured filter) and a successful/benign teardown (no
// filter bound) must NOT report a commit failure.
func TestLo0FilterApplySuccessNoError(t *testing.T) {
	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{}
	if err := d.applyLo0Filter(lo0FilterTestConfig()); err != nil {
		t.Errorf("successful apply must return nil, got %v", err)
	}
	if err := d.applyLo0Filter(&config.Config{}); err != nil {
		t.Errorf("benign teardown (no lo0 filter) must return nil, got %v", err)
	}
}

// TestNftDeleteTableLo0IdempotentAddDelete pins the #3392 teardown shape for the
// lo0 table: the teardown must NOT depend on the recent `nft destroy` verb (the
// project pins no minimum nftables version) and must instead emit an idempotent
// add-then-delete payload through the atomic nftApplyPayload runner. Reverting to
// `nft destroy` (or the bare `delete table` that errors when absent) turns this
// RED. Mirrors TestNftDeleteTableIdempotentAddDelete (#3333).
func TestNftDeleteTableLo0IdempotentAddDelete(t *testing.T) {
	var got string
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) { got = payload; return nil, nil }
	defer func() { nftApplyPayload = orig }()

	if _, err := nftDeleteTable("inet", "xpf_lo0"); err != nil {
		t.Fatalf("nftDeleteTable: %v", err)
	}
	if strings.Contains(got, "destroy") {
		t.Errorf("teardown must not use the unpinned `nft destroy` verb:\n%s", got)
	}
	for _, want := range []string{
		"add table inet xpf_lo0",
		"delete table inet xpf_lo0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("teardown payload missing %q:\n%s", want, got)
		}
	}
	// `add` must precede `delete` so the delete always has a target.
	if strings.Index(got, "add table") > strings.Index(got, "delete table") {
		t.Errorf("add must precede delete in the teardown payload:\n%s", got)
	}
}

func TestNftRuleFromTermPrefixListExpansion(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"management-hosts": {
			Name:     "management-hosts",
			Prefixes: []string{"10.0.1.0/24", "10.0.2.0/24", "192.168.1.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:      "allow-ssh",
		Protocols: []string{"tcp"},
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "management-hosts", Except: false},
		},
		DestinationPorts: []string{"22"},
		Action:           "accept",
	}

	rule := nftRule(t, term, "ip", prefixLists)
	// Should contain expanded CIDRs in nft set syntax
	want := "ip saddr { 10.0.1.0/24, 10.0.2.0/24, 192.168.1.0/24 } meta l4proto 6 th dport 22 accept"
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
		Name:      "deny-others",
		Protocols: []string{"tcp"},
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "allowed", Except: true},
		},
		DestinationPorts: []string{"22"},
		Action:           "reject",
	}

	// #3445: a `then reject` now lowers to TWO faithful rules (TCP RST + ICMP
	// admin-prohibited) mirroring the userspace reject-reply synthesis, so the
	// except predicate must appear on BOTH.
	rules := nftRulesFromTerm(term, "ip", prefixLists)
	match := "ip saddr != { 10.0.1.0/24, 10.0.2.0/24 } meta l4proto 6 th dport 22"
	want := []string{
		match + " meta l4proto 6 reject with tcp reset",
		match + " reject with icmpx type admin-prohibited",
	}
	if len(rules) != len(want) {
		t.Fatalf("reject lowered to %d rules, want %d: %v", len(rules), len(want), rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule[%d]:\n  got:  %s\n  want: %s", i, rules[i], want[i])
		}
	}
}

func TestNftRuleFromTermRejectVsDiscard(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	tests := []struct {
		action     string
		wantAction string
	}{
		{"accept", "accept"},
		{"discard", "drop"},
		// #3427: an empty action is a Junos fall-through (modifier-only term),
		// NOT a terminating accept. The kernel mirror must skip it (emit "") so
		// later discard/reject terms remain reachable. Before the fix this row
		// asserted "accept" — the control-plane fail-open this issue tracks.
		{"", ""},
	}

	for _, tt := range tests {
		term := &config.FirewallFilterTerm{
			Name:   "test",
			Action: tt.action,
		}
		rule := nftRule(t, term, "ip", prefixLists)
		if rule != tt.wantAction {
			t.Errorf("action %q: got %q, want %q", tt.action, rule, tt.wantAction)
		}
	}

	// #3445: `reject` lowers to a faithful TCP-RST + ICMP-admin-prohibited pair,
	// not the pre-fix bare `reject` (which sent ICMP port-unreachable for ALL
	// protocols including TCP — a different wire response than userspace).
	reject := nftRulesFromTerm(&config.FirewallFilterTerm{Name: "test", Action: "reject"}, "ip", prefixLists)
	wantReject := []string{
		"meta l4proto 6 reject with tcp reset",
		"reject with icmpx type admin-prohibited",
	}
	if len(reject) != len(wantReject) {
		t.Fatalf("reject lowered to %d rules, want %d: %v", len(reject), len(wantReject), reject)
	}
	for i := range wantReject {
		if reject[i] != wantReject[i] {
			t.Errorf("reject rule[%d]: got %q, want %q", i, reject[i], wantReject[i])
		}
	}
}

// TestNftRuleFromTermUnknownActionFailsClosed pins #3724 M08: an unknown /
// unhandled NON-EMPTY terminating action on an lo0 filter term must render to
// nft `drop`, NOT `accept`. The kernel lo0 chain is the PRIMARY enforcement for
// host-bound traffic (the XDP shim shunts it to the kernel before userspace),
// and the Rust filter compiler fails an unknown action CLOSED to
// FilterAction::Discard (userspace-dp/src/filter/compiler.rs). An unknown
// action cannot arrive through the CLI commit path (validateFilterActionsStrict
// / the UnknownActions capture reject it, leaving term.Action == ""), but a
// tolerant load / peer session-sync / mixed-version snapshot can carry a
// future action string in term.Action directly. Rendering that to nft `accept`
// is a mixed-version control-plane fail-open — the kernel would ADMIT host-bound
// traffic userspace-dp drops. RED on revert: the pre-#3724 default arm rendered
// `accept` for any non-discard action, so these rows asserted the fail-open and
// would fail once fixed; they now assert the fail-closed `drop`. The known
// accept/discard mappings are re-asserted so the fix does not over-drop.
func TestNftRuleFromTermUnknownActionFailsClosed(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	tests := []struct {
		name       string
		action     string
		wantAction string
	}{
		// Known terminating actions still map correctly.
		{"known-accept", "accept", "accept"},
		{"known-discard", "discard", "drop"},
		// Unknown / future action strings a mixed-version snapshot could carry.
		// All must FAIL CLOSED to drop (mirroring Rust FilterAction::Discard),
		// never fail open to accept.
		{"unknown-redirect", "redirect", "drop"},
		{"unknown-sample", "sample-and-accept", "drop"},
		{"unknown-garbage", "frobnicate", "drop"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term := &config.FirewallFilterTerm{
				Name:   tt.name,
				Action: tt.action,
			}
			rule := nftRule(t, term, "ip", prefixLists)
			if rule != tt.wantAction {
				t.Errorf("action %q: got %q, want %q (unknown must fail CLOSED to drop, #3724 M08)", tt.action, rule, tt.wantAction)
			}
		})
	}
}

func TestNftRuleFromTermMultiplePorts(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:             "allow-web",
		Protocols:        []string{"tcp"},
		DestinationPorts: []string{"80", "443"},
		Action:           "accept",
	}

	rule := nftRule(t, term, "ip", prefixLists)
	want := "meta l4proto 6 th dport { 80, 443 } accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

func TestNftRuleFromTermSingleSourceAddr(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// A v4 literal in the IPv4 chain renders its predicate verbatim.
	term := &config.FirewallFilterTerm{
		Name:            "allow-single",
		SourceAddresses: []string{"10.0.1.0/24"},
		Action:          "accept",
	}
	if rule := nftRule(t, term, "ip", prefixLists); rule != "ip saddr 10.0.1.0/24 accept" {
		t.Errorf("v4 literal in ip chain: got %q, want %q", rule, "ip saddr 10.0.1.0/24 accept")
	}
}

// TestNftRuleFromTermWrongFamilyMatchesNothing is the #3433 H02 RED-on-revert:
// a v4 literal carried in the IPv6 chain (a `family inet6` filter with a v4
// source-address) must NOT emit `ip6 saddr 10.0.1.0/24` — that is invalid nft
// (no v6 object for a v4 CIDR) that fails the atomic `nft -f -` load and, before
// the fix, the unit test even PINNED that broken output. The userspace matcher
// leaves the v6 vector empty -> constrained + empty positive -> match NOTHING, so
// the kernel mirror must skip the rule (return ""). Reverting the family-filter in
// nftFamilyAddrs makes this RED.
func TestNftRuleFromTermWrongFamilyMatchesNothing(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:            "v4-in-v6",
		SourceAddresses: []string{"10.0.1.0/24"},
		Action:          "accept",
	}
	if rule := nftRule(t, term, "ip6", prefixLists); rule != "" {
		t.Errorf("wrong-family v4 literal in ip6 chain: got %q, want \"\" (match-nothing, #3433 H02)", rule)
	}

	// Symmetric: a v6 literal in the IPv4 chain.
	term6 := &config.FirewallFilterTerm{
		Name:            "v6-in-v4",
		SourceAddresses: []string{"2001:db8::/32"},
		Action:          "discard",
	}
	if rule := nftRule(t, term6, "ip", prefixLists); rule != "" {
		t.Errorf("wrong-family v6 literal in ip chain: got %q, want \"\" (match-nothing, #3433 H02)", rule)
	}
}

// TestNftRuleFromTermAddressSemantics3433 pins the lo0 nft address /
// prefix-list lowering to the userspace matcher's set semantics
// (pkg/dataplane/userspace/filters.go + userspace-dp filter/engine/matching.rs
// nets_match_v4/v6). Each sub-case is a shape where the pre-#3433 raw string
// concatenation DIVERGED from userspace — either over-matching in the kernel
// mirror (fail-open) or emitting invalid nft that fails the atomic load.
// FAIL-ON-REVERT: restoring the raw concatenation flips every want below.
func TestNftRuleFromTermAddressSemantics3433(t *testing.T) {
	pls := map[string]*config.PrefixList{
		"trusted": {Name: "trusted", Prefixes: []string{"10.0.0.0/8", "192.168.0.0/16"}},
		"empty":   {Name: "empty", Prefixes: nil}, // defined-but-empty
	}

	tests := []struct {
		name string
		term *config.FirewallFilterTerm
		fam  string
		want string
	}{
		{
			// H01: a positive literal `any` is NO constraint (match ALL), not a
			// match-nothing empty set and not the unloadable `ip saddr any`.
			name: "positive any -> no predicate (match all)",
			term: &config.FirewallFilterTerm{
				Name: "any-accept", SourceAddresses: []string{"any"}, Action: "accept",
			},
			fam:  "ip",
			want: "accept",
		},
		{
			// H03: a defined-but-empty POSITIVE prefix-list is constrained +
			// empty -> match NOTHING. The term contributes no enforcement; the
			// rule is skipped (""). The pre-fix code emitted no saddr predicate ->
			// the rest of the rule matched ALL sources (fail-open).
			name: "empty positive prefix-list -> match nothing (skip)",
			term: &config.FirewallFilterTerm{
				Name: "empty-pos", Protocols: []string{"tcp"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "empty"}},
				DestinationPorts:  []string{"22"}, Action: "accept",
			},
			fam:  "ip",
			want: "",
		},
		{
			// Empty EXCEPT prefix-list -> "match every source NOT in {}" = match
			// ALL -> no predicate (the term still applies its other criteria).
			name: "empty except prefix-list -> match all (no predicate)",
			term: &config.FirewallFilterTerm{
				Name: "empty-exc", Protocols: []string{"tcp"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "empty", Except: true}},
				DestinationPorts:  []string{"22"}, Action: "discard",
			},
			fam:  "ip",
			want: "meta l4proto 6 th dport 22 drop",
		},
		{
			// H04: a lenient/peer-sync UNRESOLVED positive prefix-list resolves to
			// zero prefixes but stays constrained -> match NOTHING (skip). The
			// pre-fix code emitted no predicate -> unconstrained accept (fail-open).
			name: "unresolved positive prefix-list -> match nothing (skip)",
			term: &config.FirewallFilterTerm{
				Name: "typo", SourcePrefixLists: []config.PrefixListRef{{Name: "does-not-exist"}},
				Action: "accept",
			},
			fam:  "ip",
			want: "",
		},
		{
			// H05: mixed positive literal + except prefix-list (lenient path).
			// POSITIVE-WINS: emit the positive literal only, NO negation. The
			// pre-fix code folded both into one set and negated the whole thing
			// (`saddr != { 10.0.0.0/24, 10.0.0.0/8, 192.168.0.0/16 }`).
			name: "mixed positive + except -> positive wins",
			term: &config.FirewallFilterTerm{
				Name: "mixed", SourceAddresses: []string{"172.16.0.0/24"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "trusted", Except: true}},
				Action:            "discard",
			},
			fam:  "ip",
			want: "ip saddr 172.16.0.0/24 drop",
		},
		{
			// H09: an all-malformed positive literal set is constrained + empty
			// (parse drops the bad token) -> match NOTHING (skip). The pre-fix
			// code emitted `ip saddr 10.0.0.0/99 ...` -> atomic load failure.
			name: "malformed positive literal -> match nothing (skip)",
			term: &config.FirewallFilterTerm{
				Name: "bad", SourceAddresses: []string{"10.0.0.0/99"}, Action: "accept",
			},
			fam:  "ip",
			want: "",
		},
		{
			// Non-empty except is representable in nft as a negated set.
			name: "non-empty except -> negated set",
			term: &config.FirewallFilterTerm{
				Name: "exc", SourcePrefixLists: []config.PrefixListRef{{Name: "trusted", Except: true}},
				Action: "discard",
			},
			fam:  "ip",
			want: "ip saddr != { 10.0.0.0/8, 192.168.0.0/16 } drop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nftRule(t, tt.term, tt.fam, pls)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNftRuleFromTermICMPTypeCode(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// IPv6 block-ra-adv filter: icmp-type 134 icmp-code 0 → discard
	term := &config.FirewallFilterTerm{
		Name:      "block-ra",
		ICMPTypes: []int{134},
		ICMPCodes: []int{0},
		Action:    "discard",
	}
	rule := nftRule(t, term, "ip6", prefixLists)
	want := "icmpv6 type 134 icmpv6 code 0 drop"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}

	// IPv4 ICMP type only (no code)
	term2 := &config.FirewallFilterTerm{
		Name:      "block-redirect",
		ICMPTypes: []int{5},
		Action:    "discard",
	}
	rule2 := nftRule(t, term2, "ip", prefixLists)
	want2 := "icmp type 5 drop"
	if rule2 != want2 {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule2, want2)
	}
}

// TestNftRuleFromTermICMPCodeOnly is the #3483 RED-on-revert guard: an lo0
// term that specifies an `icmp code` but NO `icmp type` MUST still emit the
// `code` predicate on the kernel-nft mirror, matching the userspace matcher
// (pkg/dataplane/userspace/filters.go gates ICMPCodes on len > 0; the Rust
// matcher's icmp_code_match_enabled is a block separate from
// icmp_type_match_enabled). Before #3483 the code predicate was nested under
// `if len(term.ICMPTypes) > 0`, so a code-only discard term dropped the code
// match entirely and matched ALL ICMP (over-broad / fail-open vs userspace).
// Reverting the fix (re-nesting code under the type guard) drops the predicate
// and fails this test in both families.
func TestNftRuleFromTermICMPCodeOnly(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// IPv4: code-only, no type. nft must still constrain on the code.
	v4 := &config.FirewallFilterTerm{
		Name:      "drop-icmp-code4",
		Protocols: []string{"icmp"},
		ICMPCodes: []int{4},
		Action:    "discard",
	}
	ruleV4 := nftRule(t, v4, "ip", prefixLists)
	wantV4 := "meta l4proto 1 icmp code 4 drop"
	if ruleV4 != wantV4 {
		t.Errorf("v4 code-only:\n  got:  %s\n  want: %s", ruleV4, wantV4)
	}
	if !strings.Contains(ruleV4, "icmp code 4") {
		t.Errorf("v4 code-only rule dropped the code predicate (the #3483 bug): %q", ruleV4)
	}

	// IPv6: code-only, no type. icmpv6 family, code still emitted.
	v6 := &config.FirewallFilterTerm{
		Name:      "drop-icmpv6-code1",
		Protocols: []string{"icmpv6"},
		ICMPCodes: []int{1},
		Action:    "discard",
	}
	ruleV6 := nftRule(t, v6, "ip6", prefixLists)
	wantV6 := "meta l4proto 58 icmpv6 code 1 drop"
	if ruleV6 != wantV6 {
		t.Errorf("v6 code-only:\n  got:  %s\n  want: %s", ruleV6, wantV6)
	}
	if !strings.Contains(ruleV6, "icmpv6 code 1") {
		t.Errorf("v6 code-only rule dropped the code predicate (the #3483 bug): %q", ruleV6)
	}

	// Multi-value code-only (no type) renders an nft set.
	multi := &config.FirewallFilterTerm{
		Name:      "drop-icmp-codes",
		ICMPCodes: []int{0, 4},
		Action:    "discard",
	}
	ruleMulti := nftRule(t, multi, "ip", prefixLists)
	wantMulti := "icmp code { 0, 4 } drop"
	if ruleMulti != wantMulti {
		t.Errorf("multi code-only:\n  got:  %s\n  want: %s", ruleMulti, wantMulti)
	}
}

func TestNftRuleFromTermDSCP(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:   "dscp-match",
		DSCPs:  []string{"ef"},
		Action: "accept",
	}
	rule := nftRule(t, term, "ip", prefixLists)
	// #3436: the DSCP name resolves to its numeric value (ef == 46). nft's DSCP
	// names are lowercase only and do not cover every xpf code point (e.g. `be`),
	// so emitting the numeric value is unconditionally nft-safe.
	want := "ip dscp 46 accept"
	if rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}

	// IPv6 traffic-class
	rule6 := nftRule(t, term, "ip6", prefixLists)
	want6 := "ip6 dscp 46 accept"
	if rule6 != want6 {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule6, want6)
	}
}

// TestNftRuleFromTermProtocolAliases is the #3436 H08 proof: a firewall-filter
// `from protocol` token that is a Junos predefined-protocol alias (junos-gre,
// junos-tcp-any, junos-icmp-all, ipip, ...) — accepted by the commit gate
// filterProtocolResolvable and the userspace matcher — must lower to its NUMERIC
// nft l4proto token, never the raw alias. nft does not share the Junos alias
// table, so `meta l4proto junos-gre` is a parse error that rejects the whole
// atomic lo0 table (commit broken) or, on the lenient path, mirrors a different
// protocol than userspace. RED-on-revert: the pre-fix raw pass-through emits the
// alias verbatim.
func TestNftRuleFromTermProtocolAliases(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}
	cases := []struct {
		name  string
		proto string
		want  string // l4proto fragment
	}{
		{"junos-gre", "junos-gre", "meta l4proto 47"},
		{"junos-tcp-any", "junos-tcp-any", "meta l4proto 6"},
		{"junos-icmp-all", "junos-icmp-all", "meta l4proto 1"},
		{"ipip", "ipip", "meta l4proto 4"},
		{"junos-ip-in-ip", "junos-ip-in-ip", "meta l4proto 4"},
		{"numeric", "47", "meta l4proto 47"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			term := &config.FirewallFilterTerm{
				Name: "p", Protocols: []string{c.proto}, Action: "accept",
			}
			want := c.want + " accept"
			if rule := nftRule(t, term, "ip", prefixLists); rule != want {
				t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
			}
		})
	}
}

// TestNftRuleFromTermProtocolMultiAliasSet is the #3436 H08 multi-value proof: a
// `from protocol [ junos-gre tcp 50 ]` set must lower to a numeric nft set
// (`meta l4proto { 47, 6, 50 }`), preserving order and resolving every alias —
// not a set containing the raw alias token that fails the atomic load.
func TestNftRuleFromTermProtocolMultiAliasSet(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}
	term := &config.FirewallFilterTerm{
		Name: "p", Protocols: []string{"junos-gre", "tcp", "50"}, Action: "accept",
	}
	want := "meta l4proto { 47, 6, 50 } accept"
	if rule := nftRule(t, term, "ip", prefixLists); rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

// TestNftRuleFromTermDSCPNamesAndCase is the #3436 M01 proof: a DSCP name is
// resolved through dataplane.DSCPValues to its numeric value regardless of case
// (`EF` accepted case-insensitively by the commit gate), `be` (no nft name)
// resolves to 0, and a numeric token passes through. The pre-fix pass-through
// emitted `ip dscp EF` / `ip dscp be`, both nft parse errors that reject the
// whole atomic lo0 table.
func TestNftRuleFromTermDSCPNamesAndCase(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}
	cases := []struct {
		name string
		dscp string
		want string // dscp fragment
	}{
		{"upper-EF", "EF", "ip dscp 46"},
		{"mixed-Af11", "Af11", "ip dscp 10"},
		{"be", "be", "ip dscp 0"},
		{"numeric", "34", "ip dscp 34"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			term := &config.FirewallFilterTerm{
				Name: "d", DSCPs: []string{c.dscp}, Action: "accept",
			}
			want := c.want + " accept"
			if rule := nftRule(t, term, "ip", prefixLists); rule != want {
				t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
			}
		})
	}

	// Multi-value DSCP set with a mixed-case name and a numeric token.
	multi := &config.FirewallFilterTerm{
		Name: "d", DSCPs: []string{"EF", "af21", "0"}, Action: "accept",
	}
	want := "ip dscp { 46, 18, 0 } accept"
	if rule := nftRule(t, multi, "ip", prefixLists); rule != want {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule, want)
	}
}

// TestNftRuleFromTermTCPFlags covers the #3231 fix for the TCP-flags
// AND-semantics bug (071-06). The single-flag, plain-list, and negated
// (`syn & !ack`) forms must all lower to the canonical nft masked-equality
// form `tcp flags & (mask) == required`, NOT the pre-fix raw comma-join
// (`tcp flags syn,&,!ack`) which is an nft syntax error that rejects the whole
// atomically-loaded ruleset and fails the lo0 control-plane filter OPEN.
func TestNftRuleFromTermTCPFlags(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	cases := []struct {
		name  string
		flags []string
		want  string
	}{
		{
			// Single required flag — no parentheses needed on either side.
			name:  "syn-only",
			flags: []string{"syn"},
			want:  "meta l4proto 6 tcp flags & syn == syn drop",
		},
		{
			// Plain list is the Junos AND-conjunction (both required), NOT a
			// disjunctive comma set. mask == required == syn|ack.
			name:  "syn-ack-list",
			flags: []string{"syn", "ack"},
			want:  "meta l4proto 6 tcp flags & (syn | ack) == (syn | ack) drop",
		},
		{
			// Negated form: SYN required, ACK forbidden. The mentioned mask is
			// syn|ack; the required side is just syn (ACK must be clear).
			name:  "syn-not-ack",
			flags: []string{"syn", "&", "!ack"},
			want:  "meta l4proto 6 tcp flags & (syn | ack) == syn drop",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			term := &config.FirewallFilterTerm{
				Name:      c.name,
				Protocols: []string{"tcp"},
				TCPFlags:  c.flags,
				Action:    "discard",
			}
			rule := nftRule(t, term, "ip", prefixLists)
			if rule != c.want {
				t.Errorf("flags %v\n got:  %s\n want: %s", c.flags, rule, c.want)
			}
			// The pre-fix raw-join must never reappear (it is invalid nft).
			if strings.Contains(rule, "tcp flags "+strings.Join(c.flags, ",")) {
				t.Errorf("flags %v lowered to the raw comma-join (#3231 regression): %s", c.flags, rule)
			}
		})
	}
}

// TestNftRuleFromTermPortExcept covers the #3231 fix for dropped port-except
// matches (071-08). source-port-except / destination-port-except must emit the
// nft negated form; before the fix they were silently ignored, so a discard
// term blocked the exempt ports and an accept-all-except term bypassed them.
func TestNftRuleFromTermPortExcept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// destination-port-except, single value.
	term := &config.FirewallFilterTerm{
		Name:            "accept-except-ssh",
		Protocols:       []string{"tcp"},
		DestPortsExcept: []string{"22"},
		Action:          "accept",
	}
	rule := nftRule(t, term, "ip", prefixLists)
	want := "meta l4proto 6 th dport != 22 accept"
	if rule != want {
		t.Errorf("dest-port-except single:\n got:  %s\n want: %s", rule, want)
	}

	// destination-port-except, multi value (nft negated set).
	term2 := &config.FirewallFilterTerm{
		Name:            "accept-except-web",
		Protocols:       []string{"tcp"},
		DestPortsExcept: []string{"80", "443"},
		Action:          "accept",
	}
	rule2 := nftRule(t, term2, "ip", prefixLists)
	want2 := "meta l4proto 6 th dport != { 80, 443 } accept"
	if rule2 != want2 {
		t.Errorf("dest-port-except multi:\n got:  %s\n want: %s", rule2, want2)
	}

	// source-port-except.
	term3 := &config.FirewallFilterTerm{
		Name:              "src-except",
		Protocols:         []string{"udp"},
		SourcePortsExcept: []string{"123"},
		Action:            "discard",
	}
	rule3 := nftRule(t, term3, "ip", prefixLists)
	want3 := "meta l4proto 17 th sport != 123 drop"
	if rule3 != want3 {
		t.Errorf("source-port-except:\n got:  %s\n want: %s", rule3, want3)
	}
}

// TestNftRuleFromTermFragment covers the #3231 fix for the IPv6 is-fragment
// bug (071-09). The ip4 chain emits the IPv4 fragment-offset test; the ip6
// chain must emit the IPv6 fragment extension-header test (`exthdr frag
// exists`), NOT `ip frag-off`, which is an inet6 syntax error that rejects the
// whole ruleset and fails the lo0 filter OPEN.
func TestNftRuleFromTermFragment(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:       "drop-frags",
		IsFragment: true,
		Action:     "discard",
	}

	rule := nftRule(t, term, "ip", prefixLists)
	want := "ip frag-off & 0x1fff != 0 drop"
	if rule != want {
		t.Errorf("ip4 fragment:\n got:  %s\n want: %s", rule, want)
	}

	rule6 := nftRule(t, term, "ip6", prefixLists)
	want6 := "exthdr frag exists drop"
	if rule6 != want6 {
		t.Errorf("ip6 fragment:\n got:  %s\n want: %s", rule6, want6)
	}
	if strings.Contains(rule6, "ip frag-off") {
		t.Errorf("ip6 chain emitted IPv4-only `ip frag-off` (#3231 regression): %s", rule6)
	}
}

// TestNftRuleFromTermFallThroughNoBareAccept pins #3427: a fall-through term —
// an explicit `then next term`, or a modifier-only term (empty action) — must
// NOT emit a terminating kernel verdict that shadows later discard/reject terms.
// The kernel lo0 chain is the PRIMARY enforcement for host-bound traffic (the
// XDP shim shunts it to the kernel before userspace), so a bare `accept` here is
// a real control-plane fail-open. A fall-through term WITHOUT a honored modifier
// emits no rule; a fall-through term carrying `then log`/`then count` (#3445)
// emits a NON-TERMINATING rule (the modifier statements, no verdict) so the
// per-term log/count fires while later terms stay reachable. Every case asserts
// no terminating verdict (no accept / drop / reject) is emitted. RED before the
// #3427 fix (Action=="" returned "accept"; NextTerm was ignored so it also
// returned "accept").
func TestNftRuleFromTermFallThroughNoBareAccept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// Pure fall-through (no honored modifier): emits NO rule.
	noRule := []struct {
		name string
		term *config.FirewallFilterTerm
	}{
		{
			// H06: explicit `then next term`, scoped by a match.
			name: "explicit-next-term",
			term: &config.FirewallFilterTerm{
				Name:      "t1",
				Protocols: []string{"tcp"},
				NextTerm:  true,
			},
		},
		{
			// Bare `then next term` with no match — matches everything, falls
			// through. Must not become an accept-all.
			name: "next-term-no-match",
			term: &config.FirewallFilterTerm{
				Name:     "t1",
				NextTerm: true,
			},
		},
		{
			// Modifier-only term whose only modifier is unrepresentable on the
			// kernel mirror (forwarding-class) — nothing is honored, so no rule and
			// (commit-time) a warning. Must not shadow later terms.
			name: "modifier-only-unhonored",
			term: &config.FirewallFilterTerm{
				Name:            "t1",
				Protocols:       []string{"tcp"},
				ForwardingClass: "expedited-forwarding",
			},
		},
	}
	for _, c := range noRule {
		for _, fam := range []string{"ip", "ip6"} {
			rules := nftRulesFromTerm(c.term, fam, prefixLists)
			if len(rules) != 0 {
				t.Errorf("%s (%s): fall-through term emitted %v, want no rule", c.name, fam, rules)
			}
		}
	}

	// H07 / #3445: a modifier-only term carrying a HONORED modifier (count, log)
	// emits a single NON-TERMINATING rule (the modifier statements, no verdict),
	// so later discard/reject terms remain reachable.
	for _, fam := range []string{"ip", "ip6"} {
		term := &config.FirewallFilterTerm{
			Name:      "t1",
			Protocols: []string{"tcp"},
			Count:     "tcp-seen",
			Log:       true,
		}
		rules := nftRulesFromTerm(term, fam, prefixLists)
		if len(rules) != 1 {
			t.Fatalf("modifier-only-count+log (%s): got %d rules, want 1: %v", fam, len(rules), rules)
		}
		got := rules[0]
		want := `meta l4proto 6 log prefix "xpf-lo0 t1: " counter name "xpflo0_tcp-seen"`
		if got != want {
			t.Errorf("modifier-only-count+log (%s):\n  got:  %s\n  want: %s", fam, got, want)
		}
		// Critically: no terminating verdict, so the term cannot shadow later terms.
		for _, verdict := range []string{"accept", "drop", "reject"} {
			if strings.Contains(got, verdict) {
				t.Errorf("modifier-only fall-through (%s) emitted a terminating %q (fail-open #3427): %q", fam, verdict, got)
			}
		}
	}
}

// TestNftRuleFromTermRoutingInstanceTerminatesAccept pins #3427 M08: a
// routing-instance (PBR) term has an empty terminating action but is NOT a
// fall-through in userspace. The Rust compiler sets continue_term=false when
// routing_instance is non-empty and the evaluator RETURNS the matched term's
// action — the empty-action placeholder Accept — so the packet is ACCEPTED. The
// kernel lo0 input chain cannot perform route-selection, but the filter VERDICT
// is accept, so it must emit a TERMINATING accept (mirroring userspace). It must
// NOT skip the rule: skipping would let a later deny term over-drop legitimate
// host traffic on the kernel-primary lo0 chain.
func TestNftRuleFromTermRoutingInstanceTerminatesAccept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// Use a family-appropriate source address per chain (a v4 CIDR in the ip
	// chain, a v6 CIDR in the ip6 chain) so the test exercises the PBR
	// terminate-as-accept verdict, not the #3433 wrong-family match-nothing path.
	cases := []struct {
		fam  string
		addr string
		want string
	}{
		{"ip", "10.0.0.0/8", "ip saddr 10.0.0.0/8 accept"},
		{"ip6", "2001:db8::/32", "ip6 saddr 2001:db8::/32 accept"},
	}
	for _, c := range cases {
		term := &config.FirewallFilterTerm{
			Name:            "to-mgmt-instance",
			SourceAddresses: []string{c.addr},
			RoutingInstance: "mgmt",
		}
		rule := nftRule(t, term, c.fam, prefixLists)
		if rule != c.want {
			t.Errorf("routing-instance term (%s): got %q, want %q (terminate-as-accept, mirror userspace)", c.fam, rule, c.want)
		}
	}
}

// TestLo0PayloadFallThroughDoesNotShadowDiscard is the end-to-end #3427 proof:
// a fall-through term followed by a discard term must leave the discard
// REACHABLE in the rendered nft payload. Before the fix term1 rendered
// `meta l4proto 6 accept`, which (atomic, first-match-wins chain) made the
// later `tcp dport 22 drop` unreachable — SSH was silently permitted in the
// kernel lo0 mirror. The fix drops term1's rule entirely so the discard stands.
func TestLo0PayloadFallThroughDoesNotShadowDiscard(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{Name: "fallthrough", Protocols: []string{"tcp"}, NextTerm: true},
				{Name: "block-ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "discard"},
			},
		},
	}

	payload := buildLo0FilterPayload(cfg, "lo0-in", "")

	if strings.Contains(payload, "meta l4proto 6 accept") {
		t.Errorf("fall-through term emitted a shadowing accept in the lo0 payload (#3427 fail-open):\n%s", payload)
	}
	if !strings.Contains(payload, "th dport 22 drop") {
		t.Errorf("discard term unreachable / missing from lo0 payload:\n%s", payload)
	}
}

// TestLo0PayloadRoutingInstanceTerminatesAcceptNoOverDrop is the #3427 M08
// counterexample the coordinator caught: a routing-instance (PBR) term followed
// by a deny term. Userspace TERMINATES the matched routing-instance term as
// Accept (continue_term=false, placeholder Accept), so the packet is ACCEPTED
// and the later discard never runs. The kernel mirror must therefore emit a
// terminating `accept` for the steer term — NOT skip it. A skip lets the later
// `then discard` match and OVER-DROP legitimate host traffic on the
// kernel-primary lo0 chain. RED-on-revert: with the skip disposition the steer
// rule is absent and `meta l4proto 6 drop` is the only verdict.
func TestLo0PayloadRoutingInstanceTerminatesAcceptNoOverDrop(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{Name: "steer", Protocols: []string{"tcp"}, RoutingInstance: "mgmt"},
				{Name: "deny-rest", Protocols: []string{"tcp"}, Action: "discard"},
			},
		},
	}

	payload := buildLo0FilterPayload(cfg, "lo0-in", "")

	// The steer term must terminate as accept BEFORE the deny term, so the
	// accept appears in the payload and (first-match-wins) shields tcp traffic
	// from the drop. The over-drop bug would leave only the drop rule.
	if !strings.Contains(payload, "meta l4proto 6 accept") {
		t.Errorf("routing-instance term did not emit a terminating accept (#3427 over-drop): the later discard would over-drop host traffic:\n%s", payload)
	}
	acceptIdx := strings.Index(payload, "meta l4proto 6 accept")
	dropIdx := strings.Index(payload, "meta l4proto 6 drop")
	if acceptIdx == -1 || (dropIdx != -1 && dropIdx < acceptIdx) {
		t.Errorf("routing-instance accept must precede the deny term (first-match-wins) so legit traffic is not over-dropped:\n%s", payload)
	}
}

// TestNftRuleFromTermLogMirror is the #3445 M02 RED-on-revert: a term carrying
// `then log` / `then syslog` (both set term.Log) must emit an nft `log`
// statement on the kernel lo0 mirror, BEFORE the verdict. The pre-fix action
// switch never read term.Log, so the configured filter log was silently dropped
// for host-bound traffic the kernel handles. Reverting the fix drops the `log`
// fragment and fails this test.
func TestNftRuleFromTermLogMirror(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// log on a terminating accept: `<match> log prefix "..." accept`.
	term := &config.FirewallFilterTerm{
		Name:             "log-ssh",
		Protocols:        []string{"tcp"},
		DestinationPorts: []string{"22"},
		Log:              true,
		Action:           "accept",
	}
	got := nftRule(t, term, "ip", prefixLists)
	want := `meta l4proto 6 th dport 22 log prefix "xpf-lo0 log-ssh: " accept`
	if got != want {
		t.Errorf("log+accept:\n  got:  %s\n  want: %s", got, want)
	}
	if !strings.Contains(got, "log prefix") {
		t.Errorf("term `then log` did not emit nft `log` (#3445 M02 regression): %q", got)
	}

	// log on a discard: the log fires before the drop.
	dterm := &config.FirewallFilterTerm{Name: "log-drop", Log: true, Action: "discard"}
	dgot := nftRule(t, dterm, "ip", prefixLists)
	dwant := `log prefix "xpf-lo0 log-drop: " drop`
	if dgot != dwant {
		t.Errorf("log+discard:\n  got:  %s\n  want: %s", dgot, dwant)
	}
}

// TestNftRuleFromTermCountMirror is the #3445 M03 RED-on-revert: a term carrying
// `then count <name>` must emit a NAMED nft counter (`counter name "<n>"`) on the
// rule AND the payload must DECLARE that counter object in the table body (nft
// requires the declaration before the reference). The pre-fix action switch never
// read term.Count, so the kernel counter stayed stale while the kernel enforced
// the verdict. Reverting the fix drops the counter reference and the declaration.
func TestNftRuleFromTermCountMirror(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:             "count-ssh",
		Protocols:        []string{"tcp"},
		DestinationPorts: []string{"22"},
		Count:            "ssh-hits",
		Action:           "accept",
	}
	got := nftRule(t, term, "ip", prefixLists)
	want := `meta l4proto 6 th dport 22 counter name "xpflo0_ssh-hits" accept`
	if got != want {
		t.Errorf("count+accept:\n  got:  %s\n  want: %s", got, want)
	}

	// Payload must declare the named counter object (unquoted) before the chain.
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "lo0-in"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {Name: "lo0-in", Terms: []*config.FirewallFilterTerm{term}},
	}
	payload := buildLo0FilterPayload(cfg, "lo0-in", "")
	if !strings.Contains(payload, "  counter xpflo0_ssh-hits {") {
		t.Errorf("payload missing the named counter DECLARATION (#3445 M03):\n%s", payload)
	}
	if !strings.Contains(payload, `counter name "xpflo0_ssh-hits"`) {
		t.Errorf("payload missing the named counter REFERENCE (#3445 M03):\n%s", payload)
	}
	// The declaration must precede the chain reference.
	declIdx := strings.Index(payload, "counter xpflo0_ssh-hits {")
	refIdx := strings.Index(payload, `counter name "xpflo0_ssh-hits"`)
	if declIdx == -1 || refIdx == -1 || declIdx > refIdx {
		t.Errorf("counter declaration must precede its reference (nft requirement):\n%s", payload)
	}
}

// TestLo0PayloadSharedCounterDeclaredOnce pins that a counter object referenced
// by several terms (or by both the v4 and v6 lo0 filters, which share the inet
// table) is DECLARED exactly once — a duplicate declaration is an nft "File
// exists" hard error that rejects the whole atomic load (#3445).
func TestLo0PayloadSharedCounterDeclaredOnce(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "v4"
	cfg.System.Lo0FilterInputV6 = "v6"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"v4": {Name: "v4", Terms: []*config.FirewallFilterTerm{
			{Name: "a", Protocols: []string{"tcp"}, Count: "shared", Action: "accept"},
			{Name: "b", Protocols: []string{"udp"}, Count: "shared", Action: "discard"},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"v6": {Name: "v6", Terms: []*config.FirewallFilterTerm{
			{Name: "c", Count: "shared", Action: "accept"},
		}},
	}
	payload := buildLo0FilterPayload(cfg, "v4", "v6")
	if n := strings.Count(payload, "counter xpflo0_shared {"); n != 1 {
		t.Errorf("shared counter declared %d times, want exactly 1 (duplicate is an nft hard error):\n%s", n, payload)
	}
}
