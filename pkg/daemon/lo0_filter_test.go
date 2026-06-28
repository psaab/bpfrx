package daemon

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

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

// TestLo0FilterPayloadFlushIdiom guards the #2069 fix: the nft `-f -` payload
// must NOT use the invalid `flush ruleset <table>` form (a parse error that
// rejected the whole ruleset and made the lo0 filter fail OPEN), and must use
// the atomic create-if-absent + `flush table` idiom so the prior table is
// reset before the new rules are installed. This test FAILS against the
// pre-fix payload that began `flush ruleset inet xpf_lo0`.
func TestLo0FilterPayloadFlushIdiom(t *testing.T) {
	cfg := lo0FilterTestConfig()
	payload := buildLo0FilterPayload(cfg, cfg.System.Lo0FilterInputV4, cfg.System.Lo0FilterInputV6)

	// The invalid idiom (`flush ruleset` cannot take a table name) must be gone.
	if strings.Contains(payload, "flush ruleset") {
		t.Errorf("payload uses invalid `flush ruleset` idiom (#2069 regression); a table name after `flush ruleset` is an nft parse error that rejects the entire payload:\n%s", payload)
	}

	// The correct atomic reset idiom must be present, in order.
	wantLines := []string{
		"table inet xpf_lo0",
		"flush table inet xpf_lo0",
		"table inet xpf_lo0 {",
	}
	idx := 0
	for _, line := range strings.Split(payload, "\n") {
		if idx < len(wantLines) && strings.TrimSpace(line) == wantLines[idx] {
			idx++
		}
	}
	if idx != len(wantLines) {
		t.Errorf("payload missing the create-if-absent + `flush table` idiom (got to line %d/%d):\n%s", idx, len(wantLines), payload)
	}

	// The real filter rules must still be present (proves the flush idiom did
	// not displace the rule body).
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
		Name:      "deny-others",
		Protocols: []string{"tcp"},
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
		Protocols:        []string{"tcp"},
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

func TestNftRuleFromTermICMPTypeCode(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// IPv6 block-ra-adv filter: icmp-type 134 icmp-code 0 → discard
	term := &config.FirewallFilterTerm{
		Name:      "block-ra",
		ICMPTypes: []int{134},
		ICMPCodes: []int{0},
		Action:    "discard",
	}
	rule := nftRuleFromTerm(term, "ip6", prefixLists)
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
	rule2 := nftRuleFromTerm(term2, "ip", prefixLists)
	want2 := "icmp type 5 drop"
	if rule2 != want2 {
		t.Errorf("got:\n  %s\nwant:\n  %s", rule2, want2)
	}
}

func TestNftRuleFromTermDSCP(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	term := &config.FirewallFilterTerm{
		Name:   "dscp-match",
		DSCPs:  []string{"ef"},
		Action: "accept",
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
			want:  "meta l4proto tcp tcp flags & syn == syn drop",
		},
		{
			// Plain list is the Junos AND-conjunction (both required), NOT a
			// disjunctive comma set. mask == required == syn|ack.
			name:  "syn-ack-list",
			flags: []string{"syn", "ack"},
			want:  "meta l4proto tcp tcp flags & (syn | ack) == (syn | ack) drop",
		},
		{
			// Negated form: SYN required, ACK forbidden. The mentioned mask is
			// syn|ack; the required side is just syn (ACK must be clear).
			name:  "syn-not-ack",
			flags: []string{"syn", "&", "!ack"},
			want:  "meta l4proto tcp tcp flags & (syn | ack) == syn drop",
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
			rule := nftRuleFromTerm(term, "ip", prefixLists)
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
	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "meta l4proto tcp th dport != 22 accept"
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
	rule2 := nftRuleFromTerm(term2, "ip", prefixLists)
	want2 := "meta l4proto tcp th dport != { 80, 443 } accept"
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
	rule3 := nftRuleFromTerm(term3, "ip", prefixLists)
	want3 := "meta l4proto udp th sport != 123 drop"
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

	rule := nftRuleFromTerm(term, "ip", prefixLists)
	want := "ip frag-off & 0x1fff != 0 drop"
	if rule != want {
		t.Errorf("ip4 fragment:\n got:  %s\n want: %s", rule, want)
	}

	rule6 := nftRuleFromTerm(term, "ip6", prefixLists)
	want6 := "exthdr frag exists drop"
	if rule6 != want6 {
		t.Errorf("ip6 fragment:\n got:  %s\n want: %s", rule6, want6)
	}
	if strings.Contains(rule6, "ip frag-off") {
		t.Errorf("ip6 chain emitted IPv4-only `ip frag-off` (#3231 regression): %s", rule6)
	}
}
