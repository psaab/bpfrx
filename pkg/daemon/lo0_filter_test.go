package daemon

import (
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
					Protocol:          "tcp",
					SourcePrefixLists: []config.PrefixListRef{{Name: "trusted"}},
					DestinationPorts:  []string{"22"},
					Action:            "accept",
					ICMPType:          -1,
					ICMPCode:          -1,
				},
				{
					Name:     "deny-rest",
					Protocol: "tcp",
					Action:   "discard",
					ICMPType: -1,
					ICMPCode: -1,
				},
			},
		},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"mgmt-lockdown6": {
			Name: "mgmt-lockdown6",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:     "drop-rh0",
					ICMPType: 134,
					ICMPCode: 0,
					Action:   "discard",
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
