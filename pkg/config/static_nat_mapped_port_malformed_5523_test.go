package config

import (
	"strings"
	"testing"
)

// TestStaticNATMappedPortMalformedRejected is the C179-038 residual half: a
// NON-NUMERIC `then static-nat prefix <ip> mapped-port <token>` with NO
// `match destination-port` was silently swallowed. The token rides inside the
// children:nil static-nat leaf (bypassing the schema value validator), so
// staticNATMappedPortForNode mapped it to MappedPort==0 (== "no port
// translation"), the `MatchDestinationPort != 0 && MappedPort == 0` guard did
// not fire (no match-port), and the rule compiled clean — even though a
// WELL-FORMED value in the same position IS rejected
// (TestStaticNATMappedPortWithoutMatchPortRejected). A garbage token was thus
// treated more leniently than a valid one.
//
// Fail-on-revert: neutralize the unified presence gate in
// validateNATHostMaskStrict (`rule.MappedPortPresent && (MappedPort < 1 ||
// MappedPort > 65535)`) or revert staticNATMappedPortForNode to drop the
// presence/raw returns → the malformed token is never surfaced →
// CompileConfig succeeds → this test goes RED on a clean assertion.
func TestStaticNATMappedPortMalformedRejected(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		// Deliberately NO `match destination-port` — this is the residual path.
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port notaport",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected CompileConfig to reject a non-numeric mapped-port")
	}
	if !strings.Contains(err.Error(), "mapped-port") {
		t.Fatalf("error must mention mapped-port, got %v", err)
	}
	if !strings.Contains(err.Error(), "notaport") {
		t.Fatalf("error must name the malformed token, got %v", err)
	}
}

// TestStaticNATMappedPortMalformedLenientWarns confirms the lenient load /
// peer-sync path (#1960 no-brick) downgrades the malformed mapped-port to a
// warning rather than a hard error, and — critically — the compiled rule still
// carries MappedPort==0 so the dataplane installs a plain 1:1 (no bogus port),
// matching the pre-fix fail-closed behaviour.
func TestStaticNATMappedPortMalformedLenientWarns(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port notaport",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static NAT rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.MappedPort != 0 {
		t.Fatalf("lenient path must keep MappedPort==0 (no bogus port), got %d", rule.MappedPort)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mapped-port") && strings.Contains(w, "notaport") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning naming the malformed mapped-port, got %v", cfg.Warnings)
	}
}

// buildMappedPortTree assembles a static-NAT rule tree from the shared base
// lines plus the case-specific tail lines, using the flat-set ParseSetCommand
// + SetPath idiom (NOT NewParser, which merges newline-separated set lines).
func buildMappedPortTree(t *testing.T, tail []string) *ConfigTree {
	t.Helper()
	base := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32",
	}
	tree := &ConfigTree{}
	for _, line := range append(append([]string{}, base...), tail...) {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// TestStaticNATMappedPortPresenceGate is the #6479 fold: Codex found the
// C179-038 fix (a `MappedPortRaw string` + a strict reject for a NON-EMPTY raw
// token) left three sentinel-collision siblings SILENTLY ACCEPTED (strict
// reject=false, no warning), all the same class as C179-038 — a PRESENT
// mapped-port that becomes a no-port-translation 1:1 with no diagnostic:
//
//   - `mapped-port 0`  — Atoi("0")==(0,nil) → MappedPort==0 (the "absent"
//     sentinel), so the `MappedPort != 0` range gate was skipped even though 0
//     is outside the advertised 1-65535.
//   - `mapped-port ""` — the quoted-empty operand is a real retained token but
//     Atoi("")=err → MappedPortRaw=="" (the "absent" sentinel), so the
//     `MappedPortRaw != ""` gate was skipped.
//   - bare `mapped-port` (no operand) — the keyword-present-with-no-value case
//     set nothing at all.
//
// The fold adds an explicit MappedPortPresent signal (set whenever the
// keyword appears, regardless of operand) so ONE unified gate —
// `MappedPortPresent && (MappedPort < 1 || MappedPort > 65535)` — rejects every
// present-but-not-valid-1-65535 mapped-port and names the offending token
// (MappedPortRaw, or "(missing value)" for the empty/bare cases). A valid
// in-range port with a matching `match destination-port`, and an absent
// mapped-port, are still accepted; the lenient load / peer-sync path (#1960
// no-brick) downgrades the reject to a warning and keeps MappedPort==0 for a
// truly-malformed token so the dataplane installs a plain 1:1.
//
// Coverage spans BOTH AST shapes reachable from flat-set: the collapsed
// single-line form (`... prefix <ip> mapped-port <tok>` folds onto the prefix
// leaf's Keys) and the hierarchical sibling form (two `then static-nat` set
// lines build a `static-nat { prefix X; mapped-port P; }` node with distinct
// children, exercising the compiler's t.FindChild("mapped-port") path).
//
// Fail-on-revert: guard the unified presence gate false (keep the fields read)
// → the 0 / "" / bare / 70000 / sibling cases all go RED on clean assertions.
func TestStaticNATMappedPortPresenceGate(t *testing.T) {
	// flat is a single collapsed `then static-nat prefix <ip> <tail>` set line.
	flat := func(tail string) []string {
		return []string{"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 " + tail}
	}
	// flatMatch pairs a `match destination-port` with the collapsed then-line so
	// an in-range or out-of-range NUMERIC port is isolated from the separate
	// mapped-port-without-match-port gate.
	flatMatch := func(tail string) []string {
		return []string{
			"set security nat static rule-set rs1 rule r1 match destination-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 " + tail,
		}
	}
	// sibling emits two separate `then static-nat` set lines so the parser
	// builds the hierarchical sibling shape (prefix + mapped-port as distinct
	// children of static-nat) rather than collapsing onto one leaf's Keys.
	sibling := func(val string) []string {
		return []string{
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
			"set security nat static rule-set rs1 rule r1 then static-nat mapped-port " + val,
		}
	}
	// siblingBare is the sibling shape with a BARE `mapped-port` (no operand at
	// all) — a distinct set-line shape from sibling(`""`)'s empty quoted operand.
	siblingBare := func() []string {
		return []string{
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
			"set security nat static rule-set rs1 rule r1 then static-nat mapped-port",
		}
	}

	cases := []struct {
		name        string
		tail        []string
		wantReject  bool
		wantSubstr  string // token / placeholder the strict error + lenient warning must name
		wantMapZero bool   // lenient path must keep MappedPort==0 (truly-malformed)
		wantMapPort int    // on an accepted case, the compiled MappedPort (0 = skip)
	}{
		// Collapsed single-line (flat) malformed — the sentinel-collision core.
		{"flatZero", flat("mapped-port 0"), true, `"0"`, true, 0},
		{"flatEmpty", flat(`mapped-port ""`), true, "(missing value)", true, 0},
		{"flatBare", flat("mapped-port"), true, "(missing value)", true, 0},
		{"flatNonNumeric", flat("mapped-port notaport"), true, `"notaport"`, true, 0},
		// Numeric but out of range — carries a match-port so the mapped-port-
		// without-match-port gate stays quiet. #6479 fold: out-of-range is now
		// folded to malformed, so MappedPort is zeroed (fail-closed) → wantMapZero.
		{"flatOutOfRange", flatMatch("mapped-port 70000"), true, `"70000"`, true, 0},
		// Hierarchical sibling malformed — the sibling scan path.
		{"siblingNonNumeric", sibling("notaport"), true, `"notaport"`, true, 0},
		{"siblingZero", sibling("0"), true, `"0"`, true, 0},
		// #6479 fold NIT 2 (sibling coverage Codex noted was missing): the
		// empty / bare / out-of-range sibling shapes all fail closed too.
		{"siblingEmpty", sibling(`""`), true, "(missing value)", true, 0},
		{"siblingBare", siblingBare(), true, "(missing value)", true, 0},
		{"siblingOutOfRange", sibling("70000"), true, `"70000"`, true, 0},
		// #6479 fold NIT 2 (scan-all, not first-wins): a contradictory flat
		// duplicate fails closed — a malformed occurrence ANYWHERE zeroes the
		// port and names the bad token, never silently reduced to the good one.
		{"dupValidThenBad", flat("mapped-port 8080 mapped-port notaport"), true, `"notaport"`, true, 0},
		{"dupBadThenValid", flat("mapped-port notaport mapped-port 8080"), true, `"notaport"`, true, 0},
		{"dupValidThenBare", flat("mapped-port 8080 mapped-port"), true, "(missing value)", true, 0},
		{"dupValidThenOutOfRange", flat("mapped-port 8080 mapped-port 70000"), true, `"70000"`, true, 0},
		// Accepted: a valid in-range port WITH a matching match destination-port.
		{"validWithMatchPort", flatMatch("mapped-port 8080"), false, "", false, 8080},
		// Accepted: a duplicate where BOTH operands are valid — last-wins (9090)
		// with a matching match destination-port (#6479 fold). wantMapPort asserts
		// the LAST valid operand wins (9090), not the first (8080).
		{"dupBothValid", flatMatch("mapped-port 8080 mapped-port 9090"), false, "", false, 9090},
		// Accepted: no mapped-port keyword at all (plain host 1:1).
		{"absent", []string{"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32"}, false, "", false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Strict commit-check.
			cfgS, err := CompileConfig(buildMappedPortTree(t, tc.tail))
			if tc.wantReject {
				if err == nil {
					t.Fatalf("strict CompileConfig must reject %s", tc.name)
				}
				if !strings.Contains(err.Error(), "mapped-port") {
					t.Fatalf("strict error must mention mapped-port, got %v", err)
				}
				if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Fatalf("strict error must name %s, got %v", tc.wantSubstr, err)
				}
			} else if err != nil {
				t.Fatalf("strict CompileConfig must accept %s, got %v", tc.name, err)
			} else if tc.wantMapPort != 0 {
				// Accepted case with an expected compiled port: assert the
				// combine result (last-wins across duplicates) reached the rule.
				if len(cfgS.Security.NAT.Static) != 1 || len(cfgS.Security.NAT.Static[0].Rules) != 1 {
					t.Fatalf("expected exactly 1 static NAT rule for %s", tc.name)
				}
				if got := cfgS.Security.NAT.Static[0].Rules[0].MappedPort; got != tc.wantMapPort {
					t.Fatalf("strict path MappedPort for %s: want %d, got %d", tc.name, tc.wantMapPort, got)
				}
			}

			// Lenient load / peer-sync path (#1960 no-brick).
			cfg, errL := CompileConfigLenient(buildMappedPortTree(t, tc.tail))
			if errL != nil {
				t.Fatalf("lenient compile must not hard-error for %s, got %v", tc.name, errL)
			}
			if tc.wantReject {
				var found bool
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "mapped-port") && strings.Contains(w, tc.wantSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("lenient path must warn naming %s for %s, got %v", tc.wantSubstr, tc.name, cfg.Warnings)
				}
			}
			if tc.wantMapZero {
				if len(cfg.Security.NAT.Static) != 1 || len(cfg.Security.NAT.Static[0].Rules) != 1 {
					t.Fatalf("expected exactly 1 static NAT rule for %s", tc.name)
				}
				if got := cfg.Security.NAT.Static[0].Rules[0].MappedPort; got != 0 {
					t.Fatalf("lenient path must keep MappedPort==0 (no bogus port) for %s, got %d", tc.name, got)
				}
			}
		})
	}
}

// TestStaticNATMappedPortDoubleWarnGate is the #6479 fold NIT 1: a PRESENT-but-
// malformed `mapped-port` that lands at MappedPort==0 (`mapped-port 0`) PAIRED
// WITH a `match destination-port` must be owned SOLELY by the presence gate
// (which names the offending token), NOT double-reported by the #2769
// match-port-without-mapped-port inverse gate. Before the fold both gates fired
// on MappedPort==0: two warnings on the lenient path, and — because the #2769
// gate emits FIRST — the misleading "requires a matching `then static-nat
// mapped-port`" message won over the accurate "not a valid port number" one in
// strict mode. The fold guards the #2769 gate on !MappedPortPresent so it fires
// only on a TRUE absence.
//
// Fail-on-revert: drop `&& !rule.MappedPortPresent` from the #2769 gate →
// strict names the wrong (requires-mapped-port) message and the lenient path
// emits two mapped-port warnings → the message/count assertions go RED.
func TestStaticNATMappedPortDoubleWarnGate(t *testing.T) {
	// Present-but-malformed (`mapped-port 0`) WITH a matching match-port.
	malformedWithMatch := []string{
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 0",
	}
	// Strict: the accurate malformed-token message wins; the misleading #2769
	// "requires a matching" message must NOT appear.
	_, err := CompileConfig(buildMappedPortTree(t, malformedWithMatch))
	if err == nil {
		t.Fatalf("strict CompileConfig must reject a malformed mapped-port paired with a match-port")
	}
	if !strings.Contains(err.Error(), "not a valid port number") {
		t.Fatalf("strict error must be the malformed-token message, got %v", err)
	}
	if !strings.Contains(err.Error(), `"0"`) {
		t.Fatalf(`strict error must name the malformed token "0", got %v`, err)
	}
	if strings.Contains(err.Error(), "requires a matching") {
		t.Fatalf("strict error must NOT double-fire the #2769 requires-mapped-port gate, got %v", err)
	}
	// Lenient: EXACTLY ONE mapped-port warning (the presence gate), not two.
	cfg, errL := CompileConfigLenient(buildMappedPortTree(t, malformedWithMatch))
	if errL != nil {
		t.Fatalf("lenient compile must not hard-error, got %v", errL)
	}
	var n int
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mapped-port") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("lenient path must emit exactly ONE mapped-port warning, got %d: %v", n, cfg.Warnings)
	}

	// The genuine ABSENCE case (match-port with NO mapped-port at all) must
	// STILL be rejected by the #2769 inverse gate (MappedPortPresent==false).
	absent := []string{
		"set security nat static rule-set rs1 rule r1 match destination-port 8080",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	}
	_, errA := CompileConfig(buildMappedPortTree(t, absent))
	if errA == nil {
		t.Fatalf("strict CompileConfig must still reject a match-port with no mapped-port")
	}
	if !strings.Contains(errA.Error(), "requires a matching") {
		t.Fatalf("true-absence must be rejected by the #2769 requires-mapped-port gate, got %v", errA)
	}
}

// TestStaticNATMappedPortGrammarPosition5523 is the #6479 fold: the C179-038
// mapped-port scan was grammar-NAIVE — it treated ANY literal `mapped-port`
// token in the static-nat `then` leaf as the mapped-port modifier, regardless of
// grammar position, and it read only the FindChild-first prefix child so a
// duplicate split across two `then static-nat` set lines was first-wins. The fold
// makes detection grammar-position-aware (a `mapped-port` that is the VALUE of a
// preceding `routing-instance`/`prefix` is NOT a modifier) and combines every
// occurrence across all target children through ONE combine (fail-closed on any
// malformed operand, no first-wins).
//
// Fail-on-revert:
//   - routingInstanceNamedMappedPortAccepts goes RED if the routing-instance/
//     prefix grammar-position skip in staticNATMappedPortOperandsFromKeys is
//     reverted (the false reject of a routing-instance NAMED "mapped-port"
//     returns).
//   - crossNodeMalformedRejects goes RED if staticNATMappedPortForNode is
//     reverted to the first-wins sibling scan (only the FindChild prefix child +
//     `mapped-port` siblings): node2's `notaport` is ignored, 8080 wins, and the
//     malformed duplicate compiles clean.
func TestStaticNATMappedPortGrammarPosition5523(t *testing.T) {
	// PROBLEM 1: a translation-target routing-instance NAMED "mapped-port"
	// (#4292 allows an arbitrary routing-instance identifier) is NOT a mapped-port
	// modifier — the rule carries no mapped-port at all and must compile clean.
	t.Run("routingInstanceNamedMappedPortAccepts", func(t *testing.T) {
		tail := []string{
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 routing-instance mapped-port",
		}
		cfg, err := CompileConfig(buildMappedPortTree(t, tail))
		if err != nil {
			t.Fatalf(`a routing-instance named "mapped-port" must compile clean (no mapped-port modifier present), got %v`, err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPortPresent {
			t.Fatalf("routing-instance value \"mapped-port\" must NOT register a mapped-port modifier (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
		if rule.ThenRoutingInstance != "mapped-port" {
			t.Fatalf("the routing-instance target must be captured as \"mapped-port\", got %q", rule.ThenRoutingInstance)
		}
	})

	// A NORMAL routing-instance name is unaffected by the guard.
	t.Run("routingInstanceNormalAccepts", func(t *testing.T) {
		tail := []string{
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 routing-instance blue",
		}
		cfg, err := CompileConfig(buildMappedPortTree(t, tail))
		if err != nil {
			t.Fatalf("a normal routing-instance target must compile clean, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPortPresent {
			t.Fatalf("a normal routing-instance must not register a mapped-port modifier")
		}
		if rule.ThenRoutingInstance != "blue" {
			t.Fatalf("routing-instance target want \"blue\", got %q", rule.ThenRoutingInstance)
		}
	})

	// Only the token IMMEDIATELY after routing-instance/prefix is skipped: a
	// GENUINE mapped-port modifier alongside a routing-instance named
	// "mapped-port" still survives. node1 supplies a real mapped-port 8080 (with a
	// matching match destination-port); node2's routing-instance is named
	// "mapped-port". The real 8080 must be honored and the RI name must not poison
	// it.
	t.Run("realMappedPortPlusRINamedMappedPort", func(t *testing.T) {
		tail := []string{
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 8080",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 routing-instance mapped-port",
		}
		cfg, err := CompileConfig(buildMappedPortTree(t, tail))
		if err != nil {
			t.Fatalf(`a real mapped-port 8080 alongside a routing-instance named "mapped-port" must compile clean, got %v`, err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if !rule.MappedPortPresent || rule.MappedPort != 8080 {
			t.Fatalf("real mapped-port 8080 must survive the RI-named-mapped-port node (present=%v port=%d)", rule.MappedPortPresent, rule.MappedPort)
		}
	})

	// PROBLEM 2: a duplicate mapped-port split ACROSS two `then static-nat` set
	// lines (distinct target children under one static-nat node) must be folded
	// together and fail closed on ANY malformed occurrence — not first-wins.
	crossNode := func(a, b string) []string {
		return []string{
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port " + a,
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port " + b,
		}
	}
	t.Run("crossNodeMalformedRejects", func(t *testing.T) {
		// A matching match destination-port is present so that, under the OLD
		// first-wins behaviour, the valid first node (8080) would compile CLEAN
		// (the firsthand "ACCEPTED, notaport ignored" fail-open). The unified
		// combine must instead fail closed and NAME the malformed second token.
		tail := append([]string{
			"set security nat static rule-set rs1 rule r1 match destination-port 80",
		}, crossNode("8080", "notaport")...)
		_, err := CompileConfig(buildMappedPortTree(t, tail))
		if err == nil {
			t.Fatalf("a cross-node duplicate mapped-port with a malformed second value must fail closed (not first-wins accept)")
		}
		if !strings.Contains(err.Error(), "mapped-port") || !strings.Contains(err.Error(), "notaport") {
			t.Fatalf(`cross-node reject must name the malformed token "notaport", got %v`, err)
		}
	})
	t.Run("crossNodeMalformedFirstRejects", func(t *testing.T) {
		// Order-independence: a malformed value in the FIRST node also fails closed.
		_, err := CompileConfig(buildMappedPortTree(t, crossNode("notaport", "8080")))
		if err == nil {
			t.Fatalf("a cross-node duplicate mapped-port with a malformed first value must fail closed")
		}
		if !strings.Contains(err.Error(), "notaport") {
			t.Fatalf(`cross-node reject must name "notaport", got %v`, err)
		}
	})
	t.Run("crossNodeBothValidLastWins", func(t *testing.T) {
		// Both operands valid across nodes → accept, last-wins (9090). A match
		// destination-port is required for a valid in-range mapped-port to accept.
		tail := append([]string{
			"set security nat static rule-set rs1 rule r1 match destination-port 443",
		}, crossNode("8080", "9090")...)
		cfg, err := CompileConfig(buildMappedPortTree(t, tail))
		if err != nil {
			t.Fatalf("a cross-node duplicate with both operands valid must accept, got %v", err)
		}
		rule := cfg.Security.NAT.Static[0].Rules[0]
		if rule.MappedPort != 9090 {
			t.Fatalf("cross-node both-valid must be last-wins 9090, got %d", rule.MappedPort)
		}
	})
}
