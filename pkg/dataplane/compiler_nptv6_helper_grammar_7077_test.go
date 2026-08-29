package dataplane

// #7077 (#6894 r10): the #4960 NPTv6 hard error must fire on exactly the rules
// the Rust helper REFUSES, and never on a rule it ACCEPTS.
//
// #6894 r9 closed a real defect -- the pre-pass accepted an NPTv6 config the
// helper rejects post-mutation -- by turning a Go parse failure into a hard
// error. That inferred "the helper rejects this" from "Go cannot parse this",
// and the two grammars are not the same. Rust's `parse_prefix` parses the mask
// with `u8::from_str`, which takes a leading `+`; Go's `net.ParseCIDR` does
// not. So `nptv6-prefix fd00:9::/+48` applied SUCCESSFULLY before r9 (the
// helper installed it) and hard-failed the whole dataplane apply after -- a
// no-brick regression on the tolerant-load / HA-peer-sync path.
//
// These tests bind the corrected contract from both sides: the accepted class
// keeps warn-and-skip, the refused class keeps the hard error.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nptv6HelperGrammarCase is one row of the parity table.
//
// `wantWords` is checked as well as `wantOK` so the mirror cannot agree on the
// yes/no while disagreeing on the prefix LENGTH -- which is a live distinction,
// because `nptv6HelperWouldInstall` compares the two rules' word counts and a
// mirror that returned a constant 3 would pass a yes/no-only table while
// silently making every /64-vs-/48 pair look length-matched.
type nptv6HelperGrammarCase struct {
	in        string
	wantOK    bool
	wantWords int
}

// rustParsePrefixTable is the expected column, produced by compiling
// userspace-dp/src/nptv6.rs's `parse_prefix` VERBATIM with rustc and printing
// its answer for each string. It is a MEASUREMENT, not a reading of the Rust
// source, which is the point: a hand-transcribed expectation would encode the
// same misreading twice.
//
// Regenerate when the helper's grammar changes -- which is the remaining half
// of #7077, and is the plane that should ultimately own this rule. The `+`
// rows are the ones expected to flip to false when it does.
var rustParsePrefixTable = []nptv6HelperGrammarCase{
	// --- accepted ---
	{"2001:db8::/48", true, 3},
	{"2001:db8:1:2::/64", true, 4},
	{"fd00:beef::/48", true, 3},
	{"::/48", true, 3},
	{"::/64", true, 4},
	{"2001:DB8::/48", true, 3}, // case-insensitive hex
	{"2001:db8::/048", true, 3},
	{"2001:db8::/00048", true, 3},
	// The divergence this issue is about: Rust's u8::from_str takes ONE sign.
	{"2001:db8::/+48", false, 0},
	{"2001:db8::/+64", false, 0},
	{"2001:db8::/+048", false, 0},

	// --- refused: mask token ---
	{"2001:db8::/++48", false, 0}, // one sign only
	{"2001:db8::/-48", false, 0},
	{"2001:db8::/-0", false, 0}, // see nptv6HelperPrefixWords on sign handling
	{"2001:db8::/48+", false, 0},
	{"2001:db8::/ 48", false, 0},
	{"2001:db8::/48 ", false, 0},
	{"2001:db8::/6_4", false, 0}, // base 10 refuses Rust's '_' separators
	{"2001:db8::/4_8", false, 0},
	{"2001:db8::/0x30", false, 0},
	{"2001:db8::/๔๘", false, 0},  // non-ASCII digits ("48" in Thai)
	{"2001:db8::/999", false, 0}, // u8 overflow
	{"2001:db8::/256", false, 0}, // u8 overflow, off by one
	{"2001:db8::/0", false, 0},
	{"2001:db8::/128", false, 0},
	{"2001:db8::/56", false, 0}, // parses, but not 48 or 64

	// --- refused: shape ---
	{"not-a-prefix", false, 0},
	{"2001:db8::", false, 0},
	{"2001:db8::/", false, 0},
	{"/48", false, 0},
	{"", false, 0},
	{"2001:db8::/48/", false, 0},
	{"+2001:db8::/48", false, 0},

	// --- refused: address ---
	{"192.0.2.0/48", false, 0},      // bare IPv4 is not an Ipv6Addr
	{"fe80::1%eth0/64", false, 0},   // Ipv6Addr::from_str takes no zone
	{"fe80::%eth0/64", false, 0},    // ... even with the host bits clear
	{"::ffff:0.0.0.0/64", false, 0}, // v4-mapped: the ffff word is a host bit
	{"::ffff:1.2.3.4/64", false, 0}, // ... same, with the v4 bits set too

	// --- refused: host bits (#4519 fail-closed, no masking) ---
	{"2001:db8:0:2::/48", false, 0},
	{"2001:db8::1/64", false, 0},
}

// TestNPTv6HelperGrammarMatchesTheRustParser_7077 is the drift guard for the
// second copy of the helper's grammar this fix introduces.
func TestNPTv6HelperGrammarMatchesTheRustParser_7077(t *testing.T) {
	// Non-vacuity: a table that drifted to all-false (or all-true) would make
	// every row below satisfiable by a constant implementation.
	var accepted, refused int
	for _, tc := range rustParsePrefixTable {
		if tc.wantOK {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 5 || refused < 5 {
		t.Fatalf("the parity table has degenerated (%d accepted, %d refused) — "+
			"a one-sided table is satisfied by a constant function and binds nothing",
			accepted, refused)
	}

	for _, tc := range rustParsePrefixTable {
		words, ok := nptv6HelperPrefixWords(tc.in)
		if ok != tc.wantOK {
			t.Errorf("nptv6HelperPrefixWords(%q) accepted=%v, but rustc-measured "+
				"parse_prefix says %v — the Go mirror and the Rust helper disagree "+
				"about whether this rule installs, which is exactly the divergence "+
				"#7077 is about (in BOTH directions: a false accept re-opens the "+
				"#4960 half-applied shape, a false refuse fails an apply that works)",
				tc.in, ok, tc.wantOK)
			continue
		}
		if ok && words != tc.wantWords {
			t.Errorf("nptv6HelperPrefixWords(%q) = %d words, want %d — the yes/no "+
				"agrees but the LENGTH does not, so nptv6HelperWouldInstall would "+
				"mis-decide whether a rule's two prefixes have matching lengths",
				tc.in, words, tc.wantWords)
		}
	}
}

// TestNPTv6HelperWouldInstallPairsLengths_7077 covers the composed predicate's
// own gate: two individually-parseable prefixes of DIFFERENT lengths are a
// helper rejection (`iwords != ewords`), so the pair must not be reported as
// installable.
func TestNPTv6HelperWouldInstallPairsLengths_7077(t *testing.T) {
	for _, tc := range []struct {
		name, match, then string
		want              bool
	}{
		{"both /48", "2001:db8::/48", "fd00:9::/48", true},
		{"both /64", "2001:db8:0:1::/64", "fd00:9:0:1::/64", true},
		{"both /48, one with a + mask", "2001:db8::/48", "fd00:9::/+48", true},
		{"both /48, both with + masks", "2001:db8::/+48", "fd00:9::/+48", true},
		{"/64 vs /48", "2001:db8:0:1::/64", "fd00:9::/48", false},
		{"/48 vs /64", "2001:db8::/48", "fd00:9:0:1::/64", false},
		{"match unparseable", "not-a-prefix", "fd00:9::/48", false},
		{"then unparseable", "2001:db8::/48", "not-a-prefix", false},
		{"then host bits", "2001:db8::/48", "fd00:9:0:2::/48", false},
	} {
		if got := nptv6HelperWouldInstall(tc.match, tc.then); got != tc.want {
			t.Errorf("%s: nptv6HelperWouldInstall(%q, %q) = %v, want %v",
				tc.name, tc.match, tc.then, got, tc.want)
		}
	}
}

// #7268 retired compileNPTv6's eBPF nptv6_rules writes, so the write COUNTER
// this file used to carry (countingNPTv6DP.nptv6Writes) is gone.
//
// A counter can only observe a call that HAPPENS. Once the call is deleted a
// count-based assertion is vacuous by construction, not merely weaker — and
// `nptv6Writes != 0` would have kept passing for the wrong reason forever. The
// replacement is the #6420 tripwire, natWriteTripwireDP, with SetNPTv6Rule and
// DeleteStaleNPTv6 armed to ERROR: the assertion inverts to "a clean validate",
// which a restored write reds by propagating its error out of the `nptv6` row.
//
// What the counter USED to distinguish — "the row ran and skipped the rule"
// from "the row ran and installed it" — is no longer a distinction the compiler
// makes: after #7268 the row only ever validates. The property that replaced it
// is the DISPOSITION, which every test here already asserts directly: nil for a
// rule the helper installs, a `validate nptv6: ` error for one it refuses.

// nptv6GrammarConfig is a config carrying ONE NPTv6 rule with the given
// prefixes, on a zone with a VLAN sub-interface so that -- absent an early
// rejection -- compileZones would create a real VLAN device.
func nptv6GrammarConfig(match, then string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"xpft7077a.61"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpft7077a": {Name: "xpft7077a", Units: map[int]*config.InterfaceUnit{
			61: {Number: 61, VlanID: 61, Addresses: []string{"198.51.100.1/24"}},
		}},
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{{
		Name: "rs-7077", FromZone: "untrust",
		Rules: []*config.StaticNATRule{
			{Name: "r-7077", IsNPTv6: true, Match: match, Then: then},
		},
	}}
	return cfg
}

// TestHelperAcceptedNPTv6PrefixIsSkippedNotRejected_7077 is the fail-on-revert
// guard for the regression itself.
//
// RED-on-revert: drop `|| helperInstalls` from compileNPTv6's reject closure
// and this fails at the first check with
// "the apply was REJECTED for an NPTv6 rule the helper ACCEPTS" -- an
// ASSERTION, not a build break: the revert removes no symbol this file names.
func TestHelperAcceptedNPTv6PrefixIsSkippedNotRejected_7077(t *testing.T) {
	// The helper accepts `/+48` on both sides; Go's net.ParseCIDR does not.
	cfg := nptv6GrammarConfig("2001:db8:9::/48", "fd00:9::/+48")

	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("the apply was REJECTED for an NPTv6 rule the helper ACCEPTS, so "+
			"a config whose apply SUCCEEDS today now fails — the #1960 no-brick "+
			"regression #7077 is about: %v", err)
	}

	// It must be SKIPPED, not silently installed under a masked prefix: the Go
	// compiler cannot parse the string at all, so there is nothing correct for
	// it to write. Post-#7268 there is no write to count, so the tripwire says
	// it from the other side — a reintroduced write ERRORS and the row fails.
	dp := &natWriteTripwireDP{validationPass: true}
	if err := validateBeforeMutateWith(dp, cfg); err != nil {
		t.Fatalf("validateBeforeMutateWith disagreed with validateBeforeMutate, or a "+
			"retired NPTv6 map write was reintroduced for a prefix Go cannot parse: %v", err)
	}
	if len(dp.calls) != 0 {
		t.Errorf("compileNPTv6 called %v for a prefix Go cannot parse — the "+
			"disposition is warn-and-SKIP, and the eBPF nptv6_rules surface is "+
			"retired (#7268)", dp.calls)
	}

	// And the whole compile must proceed into the mutation phase, i.e. the
	// apply is not aborted. recordingDP's tripwire fires the moment compileZones
	// is entered, which is the proof it got that far.
	rdp := &recordingDP{}
	_, err := CompileConfig(rdp, cfg, false)
	if err == nil || !strings.Contains(err.Error(), "recordingDP tripwire") {
		t.Fatalf("want the compile to reach compileZones (the tripwire), got: %v", err)
	}
	if rdp.zoneConfigCalls != 1 {
		t.Errorf("compileZones was not entered (%d SetZoneConfig calls) — the "+
			"apply was aborted before the mutation phase for a rule the helper "+
			"installs", rdp.zoneConfigCalls)
	}
}

// TestHelperRefusedNPTv6PrefixStillHardErrors_7077 is the OVER-REACH control.
// Without it, #7077's fix is satisfied by reverting #6894 r9 outright.
//
// Every row here is a class the rustc-measured table above says `parse_prefix`
// REFUSES, so the apply already fails at publish, after compileZones mutated
// the host. Each must still be caught by the pre-pass's `nptv6` row.
func TestHelperRefusedNPTv6PrefixStillHardErrors_7077(t *testing.T) {
	for _, tc := range []struct {
		name, match, then, wantReason string
	}{
		{"codex counterexample", "2001:db8:9::/48", "not-a-prefix", "invalid nptv6-prefix"},
		{"unparseable match", "not-a-prefix", "2001:db8:9::/48", "invalid match prefix"},
		{"host bits internal", "2602:fd41:70::/48", "2001:db8:0:2::/48", "host bits set beyond the prefix length"},
		{"host bits external", "2602:fd41:70:1::/48", "2001:db8::/48", "host bits set beyond the prefix length"},
		{"length mismatch", "2001:db8:9:2::/64", "fd00:9::/48", "prefix lengths must match"},
		{"unsupported length", "2001:db8:9::/56", "fd00:9::/56", "only /48 and /64 prefix lengths supported"},
		{"double sign", "2001:db8:9::/48", "fd00:9::/++48", "invalid nptv6-prefix"},
		{"negative mask", "2001:db8:9::/48", "fd00:9::/-48", "invalid nptv6-prefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &recordingDP{}
			_, err := CompileConfig(dp, nptv6GrammarConfig(tc.match, tc.then), false)
			if err == nil {
				t.Fatal("the helper REFUSES this rule, so the apply fails at " +
					"publish after the host is mutated — the pre-pass must catch it " +
					"first (#4960)")
			}
			assertNoHostMutation(t, dp)
			if !strings.HasPrefix(err.Error(), "validate nptv6: ") {
				t.Errorf("want the failure attributed to the pre-pass's `nptv6` row, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("want the error to name %q, got: %v", tc.wantReason, err)
			}
		})
	}
}

// TestValidNPTv6StillCompiles_7077 is the other control: a well-formed rule
// must be neither skipped nor rejected. Without it, both tests above are
// satisfied by a compileNPTv6 that never writes anything.
func TestValidNPTv6StillCompiles_7077(t *testing.T) {
	dp := &natWriteTripwireDP{validationPass: true}
	if err := validateBeforeMutateWith(dp, nptv6GrammarConfig("2602:fd41:70::/48", "fd00:beef::/48")); err != nil {
		t.Fatalf("a valid NPTv6 rule must compile: %v", err)
	}
	if len(dp.calls) != 0 {
		t.Errorf("a valid NPTv6 rule called %v — the eBPF nptv6_rules surface is "+
			"retired (#7268); the helper builds its own NPTv6 state from the "+
			"config and computes its own adjustment", dp.calls)
	}

	// FIXTURE REACHABILITY, which the deleted `nptv6Writes == 2` control used to
	// provide. Without it every assertion in this file is satisfied by a
	// nptv6GrammarConfig that stopped producing an NPTv6 rule at all — the row
	// would find nothing to judge and return nil for the wrong reason.
	//
	// The same builder, one prefix changed to a class the helper REFUSES, must
	// produce the row's hard error. That is only possible if the config reaches
	// compileNPTv6's per-rule body, so it certifies the fixture for the accept
	// case above — and unlike a write counter, it survives the writes going away.
	refused := nptv6GrammarConfig("2602:fd41:70::/48", "not-a-prefix")
	err := validateBeforeMutateWith(&natWriteTripwireDP{validationPass: true}, refused)
	if err == nil {
		t.Fatal("the fixture no longer reaches compileNPTv6's per-rule body: a prefix " +
			"the helper refuses produced no error, so the accept assertions above " +
			"prove nothing")
	}
	if !strings.Contains(err.Error(), "invalid nptv6-prefix") {
		t.Errorf("want the reachability probe to fail in the nptv6 row, got: %v", err)
	}
}

// TestStrictCommitStillRejectsHelperAcceptedMalformedPrefix_7077 pins the half
// of the contract that lives in pkg/config: relaxing the dataplane disposition
// must NOT make `/+48` committable. An operator editing it in still gets a hard
// rejection; only an already-persisted or peer-synced config reaches the
// tolerant path this fix protects.
//
// Driven through the production ParseSetCommand + SetPath path (never
// NewParser, per the flat-set gotcha).
func TestStrictCommitStillRejectsHelperAcceptedMalformedPrefix_7077(t *testing.T) {
	build := func(t *testing.T) *config.ConfigTree {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, line := range []string{
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:9::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:9::/+48",
		} {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		return tree
	}

	if _, err := config.CompileConfig(build(t)); err == nil {
		t.Error("strict commit ACCEPTED `nptv6-prefix fd00:9::/+48` — the " +
			"dataplane now tolerates it on the lenient path, so the commit gate " +
			"is the only thing stopping an operator authoring a prefix the Go " +
			"compiler cannot decode (#7077)")
	}

	// ... and the lenient path RETAINS it with a warning, which is what makes
	// it reachable in pkg/dataplane at all. Without this half the test above
	// would still pass if lenient started dropping the rule, and the
	// no-brick fix would be guarding an unreachable input.
	cfg, err := config.CompileConfigLenient(build(t))
	if err != nil {
		t.Fatalf("the lenient tolerant-load path must not fail: %v", err)
	}
	var retained *config.StaticNATRule
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule != nil && rule.IsNPTv6 {
				retained = rule
			}
		}
	}
	if retained == nil {
		t.Fatal("the lenient path DROPPED the malformed NPTv6 rule, so nothing " +
			"reaches pkg/dataplane and #7077's input class is unreachable")
	}
	if retained.Then != "fd00:9::/+48" {
		t.Errorf("the lenient path rewrote the prefix to %q; the dataplane "+
			"disposition is chosen from the VERBATIM string", retained.Then)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nptv6") && strings.Contains(w, "fd00:9::/+48") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the lenient path retained the rule with no NPTv6 warning "+
			"naming it — the operator gets no signal at all\n  warnings: %v",
			cfg.Warnings)
	}

	// End of the chain: that retained config must now APPLY.
	if err := validateBeforeMutate(cfg); err != nil {
		t.Errorf("the config the lenient path produced does not apply: %v", err)
	}
}
