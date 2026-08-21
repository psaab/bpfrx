package format

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6858: bind the two halves of the accepted-but-inert story to each other.
//
// The enforced/inert VERDICT was already pinned in both directions at the
// formatter, and the unbound-vs-unsupported-type distinction was pinned too.
// What was NOT pinned is that the formatter's notion of "inert" matches the
// COMMIT ADVISORY's. Deleting the ieee-802.1 inert advisory from
// compiler_validate_warn.go reddened exactly one test — in pkg/config — and the
// formatter, the gRPC peer and cmdtree all stayed green. A developer enforcing
// 802.1 would delete the advisory, see one config test red, delete that too,
// and ship a command reporting a working rewrite as inert.

// compileCoSRewriteSet6858 runs `set` lines through the real grammar gate and
// the real compiler — the two steps a commit performs — so every fixture below
// is authored the way an operator authors config, not assembled as a struct.
func compileCoSRewriteSet6858(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// cosRewriteFamilies6858 is the set of committable rewrite-rule families, read
// from the config schema rather than re-typed.
func cosRewriteFamilies6858(t *testing.T) []string {
	t.Helper()
	got := config.CompleteSetPath([]string{"class-of-service", "rewrite-rules"})
	if len(got) == 0 {
		t.Fatal("config schema offers no `class-of-service rewrite-rules` children")
	}
	out := append([]string(nil), got...)
	sort.Strings(out)
	return out
}

// cosUnitBindableFamilies6858 is the subset an interface unit can actually
// reference. Also read from the schema: today `inet-precedence` and `exp` have
// no unit binding at all, and hardcoding that here would be a fourth copy of a
// list this PR exists to stop duplicating.
func cosUnitBindableFamilies6858(t *testing.T, iface string, unit string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range config.CompleteSetPath([]string{
		"class-of-service", "interfaces", iface, "unit", unit, "rewrite-rules",
	}) {
		out[f] = true
	}
	return out
}

// TestCoSInertAdvisoryAgreesWithRenderedEnforcement6858 asserts the biconditional
// the docs assert in prose: for each committable family, the commit emits an
// accepted-but-inert advisory IF AND ONLY IF the rendered rule carries the
// unsupported-TYPE reason.
//
// It keys on the TYPE reason ("the dataplane rewrites dscp only") rather than
// on "Enforced: no", so a family that becomes enforced but happens to be
// unbound — which correctly renders "not bound" — does not read as a violation.
//
// FAIL-ON-REVERT, either direction:
//   - delete a family's advisory from compiler_validate_warn.go and that family
//     renders the type reason with no advisory -> RED;
//   - change cosRewriteRuleEnforcement's `cpType != "dscp"` test without
//     touching the advisories and the flipped family loses (or gains) the type
//     reason while its advisory stays put -> RED.
func TestCoSInertAdvisoryAgreesWithRenderedEnforcement6858(t *testing.T) {
	const iface, unit = "ge-0-0-1", "0"
	families := cosRewriteFamilies6858(t)
	bindable := cosUnitBindableFamilies6858(t, iface, unit)

	cmds := []string{"set class-of-service forwarding-classes queue 0 best-effort"}
	for _, fam := range families {
		name := cosRuleName6858(fam)
		cmds = append(cmds, "set class-of-service rewrite-rules "+fam+" "+name+
			" forwarding-class best-effort loss-priority low code-point 0")
		// Bind wherever the schema allows, so "no advisory" can be answered
		// with "Enforced: yes" rather than "not bound".
		if bindable[fam] {
			cmds = append(cmds, "set class-of-service interfaces "+iface+" unit "+unit+
				" rewrite-rules "+fam+" "+name)
		}
	}
	cfg := compileCoSRewriteSet6858(t, cmds...)

	warnings := config.ValidateConfig(cfg)
	out := FormatCoSRewriteRules(cfg, "", "")

	// Guard against a vacuous pass: at least one family on each side.
	advised, plain := 0, 0
	for _, fam := range families {
		hasAdvisory := false
		for _, w := range warnings {
			if strings.Contains(w, "rewrite-rules "+fam) && strings.Contains(w, "inert") {
				hasAdvisory = true
				break
			}
		}
		line := ruleHeaderLine(t, out, cosRuleName6858(fam))
		saysTypeInert := strings.Contains(line, "the dataplane rewrites dscp only")

		if hasAdvisory != saysTypeInert {
			t.Errorf("family %q: commit advisory present = %v, but `show class-of-service "+
				"rewrite-rule` reports the unsupported-type reason = %v.\n"+
				"These must move together: a family that starts being enforced must lose "+
				"its advisory AND flip in cosRewriteRuleEnforcement in the same change, or "+
				"this command reports a working rewrite as inert.\nheader: %s\nwarnings: %v",
				fam, hasAdvisory, saysTypeInert, line, warnings)
		}
		if hasAdvisory {
			advised++
		} else {
			plain++
		}
	}
	if advised == 0 || plain == 0 {
		t.Fatalf("fixture is one-sided (%d advised, %d not); the biconditional would hold "+
			"vacuously", advised, plain)
	}

	// Positive control: the family with no advisory, bound to a unit, must
	// actually report enforced. Without this, "every family inert" would
	// satisfy the biconditional above.
	for _, fam := range families {
		line := ruleHeaderLine(t, out, cosRuleName6858(fam))
		if strings.Contains(line, "the dataplane rewrites dscp only") || !bindable[fam] {
			continue
		}
		if !strings.Contains(line, "Enforced: yes") {
			t.Errorf("family %q has no inert advisory and IS bound to a unit, so it must "+
				"report as enforced:\n%s", fam, line)
		}
	}
}

func cosRuleName6858(family string) string {
	return "rw-" + strings.ReplaceAll(family, ".", "-")
}

// TestFormatCoSRewriteRulesNameOnlyOrderIsSorted6858 covers the `sort.Strings`
// in appendNameOnly, whose comment claims "the output order is stable
// regardless of config-file order".
//
// Both pre-#6858 name-only fixtures held exactly ONE rule each, so the sort was
// unobservable and deleting it changed nothing. Here three rules are authored in
// deliberately non-sorted order, so the sort does work a test can see.
//
// FAIL-ON-REVERT: delete `sort.Strings(sorted)` from appendNameOnly and the
// rules render in config order (zulu, alpha, mike) -> RED.
func TestFormatCoSRewriteRulesNameOnlyOrderIsSorted6858(t *testing.T) {
	cfg := compileCoSRewriteSet6858(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service rewrite-rules inet-precedence rw-zulu forwarding-class best-effort loss-priority low code-point 0",
		"set class-of-service rewrite-rules inet-precedence rw-alpha forwarding-class best-effort loss-priority low code-point 0",
		"set class-of-service rewrite-rules inet-precedence rw-mike forwarding-class best-effort loss-priority low code-point 0",
	)
	// The compiler must have preserved config order, or the fixture proves
	// nothing about sorting.
	if got := cfg.ClassOfService.INetPrecedenceRewriteRules; len(got) != 3 || got[0] != "rw-zulu" {
		t.Fatalf("fixture does not reach the renderer in non-sorted config order: %v; "+
			"the ordering assertion below would be vacuous", got)
	}

	out := FormatCoSRewriteRules(cfg, "", "inet-precedence")
	wantOrder := []string{"rw-alpha", "rw-mike", "rw-zulu"}
	assertRenderOrder6858(t, out, "Rewrite rule: ", wantOrder,
		"name-only rewrite rules must render in sorted order regardless of config-file order")
}

// TestFormatCoSRewriteRulesRowOrderIsSorted6858 covers the
// `sort.SliceStable(blk.rows, ...)` by forwarding-class then loss-priority.
//
// Every pre-#6858 assertion on the code-point table used strings.Contains, so
// row ORDER was unobservable and the sort could be deleted with the suite
// staying green.
//
// FAIL-ON-REVERT: delete the sort.SliceStable call and rows render in config
// order (voice, best-effort, ...) -> RED.
func TestFormatCoSRewriteRulesRowOrderIsSorted6858(t *testing.T) {
	cfg := compileCoSRewriteSet6858(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 1 network-control",
		"set class-of-service forwarding-classes queue 2 voice",
		// Authored in reverse-sorted forwarding-class order, and the two
		// loss-priorities of one class are authored high-before-low so the
		// secondary key is exercised too.
		"set class-of-service rewrite-rules dscp rw forwarding-class voice loss-priority low code-point ef",
		"set class-of-service rewrite-rules dscp rw forwarding-class network-control loss-priority high code-point cs6",
		"set class-of-service rewrite-rules dscp rw forwarding-class network-control loss-priority low code-point cs7",
		"set class-of-service rewrite-rules dscp rw forwarding-class best-effort loss-priority low code-point be",
	)
	entries := cfg.ClassOfService.DSCPRewriteRules["rw"].Entries
	if len(entries) != 4 || entries[0].ForwardingClass != "voice" {
		t.Fatalf("fixture does not reach the renderer in non-sorted config order: %+v; "+
			"the ordering assertion below would be vacuous", entries)
	}

	out := FormatCoSRewriteRules(cfg, "rw", "")
	// Sorted by forwarding class, then loss priority.
	want := []string{
		"best-effort/low", "network-control/high", "network-control/low", "voice/low",
	}
	got := codePointRowKeys6858(out)
	if len(got) != len(want) {
		t.Fatalf("expected %d code-point rows, parsed %d (%v):\n%s", len(want), len(got), got, out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("code-point rows must render sorted by forwarding class then loss "+
				"priority; got %v, want %v:\n%s", got, want, out)
		}
	}
}

// codePointRowKeys6858 returns "<forwarding-class>/<loss-priority>" for each
// rendered code-point row, in render order. Parsing fields rather than matching
// padded substrings keeps the assertion about ORDER and not about the column
// widths tabwriter happens to choose.
func codePointRowKeys6858(out string) []string {
	var keys []string
	inTable := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "Forwarding" && fields[1] == "class" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if len(fields) != 3 {
			inTable = false
			continue
		}
		keys = append(keys, fields[0]+"/"+fields[1])
	}
	return keys
}

// assertRenderOrder6858 checks that each marker appears in out, and in the
// given order. Membership alone is what the pre-#6858 assertions checked, and
// membership is exactly what an ordering sort does not affect.
func assertRenderOrder6858(t *testing.T, out, prefix string, markers []string, why string) {
	t.Helper()
	prev := -1
	for _, m := range markers {
		idx := strings.Index(out, prefix+m)
		if idx < 0 {
			t.Fatalf("%s: %q missing from output:\n%s", why, prefix+m, out)
		}
		if idx < prev {
			t.Errorf("%s: %q renders out of order:\n%s", why, prefix+m, out)
		}
		prev = idx
	}
}

// TestFormatCoSRewriteRulesEmptyNamedRuleIsNotEnforced6858 binds the
// `unit.DSCPRewriteRule == ""` guard in cosBoundDSCPRewriteRules.
//
// Reachability, measured rather than assumed:
//   - `set class-of-service rewrite-rules dscp ""` COMMITS and reads back as a
//     rule keyed "" (verified through the real configstore commit path).
//   - a unit that carries any OTHER CoS binding — a classifier here — exists
//     with DSCPRewriteRule == "". That is the ordinary case, not an exotic one.
//
// So without the guard the empty string enters the bound set and the
// empty-named rule reports "Enforced: yes" while nothing references it — the
// same confidently-wrong answer the unbound pin exists to prevent.
//
// FAIL-ON-REVERT: drop `|| unit.DSCPRewriteRule == ""` from the continue
// condition in cosBoundDSCPRewriteRules -> the header reports Enforced: yes.
func TestFormatCoSRewriteRulesEmptyNamedRuleIsNotEnforced6858(t *testing.T) {
	cfg := compileCoSRewriteSet6858(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers dscp c1 forwarding-class best-effort loss-priority low code-points 0",
		`set class-of-service rewrite-rules dscp "" forwarding-class best-effort loss-priority low code-point be`,
		// A unit with a classifier binding and NO dscp rewrite-rule binding, so
		// unit.DSCPRewriteRule is "".
		"set class-of-service interfaces ge-0-0-1 unit 0 classifiers dscp c1",
	)
	if _, ok := cfg.ClassOfService.DSCPRewriteRules[""]; !ok {
		t.Fatalf("fixture precondition: an empty-named dscp rewrite rule must reach the "+
			"compiled config, got keys %v", cfg.ClassOfService.DSCPRewriteRules)
	}
	sawEmptyBinding := false
	for _, iface := range cfg.ClassOfService.Interfaces {
		if iface == nil {
			continue
		}
		for _, u := range iface.Units {
			if u != nil && u.DSCPRewriteRule == "" {
				sawEmptyBinding = true
			}
		}
	}
	if !sawEmptyBinding {
		t.Fatal("fixture precondition: a unit with an empty DSCPRewriteRule must exist, " +
			"or the guard under test is never reached")
	}

	line := ruleHeaderLine(t, FormatCoSRewriteRules(cfg, "", "dscp"), "")
	if strings.Contains(line, "Enforced: yes") {
		t.Errorf("an empty-named dscp rewrite rule reported as enforced. No unit "+
			"references it; the unit's EMPTY rewrite-rule field is the absence of a "+
			"binding, not a binding to the empty-named rule:\n%s", line)
	}
	if !strings.Contains(line, "not bound") {
		t.Errorf("the empty-named rule must report as unbound:\n%s", line)
	}
}
