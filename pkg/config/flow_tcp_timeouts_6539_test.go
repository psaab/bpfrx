package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6539 recorded that `security flow tcp-session
// initial/closing/time-wait-timeout` were modeled, parsed and committable but
// had NO dataplane wire carrier, while REST, CLI and gRPC printed them in the
// same shape as the one leaf that IS carried. #7342 carried all three and made
// them live, so the half of these tests that pinned "not enforced" now pins the
// opposite — that is the fix landing, not a guard being loosened.
//
// What did NOT change is the reason the file exists: the enforcement table is
// the single authority the advisory and all three render surfaces read, it must
// stay in agreement with the schema, and its operator-facing text must keep
// quoting the Rust constants it claims to. Those cells are untouched, and the
// advisory MECHANISM is still exercised — against a synthetic table — because
// it is what a fifth timeout leaf would fall into.

// findTCPSessionEnforcementAdvisory returns the #7342 "now ENFORCED" advisory,
// or "". Keyed on the issue number so it cannot collide with the sibling #2078
// presence-flag advisory, which shares the leading substrings.
func findTCPSessionEnforcementAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "now ENFORCED") &&
			strings.Contains(w, "#7342") {
			return w
		}
	}
	return ""
}

// findTCPSessionTimeoutAdvisory returns the OLD #6539 accepted-only advisory,
// which must no longer exist. Kept as its own finder rather than folded into
// the one above: an inverted advisory has to be checked in both directions, and
// a single finder keyed on the new text would report the old one absent whether
// it was deleted or merely reworded past the match.
func findTCPSessionTimeoutAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "accepted-only") &&
			strings.Contains(w, "#6539") {
			return w
		}
	}
	return ""
}

// #7342 inverted the advisory: each newly-enforced leaf, set alone, must
// produce the "now ENFORCED" warning AND name that specific leaf, while the old
// accepted-only text must be gone.
//
// Both directions matter. Asserting only the new text would pass if the old one
// were still emitted alongside it, which is the state an incomplete inversion
// leaves behind — two warnings telling the operator opposite things about the
// same leaf.
func TestTCPSessionEnforcementAdvisory_PerLeaf_7342(t *testing.T) {
	for _, leaf := range []string{
		TCPSessionInitialTimeoutLeaf,
		TCPSessionClosingTimeoutLeaf,
		TCPSessionTimeWaitTimeoutLeaf,
	} {
		t.Run(leaf, func(t *testing.T) {
			cfg := compileSetLines(t, []string{"set security flow tcp-session " + leaf + " 45"})
			if cfg.Security.Flow.TCPSession == nil {
				t.Fatalf("%s did not compile into TCPSession; the assertions below are vacuous", leaf)
			}
			adv := findTCPSessionEnforcementAdvisory(cfg)
			if adv == "" {
				t.Fatalf("%s did not emit the #7342 enforcement advisory; warnings=%v", leaf, cfg.Warnings)
			}
			if !strings.Contains(adv, leaf) {
				t.Fatalf("#7342 advisory does not name leaf %q: %q", leaf, adv)
			}
			// Only the leaf that was set. Without this the assertion above
			// would pass on an advisory that blanket-lists all three whatever
			// the operator configured — which is the shape that trains people
			// to ignore it.
			for _, other := range []string{
				TCPSessionInitialTimeoutLeaf,
				TCPSessionClosingTimeoutLeaf,
				TCPSessionTimeWaitTimeoutLeaf,
			} {
				if other != leaf && strings.Contains(adv, other) {
					t.Fatalf("advisory for %q wrongly also names %q: %q", leaf, other, adv)
				}
			}
			if old := findTCPSessionTimeoutAdvisory(cfg); old != "" {
				t.Fatalf("the old #6539 accepted-only advisory is still emitted for %s: %q", leaf, old)
			}
		})
	}
}

// established-timeout has been enforced since long before #6539, so nothing
// about it changed and it must produce NO advisory of either kind. This is the
// cell that fails if the inversion is "simplified" to fire on any tcp-session
// timeout.
func TestTCPSessionEnforcementAdvisory_EstablishedNotWarned_7342(t *testing.T) {
	cfg := compileSetLines(t, []string{"set security flow tcp-session established-timeout 600"})
	if cfg.Security.Flow.TCPSession == nil ||
		cfg.Security.Flow.TCPSession.EstablishedTimeout != 600 {
		t.Fatalf("established-timeout did not compile; the assertions below are vacuous")
	}
	if adv := findTCPSessionEnforcementAdvisory(cfg); adv != "" {
		t.Fatalf("established-timeout did not change with #7342 and must not warn: %q", adv)
	}
	if adv := findTCPSessionTimeoutAdvisory(cfg); adv != "" {
		t.Fatalf("established-timeout must not carry the old advisory either: %q", adv)
	}
}

// A config that sets NONE of them stays silent. Without this the per-leaf cells
// would pass an advisory that fires on every commit.
func TestTCPSessionEnforcementAdvisory_SilentWhenUnset_7342(t *testing.T) {
	quiet := compileSetLines(t, []string{"set security zones security-zone trust"})
	if adv := findTCPSessionEnforcementAdvisory(quiet); adv != "" {
		t.Fatalf("unexpected #7342 advisory with no tcp-session stanza: %q", adv)
	}
	// A tcp-session stanza carrying ONLY the leaf that did not change is also
	// silent — proving the gate is the three newly-enforced leaves and not the
	// presence of the stanza.
	est := compileSetLines(t, []string{"set security flow tcp-session established-timeout 600"})
	if adv := findTCPSessionEnforcementAdvisory(est); adv != "" {
		t.Fatalf("established-timeout alone must not raise the #7342 advisory: %q", adv)
	}
}

// The advisory states the two bounds that make activating a previously-inert
// value defensible, and an operator cannot check either from the config alone:
// an unset leaf is unaffected, and a zone with syn-flood is already bounded.
// A warning that says "this is now live" without them tells an operator to
// worry without telling them what limits the exposure.
func TestTCPSessionEnforcementAdvisory_StatesItsBounds_7342(t *testing.T) {
	cfg := compileSetLines(t, []string{"set security flow tcp-session initial-timeout 3600"})
	adv := findTCPSessionEnforcementAdvisory(cfg)
	if adv == "" {
		t.Fatal("no #7342 advisory to check the reasoning of")
	}
	for _, want := range []string{
		"UNSET",         // 0 keeps the dataplane default
		"syn-flood",     // the per-zone #3527 override still bounds that zone
		"session table", // what a large initial-timeout actually costs
	} {
		if !strings.Contains(adv, want) {
			t.Errorf("advisory omits %q, so it warns without saying what limits the exposure: %q",
				want, adv)
		}
	}

	// The half-open reasoning is CONDITIONAL on initial-timeout being the leaf
	// set. Without this the clause could be unconditional, which would put an
	// exposure in front of an operator who did not configure the knob that
	// causes it — and would make the "names only what was set" property above
	// impossible to hold.
	other := compileSetLines(t, []string{"set security flow tcp-session closing-timeout 15"})
	otherAdv := findTCPSessionEnforcementAdvisory(other)
	if otherAdv == "" {
		t.Fatal("no advisory for closing-timeout alone")
	}
	for _, unwanted := range []string{"session table", "syn-flood", "half-open window"} {
		if strings.Contains(otherAdv, unwanted) {
			t.Errorf("closing-timeout's advisory carries the half-open reasoning %q, which is "+
				"about a knob the operator did not set: %q", unwanted, otherAdv)
		}
	}
}

// The advisory MECHANISM must still work, because it is what a fifth timeout
// leaf would fall into. #7342 left the production table with nothing
// unenforced, so this drives the body against a SYNTHETIC table — otherwise the
// path is inert code whose claims nothing checks, and it would rot until the
// next leaf silently reproduced #6539.
func TestTCPSessionTimeoutAdvisoryMechanismStillWorks_7342(t *testing.T) {
	synthetic := []TCPSessionTimeoutEnforcement{
		{Leaf: TCPSessionEstablishedTimeoutLeaf, Enforced: true},
		{Leaf: TCPSessionInitialTimeoutLeaf, Note: "synthetic"},
		{Leaf: TCPSessionClosingTimeoutLeaf, Enforced: true},
		{Leaf: TCPSessionTimeWaitTimeoutLeaf, Note: "synthetic"},
	}
	ts := &TCPSessionConfig{
		EstablishedTimeout: 600,
		InitialTimeout:     45,
		ClosingTimeout:     15,
		// TimeWaitTimeout deliberately UNSET: the helper reports only leaves the
		// operator actually configured, and a version that reported every
		// unenforced leaf regardless would pass a fixture that set them all.
	}
	got := unenforcedTCPSessionTimeoutsIn(synthetic, ts)
	want := []string{TCPSessionInitialTimeoutLeaf}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unenforcedTCPSessionTimeoutsIn = %v, want %v — the advisory body no longer "+
			"selects configured-AND-unenforced leaves, so a fifth leaf would render unannotated",
			got, want)
	}
	// And the production table selects nothing, which is what makes the
	// production advisory silent rather than merely unreached.
	if live := unenforcedTCPSessionTimeouts(ts); len(live) != 0 {
		t.Fatalf("production table still reports unenforced leaves %v after #7342", live)
	}
}

// established-timeout IS carried to the dataplane, so it must NOT be warned
// about. This is the cell that fails if someone "simplifies" the advisory to
// fire on any tcp-session timeout.
func TestTCPSessionTimeoutAdvisory_EstablishedNotWarned_6539(t *testing.T) {
	cfg := compileSetLines(t, []string{"set security flow tcp-session established-timeout 600"})
	if cfg.Security.Flow.TCPSession == nil {
		t.Fatal("TCPSession is nil; established-timeout did not compile")
	}
	if cfg.Security.Flow.TCPSession.EstablishedTimeout != 600 {
		t.Fatalf("EstablishedTimeout = %d, want 600", cfg.Security.Flow.TCPSession.EstablishedTimeout)
	}
	if adv := findTCPSessionTimeoutAdvisory(cfg); adv != "" {
		t.Fatalf("established-timeout is wire-carried and must not warn; got %q", adv)
	}
}

// All three set together fold into ONE advisory naming all three — not three
// warnings, which is what an operator learns to skip past.
func TestTCPSessionEnforcementAdvisory_FoldsToOne_7342(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})
	if ts := cfg.Security.Flow.TCPSession; ts == nil ||
		ts.InitialTimeout != 45 || ts.ClosingTimeout != 15 || ts.TimeWaitTimeout != 90 {
		t.Fatalf("the three leaves did not compile as set (%+v); the assertions below are vacuous",
			cfg.Security.Flow.TCPSession)
	}
	count := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#7342") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one folded #7342 advisory, got %d; warnings=%v", count, cfg.Warnings)
	}
	adv := findTCPSessionEnforcementAdvisory(cfg)
	for _, leaf := range []string{
		TCPSessionInitialTimeoutLeaf, TCPSessionClosingTimeoutLeaf, TCPSessionTimeWaitTimeoutLeaf,
	} {
		if !strings.Contains(adv, leaf) {
			t.Fatalf("folded advisory missing %q: %q", leaf, adv)
		}
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#6539") {
			t.Fatalf("a #6539 accepted-only advisory survived #7342: %q", w)
		}
	}
}

// The enforcement table must cover EVERY value-bearing `<kind>-timeout` leaf
// the set-schema declares under tcp-session. Without this, adding a fifth
// timeout leaf to the schema would render it through the surfaces with no
// annotation and no advisory — silently reproducing #6539 for the new leaf.
func TestTCPSessionTimeoutTableCoversSchema_6539(t *testing.T) {
	node := setSchema
	for _, key := range []string{"security", "flow", "tcp-session"} {
		next, ok := node.children[key]
		if !ok {
			t.Fatalf("set-schema path %q not found (schema moved?)", key)
		}
		node = next
	}

	covered := map[string]bool{}
	for _, e := range TCPSessionTimeoutLeaves() {
		covered[e.Leaf] = true
	}

	found := 0
	for leaf, child := range node.children {
		if !strings.HasSuffix(leaf, "-timeout") {
			continue // presence flags — the #2078 advisory owns those
		}
		found++
		if child.args != 1 {
			t.Errorf("schema leaf %q takes %d args, want 1 (not a value leaf?)", leaf, child.args)
		}
		if !covered[leaf] {
			t.Errorf("schema declares tcp-session %q but the #6539 enforcement table does not cover it — "+
				"it would render with no enforcement annotation and no commit advisory", leaf)
		}
	}
	if found != len(covered) {
		t.Errorf("schema declares %d tcp-session *-timeout leaves, table covers %d", found, len(covered))
	}
	if found == 0 {
		t.Fatal("found no tcp-session *-timeout leaves in the schema — the walk is vacuous")
	}
}

// #7342: EVERY tcp-session timeout leaf is enforced, so none may carry a
// render annotation and every one must render its value unannotated.
//
// The invariant this really pins is the two-way agreement — enforced implies no
// note, unenforced implies a note AND an annotated cell — which is what keeps
// the three surfaces from disagreeing with the advisory. #7342 changes which
// side of it each leaf sits on, not the invariant.
func TestTCPSessionTimeoutTableEnforcedSet_7342(t *testing.T) {
	var enforced []string
	for _, e := range TCPSessionTimeoutLeaves() {
		if e.Enforced {
			enforced = append(enforced, e.Leaf)
			if e.Note != "" {
				t.Errorf("leaf %q is enforced but still carries a not-enforced note %q", e.Leaf, e.Note)
			}
			continue
		}
		if e.Note == "" {
			t.Errorf("leaf %q is unenforced but carries no render annotation", e.Leaf)
		}
		if got := AnnotateTCPSessionTimeout(e.Leaf, "45s"); got == "45s" {
			t.Errorf("AnnotateTCPSessionTimeout(%q) left the cell unannotated: %q", e.Leaf, got)
		}
	}
	want := []string{
		TCPSessionEstablishedTimeoutLeaf,
		TCPSessionInitialTimeoutLeaf,
		TCPSessionClosingTimeoutLeaf,
		TCPSessionTimeWaitTimeoutLeaf,
	}
	if len(enforced) != len(want) {
		t.Fatalf("enforced leaves = %v, want all four %v", enforced, want)
	}
	for i, leaf := range want {
		if enforced[i] != leaf {
			t.Fatalf("enforced leaves = %v, want %v (Junos config order)", enforced, want)
		}
		if got := AnnotateTCPSessionTimeout(leaf, "600s"); got != "600s" {
			t.Fatalf("%s is enforced and must render unannotated, got %q", leaf, got)
		}
	}
}

// The advisory and the render annotations quote fixed windows that live in
// userspace-dp/src/session/mod.rs. Go cannot import a Rust constant, so read
// the Rust source and fail if either side drifts — otherwise the text added
// here to retire one false claim quietly becomes another.
func TestTCPSessionTimeoutWindowsMatchRust_6539(t *testing.T) {
	const rustPath = "../../userspace-dp/src/session/mod.rs"
	src, err := os.ReadFile(rustPath)
	if err != nil {
		t.Fatalf("read %s: %v", rustPath, err)
	}

	// The Rust constants are nanoseconds; the Go constants are seconds.
	want := map[string]int{
		"DEFAULT_TCP_SESSION_TIMEOUT_NS": DataplaneTCPEstablishedWindowSecs,
		"DEFAULT_TCP_OPENING_TIMEOUT_NS": DataplaneTCPOpeningWindowSecs,
		"TCP_CLOSING_TIMEOUT_NS":         DataplaneTCPClosingWindowSecs,
		"TCP_RST_TIMEOUT_NS":             DataplaneTCPRSTWindowSecs,
	}
	for name, wantSecs := range want {
		re := regexp.MustCompile(`(?m)^const ` + name + `: u64 = ([0-9_]+);`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Errorf("constant %s not found in %s (renamed or moved?)", name, rustPath)
			continue
		}
		ns, err := strconv.ParseUint(strings.ReplaceAll(string(m[1]), "_", ""), 10, 64)
		if err != nil {
			t.Errorf("%s: parse %q: %v", name, m[1], err)
			continue
		}
		if gotSecs := int(ns / 1_000_000_000); gotSecs != wantSecs {
			t.Errorf("%s = %ds in Rust, but the Go operator-facing text says %ds — "+
				"the #6539 advisory and `show` annotations now quote a window the dataplane does not use",
				name, gotSecs, wantSecs)
		}
	}
}

// TCPSessionTimeoutDataplaneDefault must report a window for all four leaves.
//
// #6539 returned nothing for time-wait because the dataplane had no TIME_WAIT
// state, and printing "(default)" for it would have been the same unbacked
// enforcement claim that issue was about. #7342 gave it a state, so it has a
// window — and that window is deliberately the SAME as closing-timeout's,
// because before the state was split every post-FIN close reaped on that one
// window and an operator who sets neither leaf must see no change.
func TestTCPSessionTimeoutDataplaneDefault_7342(t *testing.T) {
	cases := []struct {
		leaf     string
		wantSecs int
		wantOK   bool
	}{
		{TCPSessionEstablishedTimeoutLeaf, DataplaneTCPEstablishedWindowSecs, true},
		{TCPSessionInitialTimeoutLeaf, DataplaneTCPOpeningWindowSecs, true},
		{TCPSessionClosingTimeoutLeaf, DataplaneTCPClosingWindowSecs, true},
		{TCPSessionTimeWaitTimeoutLeaf, DataplaneTCPClosingWindowSecs, true},
	}
	for _, tc := range cases {
		got, ok := TCPSessionTimeoutDataplaneDefault(tc.leaf)
		if ok != tc.wantOK || got != tc.wantSecs {
			t.Errorf("TCPSessionTimeoutDataplaneDefault(%q) = (%d, %v), want (%d, %v)",
				tc.leaf, got, ok, tc.wantSecs, tc.wantOK)
		}
	}
	// The established default must NOT be the Junos 1800 the CLI used to
	// print: nothing in the Go path fills that in, so the helper's own
	// fallback is what an unset leaf actually gets.
	if DataplaneTCPEstablishedWindowSecs == 1800 {
		t.Fatal("established default is 1800 — that is the Junos default, not this dataplane's fallback")
	}
}
