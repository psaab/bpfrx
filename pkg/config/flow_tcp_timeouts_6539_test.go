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

// findTCPSessionTimeoutAdvisory returns the #6539 timeout advisory, or "".
// It is keyed on the issue number so it can never collide with the sibling
// #2078 presence-flag advisory, which shares the leading substrings.
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

// #7342: every tcp-session timeout leaf is enforced, so setting ANY of them —
// alone or together — must produce NO accepted-only advisory.
//
// Driven per leaf rather than as one combined config so a leaf that regressed
// to unenforced is named, and driven through the real compile so it is the
// production table being read rather than a copy.
func TestTCPSessionTimeoutAdvisory_SilentWhenEnforced_7342(t *testing.T) {
	for _, leaf := range []string{
		TCPSessionEstablishedTimeoutLeaf,
		TCPSessionInitialTimeoutLeaf,
		TCPSessionClosingTimeoutLeaf,
		TCPSessionTimeWaitTimeoutLeaf,
	} {
		t.Run(leaf, func(t *testing.T) {
			cfg := compileSetLines(t, []string{"set security flow tcp-session " + leaf + " 45"})
			// Liveness first: a config that did not compile the leaf would be
			// silent for the wrong reason, and every assertion below would pass.
			if cfg.Security.Flow.TCPSession == nil {
				t.Fatalf("%s did not compile into TCPSession; the silence below is vacuous", leaf)
			}
			if adv := findTCPSessionTimeoutAdvisory(cfg); adv != "" {
				t.Fatalf("%s is enforced since #7342 but still emits the accepted-only advisory: %q",
					leaf, adv)
			}
		})
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

// All three formerly-unenforced leaves set together must produce NO advisory,
// and the compile must still be the thing under test: a zone-only config is the
// control that proves the search is not simply always finding nothing.
func TestTCPSessionTimeoutAdvisory_AllThreeSilent_7342(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})
	if ts := cfg.Security.Flow.TCPSession; ts == nil ||
		ts.InitialTimeout != 45 || ts.ClosingTimeout != 15 || ts.TimeWaitTimeout != 90 {
		t.Fatalf("the three leaves did not compile as set (%+v); the silence below is vacuous",
			cfg.Security.Flow.TCPSession)
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
