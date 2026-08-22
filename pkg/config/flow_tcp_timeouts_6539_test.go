package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6539: `security flow tcp-session initial/closing/time-wait-timeout` are
// modeled, parsed and committable but have NO dataplane wire carrier and no
// live consumer, while REST, CLI and gRPC all printed them in the same shape
// as the one leaf that IS carried. These tests bind the two halves of the fix:
// the commit-time advisory fires for exactly the unenforced leaves, and the
// enforcement table stays in agreement with the schema and with the Rust
// constants its operator-facing text quotes.

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

// Each unenforced timeout leaf, set alone, must produce the advisory AND the
// advisory must name that specific leaf — a generic catch-all would pass even
// if the leaf were silently dropped.
func TestTCPSessionTimeoutAdvisory_PerLeaf_6539(t *testing.T) {
	for _, leaf := range []string{
		TCPSessionInitialTimeoutLeaf,
		TCPSessionClosingTimeoutLeaf,
		TCPSessionTimeWaitTimeoutLeaf,
	} {
		t.Run(leaf, func(t *testing.T) {
			cfg := compileSetLines(t, []string{"set security flow tcp-session " + leaf + " 45"})
			adv := findTCPSessionTimeoutAdvisory(cfg)
			if adv == "" {
				t.Fatalf("%s did not emit the #6539 advisory; warnings=%v", leaf, cfg.Warnings)
			}
			if !strings.Contains(adv, leaf) {
				t.Fatalf("#6539 advisory does not name leaf %q: %q", leaf, adv)
			}
			// The advisory must name ONLY the leaf that was set. Without this
			// the per-leaf assertion above would pass on an advisory that
			// blanket-lists all three regardless of what the operator set.
			for _, other := range []string{
				TCPSessionInitialTimeoutLeaf,
				TCPSessionClosingTimeoutLeaf,
				TCPSessionTimeWaitTimeoutLeaf,
			} {
				if other == leaf {
					continue
				}
				// closing-timeout is not a substring of the others, and
				// time-wait-timeout / initial-timeout share no prefix, so a
				// plain Contains is an honest test here.
				if strings.Contains(adv, other) {
					t.Fatalf("advisory for %q wrongly also names %q: %q", leaf, other, adv)
				}
			}
		})
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

// All three unenforced leaves together fold into ONE advisory naming all
// three, and the advisory does not fire when none is set.
func TestTCPSessionTimeoutAdvisory_FoldsAndSilence_6539(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})
	count := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#6539") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one folded #6539 advisory, got %d; warnings=%v", count, cfg.Warnings)
	}
	adv := findTCPSessionTimeoutAdvisory(cfg)
	for _, leaf := range []string{
		TCPSessionInitialTimeoutLeaf, TCPSessionClosingTimeoutLeaf, TCPSessionTimeWaitTimeoutLeaf,
	} {
		if !strings.Contains(adv, leaf) {
			t.Fatalf("folded advisory missing %q: %q", leaf, adv)
		}
	}

	// A zone-only config must stay silent — proves the advisory is gated on
	// the leaves and not merely on compilation running.
	quiet := compileSetLines(t, []string{"set security zones security-zone trust"})
	if adv := findTCPSessionTimeoutAdvisory(quiet); adv != "" {
		t.Fatalf("unexpected #6539 advisory with no tcp-session stanza: %q", adv)
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

// Exactly one leaf may be marked enforced, and it must be established-timeout.
// This is the claim the whole fix rests on; if a future change carries another
// leaf to the wire it must flip the table here (which retires its annotation
// from all three surfaces and its line from the advisory at once).
func TestTCPSessionTimeoutTableEnforcedSet_6539(t *testing.T) {
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
	if len(enforced) != 1 || enforced[0] != TCPSessionEstablishedTimeoutLeaf {
		t.Fatalf("enforced leaves = %v, want exactly [%s]", enforced, TCPSessionEstablishedTimeoutLeaf)
	}
	if got := AnnotateTCPSessionTimeout(TCPSessionEstablishedTimeoutLeaf, "600s"); got != "600s" {
		t.Fatalf("established-timeout must render unannotated, got %q", got)
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

// TCPSessionTimeoutDataplaneDefault must report a window for the three leaves
// that have one and NONE for time-wait, whose state the dataplane does not
// model. A surface that printed "(default)" for time-wait would be making the
// same kind of unbacked enforcement claim this issue is about.
func TestTCPSessionTimeoutDataplaneDefault_6539(t *testing.T) {
	cases := []struct {
		leaf     string
		wantSecs int
		wantOK   bool
	}{
		{TCPSessionEstablishedTimeoutLeaf, DataplaneTCPEstablishedWindowSecs, true},
		{TCPSessionInitialTimeoutLeaf, DataplaneTCPOpeningWindowSecs, true},
		{TCPSessionClosingTimeoutLeaf, DataplaneTCPClosingWindowSecs, true},
		{TCPSessionTimeWaitTimeoutLeaf, 0, false},
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
