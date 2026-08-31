package config

import (
	"fmt"
	"strings"
)

// #6539: the `security flow tcp-session <kind>-timeout` leaves, and whether
// each one actually reaches the userspace AF_XDP dataplane.
//
// MECHANISM. buildFlowSnapshot (pkg/dataplane/userspace/flow.go) lowers a set
// value into FlowSnapshot and the helper reads it back into SessionTimeouts
// (userspace-dp/src/session/mod.rs). A leaf with no wire carrier, or with a
// carrier but no live consumer on the far side, is committed and stored and
// goes no further. The failure mode that motivated this file is that such a
// leaf is INDISTINGUISHABLE on a `show` surface from one that works: before
// #6539 all three operator surfaces printed every leaf in the same shape, so a
// deliberate hardening action looked applied while doing nothing. That is worse
// than a plainly unimplemented feature, because the surface an operator checks
// AFTER committing confirms the false belief.
//
// The table below is the SINGLE authority for which leaves are enforced. The
// commit-time advisory (compiler_validate_warn.go, the #2078 accepted-only
// doctrine) and all three render surfaces read it, so an operator cannot be
// told one thing at commit and a different thing by `show`. Three surfaces
// disagreeing about whether a knob is enforced is always a bug and never a
// legitimate divergence, so they share one authority rather than each carrying
// a copy of the wording.
//
// Do not restate the table's contents in prose anywhere, including here. The
// enforced/unenforced split changed once already (#7342) and every sentence
// that had restated it — a file header, a type doc, three field comments, and
// a function doc that ended up contradicting the switch four lines below it —
// silently became false. Nothing binds prose to a table, and nothing cheaply
// can; one statement of the fact is the fix.

// Junos leaf names under `security flow tcp-session`. Callers key the
// enforcement table by these rather than by a bare string literal.
const (
	TCPSessionEstablishedTimeoutLeaf = "established-timeout"
	TCPSessionInitialTimeoutLeaf     = "initial-timeout"
	TCPSessionClosingTimeoutLeaf     = "closing-timeout"
	TCPSessionTimeWaitTimeoutLeaf    = "time-wait-timeout"
)

// Fixed session windows the three unenforced leaves would have controlled.
// These MIRROR userspace-dp/src/session/mod.rs, which is the source of truth:
//
//	DEFAULT_TCP_OPENING_TIMEOUT_NS = 20_000_000_000  // half-open / OPENING
//	TCP_CLOSING_TIMEOUT_NS         = 30_000_000_000  // graceful FIN close
//	TCP_RST_TIMEOUT_NS             =  2_000_000_000  // RST abort
//
// They are quoted in operator-facing text, so flow_tcp_timeouts_6539_test.go
// re-reads the Rust constants and fails if either side drifts — otherwise the
// annotation added here to stop one false claim would quietly become another.
const (
	DataplaneTCPEstablishedWindowSecs = 300
	DataplaneTCPOpeningWindowSecs     = 20
	DataplaneTCPClosingWindowSecs     = 30
	DataplaneTCPRSTWindowSecs         = 2
)

// TCPSessionTimeoutDataplaneDefault returns the window the dataplane actually
// applies for leaf when the operator has NOT set it, and whether such a window
// exists at all.
//
// It exists because "default" on a `show` surface is itself an enforcement
// claim, and the CLI's were wrong in the same way the missing annotation was:
// it printed established-timeout's Junos default of 1800s, but nothing in the
// Go path ever fills that in — an unset leaf lowers as 0 and the helper falls
// back to its own constant, so the session actually idles out at 300s. Report
// the DATAPLANE's fallback here, never the Junos book value.
//
// The second return distinguishes "this leaf has no window to report" from a
// zero-valued one. Which leaves those are is the switch below; it is not
// restated in this comment.
func TCPSessionTimeoutDataplaneDefault(leaf string) (int, bool) {
	switch leaf {
	case TCPSessionEstablishedTimeoutLeaf:
		return DataplaneTCPEstablishedWindowSecs, true
	case TCPSessionInitialTimeoutLeaf:
		return DataplaneTCPOpeningWindowSecs, true
	case TCPSessionClosingTimeoutLeaf:
		return DataplaneTCPClosingWindowSecs, true
	case TCPSessionTimeWaitTimeoutLeaf:
		// #7342: TIME_WAIT now exists as a distinct state, so it has a default
		// window to report. It is the same value as closing-timeout's, and
		// deliberately so: an operator who sets neither leaf must see exactly
		// the reaping they saw before the state was split, and before #7342
		// every post-FIN close — half or fully closed — reaped on this one
		// window.
		return DataplaneTCPClosingWindowSecs, true
	default:
		return 0, false
	}
}

// TCPSessionTimeoutEnforcement describes whether one `security flow
// tcp-session` timeout leaf reaches the userspace AF_XDP dataplane.
type TCPSessionTimeoutEnforcement struct {
	// Leaf is the Junos leaf name, e.g. "initial-timeout".
	Leaf string
	// Enforced is true only when the value has BOTH a wire carrier and a live
	// dataplane consumer. A leaf that is merely modeled and committed is not
	// enforced, however faithfully it round-trips through the config store.
	Enforced bool
	// Note is the suffix a `show` surface renders beside a configured value.
	// Empty when Enforced. It names the SPECIFIC consequence rather than a
	// generic "no effect" (the #5804 rule): an operator who set the knob needs
	// to know which window is actually in force, not merely that theirs is not.
	Note string
}

// tcpSessionTimeoutEnforcement is the table itself, in Junos config order.
// #7342: all four are enforced. The three that were not each needed a
// different thing, and the order matters for why this is one change:
//
//   - initial-timeout and closing-timeout needed only a wire carrier — they map
//     1:1 onto windows the dataplane already had (`tcp_opening_ns`, and the
//     post-FIN window);
//   - time-wait-timeout needed a STATE first. `session_timeout_ns` split a TCP
//     close only into RST and not-RST, so there was no TIME_WAIT window
//     distinct from closing-timeout's, and a carrier would have had nothing to
//     drive. `SessionEntry` now tracks a FIN per DIRECTION, so a close with a
//     FIN in both is TIME_WAIT and a close with one is CLOSING.
//
// Carrying all three behind one additive wire bump is why this is one protocol
// change, one cluster smoke and one release note rather than three.
var tcpSessionTimeoutEnforcement = []TCPSessionTimeoutEnforcement{
	{Leaf: TCPSessionEstablishedTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionInitialTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionClosingTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionTimeWaitTimeoutLeaf, Enforced: true},
}

// TCPSessionTimeoutLeaves returns the enforcement table in Junos config order.
func TCPSessionTimeoutLeaves() []TCPSessionTimeoutEnforcement {
	out := make([]TCPSessionTimeoutEnforcement, len(tcpSessionTimeoutEnforcement))
	copy(out, tcpSessionTimeoutEnforcement)
	return out
}

// TCPSessionTimeoutNote returns the render suffix for leaf: "" when the leaf is
// enforced (or unknown — an unknown leaf is not something a surface may
// annotate on a guess). Render surfaces call this instead of hard-coding the
// enforced/unenforced split, so a leaf that later gains a wire carrier stops
// being annotated everywhere at once.
func TCPSessionTimeoutNote(leaf string) string {
	for _, e := range tcpSessionTimeoutEnforcement {
		if e.Leaf == leaf {
			return e.Note
		}
	}
	return ""
}

// unenforcedTCPSessionTimeouts returns the configured-but-unenforced timeout
// leaves of ts, in config order. A leaf is "configured" only when positive: 0
// means unset, and warning about a knob the operator never set would train
// them to ignore the advisory.
func unenforcedTCPSessionTimeouts(ts *TCPSessionConfig) []string {
	return unenforcedTCPSessionTimeoutsIn(tcpSessionTimeoutEnforcement, ts)
}

// unenforcedTCPSessionTimeoutsIn is the body, against a caller-supplied table.
//
// #7342 made every entry in the production table `Enforced`, so the advisory
// path this feeds is now INERT — and an inert path is one whose claims nothing
// checks. It is kept rather than deleted because
// `TestTCPSessionTimeoutTableCoversSchema_6539` exists precisely so that a
// FIFTH timeout leaf added to the schema cannot render unannotated and
// unadvised; deleting the machinery would remove the thing that test protects.
// Taking the table as a parameter is what lets a test drive it with a synthetic
// unenforced leaf, so the mechanism stays proven while the production data no
// longer exercises it.
func unenforcedTCPSessionTimeoutsIn(
	table []TCPSessionTimeoutEnforcement,
	ts *TCPSessionConfig,
) []string {
	if ts == nil {
		return nil
	}
	set := map[string]int{
		TCPSessionInitialTimeoutLeaf:  ts.InitialTimeout,
		TCPSessionClosingTimeoutLeaf:  ts.ClosingTimeout,
		TCPSessionTimeWaitTimeoutLeaf: ts.TimeWaitTimeout,
	}
	var out []string
	for _, e := range table {
		if e.Enforced {
			continue
		}
		if set[e.Leaf] > 0 {
			out = append(out, e.Leaf)
		}
	}
	return out
}

// tcpSessionTimeoutAdvisory builds the commit-time advisory for the tcp-session
// timeout leaves, or "" when none of the newly-enforced three is set.
//
// #6539 shipped this saying "configured but accepted-only". #7342 made those
// three leaves live, which turns that sentence false — and leaves a sharper
// problem behind it: the population that configured one of them is exactly the
// operators who did so AFTER being told it did nothing. For them the upgrade
// silently activates a value they had no reason to keep realistic, and
// `initial-timeout` is the sharp one, since a large value turns the half-open
// window from a fixed 20s bound into a session-table pin.
//
// So the advisory is INVERTED rather than deleted: it now fires for exactly the
// same set and says the value is in force. The surface an operator checks is
// the commit they are about to run, not a release note they read last month —
// saying nothing there is the failure mode #6539 was filed to fix, pointed the
// other way.
//
// Two bounds are stated because they are what make activating defensible rather
// than merely intended, and an operator cannot check either from the config
// alone:
//
//   - an UNSET leaf stays unset. `0` means "use the dataplane default" on this
//     wire, exactly as the established / UDP / ICMP seconds already do, so this
//     changes nothing for anyone who never configured one.
//   - a zone with `screen ... syn-flood timeout` (#3527) is already bounded
//     regardless of `initial-timeout`: the per-zone override takes precedence
//     over the global window for that zone's half-opens, so the screen control
//     an operator set per zone cannot be outranked by a global default.
//
// It is deliberately NOT keyed to a magnitude. A threshold would need a
// derivation nobody has, and a warning whose bound cannot be defended is one
// operators learn to tune out — which costs the warnings that matter.
//
// TEMPORARY, and tracked so that is not merely an intention: #8129 exists to
// delete this and nothing else. Automatic retirement would need a
// release-version predicate, which is a mechanism with its own failure modes
// for a message that costs one commit-time line — so the removal gets an object
// instead, the way the UNSURFACED queue and the dead-entry-rejecting accepted
// list do.
func tcpSessionTimeoutAdvisory(ts *TCPSessionConfig) string {
	if ts == nil {
		return ""
	}
	// The three #7342 made live, in Junos config order. established-timeout is
	// excluded: it has been enforced since long before #6539, so nothing about
	// it changed and warning would be pure noise.
	var set []string
	for _, e := range []struct {
		leaf  string
		value int
	}{
		{TCPSessionInitialTimeoutLeaf, ts.InitialTimeout},
		{TCPSessionClosingTimeoutLeaf, ts.ClosingTimeout},
		{TCPSessionTimeWaitTimeoutLeaf, ts.TimeWaitTimeout},
	} {
		// Positive only: 0 is unset, and telling an operator that a knob they
		// never set is now enforced is the noise this advisory has to avoid.
		if e.value > 0 {
			set = append(set, e.leaf)
		}
	}
	if len(set) == 0 {
		return ""
	}
	// The half-open warning is the sharp one, and it is CONDITIONAL: it applies
	// only when initial-timeout is among the leaves set. Emitting it
	// unconditionally would put a leaf name in the advisory that the operator
	// did not configure — which is both confusing and the thing that turns a
	// targeted warning into a blanket one nobody reads.
	halfOpen := ""
	if ts.InitialTimeout > 0 {
		halfOpen = fmt.Sprintf(
			" A large half-open window pins handshake-incomplete sessions in the session table for that "+
				"long instead of bounding them at %ds, so it is a session-table exposure as well as a "+
				"timeout; a zone with `screen ... syn-flood timeout` (#3527) stays bounded by that "+
				"override regardless.",
			DataplaneTCPOpeningWindowSecs)
	}
	return fmt.Sprintf(
		"security flow tcp-session %s is now ENFORCED (#7342) — until this release these leaves were "+
			"accepted-only and the dataplane kept fixed windows (half-open %ds, FIN close %ds); the value "+
			"you committed now governs the session directly, so verify it is one you want in force. An "+
			"UNSET leaf is unaffected (0 = keep the dataplane default).%s",
		strings.Join(set, ", "),
		DataplaneTCPOpeningWindowSecs, DataplaneTCPClosingWindowSecs, halfOpen)
}

// AnnotateTCPSessionTimeout appends leaf's not-enforced annotation to an
// already-rendered timeout cell (e.g. "45s", or the CLI's "30s (default)"),
// and returns the cell unchanged when leaf IS enforced.
//
// The three `show security flow ...` surfaces compose their own value text —
// they use different column widths and the CLI additionally marks defaults —
// but they must not each spell the annotation themselves: a REST reader and a
// CLI reader disagreeing about whether a knob is enforced is always a bug.
// Routing every surface through this one function makes the annotation
// byte-identical everywhere and retires it from all three at once on the day
// the leaf gains a wire carrier.
func AnnotateTCPSessionTimeout(leaf, rendered string) string {
	note := TCPSessionTimeoutNote(leaf)
	if note == "" {
		return rendered
	}
	return rendered + " (" + note + ")"
}
