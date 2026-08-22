package config

import (
	"fmt"
	"strings"
)

// #6539: of the four `security flow tcp-session <kind>-timeout` leaves, only
// established-timeout actually reaches the dataplane.
//
// buildFlowSnapshot (pkg/dataplane/userspace/flow.go) lowers EstablishedTimeout
// into FlowSnapshot.TCPSessionTimeout and the helper reads it back into
// SessionTimeouts.tcp_established_ns. The other three are parsed, typed,
// committed and stored in TCPSessionConfig and stop there: the wire struct
// (pkg/dataplane/userspace/protocol.go) has no field for them and there is no
// live consumer on either side. Before #6539 all three operator surfaces —
// REST, CLI, gRPC — printed them in exactly the same shape as the enforced
// one, so a deliberate hardening action (initial-timeout is the half-open /
// SYN-flood bounding control) looked applied while doing nothing. That is
// worse than a plainly unimplemented feature, because the surface an operator
// checks AFTER committing confirms the false belief.
//
// This table is the SINGLE authority for that fact. The commit-time advisory
// (compiler_validate_warn.go, the #2078 accepted-only doctrine) and all three
// render surfaces read it, so an operator cannot be told one thing at commit
// and a different thing by `show`. Three surfaces disagreeing about whether a
// knob is enforced is always a bug and never a legitimate divergence, so they
// share one authority rather than each carrying a copy of the wording.

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
// back to DEFAULT_TCP_SESSION_TIMEOUT_NS, so the session actually idles out at
// 300s. time-wait-timeout returns false: the dataplane has no TIME_WAIT state,
// so there is no window to report as its default (a graceful close reaps on
// the FIN window, which is closing-timeout's).
func TCPSessionTimeoutDataplaneDefault(leaf string) (int, bool) {
	switch leaf {
	case TCPSessionEstablishedTimeoutLeaf:
		return DataplaneTCPEstablishedWindowSecs, true
	case TCPSessionInitialTimeoutLeaf:
		return DataplaneTCPOpeningWindowSecs, true
	case TCPSessionClosingTimeoutLeaf:
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
var tcpSessionTimeoutEnforcement = []TCPSessionTimeoutEnforcement{
	{Leaf: TCPSessionEstablishedTimeoutLeaf, Enforced: true},
	{
		Leaf: TCPSessionInitialTimeoutLeaf,
		Note: fmt.Sprintf("not enforced — dataplane reaps half-open sessions on a fixed %ds window",
			DataplaneTCPOpeningWindowSecs),
	},
	{
		Leaf: TCPSessionClosingTimeoutLeaf,
		Note: fmt.Sprintf("not enforced — dataplane reaps a FIN close on a fixed %ds window",
			DataplaneTCPClosingWindowSecs),
	},
	{
		Leaf: TCPSessionTimeWaitTimeoutLeaf,
		Note: "not enforced — dataplane has no TIME_WAIT state",
	},
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
	if ts == nil {
		return nil
	}
	set := map[string]int{
		TCPSessionInitialTimeoutLeaf:  ts.InitialTimeout,
		TCPSessionClosingTimeoutLeaf:  ts.ClosingTimeout,
		TCPSessionTimeWaitTimeoutLeaf: ts.TimeWaitTimeout,
	}
	var out []string
	for _, e := range tcpSessionTimeoutEnforcement {
		if e.Enforced {
			continue
		}
		if set[e.Leaf] > 0 {
			out = append(out, e.Leaf)
		}
	}
	return out
}

// tcpSessionTimeoutAdvisory builds the commit-time accepted-only warning for
// the configured-but-unenforced timeout leaves, or "" when none is set. It
// states which windows ARE in force and points at the one half-open control
// that an operator can actually move today, so the advisory is actionable
// rather than merely discouraging.
func tcpSessionTimeoutAdvisory(ts *TCPSessionConfig) string {
	leaves := unenforcedTCPSessionTimeouts(ts)
	if len(leaves) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"security flow tcp-session %s configured but accepted-only — these leaves have NO dataplane wire carrier "+
			"(of the four tcp-session timeouts only established-timeout is carried), so the userspace dataplane keeps "+
			"its fixed windows: a half-open/OPENING session reaps at %ds, a graceful FIN close at %ds and an RST abort "+
			"at %ds, and there is no separate TIME_WAIT state to time out. The only half-open window an operator can "+
			"move today is the per-zone `screen ... syn-flood timeout` override (#3527) (config-only parity, #6539)",
		strings.Join(leaves, ", "),
		DataplaneTCPOpeningWindowSecs, DataplaneTCPClosingWindowSecs, DataplaneTCPRSTWindowSecs)
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
