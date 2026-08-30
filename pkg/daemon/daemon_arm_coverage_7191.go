package daemon

import (
	"fmt"
	"log/slog"
)

// #7191: make the arm-coverage proof GATE instead of only logging.
//
// THE HOLE THIS CLOSES. Daemon.dataplaneArmed tracks the rt.Start() /
// LoadUserspaceShim boundary and nothing after it. The per-interface AF_XDP
// attach happens later, inside the first ApplyConfig, and its failure modes do
// not reach the arm state at all:
//
//   - a NATIVE attach failure is a slog.Warn and the loop CONTINUES
//     (attachUserspaceShimXDP), falling back to generic;
//   - even a GENERIC failure, which does return an error, is joined as a
//     deferred commit error rather than an abort, and never touches
//     dataplaneArmed.
//
// So a box where Start succeeded but an interface never got a shim reported
// itself ARMED and kept ip_forward=1 with nothing adjudicating that interface's
// transit. Measured on a live node while writing this: ip_forward=1 and
// `nft list ruleset | grep -c "hook forward"` == 0, so the per-interface XDP
// program was the only adjudication there was.
//
// ONE SOURCE. The verdict feeds the SAME markDataplaneArmFailed path that a
// Start failure uses, so there is exactly one notion of "armed" and one set of
// side effects (sysctls, #7191 barrier, #7178 RG weight). This deliberately
// does NOT introduce a second arm flag.
//
// THE GATE IS ONE-WAY: it can only DISARM. Coverage returning to full does not
// re-arm the box, because arming is owned by the Start boundary and re-arming
// from a diagnostic would be exactly the second, independently-derived notion
// of armed the issue forbids. That matches the existing posture — pkg/daemon
// README records that there is no re-arm path after a boot arm failure either;
// the node stays transit-closed until a restart.
//
// KNOWN SHARP EDGE, recorded rather than hidden. ProveArmCoverage's coverDirect
// collapses "no tracked link" and "the link's identity could not be read" into
// the same uncovered verdict ("no shim instance attached"), because its lookup
// returns not-ok for both. This gate therefore treats a readback failure as an
// attach failure. That is the conservative direction and matches the proof's
// own stated stance ("a tracked link whose identity cannot be read is NOT proof
// of coverage"), but it means a readback fault disarms a box whose shim is
// actually attached. Distinguishing them belongs in coverDirect, not here —
// splitting the verdict at the consumer would put the classification in two
// places.

// armCoverageSource is the narrow optional capability the gate needs. It is a
// type assertion rather than a method on RuntimeDataPlane so the broad runtime
// interface (and every fake implementing it) is untouched; a runtime that does
// not provide coverage simply is not gated.
// It returns PRIMITIVES rather than the dataplane report type so this file does
// not import pkg/dataplane at all — the #1451 retirement-boundary allowlist
// exists to shrink, and adding an entry for a four-number verdict would be the
// wrong direction.
type armCoverageSource interface {
	ArmCoverageSummary() (uncovered, total int, ran, seen bool)
}

// armCoverageVerdict is the three-state classification of a coverage report.
type armCoverageVerdict int

const (
	// armCoverageUnknown: no proof has run, the runtime does not publish one,
	// or the proof could not classify. NOT evidence of a hole — gating here
	// would disarm every box before its first apply, a brick not a fence.
	armCoverageUnknown armCoverageVerdict = iota
	// armCoverageComplete: a proof ran and every required surface is covered.
	armCoverageComplete
	// armCoverageIncomplete: a proof ran and at least one surface is uncovered.
	armCoverageIncomplete
)

// classifyArmCoverage maps a report to the gate's verdict. Split out so the
// three-state logic is testable without a daemon or a kernel.
func classifyArmCoverageVerdict(uncovered int, ran, seen bool) armCoverageVerdict {
	switch {
	case !seen || !ran:
		return armCoverageUnknown
	case uncovered > 0:
		return armCoverageIncomplete
	default:
		return armCoverageComplete
	}
}

// evaluateArmCoverage consults the post-attach proof and disarms if any surface
// is uncovered. Called from the apply tail, after ApplyConfig has run the
// attach, so the proof it reads describes the attachment that just happened.
func (d *Daemon) evaluateArmCoverage(stage string) {
	if !d.DataplaneArmed() {
		// Already closed. Re-disarming would emit a duplicate Error line on
		// every commit for a box that is already in the posture.
		return
	}
	src, ok := d.dataplane().(armCoverageSource)
	if !ok {
		return
	}
	uncovered, total, ran, seen := src.ArmCoverageSummary()
	switch classifyArmCoverageVerdict(uncovered, ran, seen) {
	case armCoverageIncomplete:
		d.markDataplaneArmFailed(stage,
			"an interface has no XDP shim attached, so nothing adjudicates its transit; "+
				"check the attach warnings in the log, then restart xpfd once the interface is present",
			fmt.Errorf("arm coverage incomplete: %d of %d surface(s) uncovered", uncovered, total))
	case armCoverageComplete:
		slog.Debug("arm coverage complete", "stage", stage, "surfaces", total)
	}
}
