// shimverify runs the kernel BPF verifier against a userspace-xdp shim
// candidate object without touching any production state (#1864).
//
// It is the build-time gate invoked by
// pkg/dataplane/build-userspace-xdp.sh: the freshly-built candidate is
// verified BEFORE it may replace the git-tracked
// pkg/dataplane/userspace_xdp_bpfel.o. A REJECT here is a failed
// `make generate`, not a dead dataplane.
//
// Requires CAP_BPF (typically root): the check is a real
// BPF_PROG_LOAD against the running kernel — static analysis cannot
// substitute (the 2026-06-10 incident objects differed by only 7
// static instructions; the explosion was in the verifier's state
// walk).
//
// #4555 headroom floor: a binary PASS/REJECT cannot distinguish an
// object with room to grow from one a single edit away from the 1M
// processed-insn wall. Master sat at 0.92% headroom with every gate
// green until a routine change to the IPv6 extension-header walk hit
// that wall. So a candidate that LOADS but leaves less than
// dataplane.UserspaceShimMinVerifierHeadroomPct of the budget unused is
// also refused, with XPF_SHIM_ALLOW_LOW_HEADROOM=1 as the deliberate
// override (mirroring XPF_SHIM_ALLOW_UNPINNED_INSTALL in the recipe).
//
// UNMEASURABLE IS ALSO A FAILURE (exit 5). An earlier revision warned
// and passed when the kernel's log carried no recognisable stats line,
// reasoning that "cannot measure" is not "at the wall". That was wrong:
// this tripwire exists because nothing was watching while the shim crept
// to 0.92%, and a gate that switches itself off when the log format
// changes reproduces exactly that failure mode — silently, at the one
// moment headroom is unknown. A warning is invisible in an automated
// build, which is the only place this matters. It takes the SAME
// override, so a genuine kernel/log-format difference is one documented
// env var away from unblocking, but installing an unmeasured object now
// requires someone to say so.
//
// An OVERRIDDEN run gets its OWN exit code (6), never 0. Returning 0
// collapsed "measured and comfortably above the floor" into "we could not
// check, and someone had the variable exported", which a non-interactive
// caller cannot tell apart — and the recipe's `0) ;;` arm installed both
// without comment. 6 still INSTALLS (the override means the operator
// accepted the risk) but it is visible to the recipe and to CI as an exit
// code and as the `OVERRIDDEN` status word on stdout, without anyone
// parsing stderr. It is NOT recorded in
// pkg/dataplane/userspace_xdp_manifest.json: that file carries the object
// hash, the shim facts and the hashed inputs, and nothing about how the
// gate was satisfied. An object installed under an override is therefore
// indistinguishable from one that passed, ONCE THE BUILD LOG IS GONE.
//
// Exit codes: 0 PASS (measured, above the floor), 2 usage, 3 verifier
// REJECT, 4 loads but headroom below the floor, 5 loads but headroom could
// not be measured, 6 loads and INSTALLS with the gate overridden, 1 other
// error (including insufficient privileges).
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/dataplane"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shimverify <userspace_xdp_bpfel.o>")
		os.Exit(2)
	}
	path := os.Args[1]
	stats, err := dataplane.VerifyUserspaceShimObjectStats(path)
	if err != nil {
		if errors.Is(err, dataplane.ErrUserspaceShimVerifierReject) {
			fmt.Printf("REJECT %s\n%v\n", path, err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "shimverify: %s: %v\n", path, err)
		os.Exit(1)
	}

	overridden := os.Getenv(allowLowHeadroomEnv) == "1"
	decision := decide(stats, overridden)

	if !stats.Measured() {
		if decision.overrideConsumed {
			fmt.Printf("%s %s (headroom UNMEASURED)\n", decision.label, path)
			announceOverrideConsumed(path,
				"this kernel's verifier log carried no \"processed N insns (limit M)\" line, "+
					"so the floor could not be applied at all")
			os.Exit(decision.exit)
		}
		fmt.Printf("%s %s\n", decision.label, path)
		fmt.Fprintf(os.Stderr,
			"shimverify: the candidate LOADS, but this kernel's verifier log carried no "+
				"\"processed N insns (limit M)\" line, so the #4555 headroom floor (%.1f%%) "+
				"could NOT be applied. How close this object is to the 1M processed-insn wall "+
				"is UNKNOWN.\n"+
				"  Unmeasurable is treated as a failure on purpose. This tripwire exists "+
				"because nothing was watching while the shim crept to 0.92%% headroom; a gate "+
				"that switches itself off when the log format changes reproduces that exact "+
				"failure mode at the one moment headroom is unknown.\n"+
				"  If your kernel genuinely reports differently, set %s=1 to install anyway — "+
				"that is an explicit acknowledgement that this object shipped unmeasured.\n",
			dataplane.UserspaceShimMinVerifierHeadroomPct, allowLowHeadroomEnv)
		os.Exit(decision.exit)
	}

	headroom := stats.HeadroomPct()
	summary := fmt.Sprintf("processed %d insns (limit %d), headroom %.2f%%",
		stats.ProcessedInsns, stats.InsnLimit, headroom)

	if headroom < dataplane.UserspaceShimMinVerifierHeadroomPct {
		if decision.overrideConsumed {
			fmt.Printf("%s %s (%s)\n", decision.label, path, summary)
			announceOverrideConsumed(path, fmt.Sprintf(
				"headroom %.2f%% is below the floor of %.1f%%; the next change to the shim's "+
					"hot parsing paths may not fit",
				headroom, dataplane.UserspaceShimMinVerifierHeadroomPct))
			os.Exit(decision.exit)
		}
		fmt.Printf("%s %s (%s)\n", decision.label, path, summary)
		fmt.Fprintf(os.Stderr,
			"shimverify: the candidate LOADS, but leaves only %.2f%% of the verifier's "+
				"processed-insn budget unused — below the #4555 floor of %.1f%%.\n"+
				"  This is not a kernel rejection; it is the tripwire that exists because "+
				"a binary PASS/REJECT gate let the shim reach 0.92%% headroom unnoticed, "+
				"and the next edit to its parsing paths then hit the 1M wall (#1864 is "+
				"what that costs: both HA dataplanes down).\n"+
				"  Reduce verifier cost — the fully-unrolled IPv6 extension-header walk in "+
				"parse_ipv6 is the largest consumer, see pkg/dataplane/README.md — or set "+
				"%s=1 to install anyway with the risk understood.\n",
			headroom, dataplane.UserspaceShimMinVerifierHeadroomPct, allowLowHeadroomEnv)
		os.Exit(decision.exit)
	}

	// The override is read from the ambient environment, so a value
	// exported once to get past a low-headroom object would silently
	// disarm every later run. Surface it on the HEALTHY path too: the
	// only place staleness is visible is a build that did not need it.
	if decision.staleOverrideNote {
		fmt.Fprintf(os.Stderr,
			"shimverify: NOTE: %s=1 is set in the environment but was NOT needed — this object "+
				"is measured at %.2f%% headroom, above the %.1f%% floor. If that value is left "+
				"exported it will silently disarm the gate on a future run. Unset it.\n",
			allowLowHeadroomEnv, headroom, dataplane.UserspaceShimMinVerifierHeadroomPct)
	}
	fmt.Printf("%s %s (%s)\n", decision.label, path, summary)
}

// allowLowHeadroomEnv is the documented, deliberate override for BOTH
// #4555 refusals: measured-but-below-floor and could-not-measure.
const allowLowHeadroomEnv = "XPF_SHIM_ALLOW_LOW_HEADROOM"

// shimverifyDecision is what the #4555 gate CONCLUDES about one candidate,
// separated from how it says so. main() prints the long-form diagnostics;
// this carries the part a caller acts on.
//
// It exists so the decision can be TESTED. Before it, the only assertion
// about "an unmeasurable stats line must reach the refusal path" re-tested
// parseShimVerifierStats and HeadroomPct() — both already covered
// elsewhere — and would have stayed green with this binary passing every
// input. A gate's decision has to be checkable without a kernel verifier.
type shimverifyDecision struct {
	// exit is the process exit status; build-userspace-xdp.sh carries one
	// arm per value.
	exit int
	// label is the status word on stdout: PASS, LOW-HEADROOM,
	// UNMEASURED-HEADROOM or OVERRIDDEN.
	label string
	// overrideConsumed is true when XPF_SHIM_ALLOW_LOW_HEADROOM=1 turned a
	// refusal into an install. That run must announce itself loudly.
	overrideConsumed bool
	// staleOverrideNote is true when the override was exported but the
	// object did not need it — the only run where a stale exported value is
	// visible, so it is where we warn.
	staleOverrideNote bool
}

// decide maps (stats, override) to the gate's verdict.
//
// UNMEASURED is a refusal, not a pass: this tripwire exists because nothing
// was watching while the shim crept to 0.92% headroom, and a gate that
// switches itself off when the kernel's log format changes reproduces that
// failure at the one moment headroom is unknown. Both refusals take the
// same override, and an overridden run is 6 — never 0 — so "installed with
// the gate satisfied" and "installed because someone said so" stay distinct
// to a non-interactive caller.
func decide(stats dataplane.ShimVerifierStats, overridden bool) shimverifyDecision {
	if !stats.Measured() {
		if overridden {
			return shimverifyDecision{exit: 6, label: "OVERRIDDEN", overrideConsumed: true}
		}
		return shimverifyDecision{exit: 5, label: "UNMEASURED-HEADROOM"}
	}
	if stats.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		if overridden {
			return shimverifyDecision{exit: 6, label: "OVERRIDDEN", overrideConsumed: true}
		}
		return shimverifyDecision{exit: 4, label: "LOW-HEADROOM"}
	}
	return shimverifyDecision{exit: 0, label: "PASS", staleOverrideNote: overridden}
}

// announceOverrideConsumed logs, loudly and unambiguously, that a build
// installed an object the #4555 gate would otherwise have refused, and
// which run consumed the override. The override lives in the ambient
// environment (the recipe threads it through sudo deliberately), so
// without this a stale exported value would suppress the gate with no
// trace in the build log.
func announceOverrideConsumed(path, reason string) {
	fmt.Fprintf(os.Stderr,
		"shimverify: ============================================================\n"+
			"shimverify: #4555 HEADROOM GATE OVERRIDDEN via %s=1\n"+
			"shimverify:   object: %s\n"+
			"shimverify:   reason: %s\n"+
			"shimverify:   This object is being installed WITHOUT a satisfied headroom check.\n"+
			"shimverify:   If you did not intend this, the variable is stale in your\n"+
			"shimverify:   environment — unset it and re-run.\n"+
			"shimverify: ============================================================\n",
		allowLowHeadroomEnv, path, reason)
}
