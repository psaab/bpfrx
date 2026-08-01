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
// A kernel whose log carries no recognisable stats line cannot be
// measured; that WARNS loudly and passes, because refusing there would
// block builds over a log-format difference rather than a real risk.
//
// Exit codes: 0 PASS, 2 usage, 3 verifier REJECT, 4 loads but headroom
// below the floor, 1 other error (including insufficient privileges).
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

	if !stats.Measured() {
		fmt.Printf("PASS %s\n", path)
		fmt.Fprintf(os.Stderr,
			"shimverify: WARNING: this kernel's verifier log carried no "+
				"\"processed N insns (limit M)\" line, so the #4555 headroom floor "+
				"(%.1f%%) could NOT be checked. The object loaded; how close it is "+
				"to the 1M processed-insn wall is UNKNOWN.\n",
			dataplane.UserspaceShimMinVerifierHeadroomPct)
		return
	}

	headroom := stats.HeadroomPct()
	summary := fmt.Sprintf("processed %d insns (limit %d), headroom %.2f%%",
		stats.ProcessedInsns, stats.InsnLimit, headroom)

	if headroom < dataplane.UserspaceShimMinVerifierHeadroomPct {
		if os.Getenv("XPF_SHIM_ALLOW_LOW_HEADROOM") == "1" {
			fmt.Printf("PASS %s (%s)\n", path, summary)
			fmt.Fprintf(os.Stderr,
				"shimverify: WARNING: headroom %.2f%% is below the #4555 floor of "+
					"%.1f%%, allowed by XPF_SHIM_ALLOW_LOW_HEADROOM=1. The next change "+
					"to the shim's hot parsing paths may not fit.\n",
				headroom, dataplane.UserspaceShimMinVerifierHeadroomPct)
			return
		}
		fmt.Printf("LOW-HEADROOM %s (%s)\n", path, summary)
		fmt.Fprintf(os.Stderr,
			"shimverify: the candidate LOADS, but leaves only %.2f%% of the verifier's "+
				"processed-insn budget unused — below the #4555 floor of %.1f%%.\n"+
				"  This is not a kernel rejection; it is the tripwire that exists because "+
				"a binary PASS/REJECT gate let the shim reach 0.92%% headroom unnoticed, "+
				"and the next edit to its parsing paths then hit the 1M wall (#1864 is "+
				"what that costs: both HA dataplanes down).\n"+
				"  Reduce verifier cost — the fully-unrolled IPv6 extension-header walk in "+
				"parse_ipv6 is the largest consumer, see pkg/dataplane/README.md — or set "+
				"XPF_SHIM_ALLOW_LOW_HEADROOM=1 to install anyway with the risk understood.\n",
			headroom, dataplane.UserspaceShimMinVerifierHeadroomPct)
		os.Exit(4)
	}

	fmt.Printf("PASS %s (%s)\n", path, summary)
}
