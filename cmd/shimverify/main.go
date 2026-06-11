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
// Exit codes: 0 PASS, 2 usage, 3 verifier REJECT, 1 other error
// (including insufficient privileges).
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
	if err := dataplane.VerifyUserspaceShimObject(path); err != nil {
		if errors.Is(err, dataplane.ErrUserspaceShimVerifierReject) {
			fmt.Printf("REJECT %s\n%v\n", path, err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "shimverify: %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s\n", path)
}
