package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/lock"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// runPublishGenerationSubcommand implements `xpfd publish-generation` — the
// #1981 Option B publish step: copy the dpkg-staged binary set into a fresh,
// immutable staged-gen/<genid>/ and atomically repoint current-gen at it, so a
// later cut reads a whole, single-generation source that dpkg is NOT rewriting.
//
// It is invoked:
//   - by the .deb postinst (configure) AFTER a complete unpack, BEFORE the
//     auto-cut, so every cut sees a fresh generation;
//   - by an operator as the DEFERRED-PUBLISH RECOVERY verb (plan B-P2b): if the
//     postinst deferred the publish because the host-wide upgrade lock was busy
//     (another upgrade in progress), the new binaries are staged but
//     unpublished and a bare `xpfd upgrade` would re-read the OLD current-gen
//     and no-op. The operator runs `xpfd publish-generation` (which publishes
//     the now-complete staged set) and THEN `xpfd upgrade`. (`dpkg-reconfigure
//     xpf` is the equivalent — it re-runs the postinst publish + cut.)
//
// It takes the host-wide upgrade lock so it is mutually exclusive with an
// operator cut (and so its GC cannot delete a generation a cut is reading). A
// busy lock is reported and the publish is skipped (the prior generation stays
// the cut source — never a torn read).
//
// Exit codes: 0 success, 1 error, 2 lock busy (publish deferred).
func runPublishGenerationSubcommand(args []string) {
	fs := flag.NewFlagSet("publish-generation", flag.ContinueOnError)
	stagedDir := fs.String("staged-dir", upgrade.DefaultStagedDir, "dpkg-staged binary set dir")
	stagedGenDir := fs.String("staged-gen-dir", upgrade.DefaultStagedGenDir, "staged-generation root")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Take the host-wide upgrade lock so the publish (and its GC) is mutually
	// exclusive with an operator cut. A busy lock means another upgrade
	// operation owns it: defer (exit 2), do NOT publish — the prior generation
	// remains a valid cut source.
	h, lerr := lock.Acquire("publish-generation", "")
	if lerr != nil {
		if lock.IsBusy(lerr) {
			fmt.Fprintf(os.Stderr,
				"publish-generation: another upgrade holds the lock; deferred. "+
					"Re-run after it completes: %v\n", lerr)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "publish-generation: acquire upgrade lock: %v\n", lerr)
		os.Exit(1)
	}
	defer func() { _ = h.Release() }()

	cfg := stagedgen.Config{
		StagedDir: *stagedDir,
		Dir:       *stagedGenDir,
		Logf:      func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
	genid, err := cfg.Publish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: %v\n", err)
		os.Exit(1)
	}
	// GC the staged-generation root (current + 1 prior). No active cut runs
	// concurrently (we hold the lock), so no generation needs journal
	// protection here; the cut's own GC protects its in-flight source.
	if gcErr := cfg.GC(nil); gcErr != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: WARN gc: %v\n", gcErr)
	}
	fmt.Printf("publish-generation complete (generation %s)\n", genid)
}
