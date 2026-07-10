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
	journalPath := fs.String("journal", upgrade.DefaultJournalPath, "upgrade journal path (its pinned generation is protected from GC)")
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
	// GC the staged-generation root (current + 1 prior), PROTECTING any
	// generation a crashed/resumable cut's journal still pins. The host-wide
	// lock serializes us against a RUNNING cut, but a CRASHED cut leaves a
	// durable journal with the lock released — so the GC must read the journal
	// and protect its SourceGeneration, else a resume hard-fails on a GC'd
	// source (and a crash-after-STOP would be left daemon-down with no
	// recoverable cut).
	//
	// The protection set MUST be known before running destructive GC (#4876):
	// if the journal is present but unreadable (I/O error) or malformed, we
	// cannot see which generation a crashed cut pins, so GC is SKIPPED rather
	// than run with an empty protection set that could reap the pinned source.
	// Skipping is safe — the extra staged generations are harmless and the
	// next publish with a readable journal reclaims them.
	protected, runGC, warn := gcProtectionForPublish(*journalPath)
	if warn != "" {
		fmt.Fprintf(os.Stderr, "publish-generation: WARN %s\n", warn)
	}
	if runGC {
		if gcErr := cfg.GC(protected); gcErr != nil {
			fmt.Fprintf(os.Stderr, "publish-generation: WARN gc: %v\n", gcErr)
		}
	}
	fmt.Printf("publish-generation complete (generation %s)\n", genid)
}

// gcProtectionForPublish computes the staged-generation GC protection set for
// publish-generation and reports whether destructive GC may proceed.
//
// It reads the upgrade journal's pinned source generation. An absent or
// legacy (no-pin) journal is genuinely unprotected: GC proceeds (runGC=true)
// with the resolved protection set. A journal that is PRESENT but unreadable
// (I/O error) or malformed makes the protection set UNKNOWN — GC MUST be
// skipped (runGC=false) so a crashed/resumable cut's pinned source is never
// reaped and the resume bricked (#4876). warn is a non-empty operator message
// on the skip path, empty otherwise.
func gcProtectionForPublish(journalPath string) (protected map[string]bool, runGC bool, warn string) {
	protected = map[string]bool{}
	pinned, err := upgrade.ReadJournalSourceGeneration(journalPath)
	if err != nil {
		return protected, false, fmt.Sprintf(
			"read journal for GC protection: %v; skipping GC to avoid reaping a pinned generation", err)
	}
	if pinned != "" {
		protected[pinned] = true
	}
	return protected, true, ""
}
