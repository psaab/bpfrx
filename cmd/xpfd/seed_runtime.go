package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/upgrade"
	upruntime "github.com/psaab/xpf/pkg/upgrade/runtime"
)

// runSeedRuntimeSubcommand implements `xpfd seed-runtime` — first-install
// seeding of the versioned runtime layout (#1964 mechanism A). It is invoked
// from the .deb postinst on FIRST install (before #DEBHELPER# starts the
// unit). It copies the dpkg-staged binary set into versions/<v>/, sets
// versions/current -> <v>, and repoints /usr/local/sbin/* through
// versions/current so a later in-place upgrade always has a real rollback
// target. It performs NO cut, verify, or unit stop.
//
// Exit codes: 0 success, 1 error.
func runSeedRuntimeSubcommand(args []string) {
	flags, err := parseSeedRuntimeArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed-runtime: %v\n", err)
		os.Exit(1)
	}
	if flags.capCheck {
		fmt.Println("seed-runtime supported")
		return
	}

	if err := upruntime.Seed(upruntime.Config{
		StagedDir:    flags.stagedDir,
		VersionsDir:  flags.versionsDir,
		StagedGenDir: flags.stagedGenDir,
		SbinDir:      flags.sbinDir,
		Logf:         func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}); err != nil {
		fmt.Fprintf(os.Stderr, "seed-runtime: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("seed-runtime complete")
}

// seedRuntimeFlags holds the parsed `xpfd seed-runtime` flags. Kept in a
// struct so the flag parsing + positional-arg validation is unit-testable
// without the os.Exit / real-Seed side effects of the dispatch.
type seedRuntimeFlags struct {
	stagedDir, versionsDir, stagedGenDir, sbinDir string
	capCheck                                      bool
}

// parseSeedRuntimeArgs parses the `xpfd seed-runtime [flags]` argument set.
//
// #5322: seed-runtime takes NO positional arguments; like #4869's `xpfd
// upgrade`, it REJECTS any leftover operand instead of silently dropping it.
// `flag.FlagSet.Parse` stops at the first non-flag token, so before this guard
// `xpfd seed-runtime typo --sbin-dir /x` left the trailing flags in fs.Args()
// with the DEFAULT sbin dir and still seeded/repointed the versioned runtime —
// a mistyped operand silently ran a different privileged operation than
// intended.
func parseSeedRuntimeArgs(args []string) (seedRuntimeFlags, error) {
	fs := flag.NewFlagSet("seed-runtime", flag.ContinueOnError)
	stagedDir := fs.String("staged-dir", upgrade.DefaultStagedDir, "dpkg-staged binary set dir")
	versionsDir := fs.String("versions-dir", upgrade.DefaultVersionsDir, "runtime versioned dir")
	stagedGenDir := fs.String("staged-gen-dir", upgrade.DefaultStagedGenDir,
		"staged-generation root to publish the initial generation into (#1981)")
	sbinDir := fs.String("sbin-dir", upgrade.DefaultSbinDir, "operator-tool symlink dir")
	// --capability-check is a pure, side-effect-free probe: a hardened xpfd
	// exits 0 without touching the filesystem; a pre-#1964 binary has no
	// seed-runtime subcommand at all and exits non-zero ("unknown command").
	//
	// HISTORICAL (#1985): the .deb postrm USED to gate the downgrade teardown
	// on this probe, but EXECUTING the staged binary conflated "new binary
	// lacks the layout" with "new binary cannot run" (link/corruption/arch
	// errors), tearing the versioned runtime down on a real UPGRADE. The
	// postrm now keys the decision on the dpkg-supplied INCOMING version
	// (`$2` compared against the hardened-layout floor, exec-free) and never
	// runs this probe. The flag is RETAINED because dpkg runs the OLD
	// package's postrm during an upgrade, so a pre-#1985 postrm still invokes
	// it during the one-hop buggy->fixed transition; removing it would break
	// that call. See docs/in-place-upgrade.md ("Downgrade detection is
	// exec-free and version-keyed").
	capCheck := fs.Bool("capability-check", false,
		"probe-only: exit 0 if this binary supports the #1964 versioned-runtime "+
			"layout, without touching the filesystem")
	if err := fs.Parse(args); err != nil {
		return seedRuntimeFlags{}, err
	}
	if fs.NArg() != 0 {
		return seedRuntimeFlags{}, fmt.Errorf("unexpected argument(s) %v; "+
			"usage: xpfd seed-runtime [flags] (this verb takes no positional arguments)", fs.Args())
	}
	return seedRuntimeFlags{
		stagedDir:    *stagedDir,
		versionsDir:  *versionsDir,
		stagedGenDir: *stagedGenDir,
		sbinDir:      *sbinDir,
		capCheck:     *capCheck,
	}, nil
}
