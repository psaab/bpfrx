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
		os.Exit(1)
	}
	if *capCheck {
		fmt.Println("seed-runtime supported")
		return
	}

	if err := upruntime.Seed(upruntime.Config{
		StagedDir:    *stagedDir,
		VersionsDir:  *versionsDir,
		StagedGenDir: *stagedGenDir,
		SbinDir:      *sbinDir,
		Logf:         func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}); err != nil {
		fmt.Fprintf(os.Stderr, "seed-runtime: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("seed-runtime complete")
}
