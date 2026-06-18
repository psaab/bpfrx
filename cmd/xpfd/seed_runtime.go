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
	sbinDir := fs.String("sbin-dir", upgrade.DefaultSbinDir, "operator-tool symlink dir")
	// --capability-check is a pure, side-effect-free probe used by the .deb
	// postrm to tell whether the newly-unpacked staged binary supports the
	// #1964 hardened versioned-runtime layout. A hardened xpfd exits 0
	// without touching the filesystem; a pre-#1964 binary has no
	// seed-runtime subcommand at all and exits non-zero ("unknown command").
	// The postrm downgrade cleanup keys on this so it ONLY tears down the
	// hardened layout when downgrading to a package that genuinely lacks it
	// (never when downgrading hardened->hardened).
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
		StagedDir:   *stagedDir,
		VersionsDir: *versionsDir,
		SbinDir:     *sbinDir,
		Logf:        func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}); err != nil {
		fmt.Fprintf(os.Stderr, "seed-runtime: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("seed-runtime complete")
}
