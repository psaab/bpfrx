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
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
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
