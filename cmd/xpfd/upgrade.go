package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/upgrade"
)

// runUpgradeSubcommand implements `xpfd upgrade [--rolling]` — the in-place
// cut-over to the dpkg-staged version (#1917 increment B). It is invoked
// from the .deb postinst on a STANDALONE node and by the operator / the
// dogfood deploy driver. On a clustered node the postinst is stage-only;
// the cluster is cut ONLY via `xpfd upgrade --rolling` (or the equivalent
// external driver), which sequences a controlled per-node drain so the
// cluster keeps forwarding.
//
// Exit codes: 0 success, 1 error (including a rollback report).
func runUpgradeSubcommand(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	rolling := fs.Bool("rolling", false,
		"HA rolling upgrade: drive a controlled per-node drain + cut so the "+
			"cluster keeps forwarding (one node down at a time)")
	stagedDir := fs.String("staged-dir", upgrade.DefaultStagedDir, "dpkg-staged binary set dir")
	versionsDir := fs.String("versions-dir", upgrade.DefaultVersionsDir, "runtime versioned dir")
	sbinDir := fs.String("sbin-dir", upgrade.DefaultSbinDir, "operator-tool symlink dir")
	configDBDir := fs.String("configdb-dir", upgrade.DefaultConfigDBDir, "config DB dir (for rollback snapshot)")
	journalPath := fs.String("journal", upgrade.DefaultJournalPath, "crash-safe state journal path")
	unit := fs.String("unit", upgrade.DefaultUnit, "systemd unit name")
	healthDeadline := fs.Duration("health-deadline", 30*time.Second,
		"post-start helper-health deadline before auto-rollback (standalone)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg := upgrade.Config{
		StagedDir:           *stagedDir,
		VersionsDir:         *versionsDir,
		SbinDir:             *sbinDir,
		ConfigDBDir:         *configDBDir,
		JournalPath:         *journalPath,
		Unit:                *unit,
		StartHealthDeadline: *healthDeadline,
		Sys:                 upgrade.NewSystem(*unit),
		Logf:                func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
	r, err := upgrade.NewRunner(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upgrade: %v\n", err)
		os.Exit(1)
	}

	if *rolling {
		if err := upgrade.RunRolling(r, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade --rolling: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("rolling upgrade complete")
		return
	}

	if err := r.Run(upgrade.Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "upgrade: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("upgrade complete")
}
