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
	// #1930: `xpfd upgrade kernel ...` is the LANE-1 verify-gated in-place
	// kernel channel (a distinct sub-verb from the #1917 binary cut-over).
	if len(args) > 0 && args[0] == "kernel" {
		runUpgradeKernelSubcommand(args[1:])
		return
	}

	flags, err := parseUpgradeArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upgrade: %v\n", err)
		os.Exit(1)
	}
	rolling := &flags.rolling

	cfg := upgrade.Config{
		StagedDir:           flags.stagedDir,
		VersionsDir:         flags.versionsDir,
		StagedGenDir:        flags.stagedGenDir,
		SbinDir:             flags.sbinDir,
		ConfigDBDir:         flags.configDBDir,
		JournalPath:         flags.journalPath,
		Unit:                flags.unit,
		StartHealthDeadline: flags.healthDeadline,
		Sys:                 upgrade.NewSystem(flags.unit),
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

// upgradeFlags holds the parsed `xpfd upgrade` flags. Kept in a struct so the
// flag parsing + positional-arg validation is unit-testable without the
// os.Exit / real-System side effects of the dispatch.
type upgradeFlags struct {
	rolling                                                                       bool
	stagedDir, versionsDir, stagedGenDir, sbinDir, configDBDir, journalPath, unit string
	healthDeadline                                                                time.Duration
}

// parseUpgradeArgs parses the `xpfd upgrade [--rolling] [flags]` argument set.
//
// #4869: it REJECTS any leftover positional argument. `flag.FlagSet.Parse`
// stops at the first non-flag token and leaves it in `fs.Args()`, so before
// this guard `xpfd upgrade rolling` (missing the two dashes) silently left
// `--rolling` false and ran the STANDALONE STOP->FLIP->START cut — an
// uncoordinated cut on a clustered node with no drain/takeover. A mistyped or
// misplaced argument must be a hard usage error, not a wrong/default run.
func parseUpgradeArgs(args []string) (upgradeFlags, error) {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	rolling := fs.Bool("rolling", false,
		"HA rolling upgrade: drive a controlled per-node drain + cut so the "+
			"cluster keeps forwarding (one node down at a time)")
	stagedDir := fs.String("staged-dir", upgrade.DefaultStagedDir, "dpkg-staged binary set dir")
	versionsDir := fs.String("versions-dir", upgrade.DefaultVersionsDir, "runtime versioned dir")
	stagedGenDir := fs.String("staged-gen-dir", upgrade.DefaultStagedGenDir,
		"staged-generation root the cut copies from (#1981 Option B)")
	sbinDir := fs.String("sbin-dir", upgrade.DefaultSbinDir, "operator-tool symlink dir")
	configDBDir := fs.String("configdb-dir", upgrade.DefaultConfigDBDir, "config DB dir (for rollback snapshot)")
	journalPath := fs.String("journal", upgrade.DefaultJournalPath, "crash-safe state journal path")
	unit := fs.String("unit", upgrade.DefaultUnit, "systemd unit name")
	healthDeadline := fs.Duration("health-deadline", 30*time.Second,
		"post-start helper-health deadline before auto-rollback (standalone)")
	if err := fs.Parse(args); err != nil {
		return upgradeFlags{}, err
	}
	if fs.NArg() != 0 {
		return upgradeFlags{}, fmt.Errorf("unexpected argument(s) %v; "+
			"usage: xpfd upgrade [--rolling] [flags] "+
			"(HA rolling upgrade needs the leading dashes: --rolling)", fs.Args())
	}
	return upgradeFlags{
		rolling:        *rolling,
		stagedDir:      *stagedDir,
		versionsDir:    *versionsDir,
		stagedGenDir:   *stagedGenDir,
		sbinDir:        *sbinDir,
		configDBDir:    *configDBDir,
		journalPath:    *journalPath,
		unit:           *unit,
		healthDeadline: *healthDeadline,
	}, nil
}
