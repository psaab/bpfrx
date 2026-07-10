package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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

	cfg := newUpgradeConfig(flags)
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

	// #5284 belt-and-suspenders: fail FAST on a clustered node before
	// building a cut. A bare `xpfd upgrade` on a member (/etc/xpf/node-id
	// present) selects the UNCOORDINATED standalone STOP->FLIP->START flow
	// solely because `--rolling` was omitted (#4869 rejects only leftover
	// positional args). The authoritative invariant is enforced in
	// Runner.Run (the final privileged boundary, which also catches the
	// postinst / recovery-doc callers), but rejecting here gives the operator
	// the earliest, clearest message and never even builds the Runner.
	if upgrade.ClusterNodeIDPresent(cfg.NodeIDPath) {
		fmt.Fprintf(os.Stderr, "upgrade: refusing an UNCOORDINATED standalone cut on a "+
			"cluster member (%s present); the standalone STOP->FLIP->START flow does "+
			"NOT drain to the peer and would blackhole traffic if the peer is not "+
			"ready. Run `xpfd upgrade --rolling` for a coordinated per-node drain + "+
			"cut so the cluster keeps forwarding\n", upgrade.DefaultNodeIDFile)
		os.Exit(1)
	}

	if err := r.Run(upgrade.Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "upgrade: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("upgrade complete")
}

// newUpgradeConfig assembles the upgrade Runner Config, WIRING the post-cut
// helper-readiness probe into Sys via buildUpgradeSystem (#5286). Extracted from
// runUpgradeSubcommand (which calls os.Exit and cannot be unit-tested) so a test
// can assert the constructed Sys actually consults the helper probe rather than
// the pre-fix is-active-only NewSystem.
func newUpgradeConfig(flags upgradeFlags) upgrade.Config {
	return upgrade.Config{
		StagedDir:           flags.stagedDir,
		VersionsDir:         flags.versionsDir,
		StagedGenDir:        flags.stagedGenDir,
		SbinDir:             flags.sbinDir,
		ConfigDBDir:         flags.configDBDir,
		JournalPath:         flags.journalPath,
		Unit:                flags.unit,
		StartHealthDeadline: flags.healthDeadline,
		Sys:                 buildUpgradeSystem(flags),
		Logf:                func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
}

// buildUpgradeSystem constructs the production upgrade System, WIRING the
// post-cut helper-readiness probe (#5286). Before this fix the site built
// upgrade.NewSystem(flags.unit) — no probe — so realSystem.HelperHealthy
// degraded to a bare `systemctl is-active` poll and IGNORED expectVersion. A
// tree-wide grep found ZERO callers of NewSystemWithHelperHealth, so service
// PROCESS ACTIVITY was the only witness on the failure-critical cutover path: a
// Type=simple xpfd reports active immediately, so the cut could COMMIT (and
// clear the rollback journal / return the node to HA election) while the
// userspace helper was down / stale / crash-looping and NOT forwarding.
//
// The wired probe (upgrade.HelperHealthProbe) fails CLOSED unless, within the
// health deadline, the unit is active AND the helper reports armed+forwarding
// on the control socket AND that armed helper is executing the freshly-cut
// TARGET version's binary. Not-healthy flows into cutover.go's existing
// rollback path (standalone auto-rollback; HA surfaces the failure).
func buildUpgradeSystem(flags upgradeFlags) upgrade.System {
	unit := flags.unit
	if unit == "" {
		unit = upgrade.DefaultUnit
	}
	deps := upgrade.HelperHealthDeps{
		UnitActive:    func() bool { return upgradeUnitActive(unit) },
		Status:        upgradeHelperStatus,
		HelperExe:     upgradeHelperExe,
		ControlSocket: upgradeControlSock(flags.configDBDir),
		VersionsDir:   flags.versionsDir,
	}
	return upgrade.NewSystemWithHelperHealth(unit, upgrade.HelperHealthProbe(deps))
}

// Seams for the #5286 helper-readiness probe. Package vars so a test can point
// the control-socket status query, the exe resolution, the is-active check, and
// the socket-path resolution at fakes — and prove the production System
// actually CONSULTS the helper probe (NewSystemWithHelperHealth), not the
// pre-fix is-active-only NewSystem.
var (
	upgradeHelperStatus upgrade.HelperStatusFunc = defaultUpgradeHelperStatus
	upgradeHelperExe    upgrade.HelperExeFunc    = defaultUpgradeHelperExe
	upgradeUnitActive                            = defaultUpgradeUnitActive
	upgradeControlSock                           = defaultUpgradeControlSocket
)

// defaultUpgradeHelperStatus adapts the existing control-socket status query
// (userspace.ProbeStatus — the same one-shot "status" request the runtime and
// the #1993 boot probe use) to the primitive tuple pkg/upgrade consumes. It
// invents no new IPC.
func defaultUpgradeHelperStatus(controlSocket string, timeout time.Duration) (enabled, armed bool, pid int, err error) {
	st, perr := dpuserspace.ProbeStatus(controlSocket, timeout)
	if perr != nil {
		return false, false, 0, perr
	}
	if st == nil {
		// Helper answered !ok / no live status: not ready.
		return false, false, 0, nil
	}
	return st.Enabled, st.ForwardingArmed, st.PID, nil
}

// defaultUpgradeHelperExe resolves the executable a running PID is executing via
// /proc/<pid>/exe. The upgrade subprocess runs as root, so the readlink is
// permitted. Readlink returns the RESOLVED real path even when the helper was
// launched through the /usr/local/sbin symlink, so it lands under
// versions/<target>/ regardless of launch form.
func defaultUpgradeHelperExe(pid int) (string, error) {
	return os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
}

// defaultUpgradeUnitActive reports whether <unit>.service is active.
func defaultUpgradeUnitActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit+".service").Output()
	return strings.TrimSpace(string(out)) == "active"
}

// defaultUpgradeControlSocket resolves the helper control-socket path from the
// ACTIVE config so an operator `system dataplane control-socket <path>`
// override is honored (a cutover gate that probed the wrong socket would
// false-negative and roll back a healthy upgrade). Best-effort and read-only:
// on any failure it falls back to the default path — which is what a
// default-config deployment's helper listens on (mirrors the #1993 boot probe's
// DefaultControlSocketPath(nil) precedent). It never MUTATES config state.
func defaultUpgradeControlSocket(configDBDir string) string {
	if fi, err := os.Stat(configDBDir); err == nil && fi.IsDir() {
		if db, derr := configstore.NewDB(configDBDir); derr == nil {
			if tree, rerr := db.ReadActive(); rerr == nil && tree != nil {
				if cfg, cerr := config.CompileConfigLenient(tree); cerr == nil && cfg != nil {
					return dpuserspace.DefaultControlSocketPath(cfg)
				}
			}
		}
	}
	return dpuserspace.DefaultControlSocketPath(nil)
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
