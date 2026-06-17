package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/upgrade"
)

// runUpgradeKernelSubcommand implements `xpfd upgrade kernel ...` — the LANE-1
// verify-gated in-place kernel channel (#1930 INC-1). Sub-verbs:
//
//	xpfd upgrade kernel arm <version>   — preflight + install the candidate +
//	    arm the one-shot A/B slot boot + reboot. On success the host reboots
//	    into the candidate (this command does not return).
//	xpfd upgrade kernel promote         — the candidate-boot promotion gate,
//	    invoked by the promotion oneshot systemd unit. PASS -> promote (durable
//	    BootOrder reorder), FAIL -> revert (exit 3 so the oneshot reboots to the
//	    known-good slot).
//	xpfd upgrade kernel status          — print the kernel-channel journal state.
//
// Exit codes: 0 success/clean, 1 error, 2 channel-unavailable (use LANE 2),
// 3 candidate REVERTED (promote path — the oneshot reboots to known-good).
func runUpgradeKernelSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: xpfd upgrade kernel {arm <version>|promote|status|drain|rejoin} [flags]")
		os.Exit(1)
	}
	verb := args[0]
	fs := flag.NewFlagSet("upgrade kernel "+verb, flag.ContinueOnError)
	journalPath := fs.String("journal", upgrade.DefaultKernelJournalPath, "crash-safe kernel-channel journal path")
	strictWatchdog := fs.Bool("strict-watchdog", false,
		"Path-D1: refuse to arm unless a verified-persistent watchdog is present "+
			"(default Path-D2: BootNext still closes the boot-loop; an early hang "+
			"needs one external reset)")
	beaconDeadline := fs.Duration("beacon-deadline", 20*time.Second,
		"forward-health-beacon deadline on the candidate boot (promote)")
	drainDeadline := fs.Duration("drain-deadline", 30*time.Second,
		"deadline for the STRONG drain predicate (drain) / rejoin confirm (rejoin)")
	allowMixedHA := fs.Bool("allow-mixed-ha", false,
		"relax the drain HA-protocol-compatible precheck (the LANE-2 image-roll "+
			"mixed-base gate already validated window-compat; the exact-equality "+
			"check would otherwise abort a legitimate in-window mixed-base roll)")
	unit := fs.String("unit", "xpfd", "systemd unit (cluster gRPC target)")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(1)
	}

	cfg := upgrade.KernelConfig{
		JournalPath:    *journalPath,
		StrictWatchdog: *strictWatchdog,
		BeaconDeadline: *beaconDeadline,
		Sys:            upgrade.NewKernelSystem(),
		Logf:           func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
	r, err := upgrade.NewKernelRunner(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upgrade kernel: %v\n", err)
		os.Exit(1)
	}

	switch verb {
	case "arm":
		rest := fs.Args()
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: xpfd upgrade kernel arm <version>")
			os.Exit(1)
		}
		if err := r.Arm(rest[0]); err != nil {
			if errors.Is(err, upgrade.ErrKernelChannelUnavailable) {
				fmt.Fprintf(os.Stderr, "upgrade kernel arm: %v\n", err)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "upgrade kernel arm: %v\n", err)
			os.Exit(1)
		}
		// Arm() reboots on success and does not return; reaching here means a
		// test/no-op reboot surface — report and exit 0.
		fmt.Println("kernel candidate armed; reboot pending")

	case "promote":
		if err := r.Promote(); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel promote: %v\n", err)
			// A REVERT is the expected "candidate failed the gate" outcome:
			// exit 3 so the promotion oneshot reboots to the known-good slot.
			// Any OTHER error (journal/firmware/BootOrder-write failure) is a
			// genuine infra error: exit 1 (the oneshot must NOT treat it as a
			// clean revert) — r1 Codex High.
			if errors.Is(err, upgrade.ErrKernelReverted) {
				os.Exit(3)
			}
			os.Exit(1)
		}
		fmt.Println("kernel candidate promoted")

	case "status":
		// Report the durable promotion marker too — the external HA orchestrator
		// (INC-2) polls this post-reboot to confirm "this node promoted version
		// X" (the journal is cleared on promote, so the marker is the durable
		// signal). Machine-parseable: "promoted=<uname>" / "promoted=none".
		promoted, perr := cfg.Sys.ReadPromotionMarker()
		if perr != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel status: read promotion marker: %v\n", perr)
			os.Exit(1)
		}
		if promoted == "" {
			fmt.Println("promoted=none")
		} else {
			fmt.Printf("promoted=%s\n", promoted)
		}
		armed, j, err := r.IsArmed()
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel status: %v\n", err)
			os.Exit(1)
		}
		if !armed {
			fmt.Println("armed=none")
			return
		}
		fmt.Printf("armed=true candidate=%s known-good=%s active-slot=%s inactive-slot=%s state=%s\n",
			j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot, j.InactiveSlot, j.State)

	case "drain":
		// Non-interactive drain for the external HA roll (r1 Codex Critical:
		// `cli -c 'request system ... in-service-upgrade'` cannot confirm in a
		// non-TTY, and the cli path needs interactive confirmation). This drives
		// the SAME automation path #1917 rolling uses (ForceSecondary via the
		// gRPC SystemAction) and CONFIRMS the STRONG drain predicate (peer holds
		// the RGs + sync clean) before reporting success — so the orchestrator
		// never arms+reboots an undrained primary.
		cl := upgrade.NewCLICluster(*unit)
		if err := upgrade.DrainAndConfirm(cl, *drainDeadline, *allowMixedHA); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel drain: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("drained (peer holds all RGs, sync clean)")

	case "rejoin":
		// Non-interactive rejoin: clear manual failover on all RGs and confirm
		// the node is back as an eligible cluster member with sync re-established
		// (so the orchestrator never advances to the peer until this node is
		// fully rejoined — r1 Codex Critical "never both down").
		cl := upgrade.NewCLICluster(*unit)
		if err := upgrade.RejoinAndConfirm(cl, *drainDeadline); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel rejoin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("rejoined (manual failover cleared, sync re-established)")

	default:
		fmt.Fprintf(os.Stderr, "upgrade kernel: unknown verb %q (want arm|promote|status|drain|rejoin)\n", verb)
		os.Exit(1)
	}
}
