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
		fmt.Fprintln(os.Stderr, "usage: xpfd upgrade kernel {arm <version>|promote|status} [flags]")
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
			// A revert is a non-error outcome of the gate: the candidate did
			// not pass, the box must reboot to the known-good slot. Exit 3 so
			// the promotion oneshot distinguishes revert (reboot) from a real
			// error (1).
			fmt.Fprintf(os.Stderr, "upgrade kernel promote: %v\n", err)
			os.Exit(3)
		}
		fmt.Println("kernel candidate promoted")

	case "status":
		armed, j, err := r.IsArmed()
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel status: %v\n", err)
			os.Exit(1)
		}
		if !armed {
			fmt.Println("no kernel upgrade armed")
			return
		}
		fmt.Printf("armed: candidate=%s known-good=%s active-slot=%s inactive-slot=%s state=%s\n",
			j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot, j.InactiveSlot, j.State)

	default:
		fmt.Fprintf(os.Stderr, "upgrade kernel: unknown verb %q (want arm|promote|status)\n", verb)
		os.Exit(1)
	}
}
