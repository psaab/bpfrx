// xpfd is the xpf firewall daemon.
//
// It provides a Junos-style CLI for configuring the xpf firewall.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/xpf/pkg/daemon"
	"github.com/psaab/xpf/pkg/dataplane"
	_ "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/frr"
)

// Version information set at build time via ldflags.
var (
	version   = "dev"
	buildTime = "unknown"
	commit    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("xpfd %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		if err := dataplane.Cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup BPF: %v\n", err)
			os.Exit(1)
		}
		// Remove fabric IPVLAN interfaces created by the daemon.
		daemon.CleanupFabricIPVLANs()
		// Also clear FRR managed routes so the kernel routing table is
		// clean. One-shot contract (#1880): no degraded-retry loop in
		// this short-lived process; a degraded/failed reload is logged
		// LOUDLY but keeps exit status 0 — deploy tooling wraps cleanup
		// in `|| true`, and the deploy flow itself bounds convergence
		// (the new daemon's first ApplyFull full-diffs any residue).
		// Critically, Clear() never runs `systemctl reload frr`: the
		// FRR 10.6 ExecReload bounces watchfrr (the unit MainPID) and
		// parks frr.service in a 2-minute stop-sigterm that queued
		// post-deploy reboots behind it (the #1880 failover-harness
		// budget misses) and ended in systemd SIGKILLing FRR.
		fm := frr.New()
		fm.DisableDegradedRetry()
		if err := fm.Clear(); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup: FRR managed-section clear: %v\n"+
				"  frr.conf was rewritten without the managed section, but the running\n"+
				"  FRR config may retain it until the next xpfd start reapplies FRR.\n", err)
		}
		fm.Stop()
		fmt.Println("all pinned BPF state and managed routes removed")
		return
	}

	// #1864 deploy-time pre-flight: run the kernel BPF verifier against
	// the shim object EMBEDDED IN THIS BINARY without touching any
	// production state (anonymous maps, no pins, no attach, nothing
	// detached — a running daemon's loaded program keeps forwarding).
	// Deploy tooling pushes the NEW binary to a temp path and runs
	// this BEFORE stopping the old daemon; a REJECT refuses the deploy
	// instead of killing the dataplane (the 2026-06-10 incident shape).
	if len(os.Args) > 1 && os.Args[1] == "verify-dataplane" {
		if err := dataplane.VerifyEmbeddedUserspaceShim(); err != nil {
			if errors.Is(err, dataplane.ErrUserspaceShimVerifierReject) {
				fmt.Printf("REJECT embedded userspace shim\n%v\n", err)
				os.Exit(3)
			}
			fmt.Fprintf(os.Stderr, "verify-dataplane: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("PASS embedded userspace shim (verifier accepted; no production state touched)")
		return
	}

	// Reject unknown positional arguments — prevents accidentally starting
	// a second daemon when running "xpfd show ..." outside the CLI.
	// Use the "cli" binary or run xpfd interactively for show/request/configure.
	if len(os.Args) > 1 && os.Args[1] != "" && os.Args[1][0] != '-' {
		fmt.Fprintf(os.Stderr, "xpfd: unknown command %q\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "  use the 'cli' binary for remote commands, or run xpfd on a TTY\n")
		os.Exit(1)
	}

	configFile := flag.String("config", "/etc/xpf/xpf.conf", "configuration file path")
	noDataplane := flag.Bool("no-dataplane", false, "run without a dataplane (config-only mode)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "HTTP API listen address (empty to disable)")
	grpcAddr := flag.String("grpc-addr", "127.0.0.1:50051", "gRPC API listen address")
	debug := flag.Bool("debug", false, "enable debug logging")
	// #1620: cold-path latency histogram sample mask. Default 0xff
	// = 1-in-256 sampling. Powers-of-two-minus-one only. For 1-in-1
	// sampling (256× CPU cost — bounded-cohort microbench only),
	// also pass --enable-cold-path-1-in-1-sampling.
	const (
		flagColdPathSampleMask = "cold-path-sample-mask"
		flagColdPath1in1       = "enable-cold-path-1-in-1-sampling"
	)
	coldPathSampleMask := flag.Uint64(flagColdPathSampleMask, 0xff,
		"Cold-path latency histogram sample mask (powers-of-two minus one). "+
			"Default 0xff = 1-in-256 sampling. Allowed values: 0x1, 0x3, 0x7, "+
			"0xff, 0x3ff, ..., 0x7fffffffffffffff. For 1-in-1 sampling (256× "+
			"CPU cost — bounded-cohort microbench only), use "+
			"--enable-cold-path-1-in-1-sampling.")
	enableColdPath1in1 := flag.Bool(flagColdPath1in1, false,
		"Enable 1-in-1 cold-path latency sampling (256× CPU cost). "+
			"Required for bounded-cohort microbench (#1622); never use in "+
			"production. Overrides --cold-path-sample-mask to 0.")
	flag.Parse()

	// #1620: validate the cold-path sample mask. Two-flag scheme per
	// plan v4 §4.3.
	effectiveMask := *coldPathSampleMask
	if *enableColdPath1in1 {
		effectiveMask = 0
	}
	// AGY r3 [MED-2] + Codex r3: reject mask=0 unless explicit 1-in-1.
	if effectiveMask == 0 && !*enableColdPath1in1 {
		fmt.Fprintf(os.Stderr,
			"xpfd: --cold-path-sample-mask=0 requires explicit "+
				"--enable-cold-path-1-in-1-sampling (256× CPU cost — "+
				"bounded-cohort microbench only)\n")
		os.Exit(1)
	}
	// Codex r2 MED + Codex r3 + AGY r3: validate pow-of-2-minus-1 for
	// non-zero masks. u64::MAX (next wraps to 0) is rejected.
	if effectiveMask != 0 {
		next := effectiveMask + 1 // uint64; Go-defined wrap to 0 if MAX
		if next == 0 || (effectiveMask&next) != 0 {
			fmt.Fprintf(os.Stderr,
				"xpfd: --cold-path-sample-mask=0x%x: must be a power-of-two "+
					"minus one (0x1, 0x3, 0x7, 0xff, 0x3ff, ..., 0x7fff_ffff_ffff_ffff) "+
					"or 0 with --enable-cold-path-1-in-1-sampling. Rejecting "+
					"u64::MAX as ambiguous.\n",
				effectiveMask)
			os.Exit(1)
		}
	}
	// Forward the validated mask to the daemon only when the operator
	// explicitly provided a cold-path flag. nil means "use the
	// userspace-dp built-in default" so older daemons that omit the
	// flag never accidentally serialize 0 and trigger 1-in-1 sampling.
	var coldPathMaskPtr *uint64
	flag.Visit(func(f *flag.Flag) {
		if f.Name == flagColdPathSampleMask || f.Name == flagColdPath1in1 {
			m := effectiveMask
			coldPathMaskPtr = &m
		}
	})

	// Set up structured logging
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))

	d, err := daemon.New(daemon.Options{
		ConfigFile:         *configFile,
		NoDataplane:        *noDataplane,
		APIAddr:            *apiAddr,
		GRPCAddr:           *grpcAddr,
		Version:            version,
		ColdPathSampleMask: coldPathMaskPtr,
	})
	if err != nil {
		// #1893: fail closed — a daemon that cannot persist config must
		// not boot pretending otherwise.
		fmt.Fprintf(os.Stderr, "xpfd: %v\n", err)
		os.Exit(1)
	}

	if err := d.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "xpfd: %v\n", err)
		os.Exit(1)
	}
}
