// bpfrxd is the bpfrx firewall daemon.
//
// It provides a Junos-style CLI for configuring an eBPF-based firewall
// that replicates Juniper vSRX capabilities.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/bpfrx/pkg/daemon"
	"github.com/psaab/bpfrx/pkg/dataplane"
	_ "github.com/psaab/bpfrx/pkg/dataplane/dpdk"
	_ "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/frr"
)

// Version information set at build time via ldflags.
var (
	version   = "dev"
	buildTime = "unknown"
	commit    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("bpfrxd %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		if err := dataplane.Cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup BPF: %v\n", err)
			os.Exit(1)
		}
		// Remove fabric IPVLAN interfaces created by the daemon.
		daemon.CleanupFabricIPVLANs()
		// Also clear FRR managed routes so the kernel routing table is clean.
		frr.New().Clear()
		fmt.Println("all pinned BPF state and managed routes removed")
		return
	}

	// Reject unknown positional arguments — prevents accidentally starting
	// a second daemon when running "bpfrxd show ..." outside the CLI.
	// Use the "cli" binary or run bpfrxd interactively for show/request/configure.
	if len(os.Args) > 1 && os.Args[1] != "" && os.Args[1][0] != '-' {
		fmt.Fprintf(os.Stderr, "bpfrxd: unknown command %q\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "  use the 'cli' binary for remote commands, or run bpfrxd on a TTY\n")
		os.Exit(1)
	}

	configFile := flag.String("config", "/etc/bpfrx/bpfrx.conf", "configuration file path")
	noDataplane := flag.Bool("no-dataplane", false, "run without eBPF (config-only mode)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "HTTP API listen address (empty to disable)")
	grpcAddr := flag.String("grpc-addr", "127.0.0.1:50051", "gRPC API listen address")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	// Set up structured logging
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))

	d := daemon.New(daemon.Options{
		ConfigFile:  *configFile,
		NoDataplane: *noDataplane,
		APIAddr:     *apiAddr,
		GRPCAddr:    *grpcAddr,
		Version:     version,
	})

	if err := d.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "bpfrxd: %v\n", err)
		os.Exit(1)
	}
}
