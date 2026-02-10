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
)

func main() {
	configFile := flag.String("config", "/etc/bpfrx/bpfrx.conf", "configuration file path")
	noDataplane := flag.Bool("no-dataplane", false, "run without eBPF (config-only mode)")
	apiAddr := flag.String("api-addr", "", "HTTP API listen address (e.g. 127.0.0.1:8080)")
	grpcAddr := flag.String("grpc-addr", "", "gRPC API listen address (e.g. 127.0.0.1:50051)")
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
	})

	if err := d.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "bpfrxd: %v\n", err)
		os.Exit(1)
	}
}
