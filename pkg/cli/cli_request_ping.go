package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

func (c *CLI) handlePing(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: ping <target> [count <N>] [source <IP>] [size <N>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	count := "5"
	source := ""
	size := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "count":
			count = args[i+1]
			i++
		case "source":
			source = args[i+1]
			i++
		case "size":
			size = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	cmdArgs := buildPingArgv(target, count, source, size, vrfName)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

// buildPingArgv builds the argv for the local CLI ping command. It
// delegates to the shared diagcmd builder so the VRF-device
// normalization (apply "vrf-" exactly once, #2143) and the "--"
// end-of-options separator (#2084) match the REST and gRPC surfaces
// byte-for-byte. Before #2143 this path prepended "vrf-"
// unconditionally, turning `routing-instance vrf-red` into the
// non-existent device `vrf-vrf-red`.
func buildPingArgv(target, count, source, size, vrfName string) []string {
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          target,
		Count:           count,
		Source:          source,
		Size:            size,
		RoutingInstance: vrfName,
	})
}

func (c *CLI) handleTraceroute(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: traceroute <target> [source <IP>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	source := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "source":
			source = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	cmdArgs := buildTracerouteArgv(target, source, vrfName)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

// buildTracerouteArgv builds the argv for the local CLI traceroute
// command. Like buildPingArgv it delegates to the shared diagcmd builder
// so VRF normalization (#2143) and the "--" separator (#2084) stay
// identical across the CLI, REST, and gRPC surfaces.
func buildTracerouteArgv(target, source, vrfName string) []string {
	return diagcmd.TracerouteArgv(diagcmd.TracerouteOptions{
		Target:          target,
		Source:          source,
		RoutingInstance: vrfName,
	})
}
