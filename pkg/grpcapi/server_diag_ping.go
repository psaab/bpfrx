package grpcapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Diagnostic RPCs ---

func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	count := int(req.Count)
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}
	cmd := buildPingArgv(req, count)

	return streamDiagCmd(stream.Context(), pingExecTimeout(count), cmd, func(line string) error {
		return stream.Send(&pb.PingResponse{Output: line})
	})
}

// buildPingArgv builds the argv for the gRPC Ping diag. It delegates to
// the shared diagcmd builder so the VRF-device normalization (apply
// "vrf-" exactly once, #2143) and the "--" end-of-options separator
// (option-confusion hardening, #2084) match the CLI and REST surfaces
// byte-for-byte. count is the already-clamped probe count.
func buildPingArgv(req *pb.PingRequest, count int) []string {
	size := ""
	if req.Size > 0 {
		size = fmt.Sprintf("%d", req.Size)
	}
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          req.Target,
		Count:           fmt.Sprintf("%d", count),
		Source:          req.Source,
		Size:            size,
		RoutingInstance: req.RoutingInstance,
	})
}

func (s *Server) Traceroute(req *pb.TracerouteRequest, stream grpc.ServerStreamingServer[pb.TracerouteResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	cmd := buildTracerouteArgv(req)

	return streamDiagCmd(stream.Context(), diagTracerouteTimeout, cmd, func(line string) error {
		return stream.Send(&pb.TracerouteResponse{Output: line})
	})
}

// buildTracerouteArgv builds the argv for the gRPC Traceroute diag.
// Like buildPingArgv it delegates to the shared diagcmd builder so VRF
// normalization (#2143) and the "--" separator (#2084) stay identical
// across the CLI, REST, and gRPC surfaces.
func buildTracerouteArgv(req *pb.TracerouteRequest) []string {
	return diagcmd.TracerouteArgv(diagcmd.TracerouteOptions{
		Target:          req.Target,
		Source:          req.Source,
		RoutingInstance: req.RoutingInstance,
	})
}

// streamDiagCmd runs a command and streams each line of combined output
// via sendFn. timeout is request-sized by the caller (#1819, see the
// diag-stream budget block in exec_timeout.go); it is always capped at
// diagExecCeiling so a pathological request cannot pin the handler.
func streamDiagCmd(ctx context.Context, timeout time.Duration, cmd []string, sendFn func(string) error) error {
	ctx, cancelTimeout := context.WithTimeout(ctx, clampDiagTimeout(timeout))
	defer cancelTimeout()
	// Cancelable layer for the send-failure path: when sendFn fails the
	// scanner goroutine stops reading the pipe, so without an explicit
	// cancel the child would block on writes until the deadline killed
	// it — cancel here makes CommandContext kill it promptly (#1819).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	// U3 parity (#1805): cap the post-kill pipe-drain window so a child
	// that inherited the output pipe cannot block Wait past the ctx kill.
	c.WaitDelay = requestExecWaitDelay

	// Merge stdout and stderr into a single pipe.
	pr, pw := io.Pipe()
	c.Stdout = pw
	c.Stderr = pw

	if err := c.Start(); err != nil {
		return status.Errorf(codes.Internal, "exec: %v", err)
	}

	// Scan lines and stream each one.
	scanner := bufio.NewScanner(pr)
	scanDone := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			if err := sendFn(scanner.Text()); err != nil {
				// Nobody reads the pipe after this point — kill the
				// child now instead of letting it block on writes for
				// the rest of the budget, AND close the read end:
				// exec.Cmd's internal copy goroutine may already be
				// blocked in pw.Write on a burst the scanner never
				// consumed, and WaitDelay only closes the exec-owned
				// OS pipes, not this io.Pipe — pr.Close makes that
				// blocked write return ErrClosedPipe so c.Wait can
				// finish (Codex review on PR #1823).
				cancel()
				pr.Close()
				scanDone <- err
				return
			}
		}
		scanDone <- scanner.Err()
	}()

	// Wait for the command to finish, then close the write end so scanner terminates.
	cmdErr := c.Wait()
	pw.Close()
	scanErr := <-scanDone

	if scanErr != nil {
		return scanErr
	}
	if cmdErr != nil {
		// Send the exit error as a final line rather than failing the RPC,
		// so the client still sees partial output (e.g. "ping: unknown host").
		_ = sendFn(cmdErr.Error())
	}
	return nil
}
