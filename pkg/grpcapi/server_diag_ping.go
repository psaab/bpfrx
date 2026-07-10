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

// maxDiagField bounds every operator-supplied diag argument (target, source,
// routing-instance). It is far below the line-scanner token cap
// (diagScanMaxBuf) so a legitimate hostname (RFC 1035 caps at 253), IP literal,
// or VRF name always fits, while a pathological oversized field — the gRPC recv
// cap is 16 MiB — is rejected at the RPC boundary rather than reaching exec or
// the combined-output line scanner as a single >64 KiB line (#5060).
const maxDiagField = 256

// diagScanInitBuf / diagScanMaxBuf size the combined-output line scanner in
// streamDiagCmd. The max is set explicitly (rather than relying on the bufio
// default) to make the per-line ceiling a deliberate, documented bound: a line
// beyond it is a controlled bufio.ErrTooLong that the streamDiagCmd cleanup
// path handles without leaking the child/goroutine (#5060).
const (
	diagScanInitBuf = 4 << 10  // 4 KiB initial
	diagScanMaxBuf  = 64 << 10 // 64 KiB hard per-line cap
)

// validateDiagField rejects an over-length diag argument with InvalidArgument.
func validateDiagField(name, v string) error {
	if len(v) > maxDiagField {
		return status.Errorf(codes.InvalidArgument, "%s too long (%d > %d bytes)", name, len(v), maxDiagField)
	}
	return nil
}

func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := validateDiagField("target", req.Target); err != nil {
		return err
	}
	if err := validateDiagField("source", req.Source); err != nil {
		return err
	}
	if err := validateDiagField("routing-instance", req.RoutingInstance); err != nil {
		return err
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
	if err := validateDiagField("target", req.Target); err != nil {
		return err
	}
	if err := validateDiagField("source", req.Source); err != nil {
		return err
	}
	if err := validateDiagField("routing-instance", req.RoutingInstance); err != nil {
		return err
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
	// Bound the per-line token deliberately (#5060): a combined-output line
	// larger than diagScanMaxBuf is a controlled bufio.ErrTooLong, not an
	// unbounded allocation. Diag output lines are short, so 64 KiB is generous.
	scanner.Buffer(make([]byte, 0, diagScanInitBuf), diagScanMaxBuf)
	scanDone := make(chan error, 1)
	go func() {
		// #5060: own and close BOTH pipe ends on EVERY scanner exit — the
		// send-failure path AND the scanner-error/EOF path — not just the
		// former. On a scanner error (e.g. bufio.ErrTooLong from a line beyond
		// diagScanMaxBuf) the goroutine stops reading pr; without this close,
		// exec.Cmd's internal copy goroutine stays blocked in pw.Write
		// (WaitDelay only closes the exec-owned OS pipes, not this io.Pipe), so
		// c.Wait() below never returns and the RPC + goroutine leak past the
		// deadline. pr.Close() makes that blocked write return ErrClosedPipe;
		// cancel() kills the child promptly. Both are idempotent and harmless
		// on the normal-EOF path (child already exited, pr already at EOF).
		defer func() {
			cancel()
			pr.Close()
		}()
		for scanner.Scan() {
			if err := sendFn(scanner.Text()); err != nil {
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
