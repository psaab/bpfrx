// Pin the CLI success-marker contract that test/incus/cos-apply-lib.sh depends
// on (#6440).
//
// `apply-cos-config.sh` drives this binary by piping a heredoc into it. That
// form is a REPL: main's read loop prints "error: %v" for a failed command,
// CONTINUES to the next line, and the process still exits 0. So the script
// cannot gate on the session's exit status — it gates on the success markers
// these handlers print instead.
//
// That makes the marker STRINGS a cross-language contract. Reword one here and
// the shell gate silently stops detecting failures: it would keep looking for
// text the CLI no longer emits, fail every apply, or — worse for the reverse
// edit — accept a failed apply. These tests fix both halves of the contract:
//
//	(a) on SUCCESS the exact marker is printed, and
//	(b) on FAILURE it is NOT printed (an error is returned instead).
//
// (b) is the load-bearing half. A gate keyed on a marker the CLI prints
// unconditionally would be vacuous.
//
// Keep the constants below in sync with COS_MARKER_* in
// test/incus/cos-apply-lib.sh.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// The marker strings test/incus/cos-apply-lib.sh greps for.
const (
	cosMarkerLoadMerge   = "load merge complete"
	cosMarkerCommitCheck = "configuration check succeeds"
	cosMarkerCommit      = "commit complete"
	cosMarkerRollback    = "configuration rolled back"
)

// markerClient stubs the four config RPCs the CoS apply path uses. Each can be
// switched to fail so the same call site is exercised on both paths.
type markerClient struct {
	pb.BpfrxServiceClient

	loadErr     error
	checkErr    error
	commitErr   error
	rollbackErr error
}

func (m *markerClient) Load(_ context.Context, _ *pb.LoadRequest, _ ...grpc.CallOption) (*pb.LoadResponse, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return &pb.LoadResponse{}, nil
}

func (m *markerClient) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest, _ ...grpc.CallOption) (*pb.CommitCheckResponse, error) {
	if m.checkErr != nil {
		return nil, m.checkErr
	}
	return &pb.CommitCheckResponse{}, nil
}

func (m *markerClient) Commit(_ context.Context, _ *pb.CommitRequest, _ ...grpc.CallOption) (*pb.CommitResponse, error) {
	if m.commitErr != nil {
		return nil, m.commitErr
	}
	return &pb.CommitResponse{}, nil
}

func (m *markerClient) Rollback(_ context.Context, _ *pb.RollbackRequest, _ ...grpc.CallOption) (*pb.RollbackResponse, error) {
	if m.rollbackErr != nil {
		return nil, m.rollbackErr
	}
	return &pb.RollbackResponse{}, nil
}

// GetStatus backs refreshPrompt() on the commit success path.
func (m *markerClient) GetStatus(_ context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// captureDispatch runs c.dispatch(line) with stdout redirected, returning what
// was printed plus the dispatch error.
func captureDispatch(t *testing.T, c *ctl, line string) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	dispatchErr := c.dispatch(line)

	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	r.Close()
	return buf.String(), dispatchErr
}

// hasMarkerLine mirrors cos_transcript_has_marker: the marker must start a
// LINE, not merely appear somewhere in the output.
func hasMarkerLine(out, marker string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, marker) {
			return true
		}
	}
	return false
}

// A `load merge <file>` that the daemon accepts must print the exact marker.
func TestLoadMergePrintsMarkerOnSuccess_6440(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sets")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := f.WriteString("set class-of-service interfaces reth0 unit 80 shaping-rate 25g\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	c := configModeCtl(&markerClient{})
	out, err := captureDispatch(t, c, "load merge "+f.Name())
	if err != nil {
		t.Fatalf("load merge must succeed, got: %v", err)
	}
	if !hasMarkerLine(out, cosMarkerLoadMerge) {
		t.Fatalf("load merge success must print %q at line start; got:\n%s", cosMarkerLoadMerge, out)
	}
}

// ...and a `load merge` the daemon REJECTS must NOT print it. This is the
// #6440 case: the REPL prints an error and continues, so the marker's absence
// is the only in-band signal the shell gate can key on.
func TestLoadMergeWithholdsMarkerOnFailure_6440(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sets")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := f.WriteString("set class-of-service interfaces reth0 unit 80 shaping-rate 25g\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	c := configModeCtl(&markerClient{loadErr: fmt.Errorf("line 12: not a set/delete command")})
	out, err := captureDispatch(t, c, "load merge "+f.Name())
	if err == nil {
		t.Fatal("a rejected load merge must return an error")
	}
	if hasMarkerLine(out, cosMarkerLoadMerge) {
		t.Fatalf("a FAILED load merge must NOT print %q; got:\n%s", cosMarkerLoadMerge, out)
	}
}

func TestCommitCheckMarkerContract_6440(t *testing.T) {
	c := configModeCtl(&markerClient{})
	out, err := captureDispatch(t, c, "commit check")
	if err != nil {
		t.Fatalf("commit check must succeed, got: %v", err)
	}
	if !hasMarkerLine(out, cosMarkerCommitCheck) {
		t.Fatalf("commit check success must print %q; got:\n%s", cosMarkerCommitCheck, out)
	}

	c = configModeCtl(&markerClient{checkErr: fmt.Errorf("zone trust references undefined policy")})
	out, err = captureDispatch(t, c, "commit check")
	if err == nil {
		t.Fatal("a failed commit check must return an error")
	}
	if hasMarkerLine(out, cosMarkerCommitCheck) {
		t.Fatalf("a FAILED commit check must NOT print %q; got:\n%s", cosMarkerCommitCheck, out)
	}
}

func TestCommitMarkerContract_6440(t *testing.T) {
	c := configModeCtl(&markerClient{})
	out, err := captureDispatch(t, c, "commit")
	if err != nil {
		t.Fatalf("commit must succeed, got: %v", err)
	}
	if !hasMarkerLine(out, cosMarkerCommit) {
		t.Fatalf("commit success must print %q; got:\n%s", cosMarkerCommit, out)
	}

	c = configModeCtl(&markerClient{commitErr: fmt.Errorf("dataplane apply failed")})
	out, err = captureDispatch(t, c, "commit")
	if err == nil {
		t.Fatal("a failed commit must return an error")
	}
	if hasMarkerLine(out, cosMarkerCommit) {
		t.Fatalf("a FAILED commit must NOT print %q; got:\n%s", cosMarkerCommit, out)
	}
}

func TestRollbackMarkerContract_6440(t *testing.T) {
	c := configModeCtl(&markerClient{})
	out, err := captureDispatch(t, c, "rollback 1")
	if err != nil {
		t.Fatalf("rollback must succeed, got: %v", err)
	}
	if !hasMarkerLine(out, cosMarkerRollback) {
		t.Fatalf("rollback success must print %q; got:\n%s", cosMarkerRollback, out)
	}

	c = configModeCtl(&markerClient{rollbackErr: fmt.Errorf("no previous configuration")})
	out, err = captureDispatch(t, c, "rollback 1")
	if err == nil {
		t.Fatal("a failed rollback must return an error")
	}
	if hasMarkerLine(out, cosMarkerRollback) {
		t.Fatalf("a FAILED rollback must NOT print %q; got:\n%s", cosMarkerRollback, out)
	}
}

// The shell gate and this file must agree on the literal strings. Read them
// back out of the library so a one-sided rename fails here instead of silently
// disarming the gate on the cluster.
func TestShellGateMarkersMatchCLI_6440(t *testing.T) {
	data, err := os.ReadFile("../../test/incus/cos-apply-lib.sh")
	if err != nil {
		t.Fatalf("read cos-apply-lib.sh: %v", err)
	}
	lib := string(data)
	for _, want := range []struct{ shellVar, marker string }{
		{"COS_MARKER_LOAD_MERGE", cosMarkerLoadMerge},
		{"COS_MARKER_COMMIT_CHECK", cosMarkerCommitCheck},
		{"COS_MARKER_COMMIT", cosMarkerCommit},
		{"COS_MARKER_ROLLBACK", cosMarkerRollback},
	} {
		assign := fmt.Sprintf("%s=%q", want.shellVar, want.marker)
		if !strings.Contains(lib, assign) {
			t.Errorf("test/incus/cos-apply-lib.sh must define %s — the CLI prints %q but the shell gate does not grep for it",
				assign, want.marker)
		}
	}
}
