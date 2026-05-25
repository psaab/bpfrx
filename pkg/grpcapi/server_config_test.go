package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func newGRPCCommitWarningStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system dataplane-type ebpf"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	return store
}

func TestCommitCheckReturnsValidationWarnings(t *testing.T) {
	s := &Server{store: newGRPCCommitWarningStore(t)}

	resp, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
	if err != nil {
		t.Fatalf("CommitCheck() error = %v", err)
	}
	if !grpcWarningsContain(resp.GetWarnings(), "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.GetWarnings())
	}
}

func TestCommitReturnsValidationWarnings(t *testing.T) {
	store := newGRPCCommitWarningStore(t)
	s := &Server{
		store: store,
		commitFn: func(context.Context, string) (*config.Config, error) {
			return store.Commit()
		},
	}

	resp, err := s.Commit(context.Background(), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if !grpcWarningsContain(resp.GetWarnings(), "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.GetWarnings())
	}
}

func TestCommitConfirmedReturnsValidationWarnings(t *testing.T) {
	store := newGRPCCommitWarningStore(t)
	s := &Server{
		store: store,
		commitConfirmedFn: func(context.Context, int) (*config.Config, error) {
			return store.CommitConfirmed(10)
		},
	}

	resp, err := s.CommitConfirmed(context.Background(), &pb.CommitConfirmedRequest{Minutes: 10})
	if err != nil {
		t.Fatalf("CommitConfirmed() error = %v", err)
	}
	if !grpcWarningsContain(resp.GetWarnings(), "system dataplane-type ebpf selects") {
		t.Fatalf("warnings = %v, want explicit ebpf warning", resp.GetWarnings())
	}
}

func grpcWarningsContain(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

// TestCompileCheckMultiErrorRendersThroughGRPC verifies that
// #1538's accumulator multi-error renders correctly through the
// gRPC CommitCheck handler. Two independent strict-validator
// families (CoS equal-flow-enforcement + three-color-policer
// missing committed-information-rate) must produce one
// codes.InvalidArgument status whose message contains BOTH
// validator substrings separated by exactly one '\n'. Captures
// the actual operator-facing surface rendered by
// pkg/grpcapi/server_config.go:176 (`status.Errorf(codes.
// InvalidArgument, "%v", err)`).
//
// Direct-handler style per the existing pattern in this file —
// no bufconn. Same fixture as
// pkg/config/compiler_test.go::TestCompileMultipleStrictErrorsAccumulated
// so the two tests pin the same UX contract at two layers.
func TestCompileCheckMultiErrorRendersThroughGRPC(t *testing.T) {
	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	setLines := []string{
		"set system dataplane-type userspace",
		"set class-of-service schedulers bad-sched equal-flow-enforcement",
		"set firewall three-color-policer bad-pol single-rate color-blind",
		"set firewall three-color-policer bad-pol then discard",
	}
	for _, line := range setLines {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}

	s := &Server{store: store}
	_, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
	if err == nil {
		t.Fatal("CommitCheck() succeeded; expected accumulated strict-validator error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("CommitCheck() error is not a *status.Status: %T (%v)", err, err)
	}
	if got, want := st.Code(), codes.InvalidArgument; got != want {
		t.Errorf("status.Code() = %v, want %v", got, want)
	}

	msg := st.Message()
	if !strings.Contains(msg, "equal-flow-enforcement") {
		t.Errorf("status.Message() missing CoS substring 'equal-flow-enforcement': %q", msg)
	}
	if !strings.Contains(msg, "committed-information-rate") {
		t.Errorf("status.Message() missing policer substring 'committed-information-rate': %q", msg)
	}
	// Exactly one '\n' separator → exactly two joined errors
	// rendered into the gRPC status message via %v.
	if got, want := strings.Count(msg, "\n"), 1; got != want {
		t.Errorf("newline count = %d, want %d (one '\\n' between two joined errors): %q",
			got, want, msg)
	}
}
