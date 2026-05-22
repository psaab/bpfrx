package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

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
