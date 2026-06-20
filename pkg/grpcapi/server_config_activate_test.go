package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// newGRPCConfigStore returns a store in config mode with an active
// system/name-server node staged, for activate/deactivate routing tests.
func newGRPCConfigStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set system host-name keep",
		"set system name-server 9.9.9.9",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	return store
}

// #2051 anti-mangling regression: the gRPC Set RPC must prefix-route a
// `deactivate <path>` input to DeactivateFromInput so the node becomes ACTUALLY
// inactive. Before the fix it fell through to SetFromInput, which parsed
// `set deactivate <path>` and created a junk config node named "deactivate".
// The assertion is on real inactivation (display-set emits `deactivate <path>`
// only for an Inactive node), NOT merely a nil error — a no-error test would
// have passed against the broken mangling behavior.
func TestSetRPCDeactivateRoutesNotMangled(t *testing.T) {
	store := newGRPCConfigStore(t)
	s := &Server{store: store}

	if _, err := s.Set(context.Background(), &pb.SetRequest{
		Input: "deactivate system name-server 9.9.9.9",
	}); err != nil {
		t.Fatalf("Set(deactivate ...) error = %v", err)
	}

	out := store.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("Set RPC did not actually mark the node inactive:\n%s", out)
	}
	// The smoking gun for the mangling regression: a node named "deactivate".
	if strings.Contains(out, "set deactivate ") {
		t.Fatalf("deactivate input mangled into a junk set path:\n%s", out)
	}
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("active sibling lost:\n%s", out)
	}
}

// The gRPC Set RPC must round-trip activate back to active.
func TestSetRPCActivateRoutesNotMangled(t *testing.T) {
	store := newGRPCConfigStore(t)
	s := &Server{store: store}

	if _, err := s.Set(context.Background(), &pb.SetRequest{
		Input: "deactivate system name-server 9.9.9.9",
	}); err != nil {
		t.Fatalf("Set(deactivate ...) error = %v", err)
	}
	if _, err := s.Set(context.Background(), &pb.SetRequest{
		Input: "activate system name-server 9.9.9.9",
	}); err != nil {
		t.Fatalf("Set(activate ...) error = %v", err)
	}

	out := store.ShowCandidateSet()
	if strings.Contains(out, "deactivate ") {
		t.Fatalf("activate via Set RPC did not clear the marker:\n%s", out)
	}
	if strings.Contains(out, "set activate ") {
		t.Fatalf("activate input mangled into a junk set path:\n%s", out)
	}
}

// #2052: the gRPC Load RPC with mode=="set" must replay flat lines through
// LoadSet so a body containing `deactivate <path>` reconstructs an inactive
// node. Before the fix mode=="set" hit the default branch and was rejected.
func TestLoadRPCModeSetAppliesDeactivate(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}

	body := strings.Join([]string{
		"set system host-name keep",
		"set system name-server 9.9.9.9",
		"deactivate system name-server 9.9.9.9",
	}, "\n")

	if _, err := s.Load(context.Background(), &pb.LoadRequest{Mode: "set", Content: body}); err != nil {
		t.Fatalf("Load(mode=set) error = %v", err)
	}

	out := store.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("Load mode=set did not preserve the deactivate marker:\n%s", out)
	}
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("Load mode=set dropped an active node:\n%s", out)
	}
}
