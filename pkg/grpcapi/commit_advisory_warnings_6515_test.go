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

// #6515 requirement (b), transport half. The local CLI prints config warnings
// on the bare-commit path (pkg/cli guards that), but the operator who runs the
// `cli` binary reaches the daemon over gRPC, and a warning that never leaves
// the daemon cannot be printed by anything downstream. CommitResponse.Warnings
// is that carrier: gate the transport and everything it carries is gated.
//
// The advisory says a per-interface host-inbound-traffic stanza REPLACES the
// zone-level one — so services the zone admits are DENIED on that interface,
// and established sessions to them are FLUSHED at commit (#5566) rather than
// merely refused for new connections.
//
// SCOPE, stated because the first draft of this file got it wrong. The RPC
// handlers do not commit anything themselves: they delegate to the daemon-
// supplied commitFn / commitConfirmedFn seams and project whatever config
// those return through configWarnings(). A fixture that leaves those seams nil
// gets `commit handler not wired` — an Internal error from the fixture, NOT
// evidence that the RPC drops warnings. These tests wire the seams to the same
// store commit the daemon's seam ultimately performs, so what is pinned here is
// the handler's own projection: that each of the three commit RPCs returns the
// compiled config's warnings rather than only CommitCheck doing so. The
// daemon-side seams (grpcCommitFn -> commitAndApplyOperator) are separately
// covered in pkg/daemon.

// hostInboundNarrowingStore stages a candidate whose interface stanza takes
// `ssh` away from an interface the zone admits it on, with the commit seams
// wired the way the daemon wires them.
func hostInboundNarrowingStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	return &Server{
		store: store,
		commitFn: func(_ context.Context, _ configstore.CommitAuthority, comment string) (*config.Config, error) {
			if comment != "" {
				return store.CommitWithDescription(comment)
			}
			return store.Commit()
		},
		commitConfirmedFn: func(_ context.Context, _ configstore.CommitAuthority, minutes int) (*config.Config, error) {
			return store.CommitConfirmed(minutes)
		},
	}
}

// assertNarrowingWarning checks a Warnings slice carries the advisory, names
// what is being taken away, and says established sessions are flushed. The
// flush clause is checked on its own because it is the half an operator's
// instinct gets wrong: "ssh is no longer admitted here" invites "fine, I am
// already connected", which is false.
func assertNarrowingWarning(t *testing.T, rpc string, warnings []string) {
	t.Helper()
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		"REPLACES the zone-level stanza",
		`zone "trust"`,
		`interface "ge-0/0/0.0"`,
		"ssh",
		"flushed",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s response warnings do not mention %q — a warning the daemon does not "+
				"return cannot be printed by the remote CLI.\n--- warnings ---\n%s",
				rpc, want, joined)
		}
	}
}

// TestCommitRPCReturnsHostInboundNarrowingWarning_6515 is the requirement: the
// warning rides the COMMIT response, not only the commit-check one.
func TestCommitRPCReturnsHostInboundNarrowingWarning_6515(t *testing.T) {
	s := hostInboundNarrowingStore(t)
	resp, err := s.Commit(context.Background(), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("Commit: %v (the advisory is WARN-only and must never reject)", err)
	}
	assertNarrowingWarning(t, "Commit", resp.GetWarnings())
}

// TestCommitCheckRPCReturnsHostInboundNarrowingWarning_6515 is the control: the
// check RPC carries it too, so a regression that moved the warning to
// commit-only would not read as a pass here.
func TestCommitCheckRPCReturnsHostInboundNarrowingWarning_6515(t *testing.T) {
	s := hostInboundNarrowingStore(t)
	resp, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	assertNarrowingWarning(t, "CommitCheck", resp.GetWarnings())
}

// TestCommitConfirmedRPCReturnsHostInboundNarrowingWarning_6515 covers the
// third entry point. `commit confirmed` is what an operator reaches for when
// they suspect a change may lock them out, so an advisory about lockout that
// went missing precisely there would be the worst of the three gaps.
func TestCommitConfirmedRPCReturnsHostInboundNarrowingWarning_6515(t *testing.T) {
	s := hostInboundNarrowingStore(t)
	resp, err := s.CommitConfirmed(context.Background(), &pb.CommitConfirmedRequest{Minutes: 5})
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	assertNarrowingWarning(t, "CommitConfirmed", resp.GetWarnings())
}
