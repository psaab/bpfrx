package grpcapi

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #6495: `show system kernel-upgrade` over the gRPC ShowText path.
//
// Before this the ONLY readout of the #1930 kernel channel was a root shell
// running `xpfd upgrade kernel status`, or journald — while the xpf-deploy roll
// orchestrator polled that same verb over node_exec. Automation had a path; the
// human operator did not, during exactly the maintenance window where they are
// most anxious about node state.

// Constructed through NewServer, not a bare &Server{...}: the wiring under test
// is Config.KernelUpgradeStatusFn -> server.kernelUpgradeStatusFn, and a test
// that sets the private field directly passes with that assignment deleted.
func newKernelUpgradeServer(t *testing.T, st upgrade.ChannelStatus) *Server {
	t.Helper()
	return NewServer("127.0.0.1:0", Config{
		Store:                 newConfigStore(t, t.TempDir()+"/xpf.conf"),
		KernelUpgradeStatusFn: func() upgrade.ChannelStatus { return st },
	})
}

func TestShowTextKernelUpgradeRendersTheWiredSnapshot(t *testing.T) {
	s := newKernelUpgradeServer(t, upgrade.ChannelStatus{
		Armed: true,
		Journal: upgrade.KernelJournal{
			CandidateVersion: "6.19.0-1-generic",
			KnownGoodVersion: "6.18.4-11-generic",
			ActiveSlot:       upgrade.SlotA, InactiveSlot: upgrade.SlotB,
			State: upgrade.KernelStateArmed,
		},
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "kernel-upgrade"})
	if err != nil {
		t.Fatalf("ShowText(kernel-upgrade) error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{"6.19.0-1-generic", "6.18.4-11-generic", "IN FLIGHT"} {
		if !strings.Contains(out, want) {
			t.Errorf("wired snapshot not rendered (missing %q):\n%s", want, out)
		}
	}
}

// The post-revert case: the journal is cleared by design, so without the
// durable last-roll record this renders as a box that never tried.
func TestShowTextKernelUpgradeRendersThePostRevertHistory(t *testing.T) {
	s := newKernelUpgradeServer(t, upgrade.ChannelStatus{
		LastRoll: upgrade.KernelRollOutcome{
			Version: "6.19.0-1-generic", KnownGood: "6.18.4-11-generic",
			Outcome: upgrade.RollOutcomeReverted,
			Reason:  "forward beacon FAILED on candidate kernel",
			UnixSec: 1755792000,
		},
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "kernel-upgrade"})
	if err != nil {
		t.Fatalf("ShowText: %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "reverted") || !strings.Contains(out, "forward beacon FAILED") {
		t.Errorf("post-revert history not rendered — this is the amnesia #6495 "+
			"exists to fix:\n%s", out)
	}
}

// Byte-identical to pkg/upgrade's renderer, so the remote `cli`, the console
// CLI and the shell verb cannot tell an operator three different things about
// one node mid-roll.
func TestShowTextKernelUpgradeMatchesTheSharedRenderer(t *testing.T) {
	for _, st := range []upgrade.ChannelStatus{
		{},
		{Armed: true, Journal: upgrade.KernelJournal{
			CandidateVersion: "c", KnownGoodVersion: "k",
			ActiveSlot: upgrade.SlotA, InactiveSlot: upgrade.SlotB,
			State: upgrade.KernelStateArmed}},
		{PromotedVersion: "6.19.0-1-generic"},
		{LastRoll: upgrade.KernelRollOutcome{
			Version: "c", Outcome: upgrade.RollOutcomeReverted,
			Reason: "why", UnixSec: 1755792000}},
		{HoldReason: "held for a reason"},
	} {
		s := newKernelUpgradeServer(t, st)
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "kernel-upgrade"})
		if err != nil {
			t.Fatalf("ShowText: %v", err)
		}
		var want bytes.Buffer
		upgrade.RenderChannelStatus(&want, st)
		if resp.GetOutput() != want.String() {
			t.Errorf("ShowText render diverges from RenderChannelStatus\n"+
				"--- ShowText ---\n%s\n--- shared ---\n%s",
				resp.GetOutput(), want.String())
		}
	}
}

// A no-daemon build must still render an answer rather than an empty body an
// operator would read as "nothing to report".
func TestShowTextKernelUpgradeWithNoHookStillRenders(t *testing.T) {
	s := NewServer("127.0.0.1:0", Config{
		Store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "kernel-upgrade"})
	if err != nil {
		t.Fatalf("ShowText with nil hook: %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "no candidate kernel is armed") {
		t.Errorf("nil hook must render an idle channel:\n%s", resp.GetOutput())
	}
}
