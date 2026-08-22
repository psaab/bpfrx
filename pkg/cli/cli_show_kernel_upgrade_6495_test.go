package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade"
)

// #6495: `show system kernel-upgrade` on the in-process console CLI.
// Uses the package-local captureStdout helper (cluster_failover_test.go).

// Wired through SetKernelUpgradeStatusFn, NOT by assigning the private field:
// the setter is the seam the daemon uses, and a test that writes the field
// directly stays green with the setter's body emptied.
func TestHandleShowSystemDispatchesKernelUpgrade(t *testing.T) {
	c := &CLI{}
	c.SetKernelUpgradeStatusFn(func() upgrade.ChannelStatus {
		return upgrade.ChannelStatus{
			Armed: true,
			Journal: upgrade.KernelJournal{
				CandidateVersion: "6.19.0-1-generic",
				KnownGoodVersion: "6.18.4-11-generic",
				ActiveSlot:       upgrade.SlotA, InactiveSlot: upgrade.SlotB,
				State: upgrade.KernelStateArmed,
			},
			HoldReason: "kernel-candidate promotion gate (test literal)",
		}
	})
	var err error
	out := captureStdout(t, func() { err = c.handleShowSystem([]string{"kernel-upgrade"}) })
	if err != nil {
		t.Fatalf("handleShowSystem(kernel-upgrade) error = %v", err)
	}
	if !strings.Contains(out, "6.19.0-1-generic") {
		t.Errorf("armed candidate not rendered on the console path:\n%s", out)
	}
	if !strings.Contains(out, "HELD SECONDARY") {
		t.Errorf("the election hold must be visible where the operator is "+
			"standing during a roll:\n%s", out)
	}
}

// Byte-identical to the shared renderer, which the gRPC path also emits.
func TestConsoleKernelUpgradeMatchesTheSharedRenderer(t *testing.T) {
	for _, st := range []upgrade.ChannelStatus{
		{},
		{Armed: true, Journal: upgrade.KernelJournal{
			CandidateVersion: "c", State: upgrade.KernelStateArmed}},
		{LastRoll: upgrade.KernelRollOutcome{
			Version: "c", Outcome: upgrade.RollOutcomeReverted, UnixSec: 1755792000}},
	} {
		c := &CLI{}
		c.SetKernelUpgradeStatusFn(func() upgrade.ChannelStatus { return st })
		out := captureStdout(t, func() { _ = c.handleShowSystem([]string{"kernel-upgrade"}) })
		var want bytes.Buffer
		upgrade.RenderChannelStatus(&want, st)
		if out != want.String() {
			t.Errorf("console render diverges from RenderChannelStatus\n"+
				"--- console ---\n%s\n--- shared ---\n%s", out, want.String())
		}
	}
}

func TestConsoleKernelUpgradeWithNoHookStillRenders(t *testing.T) {
	c := &CLI{}
	out := captureStdout(t, func() { _ = c.handleShowSystem([]string{"kernel-upgrade"}) })
	if !strings.Contains(out, "no candidate kernel is armed") {
		t.Errorf("nil hook must render an idle channel:\n%s", out)
	}
}
