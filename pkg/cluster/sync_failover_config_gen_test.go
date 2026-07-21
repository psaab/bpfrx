package cluster

import (
	"strings"
	"testing"
)

// #5563 — planned/manual failover readiness must refuse a config-stale standby.
//
// Before this fix, TransferReadinessSnapshot.ReadyForManualFailover() was
// defined SOLELY in terms of session bulk state (PendingBulkAckEpoch /
// BulkReceiveInProgress). It carried NEITHER the config sender's current
// committed generation NOR the receiver's successfully-applied generation, so a
// standby could be promoted while running an OLDER policy/zone/application
// snapshot than the primary committed: fail-open after a tightening commit,
// false-deny after a loosening commit. These tests pin the config-generation
// gate. They are written so that reverting the gate makes them RED as clean
// assertion failures.

// TestReadyForManualFailoverConfigStaleGate is the canonical fail-on-revert
// pin. It binds the config-staleness term in
// TransferReadinessSnapshot.ReadyForManualFailover() (the `!s.ConfigStale()`
// conjunct in pkg/cluster/sync.go). Neutralizing that term — e.g. dropping
// `&& !s.ConfigStale()` or forcing ConfigStale() to return false — turns the
// "behind" assertion below from a refusal into a promotion, failing this test.
func TestReadyForManualFailoverConfigStaleGate(t *testing.T) {
	// Standby has RECEIVED a newer config generation from the peer than it has
	// APPLIED: promoting it now would run the stale (pre-commit) policy.
	behind := TransferReadinessSnapshot{PeerConfigGen: 7, AppliedConfigGen: 6}
	if !behind.ConfigStale() {
		t.Fatal("applied gen 6 behind peer committed gen 7 must report ConfigStale()=true")
	}
	if behind.ReadyForManualFailover() {
		t.Fatal("config-stale standby (applied 6 < peer 7) must NOT be ready for manual failover")
	}
	if got := behind.Reason(); !strings.Contains(got, "config stale") {
		t.Fatalf("blocker reason must explain config staleness, got %q", got)
	}

	// Control: a LEGITIMATE same-generation failover — the standby has applied
	// everything the primary committed — must still be ready. The gate is
	// scoped to the genuine behind-the-primary case, not a blanket block.
	caughtUp := TransferReadinessSnapshot{PeerConfigGen: 7, AppliedConfigGen: 7}
	if caughtUp.ConfigStale() {
		t.Fatal("applied gen == peer committed gen must NOT be config-stale")
	}
	if !caughtUp.ReadyForManualFailover() {
		t.Fatal("caught-up standby (applied 7 == peer 7) must remain ready — gate must not blanket-block")
	}
	if got := caughtUp.Reason(); got != "" {
		t.Fatalf("caught-up standby must have no blocker reason, got %q", got)
	}

	// Control: a fresh node or a legacy (gen-0) peer reports both generations as
	// 0, which is NOT stale — the config gate must not fire and strand it.
	fresh := TransferReadinessSnapshot{}
	if fresh.ConfigStale() {
		t.Fatal("fresh/legacy standby (both gen 0) must NOT be config-stale")
	}
	if !fresh.ReadyForManualFailover() {
		t.Fatal("fresh/legacy standby (both gen 0) must remain ready")
	}
}

// TestReadyForManualFailoverConfigGateIndependentOfBulk proves the config gate
// is an ADDITIONAL, independent blocker: a standby whose session bulk state is
// fully settled is still refused when it is config-stale.
func TestReadyForManualFailoverConfigGateIndependentOfBulk(t *testing.T) {
	settledButStale := TransferReadinessSnapshot{
		Connected:        true,
		PeerConfigGen:    12,
		AppliedConfigGen: 11,
		// No pending bulk ack, no bulk receive in progress: session state is
		// settled, so ONLY the config gate can block here.
	}
	if settledButStale.ReadyForManualFailover() {
		t.Fatal("bulk-settled but config-stale standby must NOT be ready — config gate is independent of bulk state")
	}
}

// TestTransferReadinessCarriesConfigGenerations drives the real receive path:
// a config-sync message advances the received-config high-water
// (lastRecvConfigGen) in the syncMsgConfig handler, and TransferReadiness()
// surfaces it as PeerConfigGen alongside the applied high-water. Because the
// apply loop is not running here, AppliedConfigGen stays behind, so the
// snapshot must report not-ready. This binds both the receive-handler
// high-water recording and the TransferReadiness() field population.
func TestTransferReadinessCarriesConfigGenerations(t *testing.T) {
	dp := &mockSweepDP{}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Peer commits and pushes config generation 7. The receive handler records
	// it as the received high-water (before apply).
	ss.handleMessage(nil, syncMsgConfig, encodeConfigPayload("set system host-name node0\n", 7))

	snap := ss.TransferReadiness()
	if snap.PeerConfigGen != 7 {
		t.Fatalf("TransferReadiness must report received config gen 7, got %d", snap.PeerConfigGen)
	}
	if snap.AppliedConfigGen != 0 {
		t.Fatalf("no apply has completed, applied gen must be 0, got %d", snap.AppliedConfigGen)
	}
	if snap.ReadyForManualFailover() {
		t.Fatal("standby that received gen 7 but applied 0 must NOT be ready for manual failover")
	}
	if got := snap.Reason(); !strings.Contains(got, "config stale") {
		t.Fatalf("reason must explain config staleness, got %q", got)
	}

	// Once the apply lands (high-water advances to the received generation), the
	// standby is config-caught-up and readiness returns.
	ss.recordAppliedConfigGen(7)
	snap = ss.TransferReadiness()
	if snap.AppliedConfigGen != 7 {
		t.Fatalf("after apply, applied gen must be 7, got %d", snap.AppliedConfigGen)
	}
	if !snap.ReadyForManualFailover() {
		t.Fatalf("caught-up standby must be ready, reason=%q", snap.Reason())
	}
}

// TestResetRecvGenClearsReceivedConfigHighWater guards the applied<=received
// invariant across a peer bulk re-prime. resetRecvGen() zeroes BOTH the applied
// mark and the received high-water; if only the applied mark were reset, the
// snapshot would spuriously report the node config-stale (received>applied)
// after every reconnect until the re-push landed.
func TestResetRecvGenClearsReceivedConfigHighWater(t *testing.T) {
	dp := &mockSweepDP{}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	ss.handleMessage(nil, syncMsgConfig, encodeConfigPayload("cfg", 9))
	ss.recordAppliedConfigGen(9)
	if snap := ss.TransferReadiness(); snap.ConfigStale() {
		t.Fatalf("applied==received must not be stale before reset, got peer=%d applied=%d",
			snap.PeerConfigGen, snap.AppliedConfigGen)
	}

	ss.resetRecvGen()
	snap := ss.TransferReadiness()
	if snap.PeerConfigGen != 0 || snap.AppliedConfigGen != 0 {
		t.Fatalf("resetRecvGen must zero BOTH config generations, got peer=%d applied=%d",
			snap.PeerConfigGen, snap.AppliedConfigGen)
	}
	if snap.ConfigStale() {
		t.Fatal("after resetRecvGen both generations are 0 — must not report config-stale")
	}
}
