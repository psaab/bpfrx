package cluster

import (
	"fmt"
	"log/slog"
	"time"
)

// Confirmed peer fencing policy (#7147).

const (
	// PeerFencingDisableRG is the original best-effort fence: send
	// syncMsgFence and take over regardless. Behaviour is unchanged by #7147.
	PeerFencingDisableRG = "disable-rg"

	// PeerFencingDisableRGConfirmed sends a SEQUENCED fence before the
	// single-node election and waits, bounded, for the peer to confirm that it
	// disabled every redundancy group in its live config.
	//
	// It is strictly an ORDERING guarantee for the reachable-peer case, never
	// an availability risk — every failure path proceeds with the takeover.
	PeerFencingDisableRGConfirmed = "disable-rg-confirmed"
)

// FenceConfirmTimeout bounds the wait for a peer fence acknowledgement.
//
// HOW THIS NUMBER WAS CHOSEN, and why it is a constant rather than a knob.
//
// The wait can only be entered when the session-sync socket is live
// (SendFenceAwait returns immediately with "peer not connected" otherwise), so
// the ordinary dead-peer takeover never spends any of it.
//
// WHAT THE PEER ACTUALLY DOES BEFORE IT CAN ANSWER. This was mis-sized at
// first, on the assumption that the receiver's fence is a fabric round trip
// plus "a handful of dataplane writes". It is not. Each RG's
// SetRGActive(false) reaches userspace Manager.UpdateRGActive, which takes the
// helper manager's OWN mutex — shared with the 1/s status poll, session
// installs and snapshot apply — and issues an `update_ha_state` request on the
// shared control socket, whose base deadline is controlBaseDeadline = 3s
// (pkg/dataplane/userspace/process_control.go). That happens once per RG,
// sequentially, and the reply then queues behind s.writeMu, which a stalled
// send loop can hold for syncWriteDeadline = 2s. A peer loss frequently
// follows a fabric reconnect, i.e. exactly when that socket is most contended.
//
// So no bound short enough to sit in a takeover path can GUARANTEE the ack
// arrives. This value is therefore a POLICY bound, not a derivation of the
// peer's worst case: wait long enough that an uncontended cluster — where the
// round trip is milliseconds — actually gets its confirmation, and fail open
// rather than let a contended control socket hold the takeover.
//
// 1s is that compromise. It comfortably covers several control round trips on
// an idle helper, it is bounded well below a single 3s control deadline so a
// genuinely wedged socket fails open instead of stalling, and it is on the
// order of the ~1s heartbeat detection (200ms interval x threshold 5) that
// already elapsed before this code runs — not the ~60ms VRRP number, which
// this path is not on. FenceAcksTimedOut is what tells an operator the bound
// is being exceeded in practice.
//
// It is not configurable because there is no operator input that would improve
// it: shorter stops the gate ever engaging on a loaded fabric, longer extends
// an outage window in the only case that reaches it, and the policy leaf
// already expresses the one decision an operator actually has (gate, or do
// not).
const FenceConfirmTimeout = 1 * time.Second

// awaitPeerFenceLocked runs the confirmed peer fence.
//
// Called with m.mu HELD; it releases the lock across the network wait and
// re-acquires it before returning, exactly as the `disable-rg` fence branch in
// handlePeerTimeout does. handlePeerTimeout holds m.mu via defer, so the caller
// keeps the lock afterwards either way.
//
// IT ALWAYS RETURNS AND NEVER BLOCKS THE TAKEOVER INDEFINITELY. That is the
// central safety property, so it is worth stating what each path costs:
//
//   - no confirm function armed: returns immediately.
//   - peer not connected: SendFenceAwait returns immediately. This is the
//     ordinary dead-peer takeover and it is why the policy does not slow it
//     down — with no socket there is nothing to wait on.
//   - peer predates #7147: SendFenceAwait returns immediately on the missing
//     capability, so a rolling upgrade never pays the timeout.
//   - write failed: returns immediately.
//   - peer answered: the common reachable-peer case, one fabric round trip.
//   - peer silent with a live socket: bounded by FenceConfirmTimeout, then
//     proceeds anyway.
//
// A takeover that proceeded WITHOUT confirmation is recorded to the EventFence
// history with the reason, because the operator selected this policy expecting
// a guarantee and the one case where they did not get it must be visible. It is
// also counted in SyncStats.FenceAcksTimedOut for the timeout case.
//
// TWO CONSEQUENCES OF RELEASING m.mu HERE, both deliberate.
//
// First, this widens a window that `disable-rg` does not have. Under
// `disable-rg` the peer-loss decision and electSingleNode run under one
// unbroken hold of m.mu; here the lock is released between them, so a peer
// heartbeat can land during the wait and set peerAlive back to true before the
// election runs. This function does NOT abort on that, and must not: by the
// time it could notice, the fence has already been delivered and the peer has
// disabled every RG it owns. Aborting the takeover at that point would leave
// the peer dark AND this node passive — a total outage, and a strictly worse
// outcome than the momentary dual-primary the abort would be trying to avoid.
// Having fenced, committing to the takeover is the only safe direction. (The
// #2080 pre-guard re-check at the top of handlePeerTimeout still applies; it
// runs BEFORE anything has been fenced, which is what makes aborting safe
// there and unsafe here.)
//
// Second, on WHICH goroutine this blocks — the answer matters, because
// believing it was the receive path is what made the hazard above look
// impossible. handlePeerTimeout runs on heartbeatReceiver.timeoutLoop, a
// dedicated ticker goroutine (heartbeat.go), NOT on the frame-receive path
// that runs handlePeerHeartbeat. Those are different goroutines, so the
// receive path keeps running for the whole wait — which is precisely how a
// late heartbeat gets in to flip peerAlive.
//
// The cost of the wait itself is therefore only a delayed next timeout tick,
// which is harmless: the re-entry hits handlePeerTimeout's `!m.peerAlive`
// early return. The wait is not moved to a goroutine because a fence that
// completed asynchronously could not gate the election it exists to precede.
func (m *Manager) awaitPeerFenceLocked() {
	fn := m.peerFenceConfirmFn
	if fn == nil {
		slog.Warn("cluster: fence: sync not available, taking over without peer confirmation")
		m.history.Record(EventFence, -1, "Fence skipped: sync not available")
		return
	}

	// Release the lock for the network call + bounded wait.
	m.mu.Unlock()
	ack, err := fn(FenceConfirmTimeout)
	m.mu.Lock()
	// RE-ESTABLISH THE PEER-LOST DECISION. This is not defensive tidying; it
	// repairs an atomicity that releasing m.mu above breaks, and getting it
	// wrong strands the cluster with NO primary.
	//
	// handlePeerTimeout sets m.peerAlive = false specifically so that
	// electSingleNode's #7161 readiness gate — armed only when
	// `m.controlInterface != "" && (m.peerAlive || !m.peerEverSeen)`
	// (election.go) — is BYPASSED on a genuine peer loss. Pre-#7147 that write
	// and the election ran under one unbroken hold, so nothing could flip it in
	// between. The wait above opens exactly that window, and
	// handlePeerHeartbeat runs on a DIFFERENT goroutine that is blocked on
	// m.mu: the moment we release it, a late heartbeat frame can set
	// peerAlive = true.
	//
	// The consequence is not a stale field. It re-arms the readiness gate, so
	// electSingleNode reaches `if !promote { continue }` and declines to
	// promote — AFTER the fence has already driven every RG on the peer to
	// rg_active=false. Peer dark, this node passive: the total outage this
	// policy exists to avoid, produced by the policy itself.
	//
	// So the peer-loss decision, which was made and acted on before the fence
	// went out, is re-asserted here. It is honest as well as necessary: we have
	// just told the peer to relinquish everything, so "the peer does not own
	// its groups" is exactly the state we created. A genuinely-recovered peer
	// re-establishes peerAlive on its next heartbeat (<= one interval) and the
	// normal election reconverges — the same recovery path as before #7147.
	//
	// Only peerAlive is restored: it is the sole field in the peer-loss block
	// that electSingleNode's promotion decision reads. peerGroups/peerMonitors
	// are rebuilt by whichever heartbeat won the window and do not gate
	// promotion.
	m.peerAlive = false

	if err != nil {
		slog.Warn("cluster: fence: taking over WITHOUT peer confirmation", "err", err)
		m.history.Record(EventFence, -1, fmt.Sprintf("Fence unconfirmed, took over anyway: %v", err))
		return
	}
	if ack.Confirmed() {
		slog.Info("cluster: fence: peer confirmed fence",
			"rgs_fenced", ack.RGsFenced, "rgs_total", ack.RGsTotal)
		m.history.Record(EventFence, -1, fmt.Sprintf("Fence confirmed by peer (%s)", ack.Reason()))
		return
	}
	// A negative ack is not retried: the peer has already told us it could not
	// fully comply, and repeating the request cannot change that within the
	// takeover window. Fail open, loudly.
	slog.Warn("cluster: fence: peer reported an INCOMPLETE fence, taking over anyway",
		"status", ack.Status, "rgs_fenced", ack.RGsFenced, "rgs_total", ack.RGsTotal)
	m.history.Record(EventFence, -1, fmt.Sprintf("Fence NOT confirmed (%s), took over anyway", ack.Reason()))
}
