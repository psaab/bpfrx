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
// the EXPECTED cost is one TCP round trip on the fabric link plus the peer's
// fenceAllRedundancyGroups — sub-millisecond plus a handful of dataplane
// writes. 250ms is roughly three orders of magnitude of headroom over that.
//
// The bound matters for the one case that does spend it: a peer that has lost
// power while its TCP socket has not yet noticed. There the socket looks alive,
// no ack ever comes, and this timeout is what releases the takeover. It is
// therefore sized against the heartbeat detection window that precedes it —
// 200ms interval x threshold 5 = ~1s — so the worst case adds ~25% to a
// detection that has already taken a second, rather than to the ~60ms VRRP
// number, which this path is not on.
//
// It is not configurable because there is no operator input that would improve
// it: shorter defeats the purpose on a loaded fabric, longer extends an outage
// window in the only case that reaches it, and the policy leaf already
// expresses the one decision an operator actually has (gate, or do not).
const FenceConfirmTimeout = 250 * time.Millisecond

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
