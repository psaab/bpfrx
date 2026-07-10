package cluster

// upgrade_drain.go fences the operator-facing "in-service upgrade" (ISSU)
// drain report on an OBSERVED peer handoff instead of on desired state alone
// (#5039). ForceSecondary (failover.go) only mutates desired manager state and
// enqueues a droppable election event — the real demotion / VRRP resignation /
// VIP handoff happens asynchronously and can lag or be dropped. The ISSU
// command must therefore never certify "traffic drained — you may stop this
// node" straight off ForceSecondary's return; it waits (bounded) to see the
// peer actually take over, and otherwise warns and withholds the stop
// instruction. The observer + the honest report live together here so the
// "message fenced on applied+acked state, not on a heartbeat" invariant is
// answerable by reading one file.

import (
	"context"
	"time"
)

// DefaultUpgradeHandoffTimeout bounds how long the ISSU command waits to
// observe that the peer has actually taken over primary ownership after
// ForceSecondary before it reports the outcome. Observed VRRP failover plus
// the heartbeat re-report of the peer's primary state completes in ~1-2s; 10s
// is a generous ceiling that still returns promptly when the handoff never
// happens (e.g. a dropped election event — the exact desired-vs-applied gap
// #5039 is about).
const DefaultUpgradeHandoffTimeout = 10 * time.Second

// DefaultUpgradeHandoffPoll is the observation interval used while waiting for
// the ISSU handoff.
const DefaultUpgradeHandoffPoll = 200 * time.Millisecond

// upgradeHandoffComplete reports whether the ISSU drain has actually taken
// effect: the peer is alive, this node no longer owns ANY non-disabled RG as
// primary, and EVERY non-disabled RG this node relinquished is now owned by the
// peer as primary. It is a read-only snapshot taken under a single RLock so
// there is no torn view across the RG/peer maps.
//
// The all-RGs requirement is load-bearing (#5039): ForceSecondary drains every
// RG, but the peer's takeover of each is asynchronous and its election events
// on this node can be dropped. In the default multi-RG config, confirming on
// the FIRST peer-primary RG (e.g. control-plane RG0, which carries no data VIP)
// would report "drained — safe to stop" while a still-locally-relevant data RG
// remains un-transferred — blackholing it. The drain is complete only when the
// peer owns primary for every RG this node gave up.
func (m *Manager) upgradeHandoffComplete() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.peerAlive {
		return false
	}
	relinquished := 0
	for gid, rg := range m.groups {
		if rg.State == StateDisabled {
			continue // administratively disabled — nothing to hand off
		}
		if rg.State == StatePrimary {
			return false // still own an RG locally — not drained
		}
		relinquished++
		pg, ok := m.peerGroups[gid]
		if !ok || pg.State != StatePrimary {
			return false // peer has not (yet) taken this RG as primary
		}
	}
	// Confirm only once every non-disabled RG we relinquished is peer-primary.
	// A node with no enabled RGs has nothing to drain and must not confirm.
	return relinquished > 0
}

// WaitForUpgradeHandoff blocks until the peer has acknowledged primary
// ownership after an ISSU ForceSecondary drain (see upgradeHandoffComplete) or
// until ctx is done, whichever comes first. It returns true only when the
// handoff was actually observed.
//
// This is a READ-ONLY observer: it mutates no cluster, VRRP, or dataplane
// state and therefore does not change the drain behavior itself. Its sole
// purpose is to let the ISSU command fence its "traffic drained — you may stop
// this node" message on an OBSERVED peer takeover rather than on desired state
// alone (#5039).
func (m *Manager) WaitForUpgradeHandoff(ctx context.Context, poll time.Duration) bool {
	if poll <= 0 {
		poll = DefaultUpgradeHandoffPoll
	}
	for {
		if m.upgradeHandoffComplete() {
			return true
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			// Final observation: the handoff may have completed in the same
			// instant the deadline elapsed.
			return m.upgradeHandoffComplete()
		case <-timer.C:
		}
	}
}

// UpgradeDrainReport returns the operator-facing lines the ISSU command prints
// after a ForceSecondary drain. The report is fenced on whether the peer
// takeover was actually observed (handoffConfirmed):
//
//   - confirmed:     report the drain complete and that it is safe to stop this
//     node and swap the binary.
//   - NOT confirmed: WARN that the drain did not complete and DO NOT instruct
//     the operator to stop the only forwarding owner; direct them to verify the
//     handoff with `show chassis cluster status` first.
//
// #5039: the pre-fix command unconditionally printed "Traffic has been drained
// to peer" + stop instructions straight off ForceSecondary's return — desired
// state only, no handoff ack — certifying a drain that may not have happened
// and telling the operator to blackhole traffic.
func UpgradeDrainReport(handoffConfirmed bool) []string {
	if handoffConfirmed {
		return []string{
			"Node is now secondary for all redundancy groups.",
			"Peer has taken over as primary — traffic drained to peer.",
			"You may now replace the binary and restart the service:",
			"  systemctl stop xpfd && <replace binary> && systemctl start xpfd",
		}
	}
	// Deliberately NO copy-pasteable `systemctl stop` command here: a hurried
	// operator could paste it despite the warning and blackhole traffic. The
	// stop/swap instruction is printed ONLY on the confirmed path above.
	return []string{
		"Node has been requested secondary for all redundancy groups.",
		"WARNING: peer takeover was NOT confirmed — traffic may NOT be drained.",
		"Do NOT stop xpfd yet: this node may still be the only forwarding owner.",
		"Verify with 'show chassis cluster status' that the peer is primary and",
		"this node is secondary for ALL redundancy groups before replacing the",
		"binary and restarting the service.",
	}
}
