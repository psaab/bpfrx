package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ErrPeerSnapshotProtocolIncompatible reports that the cluster peer cannot
// represent a shape in the candidate config, so committing it would push the
// peer a config it will silently NARROW (#6650).
//
// It is a COMMIT preflight failure, not an apply failure: the commit is refused
// before the store promotes anything, so the two chassis are never left holding
// different policy sets. Letting the local commit succeed and merely skipping
// the push would trade a narrowing for a divergence — config-sync exists to
// keep the pair identical, and on failover the peer would enforce the other
// policy set.
var ErrPeerSnapshotProtocolIncompatible = errors.New("cluster peer cannot represent this config")

// peerSnapshotProtocolCommitPreflight refuses a commit whose config the cluster
// peer cannot represent (#6650).
//
// This is the cross-chassis half of the #5488 gate. That gate asks "can MY
// helper represent this?"; on a chassis cluster upgraded one node at a time —
// which is what a rolling upgrade means on this product — the upgraded
// primary's gate short-circuits, the commit succeeds, and the config TEXT is
// pushed to a peer that recompiles it with an older compiler and installs a
// narrowed policy. The peer cannot defend itself: it is the old binary.
//
// Four conditions must ALL hold to refuse, and each exists to avoid a worse
// failure than the one being prevented:
//
//   - The node is clustered with config-sync ON. Without a push there is no
//     way for the peer to receive, hence narrow, anything.
//   - A peer is CONNECTED. A node whose peer is down or absent must keep being
//     able to commit; refusing would turn a dead peer into a config freeze,
//     and a disconnected peer receives no push to narrow. This is why the
//     "advertises nothing" case below is safe to read as incapable — it is
//     scoped to a peer that is demonstrably there.
//   - The config actually carries the misrepresentable shape, decided by the
//     SAME predicate that arms the local gate.
//   - The peer's advertised version is below the per-feature floor.
//
// The floor is userspace.MinProtocolMultiZoneScopedPolicy (an immutable 4),
// NOT userspace.ProtocolVersion. Gating on the shared constant would make
// every future unrelated wire bump retroactively refuse multi-zone commits
// across any version skew — the defect open #6648 describes in the local
// gates. The question here is "can the peer represent THIS shape", and the
// answer to that stopped changing at v4.
func (d *Daemon) peerSnapshotProtocolCommitPreflight(cand *config.Config) error {
	if d == nil || cand == nil {
		return nil
	}
	clustered := d.cluster != nil && cand.Chassis.Cluster != nil && cand.Chassis.Cluster.ConfigSync
	ss := d.getSessionSync()
	peerConnected := ss != nil && ss.IsConnected()
	var peerProto uint16
	if ss != nil {
		peerProto = ss.PeerSnapshotProtocolVersion()
	}
	return peerSnapshotProtocolDecision(
		clustered, peerConnected, userspace.ConfigHasMultiZoneScopedPolicy(cand), peerProto)
}

// peerSnapshotProtocolDecision is the gate's whole decision, split out from the
// Daemon so every combination is directly testable. A *SessionSync cannot be
// driven into the "connected, advertising v3" state from outside pkg/cluster —
// its connection state is unexported — so a method-only gate would be testable
// mainly in the arms that return nil, which is the half that proves least.
func peerSnapshotProtocolDecision(clustered, peerConnected, hasMultiZone bool, peerProto uint16) error {
	if !clustered || !peerConnected || !hasMultiZone {
		return nil
	}
	if peerProto >= userspace.MinProtocolMultiZoneScopedPolicy {
		return nil
	}
	// peerProto == 0 is a CONNECTED peer that advertised nothing, i.e. a build
	// predating #6650 — which necessarily predates v4 too. Say so explicitly
	// rather than printing "version 0", which reads like a decode bug.
	peerDesc := fmt.Sprintf("%d", peerProto)
	if peerProto == 0 {
		peerDesc = "pre-#6650 (advertises no version)"
	}
	return fmt.Errorf(
		"%w: this config contains a multi-zone scoped policy, which needs config-snapshot "+
			"protocol %d; the cluster peer is at %s and would read only the first zone of the "+
			"scope, silently NARROWING the policy on that node. Upgrade the peer, then re-commit "+
			"(or express the policy as one rule per zone, which both nodes represent identically)",
		ErrPeerSnapshotProtocolIncompatible,
		userspace.MinProtocolMultiZoneScopedPolicy,
		peerDesc,
	)
}
