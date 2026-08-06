package config

import "fmt"

// Peer-effective strict validation (#5876, generalised for #4785).
//
// The strict commit gate compiles ONLY the submitting node's effective view:
// configstore.compileTreeStrict calls CompileConfigForNode(tree, localNodeID).
// On a chassis cluster the tree that synchronises is the RAW group tree —
// Store.ShowActive returns s.active.Format() and daemon_ha_sync hands that text
// to QueueConfig — and the standby ingests it through the TOLERANT path
// (Store.SyncApply -> CompileConfigForNodeLenient), which downgrades every
// strict gate to a warning so an already-persisted config still boots (#1960).
//
// So a `${node}` apply-group substitution or per-node `groups nodeN` block that
// is valid on the ORIGIN's effective view but invalid on the PEER's gets NO
// strict check anywhere: the origin commits green, the peer lenient-loads, and
// the defect installs on the node that actually received it. The origin's commit
// is the only strict gate that ever sees the peer view, so the peer's strict
// concerns must be pulled forward to it.
//
// WHY A REGISTRY RATHER THAN ONE FUNCTION PER CONCERN. #5876 shipped this as a
// single source-NAT-specific entry point, and #4785 needs the same treatment for
// `tunnel mode ipip`. Compiling the peer view is a FULL compile
// (CompileConfigForNodeLenient); a second standalone entry point would run it
// twice on every cluster commit, and a third concern three times. The registry
// compiles once and runs every registered subject against that one view. Adding
// the next concern is a registration, not another compile.
//
// WHAT BELONGS HERE. A strict gate whose input can DIVERGE between node views —
// anything that reads a per-node address, a `${node}`-substituted name, or a
// `groups nodeN` stanza. A gate whose verdict is node-independent gains nothing
// here and only costs the walk.

// peerEffectiveStrictSubject is one strict concern re-run against the peer
// node's effective compiled view.
//
// fn takes an ALREADY-COMPILED *Config and REUSES the local-path strict
// validators verbatim — no peer-only rules — so the peer gate and the local
// commit path cannot drift on what is acceptable.
//
// format frames the rejection for the operator; it takes the peer node id and
// wraps the underlying error with %w.
type peerEffectiveStrictSubject struct {
	format string
	fn     func(*Config) error
}

// peerEffectiveStrictSubjects is the registered set, run in order. The first
// failing subject wins, so the order fixes which of two simultaneous
// peer-only defects the operator is shown first; both are real and fixing one
// surfaces the other on the next commit.
var peerEffectiveStrictSubjects = []peerEffectiveStrictSubject{
	{
		// #5876. A per-node pool address, a divergent `port range`, or a
		// top-level rule referencing a pool only a peer `groups nodeN` block
		// defines: the origin commits green and the standby's lenient
		// SyncApply installs nothing, so SNAT silently fails closed on the
		// node that just took over.
		format: "chassis cluster peer node%d effective source-NAT is not " +
			"representable (a shared commit would strand the standby): %w",
		fn: validateSourceNATStrictView,
	},
	{
		// #4785. An `ip-*` interface (or an explicit `mode ipip`) that only
		// the peer's effective view resolves: the origin commits green and
		// the standby installs a tunnel endpoint the userspace dataplane
		// drops in both directions — the exact dead tunnel the local gate
		// exists to reject.
		format: "chassis cluster peer node%d effective tunnel configuration is " +
			"not installable (a shared commit would give the standby a dead " +
			"tunnel): %w",
		fn: validateIpipTunnelStrictView,
	},
}

// ValidatePeerEffectiveStrict re-runs every registered strict subject against
// the PEER node's effective compiled view, so a chassis-cluster commit proves
// BOTH node-effective outputs are installable before promotion.
//
// The peer view is produced with CompileConfigForNodeLenient(peerID) — the EXACT
// transform the standby applies on Store.SyncApply — so what is validated is
// precisely what the peer will instantiate (same ${node} apply-group
// substitution and per-node rewrites). The lenient compile downgrades every gate
// to a warning, so it always yields the peer-effective *Config even when some
// OTHER gate would strict-reject; a peer view that will not compile at all is a
// broader structural problem left to the peer's own load path rather than a
// false-reject of the origin commit.
//
// Standalone (localNodeID < 0) has no peer and is a no-op — zero behaviour
// change off a cluster. The verdict is deterministic: CompileConfigForNodeLenient
// is a pure function of the candidate tree and every reused validator walks its
// inputs in sorted order, so the first-reported offender is stable across runs
// and identical on both nodes.
func ValidatePeerEffectiveStrict(tree *ConfigTree, localNodeID int) error {
	if tree == nil || localNodeID < 0 {
		return nil
	}
	peerID, ok := peerNodeID(localNodeID)
	if !ok {
		return nil
	}
	// Compile the peer view the SAME way the standby ingests a config-synced
	// snapshot (Store.SyncApply -> compileTreeLenient -> CompileConfigForNodeLenient).
	// ONE compile, shared by every subject below.
	peerCfg, err := CompileConfigForNodeLenient(tree, peerID)
	if err != nil || peerCfg == nil {
		return nil
	}
	for _, subject := range peerEffectiveStrictSubjects {
		if err := subject.fn(peerCfg); err != nil {
			return fmt.Errorf(subject.format, peerID, err)
		}
	}
	return nil
}

// peerNodeID returns the OTHER node id in a 2-node chassis cluster (0<->1). ok is
// false for any id that has no defined 2-node peer (nodes are always 0 or 1).
func peerNodeID(nodeID int) (int, bool) {
	switch nodeID {
	case 0:
		return 1, true
	case 1:
		return 0, true
	default:
		return 0, false
	}
}

// validateIpipTunnelStrictView is the #4785 peer-effective subject: it REUSES
// the local strict gate verbatim against an already-compiled peer view.
//
// Reuse, not a reimplementation, is the point. The local gate keys on the
// EMITTED endpoint set (EmitTunnelEndpointNames), which is also what the
// dataplane snapshot builder consumes; a hand-rolled peer-side model would be a
// second answer to a question the codebase already answers once, and the two
// would drift. lenient=false because this IS the strict path — the origin's
// commit is the only strict gate the peer view ever gets.
func validateIpipTunnelStrictView(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	_, err := validateIpipTunnelUnimplementedStrict(cfg, false)
	return err
}
