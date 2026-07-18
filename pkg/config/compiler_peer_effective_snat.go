package config

import "fmt"

// ValidatePeerEffectiveSourceNATStrict re-runs the strict SOURCE-NAT
// representability validators against the PEER node's effective compiled view so
// a chassis-cluster commit proves BOTH node-effective source-NAT outputs are
// installable before promotion (#5876).
//
// The strict SNAT gates (validateSourceNATPoolStrict,
// validateSourceNATPoolAddressGrammarStrict, validateSourceNATPoolAddressScopeStrict,
// validateSourceNATPersistentNoTranslationStrict, validateSourceNATAggregateCardinalityStrict,
// validateNATPoolReferencesStrict, validateNATSourceAddressNameReferencesStrict)
// already run inside
// compileExpanded — but ONLY against the single node the commit compiles for.
// The strict commit gate (configstore.compileTreeStrict) compiles
// CompileConfigForNode(localNodeID) alone, so a source-NAT pool / reference error
// that is valid on the ORIGIN's effective view but invalid on the PEER's — a
// per-node pool address, a divergent `port range`, a top-level rule referencing a
// pool that only a peer `groups nodeN` block defines — is chassis-aware compiled
// only for the local node and never strict-validated. The originating commit
// passes green; the standby then ingests the synced snapshot via the TOLERANT
// path (Store.SyncApply -> CompileConfigForNodeLenient), which downgrades the
// strict SNAT gate to a warning and installs nothing (fail-closed) — SNAT
// silently degrades on the node that just took over. This gate pulls the peer's
// strict SNAT check forward to the origin's commit.
//
// The peer-effective view is produced with CompileConfigForNodeLenient(peerID) —
// the EXACT transform the standby applies on Store.SyncApply — so the pools and
// rules we validate are precisely what the peer will instantiate (same ${node}
// apply-group substitution and per-node rewrites). The lenient compile downgrades
// every gate to a warning, so it always yields the peer-effective *Config even
// when a NON-source-NAT gate would strict-reject; those non-SNAT concerns are
// OUT OF SCOPE for #5876 (a peer view that will not compile at all is a broader
// structural problem left to the peer's own load path — we do not false-reject
// the origin commit for it). Only the strict SOURCE-NAT validators are re-run.
//
// Standalone (localNodeID < 0) has no peer and is a no-op — zero behavior change
// off a cluster. The verdict is deterministic: CompileConfigForNodeLenient(peerID)
// is a pure function of the candidate tree, and the reused validators already walk
// pools / rule-sets in sorted order for a stable first-reported offender.
func ValidatePeerEffectiveSourceNATStrict(tree *ConfigTree, localNodeID int) error {
	if tree == nil || localNodeID < 0 {
		return nil
	}
	peerID, ok := peerNodeID(localNodeID)
	if !ok {
		return nil
	}
	// Compile the peer view the SAME way the standby ingests a config-synced
	// snapshot (Store.SyncApply -> compileTreeLenient -> CompileConfigForNodeLenient):
	// the lenient path downgrades every strict gate to a warning, so it produces
	// the peer-effective *Config even where a non-SNAT gate would hard-reject.
	peerCfg, err := CompileConfigForNodeLenient(tree, peerID)
	if err != nil || peerCfg == nil {
		// A peer view that will not compile AT ALL is a structural concern
		// broader than source-NAT representability (#5876 scope). Leave it to the
		// peer's own strict/load path rather than false-rejecting the origin
		// commit here.
		return nil
	}
	if err := validateSourceNATStrictView(peerCfg); err != nil {
		return fmt.Errorf("chassis cluster peer node%d effective source-NAT is not "+
			"representable (a shared commit would strand the standby): %w", peerID, err)
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

// validateSourceNATStrictView runs the strict NAT representability validators
// that touch source-NAT rules (the source-NAT-relevant validators the NAT gates
// in runUniformGates dispatch on the local compiled view) against an
// ALREADY-COMPILED *Config. It REUSES the existing validators verbatim — no new
// SNAT rules — so the peer-effective gate (#5876) and the local commit path
// cannot drift on what a representable source pool / rule is.
//
// The peer view is validated by exactly the strict validators that iterate the
// source-NAT config, because the standby's own SyncApply is LENIENT — the origin's
// peer gate is the SOLE strict check the peer view ever gets, so any strict
// validator that could catch a peer-only ${node}/groups divergence in a source
// rule must run here (else that divergence strands the standby, the #5876 shape).
// This includes the pool/reference/grammar/persistent validators AND the
// rule-match/action validators (match-destination-port, terminal-action
// cardinality, and match-applications — the last fails OPEN to a wildcard
// translation, so omitting it would leave a peer-only fail-open, #6048 review).
// validateNATPoolReferencesStrict / validateNATSourceAddressNameReferencesStrict /
// the three match-action validators also cover destination NAT; they are included
// whole (splitting them would duplicate logic) so the peer gate is a beneficial
// superset that matches their local-view behavior exactly — a peer-only DNAT
// pool / address-name / match error is caught too, never a false-reject.
func validateSourceNATStrictView(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if err := validateSourceNATPoolStrict(cfg); err != nil {
		return err
	}
	if err := validateNATPoolReferencesStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATPoolAddressScopeStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATPoolAddressGrammarStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATPersistentNoTranslationStrict(cfg); err != nil {
		return err
	}
	if err := validateSourceNATAggregateCardinalityStrict(cfg); err != nil {
		return err
	}
	if err := validateNATSourceAddressNameReferencesStrict(cfg); err != nil {
		return err
	}
	if err := validateNATMatchDestinationPortStrict(cfg); err != nil {
		return err
	}
	if err := validateNATTerminalActionCardinalityStrict(cfg); err != nil {
		return err
	}
	if err := validateNATMatchApplicationsStrict(cfg); err != nil {
		return err
	}
	return nil
}
