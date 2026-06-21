package config

import (
	"errors"
	"fmt"
	"strings"
)

// ErrDPDKDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type dpdk`. External
// API consumers (gRPC orchestration, REST wrappers, CLI tooling) can
// match this with errors.Is rather than substring-searching the wrapped
// error text. The wrapped form is preserved verbatim so the operator-
// facing migration message remains stable; see #1525.
//
// Mirrors the runtime-side dataplane.ErrDPDKBackendRetired sentinel
// introduced by #1527 so the config-time and runtime layers both expose
// structured rejections.
var ErrDPDKDataplaneRetired = errors.New(
	"the DPDK dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1525)")

// ErrEBPFDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type ebpf`. The
// parse path still accepts the token as a legal value so that
// `load merge` / `load override` of a pre-retirement configuration
// does not syntax-error; this strict validator is what tells the
// operator to migrate.
//
// Mirrors the runtime-side dataplane.ErrEBPFBackendRetired sentinel
// introduced by #1476 so the config-time and runtime layers both
// expose structured rejections. The verbatim message must remain
// stable for downstream tooling that matches by text.
var ErrEBPFDataplaneRetired = errors.New(
	"the legacy eBPF dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1373)")

// compileOpts carries per-call compilation policy. It is threaded into
// compileExpanded so the strict commit path and the tolerant
// load/peer-sync path can share the identical compile + group-expansion
// pipeline while differing on a single, narrow validator's severity.
type compileOpts struct {
	// #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
	// retired along with validateEqualFlowWorkerCapStrict — the
	// dataplane no longer caps equal-flow-enforcement at 32 workers, so
	// there is no severity to downgrade. The lenient compile entry
	// points remain for the flags below.

	// sanitizeFreeTextControlChars (#1798) downgrades the control-
	// character gate from a hard compile error to sanitize-in-place
	// plus a cfg.Warnings entry. The strict commit / commit-check path
	// rejects any value or annotation containing ASCII control
	// characters — the lexer maps "\n" inside a quoted string to a
	// real newline, which injects arbitrary directives into generated
	// networkd/FRR/strongSwan files. The tolerant load / peer-sync /
	// peer-display paths must instead scrub the value and keep going
	// so an already-persisted bad config cannot blackout-boot a node
	// or alarm-loop HA config sync. This check deliberately does NOT
	// live in SchemaValidate: the tolerant paths need the value scrubbed
	// in place, which the read-only schema walk cannot do (and since
	// #1319 PR 2 SchemaValidate violations are themselves downgraded to
	// warnings on the tolerant paths — see configstore.compileTreeLenient).
	// See freetext.go for the full three-layer design.
	sanitizeFreeTextControlChars bool

	// lenientVRRPTrackDuplicates (#1814) downgrades the duplicate
	// `track-interface` gate (more than one track-interface statement
	// inside a single vrrp-group) from a hard compile error to a
	// cfg.Warnings entry with deterministic first-wins pruning of the
	// extras. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient) so an
	// already-persisted or peer-synced config still boots; candidate
	// commit / commit-check stay strict and hard-reject new operator
	// edits. Like the other lenient gates, this check deliberately does
	// NOT live in SchemaValidate: pruning the duplicates is an AST-level
	// compile decision the read-only schema walk cannot make (and since
	// #1319 PR 2 SchemaValidate violations only warn on tolerant paths).
	lenientVRRPTrackDuplicates bool

	// lenientDeviceMap (#1956 V-1) downgrades the cross-entry device-map
	// validator (validateDeviceMapStrict) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): an active node's
	// strict commit validates only ITS OWN node section against its own
	// hardware (R-8 pre-flight does the live-hardware half), but it cannot
	// fail on the PEER node's section (different box, structural rules like
	// FPC/node alignment differ per node). The peer's SyncApply compiles
	// leniently, so a peer-section structural finding warns rather than
	// stalling the whole config sync. The narrow management-lockout class
	// that lenient must NOT swallow is handled by the daemon's passive-node
	// SyncApply admission gate (V-1), not by this compile flag.
	lenientDeviceMap bool

	// lenientTCPMSSRange (#1979 Layer B Tier 3) downgrades the tcp-mss
	// commit-time range gate (validateTCPMSSRanges) from a hard compile
	// error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths (CompileConfigLenient / CompileConfigForNodeLenient):
	// a persisted or peer-synced config carrying an out-of-range MSS value
	// an OLDER binary accepted (before this gate existed) must still boot,
	// not blackout the upgraded node — the dataplane coerces it safely
	// (Layer A, flow.go coerceWireU16) and the operator's next strict commit
	// rejects it loudly. Same doctrine as lenientVRRPTrackDuplicates. Like
	// the other lenient gates this is an AST-level compile decision (the MSS
	// value can live in two positions) and deliberately does NOT live in
	// SchemaValidate (tcp-mss stays opaque there).
	lenientTCPMSSRange bool

	// lenientNATPoolAlarmThreshold (#2079) downgrades the
	// security-nat-source pool-utilization-alarm threshold gate
	// (validatePoolUtilizationAlarm) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): the thresholds
	// had NO validation before #2079, so an operator could (and would) have
	// committed a bare `pool-utilization-alarm;` (raise=0/clear=0) or an
	// inverted/equal pair, persisted to active.json. After upgrade that
	// config must still LOAD (warn) instead of failing the daemon closed on
	// restart (fail-closed-on-compile-failure, #1960); the operator's next
	// strict commit rejects it loudly. The runtime monitor treats raise<=0 as
	// "feature disabled", so a leniently-loaded bad config is inert, not
	// always-firing. Same doctrine as lenientTCPMSSRange.
	lenientNATPoolAlarmThreshold bool

	// lenientPolicyMatchAddress (#2008) downgrades the policy match-
	// address validator (validatePolicyMatchAddressesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a policy source-address /
	// destination-address token that is neither a known address-book
	// name, the `any` keyword, nor a parseable CIDR / IP — a typo would
	// otherwise reach the dataplane, be silently dropped to an empty
	// set, and (under `*-address-excluded` inversion) FAIL OPEN to
	// match-all. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still boots
	// (the dataplane is independently hardened to fail CLOSED on an
	// empty excluded set, so a slipped-through typo denies rather than
	// opens). Like the other lenient gates this is an AST/typed-config
	// compile decision and deliberately does NOT live in SchemaValidate
	// (which only warns on the tolerant paths since #1319 PR 2).
	lenientPolicyMatchAddress bool
	// lenientEventAttributesMatch downgrades an uncompilable
	// event-options attributes-match regex from a hard error to a warning
	// on the tolerant load path. A config persisted under pre-#2008 xpf
	// (literal-equality matcher, any string accepted) may hold a pattern
	// that is not valid RE2; a node upgrading to the regex matcher must
	// still boot through that already-committed config rather than fail to
	// load. Commit stays strict (see the validator call site).
	lenientEventAttributesMatch bool
	// lenientIPsecPolicyProposalRef (#2073) downgrades the IPsec policy
	// proposal cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths. A dangling `proposals` reference (or
	// a PFS policy with no resolvable proposal) silently drops the
	// configured perfect-forward-secrecy group to the strongSwan default at
	// render time; commit/commit-check hard-reject it so a new operator edit
	// fails loudly, but an already-persisted or peer-synced config carrying
	// this latent misconfiguration must still boot (the render-path safety
	// net in pkg/ipsec resolveESPSettings preserves the PFS group on that
	// boot). Same doctrine as lenientPolicyMatchAddress.
	lenientIPsecPolicyProposalRef bool

	// lenientIPsecGatewayRefs (#2074) downgrades the IPsec VPN -> IKE
	// gateway cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient). A config persisted by an older binary,
	// or synced from a peer, may carry a VPN that references an undefined
	// or addressless gateway; an upgrading / receiving node must still
	// boot through it (warn) rather than fail-closed-on-load (#1960
	// class). Commit / commit-check stay strict — a new operator edit that
	// would render `remote_addrs = <gateway-name>` (a silently-dead
	// tunnel) is rejected. Same doctrine as lenientDeviceMap /
	// lenientPolicyMatchAddress.
	lenientIPsecGatewayRefs bool

	// lenientLogProfileStreamRef (#2008 H7) downgrades the
	// `security log profile <name> stream-name <stream>` cross-reference
	// from a hard error to a warning on the tolerant load / peer-sync
	// paths. A config persisted by an older binary (which silently dropped
	// the whole profile stanza), or synced from a peer, may carry a profile
	// naming a stream that is not configured; an upgrading / receiving node
	// must still boot through it (warn) rather than fail-closed-on-load
	// (#1960 class). Commit / commit-check stay strict — a new operator
	// edit that names a non-existent stream (a typo whose log routing would
	// silently never fire) is rejected. Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientLogProfileStreamRef bool

	// lenientNATHostMask (#2173) downgrades the static-NAT / NAT64
	// host-mask gate (validateNATHostMaskStrict) from a hard compile error
	// to a cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync
	// paths (CompileConfigLenient / CompileConfigForNodeLenient): #2132 made
	// the Rust dataplane tolerate the canonical host mask, PR #2167 then
	// hardened it to REJECT a non-host mask, so a config persisted/synced
	// with a non-host static-NAT match/prefix or NAT64 pool address (which
	// an older binary parsed-out silently, or a peer authored) must still
	// BOOT after upgrade (warn) instead of failing closed (#1960). Commit /
	// commit-check stay strict — a new operator edit whose rule the
	// dataplane will silently drop is rejected loudly. The dataplane drops
	// the bad entry independently, so a leniently-loaded config is already
	// inert for that rule. Same doctrine as lenientNATPoolAlarmThreshold.
	lenientNATHostMask bool

	// lenientUnsupportedInterfaceStanzas (#2008 H9/H10) downgrades the
	// interface silent-drop gate (validateUnsupportedInterfaceStanzasAST:
	// `interface [unit] mac` static-MAC override, `family inet|inet6
	// policer arp` per-unit ARP policer) from a hard error to a warning on
	// the tolerant load / peer-sync paths. Both stanzas parse-accept and
	// silently drop on every binary up to this gate, so an
	// already-persisted or peer-synced config may carry them; an upgrading
	// / receiving node must still boot through it (warn) rather than
	// fail-closed-on-load (#1960 class). Commit / commit-check stay strict
	// — a new operator edit that the dataplane cannot honour is rejected
	// instead of silently ignored. Same doctrine as
	// lenientVRRPTrackDuplicates / lenientLogProfileStreamRef.
	lenientUnsupportedInterfaceStanzas bool

	// lenientRoutingExportRef (#2144) downgrades the routing-export
	// cross-reference gate (validateRoutingExportReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. Set ONLY on the tolerant
	// load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient): a dynamic-protocol `export`, RIP
	// `redistribute`, BGP group/neighbor `export`, or `routing-options
	// forwarding-table export` naming an undefined policy-statement (or a
	// non-protocol typo) passed commit on every binary up to this gate, so
	// an already-persisted or peer-synced config may carry it; an upgrading
	// / receiving node must still BOOT through it (warn) rather than fail
	// closed (#1960). Commit / commit-check stay strict — a new operator
	// edit whose export FRR would reject, silently no-op, fail open
	// (route-map permit-all), or silently disable ECMP is rejected loudly.
	// The render-path fallbacks keep a leniently-loaded config behaving
	// exactly as it did before this gate. Same doctrine as
	// lenientLogProfileStreamRef.
	lenientRoutingExportRef bool
	// lenientApplicationSpecs (#2142) downgrades the application-definition
	// port/protocol gate (validateApplicationSpecsStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `set applications application <name>` whose
	// destination-port / source-port is malformed (non-numeric, out of
	// 1..65535, or an inverted low>high range) or whose protocol token is
	// neither a known name, a junos-* alias, nor a 0..255 number. Such a spec
	// was previously only WARNED (ValidateConfig): commit succeeded, the
	// dataplane app-id compiler skipped the unparsable port (recording the
	// AppID name first, then `continue`-ing past the bad port — a never-match
	// AppID), and a policy referencing it failed CLOSED on permit / fell
	// through OPEN on deny. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config carrying a bad app
	// def still BOOTS (#1960 no-brick) — the dataplane independently skips the
	// unparsable port, and the runtime #2124 capability gate
	// (expandUserspacePolicyApplications) fails the snapshot closed
	// (ForwardingSupported=false) for a referenced app it cannot represent, so
	// a leniently-loaded bad app is inert rather than silently mis-matching.
	// Commit stays strict so the operator's next edit fails loudly. This is an
	// AST/typed-config compile decision and deliberately does NOT live in
	// SchemaValidate (applications stay opaque there). Same doctrine as
	// lenientPolicyMatchAddress / lenientNATHostMask.
	lenientApplicationSpecs bool
	// lenientFilterProtocols (#2175 review) downgrades the firewall-filter
	// `from protocol <token>` gate (validateFilterProtocolsStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose protocol token is neither
	// a known protocol name, a junos-* alias, nor a 0..255 number — the same
	// acceptance set the centralized appid.ProtocolNumber SSOT admits (#2124
	// / #2175). Before this gate such a token was caught only by the
	// dataplane compiler (compileFirewallFilters → validateFilterProtocols),
	// whose error the daemon SWALLOWS (it is not in
	// requiredProtocolGateSentinels, so compileErrorMustAbortApply == false):
	// commit returned SUCCESS, the config was promoted, and the term silently
	// programmed NO protocol match (the pre-#2175 "match protocol 0"
	// surprise). The dataplane gate stays as defense-in-depth; this commit-
	// check gate makes the refusal operator-visible. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying a bad token still BOOTS (#1960 no-brick) —
	// the dataplane independently drops the protocol constraint, so a
	// leniently-loaded bad term is inert (it matches without a protocol
	// constraint, never silently "protocol 0"). Same doctrine as
	// lenientApplicationSpecs.
	lenientFilterProtocols bool
	// lenientNPTv6 (#2240) downgrades the NPTv6 (RFC 6296) validation gate
	// (validateNPTv6Strict) from a hard compile error to a cfg.Warnings entry.
	// The strict commit / commit-check path hard-rejects an NPTv6 static-NAT
	// rule whose `match destination-address` / `then static-nat nptv6-prefix` is
	// unparseable, not a /48 or /64, has mismatched prefix lengths, or is
	// non-IPv6. Before this gate such a rule was only WARNED by the dataplane
	// compiler (compileNPTv6 logged + `continue`d) and then DeleteStaleNPTv6
	// tore down the working translation entries of the valid subset's
	// predecessors — a fail-OPEN that silently disabled a working translation on
	// a typo. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying a bad NPTv6 rule still
	// BOOTS (#1960 no-brick) — the Rust helper's #2240 backstop
	// (Nptv6State::try_from_snapshots) rejects the snapshot at apply, so the
	// preflight keeps the previous live state and a leniently-loaded bad config
	// is inert. Commit stays strict so the operator's next edit fails loudly.
	// Same doctrine as lenientNATHostMask.
	lenientNPTv6 bool
}

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
// It clones the tree before expansion so the original tree is not mutated.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{})
}

// CompileConfigLenient is CompileConfig with the tolerant-path
// downgrades enabled (#1798 control-char sanitize-in-place, lenient
// VRRP track duplicates). Use on TOLERANT paths that compile an
// already-active / already-persisted config the operator did not just
// author — e.g. Store.Load of a persisted config — so an upgraded node
// boots through. MUST NOT be used on the candidate-commit path:
// commit / commit-check use the strict CompileConfig so new operator
// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
// covers the cluster paths (Store.SyncApply, peer-interface display).
// (The former #1733 equal-flow worker-cap downgrade was retired in
// #1830 (e) — the dataplane no longer caps equal-flow at 32 workers.)
func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{
		sanitizeFreeTextControlChars:       true,
		lenientVRRPTrackDuplicates:         true,
		lenientDeviceMap:                   true,
		lenientPolicyMatchAddress:          true,
		lenientTCPMSSRange:                 true,
		lenientEventAttributesMatch:        true,
		lenientIPsecPolicyProposalRef:      true,
		lenientIPsecGatewayRefs:            true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
		lenientRoutingExportRef:            true,
		lenientApplicationSpecs:            true,
		lenientFilterProtocols:             true,
		lenientNPTv6:                       true,
	})
}

func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:`-marked subtrees BEFORE every other
	// pre-expansion gate, group expansion, and compilation. Doing it first
	// means the tunnel-id collision gate ignores inactive tunnel
	// definitions, an `inactive: apply-groups foo` suppresses the inherited
	// config, and inactive nodes inside a `groups {}` body are pruned —
	// none of the ~15 compiler files or validators ever observe an inactive
	// node. cloneForExpansion returns a fresh, freely-mutable pruned tree in a
	// single deep copy (no double-clone on the has-inactive path); the result
	// never aliases the caller's tree, so the caller retains groups/apply-groups
	// nodes for `show configuration` and ExpandGroups below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #1873 R-B: tunnel-endpoint id collision gate. Runs on the
	// PRE-expansion tree (ExpandGroups removes the groups stanza) so
	// the check covers the UNION of tunnel names across all groups —
	// both cluster nodes accept/reject identically. Strict paths
	// hard-reject; lenient paths warn (see tunnelid.go). Read-only, so it is
	// safe to run on the soon-to-be-expanded copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	usedNodeFallback := false

	// Expand groups before compilation — resolve all apply-groups references.
	if err := tree.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
				return nil, fmt.Errorf("apply-groups: %w", err2)
			}
			usedNodeFallback = true
		} else {
			return nil, fmt.Errorf("apply-groups: %w", err)
		}
	}

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}
	if usedNodeFallback {
		cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
	}
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	return cfg, nil
}

// CompileConfigForNode is like CompileConfig but resolves ${node} variables
// in apply-groups names before lookup. nodeID selects which per-node group
// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
// resolves to group "node0"). This supports a single shared config for both
// nodes in a chassis cluster.
func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
}

// CompileConfigForNodeLenient is CompileConfigForNode with the
// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
// node-aware TOLERANT paths that compile an already-active / peer-synced
// config the local operator did not just author: Store.SyncApply (HA
// peer-sync ingress) and the read-only peer-interface display re-compiles
// (cli_show_interfaces.go, server_show_interfaces.go). MUST NOT be used on
// the candidate-commit path — see CompileConfigLenient.
func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
		sanitizeFreeTextControlChars:       true,
		lenientVRRPTrackDuplicates:         true,
		lenientDeviceMap:                   true,
		lenientPolicyMatchAddress:          true,
		lenientTCPMSSRange:                 true,
		lenientEventAttributesMatch:        true,
		lenientIPsecPolicyProposalRef:      true,
		lenientIPsecGatewayRefs:            true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
		lenientRoutingExportRef:            true,
		lenientApplicationSpecs:            true,
		lenientFilterProtocols:             true,
		lenientNPTv6:                       true,
	})
}

func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:` subtrees first — see compileConfigWithOpts.
	// Centralizing the strip in this shared node-aware entry guarantees BOTH
	// cluster nodes compile the identical active set from the same persisted
	// (Inactive-flag-carrying, JSON-synced) tree, so a deactivated stanza is
	// dead on both nodes — no split-brain firewall posture. cloneForExpansion
	// returns a fresh, freely-mutable pruned tree in a single deep copy (never
	// aliases the caller's tree) so ExpandGroupsWithVars below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #1873 R-B: union-of-groups tunnel id collision gate — see
	// compileConfigWithOpts. Pre-expansion on purpose; read-only, safe on the copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := tree.ExpandGroupsWithVars(vars); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	return cfg, nil
}

// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// #1798 free-text control-character gate. Strict (commit /
	// commit-check): hard-reject. Lenient (load / peer-sync / peer
	// display): scrub in place on this already-cloned tree and warn.
	// Runs on the group-expanded tree so values inherited via
	// apply-groups are covered, and BEFORE section compilation so the
	// lenient path's typed Config is built from the scrubbed values.
	var ctrlCharWarnings []string
	if opts.sanitizeFreeTextControlChars {
		for _, p := range sanitizeNodesControlChars(tree.Children, "") {
			ctrlCharWarnings = append(ctrlCharWarnings, fmt.Sprintf(
				"sanitized control characters in configuration value at %q (#1798)", p))
		}
	} else if err := validateNodesControlChars(tree.Children, ""); err != nil {
		return nil, err
	}

	// #1814 VRRP track-interface AST pre-walk. Runs on the group-expanded
	// tree (so apply-groups-inherited statements are covered) and BEFORE
	// section compilation so the lenient path's first-wins pruning is
	// what the compiler actually sees. Strict (commit / commit-check):
	// duplicate track-interface inside one vrrp-group hard-rejects.
	// Lenient (load / peer-sync): prune to the first + warn. Shape-only
	// warnings (nested+sibling both present, orphan priority-cost) come
	// from here too — the typed config cannot distinguish them
	// post-compile.
	trackWarnings, err := validateVRRPTrackInterfaceAST(tree.Children, "", opts.lenientVRRPTrackDuplicates)
	if err != nil {
		return nil, err
	}

	// #1979 Layer B Tier 3: tcp-mss range AST pre-walk. tcp-mss carries its
	// MSS value in either the kind node's flat Keys[1] or a hierarchical
	// `mss` child — a dual value-location the declarative SchemaValidate
	// walker cannot express, so it stays opaque in setSchema and is
	// range-checked here on the group-expanded tree (apply-groups-inherited
	// values covered), BEFORE the snapshot builder's Layer-A coercion would
	// see it. Strict (commit / commit-check): out-of-range hard-rejects.
	// Lenient (load / peer-sync): warn + let Layer A coerce so an upgraded
	// node loading a legacy out-of-range MSS still boots.
	mssWarnings, err := validateTCPMSSRanges(tree.Children, "", opts.lenientTCPMSSRange)
	if err != nil {
		return nil, err
	}

	// #2008 H9/H10 interface silent-drop gate. Runs on the group-expanded,
	// inactive-pruned tree (apply-groups-inherited stanzas covered;
	// `inactive:` stanzas already stripped upstream) and BEFORE section
	// compilation. Strict (commit / commit-check): a static `mac` override
	// or a `family inet|inet6 policer arp` — neither of which the dataplane
	// can honour — hard-rejects. Lenient (load / peer-sync): warn so an
	// already-persisted or peer-synced config that an older binary silently
	// accepted still boots (#1960 fail-closed-on-load class).
	unsupportedIfaceWarnings, err := validateUnsupportedInterfaceStanzasAST(
		tree.Children, opts.lenientUnsupportedInterfaceStanzas)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications:    make(map[string]*Application),
			ApplicationSets: make(map[string]*ApplicationSet),
		},
		ClassOfService: &ClassOfServiceConfig{
			ForwardingClasses: make(map[string]*CoSForwardingClass),
			DSCPClassifiers:   make(map[string]*CoSDSCPClassifier),
			DSCPRewriteRules:  make(map[string]*CoSDSCPRewriteRule),
			Schedulers:        make(map[string]*CoSScheduler),
			SchedulerMaps:     make(map[string]*CoSSchedulerMap),
			Interfaces:        make(map[string]*CoSInterface),
		},
	}
	cfg.Warnings = append(cfg.Warnings, ctrlCharWarnings...)
	cfg.Warnings = append(cfg.Warnings, trackWarnings...)
	cfg.Warnings = append(cfg.Warnings, mssWarnings...)
	cfg.Warnings = append(cfg.Warnings, unsupportedIfaceWarnings...)

	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return nil, fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
				return nil, fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return nil, fmt.Errorf("applications: %w", err)
			}
		case "routing-options":
			if err := compileRoutingOptions(node, &cfg.RoutingOptions); err != nil {
				return nil, fmt.Errorf("routing-options: %w", err)
			}
		case "protocols":
			if err := compileProtocols(node, &cfg.Protocols); err != nil {
				return nil, fmt.Errorf("protocols: %w", err)
			}
		case "routing-instances":
			if err := compileRoutingInstances(node, cfg); err != nil {
				return nil, fmt.Errorf("routing-instances: %w", err)
			}
		case "firewall":
			if err := compileFirewall(node, &cfg.Firewall); err != nil {
				return nil, fmt.Errorf("firewall: %w", err)
			}
		case "class-of-service":
			if err := compileClassOfService(node, cfg.ClassOfService); err != nil {
				return nil, fmt.Errorf("class-of-service: %w", err)
			}
		case "services":
			if err := compileServices(node, &cfg.Services); err != nil {
				return nil, fmt.Errorf("services: %w", err)
			}
		case "forwarding-options":
			if err := compileForwardingOptions(node, &cfg.ForwardingOptions); err != nil {
				return nil, fmt.Errorf("forwarding-options: %w", err)
			}
		case "system":
			if err := compileSystem(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("system: %w", err)
			}
		case "schedulers":
			if err := compileSchedulers(node, cfg); err != nil {
				return nil, fmt.Errorf("schedulers: %w", err)
			}
		case "policy-options":
			if err := compilePolicyOptions(node, &cfg.PolicyOptions); err != nil {
				return nil, fmt.Errorf("policy-options: %w", err)
			}
		case "chassis":
			if err := compileChassis(node, &cfg.Chassis); err != nil {
				return nil, fmt.Errorf("chassis: %w", err)
			}
		case "event-options":
			if err := compileEventOptions(node, &cfg.EventOptions); err != nil {
				return nil, fmt.Errorf("event-options: %w", err)
			}
		case "snmp":
			// Top-level snmp stanza (same format as system { snmp { ... } })
			if err := compileSNMP(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("snmp: %w", err)
			}
		case "bridge-domains":
			if err := compileBridgeDomains(node, &cfg.BridgeDomains); err != nil {
				return nil, fmt.Errorf("bridge-domains: %w", err)
			}
		}
	}

	// Extract lo0 filter input from parsed interfaces into SystemConfig.
	if lo0 := cfg.Interfaces.Interfaces["lo0"]; lo0 != nil {
		if u0 := lo0.Units[0]; u0 != nil {
			cfg.System.Lo0FilterInputV4 = u0.FilterInputV4
			cfg.System.Lo0FilterInputV6 = u0.FilterInputV6
		}
	}

	// Post-compilation fixup: resolve vSRX-style fabric member-interfaces.
	// For fab0/fab1 with fabric-options member-interfaces, resolve which member
	// belongs to the local node using FPC slot → node-id mapping (slot 0 → node0,
	// slot 7 → node1). Also auto-populate FabricInterface/Fabric1Interface when
	// not explicitly set in chassis cluster config.
	if cc := cfg.Chassis.Cluster; cc != nil {
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if !strings.HasPrefix(ifName, "fab") || len(ifc.FabricMembers) == 0 {
				continue
			}
			for _, member := range ifc.FabricMembers {
				slot := InterfaceSlot(member)
				if slot >= 0 && SlotToNodeID(slot) == cc.NodeID {
					ifc.LocalFabricMember = member
					break
				}
			}
		}
		// Auto-detect fabric interfaces from fab0/fab1 member-interfaces
		// when not explicitly configured via fabric-interface/fabric1-interface.
		// Only set if the local node has a member (LocalFabricMember resolved above).
		// Dual-fabric: if both fab0 and fab1 have local members, set both
		// FabricInterface and Fabric1Interface (#130).
		// Single-fabric: only one fab is local → FabricInterface only.
		if cc.FabricInterface == "" {
			if f0, ok := cfg.Interfaces.Interfaces["fab0"]; ok && f0.LocalFabricMember != "" {
				cc.FabricInterface = "fab0"
			} else if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.FabricInterface = "fab1"
			}
		}
		// Auto-detect secondary fabric: fab1 when primary is fab0 and fab1
		// also has a local member (dual-fabric topology).
		if cc.Fabric1Interface == "" && cc.FabricInterface == "fab0" {
			if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.Fabric1Interface = "fab1"
			}
		}
		// Auto-derive Fabric1PeerAddress from the fab1 interface's /30 or /31
		// address when not explicitly configured.
		if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress == "" {
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				if u0 := f1.Units[0]; u0 != nil {
					for _, addr := range u0.Addresses {
						if peer := peerFromPointToPoint(addr); peer != "" {
							cc.Fabric1PeerAddress = peer
							break
						}
					}
				}
			}
		}
	}

	// #1526 — reject retired dataplane backends at commit time.
	// Placed BEFORE the other strict validators so that an operator
	// editing a candidate that has BOTH a retired dataplane-type and
	// an unrelated structural error (CoS, policers, scheduler-map)
	// sees the migration message first. The retirement is the
	// documented migration path; the other errors only become
	// actionable after migration. This precheck stays fail-fast
	// (the no-leak contract is pinned by
	// TestDataplaneTypeDPDKRejectedAtCommitFiresFirst in
	// parser_ast_test.go).
	//
	// Store.Load and Store.SyncApply tolerate retired-backend
	// configs via rewriteRetiredDataplaneType which strips the
	// retired leaf from the AST before compile (#1373 ebpf +
	// #1525 dpdk handle both this way). See
	// pkg/configstore/dataplane_retire.go.
	if err := validateDataplaneTypeStrict(cfg); err != nil {
		return nil, err
	}

	// #1538 — accumulate independent strict-validator families so
	// `commit check` surfaces one error per family in a single
	// response. This saves operator round-trips on first-touch
	// upgrades from legacy candidates that carry several dormant
	// structural findings at once. Validators in this group MUST
	// remain independent: each reads its own typed sub-struct of
	// *Config and does not depend on another's success. Each
	// validator still fail-fasts INTERNALLY (one error per family
	// in a single response), which is sufficient for the upgrade
	// UX win; full intra-validator accumulation is deliberately
	// out of scope. If a future validator depends on another's
	// success it must be added as a separate post-accumulator
	// step with its own guard rather than slotted in alongside
	// the independent set.
	var strictErrs []error
	if err := validateClassOfServiceStrict(cfg.ClassOfService); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateRPMProbePinsStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateIPMonitoringStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	// #1830 (e): the #1733 equal-flow worker-cap validator
	// (validateEqualFlowWorkerCapStrict / MaxEqualFlowWorkers) is retired.
	// The v8 lease rotation now sizes its per-worker scratch from the true
	// worker count (heap scratch in rotate_epoch_v8.rs), so
	// equal-flow-enforcement no longer fail-opens above 32 workers and the
	// commit-time rejection has nothing left to guard.
	if err := errors.Join(strictErrs...); err != nil {
		return nil, err
	}

	// #1956 device-map cross-entry validation. Strict on commit /
	// commit-check (hard-reject duplicate names/PCI/MAC, RETH key-mac,
	// FPC/node misalignment); lenient on load / peer-sync (warn so an
	// already-persisted or peer-section config still boots — V-1). Runs
	// AFTER the accumulator so a structural CoS/policer error still wins
	// the first-error slot.
	if err := validateDeviceMapStrict(cfg); err != nil {
		if opts.lenientDeviceMap {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("device-map (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 policy match-address fail-open gate. Strict on commit /
	// commit-check (hard-reject a typo'd source/destination address
	// that would be silently dropped and — under `*-address-excluded`
	// inversion — fail open to match-all); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots).
	// Runs AFTER the strict accumulator + device-map so a structural
	// CoS/policer/device-map error still wins the first-error slot.
	if err := validatePolicyMatchAddressesStrict(cfg); err != nil {
		if opts.lenientPolicyMatchAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2142 application-definition port/protocol fail-open gate. Strict on
	// commit / commit-check (hard-reject a `set applications application` whose
	// destination-port / source-port is malformed or whose protocol is unknown
	// — such a spec was only warned, then compiled into a never-match AppID a
	// referenced policy depends on, failing CLOSED on permit / OPEN on deny);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config carrying a bad app def still boots — the dataplane skips the bad
	// port and the #2124 runtime capability gate fails closed for a referenced
	// app it cannot represent). Reuses validatePortSpec / validateProtocol, the
	// same config-layer validators that produced the warning, so no new
	// divergent table is introduced.
	if err := validateApplicationSpecsStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application spec (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2175 firewall-filter `from protocol <token>` fail-open gate. Strict on
	// commit / commit-check (hard-reject a term whose protocol token is not
	// resolvable by the centralized appid.ProtocolNumber SSOT — neither a
	// known protocol name, a junos-* alias, nor a 0..255 number). Before this
	// gate such a token was caught only by the dataplane compiler
	// (compileFirewallFilters → validateFilterProtocols), whose error the
	// daemon SWALLOWS (not in requiredProtocolGateSentinels, so
	// compileErrorMustAbortApply == false): commit returned SUCCESS, the
	// config was promoted, and the term silently programmed NO protocol match
	// (the pre-#2175 "match protocol 0" surprise). The dataplane gate remains
	// as defense-in-depth; this gate makes the refusal operator-visible at
	// commit, consistent with validateApplicationSpecsStrict / the other
	// fail-open gates. Lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config carrying a bad token still boots — #1960
	// no-brick; the dataplane drops the constraint independently so the term
	// is inert, never silently "protocol 0"). Runs on the fully-compiled
	// *Config (firewall filters compiled) so the typed term list is populated.
	if err := validateFilterProtocolsStrict(cfg); err != nil {
		if opts.lenientFilterProtocols {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2073 IPsec policy proposal cross-reference gate. Strict on commit /
	// commit-check (hard-reject a dangling ipsec policy -> proposal
	// reference that would silently drop the configured perfect-forward-
	// secrecy group to the strongSwan default); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — the
	// render-path safety net in pkg/ipsec preserves the PFS group on that
	// boot). Runs alongside the other tolerant-downgradable cross-ref gates.
	if err := validateIPsecPolicyProposalReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecPolicyProposalRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec policy proposal reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 M7 / #2141: event-options attributes-match patterns are RE2
	// regexes (Junos `matches` semantics). The strict validator rejects at
	// commit not only an uncompilable pattern (#2008 M7) but also a malformed
	// match expression and an unknown <field> name (#2141) — both previously
	// fail-open: the runtime matcher silently DROPPED the constraint, turning
	// targeted remediation into broad config mutation while commit succeeded.
	// Strict-reject gives the operator immediate feedback. On the tolerant
	// LOAD path (#2063 review), downgrade to a warning: a config persisted
	// under the pre-#2008 literal-equality matcher could hold a non-RE2
	// pattern or a now-rejected malformed/unknown line, and an upgrading node
	// must still boot through it (mirrors every sibling validator above). The
	// runtime matcher then fails CLOSED on the legacy malformed line (#2141 /
	// #2124 doctrine) so the suspicious policy does not over-fire. Commit
	// stays strict.
	if err := ValidateEventAttributesMatchStrict(cfg); err != nil {
		if opts.lenientEventAttributesMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("event-options attributes-match (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2074 IPsec VPN -> IKE gateway cross-reference. A VPN that
	// references a gateway which is neither a defined gateway object nor a
	// usable inline IP/hostname would render `remote_addrs = <gateway-name>`
	// — a config-object name strongSwan cannot use, a silently-dead tunnel.
	// Strict on commit / commit-check (hard reject so the operator gets a
	// diagnostic); lenient on load / peer-sync (warn so a pre-fix or
	// peer-synced config still boots — #1960 fail-closed-on-load class).
	// Runs on the fully-compiled *Config so both ike{} and ipsec{} gateway
	// definitions are present regardless of stanza authoring order. Mirrors
	// validateDeviceMapStrict / the policy match-address gate above.
	if err := validateIPsecGatewayReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecGatewayRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec gateway reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 H7 security log profile -> stream cross-reference. A
	// `security log profile <name> stream-name <stream>` that names a
	// stream which is not configured would route to nowhere — the operator
	// authored a log profile whose target silently never receives events.
	// Before H7 the whole profile stanza was dropped silently; now it is
	// compiled and the reference is checked. Strict on commit / commit-
	// check (hard reject so the typo is operator-visible); lenient on load
	// / peer-sync (warn so a config persisted by an older binary that
	// dropped the stanza, or a peer-synced config, still boots — #1960
	// fail-closed-on-load class). Runs on the fully-compiled *Config so the
	// stream map is fully populated regardless of authoring order. Mirrors
	// validateIPsecPolicyProposalReferencesStrict.
	if err := validateLogProfileStreamReferencesStrict(cfg); err != nil {
		if opts.lenientLogProfileStreamRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("security log profile stream reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2144 routing export cross-reference gate. A dynamic-protocol
	// `export` (OSPF/OSPFv3/BGP/IS-IS), a RIP `redistribute`, a BGP
	// group/neighbor `export`, or a `routing-options forwarding-table
	// export` whose token is neither a known redistribution protocol nor a
	// defined policy-statement passes commit unnoticed, then at FRR render
	// time either fails the reload, silently no-ops, fails OPEN as a
	// permit-all route-map, or silently disables ECMP. Strict on commit /
	// commit-check (hard reject so the typo is operator-visible); lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 fail-closed-on-load class). Runs on the fully-
	// compiled *Config so the policy-statement map is populated regardless
	// of authoring order. Mirrors validateLogProfileStreamReferencesStrict.
	if err := validateRoutingExportReferencesStrict(cfg); err != nil {
		if opts.lenientRoutingExportRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("routing export reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	if warnings := ValidateConfig(cfg); len(warnings) > 0 {
		for _, w := range warnings {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}

	// #1814 typed-config track warnings (both strict and lenient paths):
	// track-interface without any priority-cost (no effect),
	// track-priority-cost without track-interface (no effect), and
	// tracking on an address-owner group (priority 255) where the
	// runtime ignores tracking.
	cfg.Warnings = append(cfg.Warnings, vrrpTrackConfigWarnings(cfg)...)

	// #2079: NAT source pool-utilization-alarm threshold gate. Require
	// 0 < clear < raise <= 100. Strict (commit / commit-check): hard-reject a
	// bare `pool-utilization-alarm;` (raise=0/clear=0, always-firing) or an
	// inverted/equal pair. Lenient (load / peer-sync): warn + let the runtime
	// monitor treat raise<=0 as disabled, so an upgraded node loading a legacy
	// config committed before this gate existed still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick it).
	napWarnings, err := validatePoolUtilizationAlarm(cfg, opts.lenientNATPoolAlarmThreshold)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, napWarnings...)

	// #2227 MAJOR-1: port-scan / ip-sweep threshold clamp warning. The AF_XDP
	// dataplane bounds its per-(zone,source) unique-destination set at
	// MAX_UNIQUE_PER_SOURCE and clamps the effective detection threshold to
	// maxScanSweepThreshold (= MAX_UNIQUE_PER_SOURCE - 1) so an over-cap
	// threshold detects at the cap (fail-closed) instead of never (the
	// pre-fix silent fail-OPEN). A configured threshold above the maximum is
	// preserved unchanged but warned about here — clamp-warn, never reject, so
	// existing/peer-synced configs keep booting on both compile paths.
	cfg.Warnings = append(cfg.Warnings, validateScreenScanSweepThresholds(cfg)...)

	// #2173: static-NAT / NAT64 host-mask gate. #2132 made the Rust
	// dataplane tolerate the canonical /32-/128 host mask and PR #2167 then
	// hardened it to REJECT a non-host mask — so a misconfigured non-host
	// static-NAT match/prefix or NAT64 pool address is now SILENTLY DROPPED
	// at the dataplane (parsed-out, never installed) with no operator
	// feedback. Strict (commit / commit-check): hard-reject a non-host mask
	// (static NAT is strictly host-1:1, NAT64 pool entries are discrete host
	// IPs). Lenient (load / peer-sync): warn so a config committed before
	// this gate existed (or peer-synced) still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick restart); the
	// dataplane drops the bad entry independently, so it is already inert.
	hostMaskWarnings, err := validateNATHostMaskStrict(cfg, opts.lenientNATHostMask)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, hostMaskWarnings...)

	// #2240: NPTv6 (RFC 6296) validation gate. The dataplane compiler
	// (compileNPTv6) historically warned + `continue`d past a malformed NPTv6
	// rule and then deleted stale entries over only the VALID subset, so a typo
	// in one rule silently tore down a previously-working translation
	// (fail-open). Strict (commit / commit-check): hard-reject a malformed NPTv6
	// rule so the operator sees the misconfiguration and the previous forwarding
	// state is preserved. Lenient (load / peer-sync): warn so a config committed
	// before this gate existed still boots; the Rust helper independently
	// rejects the snapshot and keeps the previous live state, so the bad config
	// is inert.
	nptv6Warnings, err := validateNPTv6Strict(cfg, opts.lenientNPTv6)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, nptv6Warnings...)

	// #1892: retired DPDK-era `system dataplane` knobs (cores, memory,
	// socket-mem, rx-mode, ports) parse for stored-config compatibility
	// but configure nothing — warn so the operator knows the stanza is
	// inert instead of silently dropping it.
	cfg.Warnings = append(cfg.Warnings, userspaceRetiredKnobWarnings(cfg)...)

	// #1539: the structural invariant `cfg.System.DPDKDataplane = nil`
	// was added on master (PR #1553) as a runtime safeguard against
	// AST leakage of retired DPDK sub-tree fields. After this PR
	// deletes the DPDKDataplane field entirely (per #1539 author's
	// explicit note: "This is dead code after #1528 (Phase 3) deletes
	// the field entirely; remove this line in #1528"), the field no
	// longer exists, so the Go compiler enforces the invariant at
	// compile time — there is no value to nil out.

	return cfg, nil
}
