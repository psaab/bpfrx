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

	// lenientIKEPolicyChainRef (#2270) downgrades the IKE (Phase 1)
	// gateway -> ike-policy -> ike-proposal cross-reference check from a
	// hard error to a warning on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient). A dangling
	// ike-policy reference (the policy is undefined, or its `proposals`
	// reference dangles) made resolveIKESettings return an empty proposal,
	// which renderConfig omitted entirely — strongSwan then negotiated
	// phase-1 with its compiled-in default set (a silent crypto downgrade).
	// Commit / commit-check hard-reject it so a new operator edit fails
	// loudly, but an already-persisted or peer-synced config carrying this
	// latent misconfiguration must still boot (the render-path safety net in
	// pkg/ipsec resolveIKESettings -> renderConfig skips the unrenderable VPN
	// rather than negotiating with defaults). Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientIKEPolicyChainRef bool

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
	// lenientFRRAuthValues (#2889) downgrades the FRR auth-value gate
	// (validateFRRAuthValuesStrict) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths.
	// A BGP neighbor TCP-MD5 password or an OSPF/RIP/IS-IS authentication
	// key containing whitespace cannot be expressed as a single FRR/vtysh
	// token (FRR's command lexer, lib/command_lex.l, tokenizes purely on
	// whitespace and has NO quoted-string and NO rest-of-line token), so it
	// would be split into multiple args at frr.conf load — truncating the
	// secret at the first space or, worse, treating trailing words as extra
	// vtysh arguments. This gate rejects such a value at commit so the
	// operator sees it, instead of a silently-broken authentication setup.
	// Commit / commit-check stay strict; an already-persisted or peer-synced
	// config carrying such a value must still BOOT (warn) per the #1960
	// fail-closed-on-load doctrine — the render path already strips control
	// chars (sanitizeFRRValue) so the malformed line stays inert/single-line.
	// Same doctrine as lenientRoutingExportRef.
	lenientFRRAuthValues bool
	// lenientRouteFilterMatchTypes (#2525) downgrades the route-filter
	// match-type gate (validateRouteFilterMatchTypesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects an FRR-unsupported `through` match-type and a
	// malformed / inverted / out-of-range / below-base `prefix-length-range`.
	// These match-types committed unnoticed before this gate (the schema
	// admitted them and the renderer silently degraded them to an open-ended
	// `le maxLen`), so an already-persisted or peer-synced config may carry
	// one; an upgrading / receiving node must still BOOT through it (warn)
	// rather than fail closed (#1960). The renderer skips the offending entry
	// on the tolerant path (match-nothing, fail-closed). Same doctrine as
	// lenientRoutingExportRef.
	lenientRouteFilterMatchTypes bool
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
	// lenientFilterActions (#2399 finding 032-16) downgrades the
	// firewall-filter `then` action gate (validateFilterActionsStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose `then` block carries a token
	// that is neither a recognized terminating action (accept/reject/discard)
	// nor a recognized modifier. Before this gate such a token was silently
	// DROPPED at compile, leaving Action == "" which the dataplane compiler and
	// the Rust filter both map to ACCEPT (a fail-open permit). The tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying an unknown action still BOOTS (#1960
	// no-brick). Same doctrine as lenientFilterProtocols.
	lenientFilterActions bool
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
	// lenientFirewallRefs (#2217) downgrades the firewall-filter term
	// cross-reference gates — `then policer <name>` (Finding A,
	// validateFirewallPolicerReferencesStrict) and `then routing-instance
	// <name>` FBF (Finding C, validateFirewallRoutingInstanceReferencesStrict)
	// — from a hard compile error to a cfg.Warnings entry. Both references were
	// previously unvalidated: a dangling policer silently never rate-limited
	// (fail-open) and a dangling FBF routing-instance silently blackholed /
	// fell through to the default table. The strict commit / commit-check path
	// hard-rejects so the typo is operator-visible; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config still
	// BOOTS (#1960 fail-closed-on-load class) — the dataplane behaves as it did
	// before (term unpoliced / steered to a missing table), so a leniently-
	// loaded config is no worse than before the gate. Same doctrine as
	// lenientRoutingExportRef.
	lenientFirewallRefs bool
	// lenientFlowServerTemplateRef (#2461) downgrades the per-flow-server
	// NetFlow v9 / IPFIX template cross-reference gate
	// (validateFlowServerTemplateReferencesStrict) from a hard compile
	// error to a cfg.Warnings entry. A flow-server `version9 { template
	// <name> }` / `version-ipfix { template <name> }` (or the flat
	// `version9-template` / `version-ipfix-template`) reference that names
	// no defined `services flow-monitoring` template was previously
	// unvalidated: the live exporter ignored the reference and silently
	// used the first map-iteration template, so a collector received a
	// template (timeouts / export-extensions) it never requested and the
	// choice flipped nondeterministically across restarts. The strict
	// commit / commit-check path hard-rejects so the typo is operator-
	// visible; the tolerant load / peer-sync paths warn so an already-
	// persisted or peer-synced config carrying a dangling reference still
	// BOOTS (#1960 fail-closed-on-load class) — the resolver drops a group
	// whose template is undefined, so a leniently-loaded config exports
	// nothing for that collector rather than the wrong template. Same
	// doctrine as lenientLogProfileStreamRef.
	lenientFlowServerTemplateRef bool
	// lenientSamplingInstanceConflicts (#2462) downgrades the
	// multi-sampling-instance conflict gate
	// (validateSamplingInstanceConflictsStrict) from a hard compile error to
	// a cfg.Warnings entry. Two `forwarding-options sampling instance` blocks
	// that each export the SAME (export-version, address-family) pair are
	// genuinely ambiguous — there is no per-interface sampling-instance
	// selector, so a flow of that family cannot be attributed to one instance
	// — and were previously silently flattened into one global policy (one
	// map-order-dependent rate, one merged collector set; flows from instance
	// A reaching instance B's collectors). The strict commit / commit-check
	// path hard-rejects so the operator sees it; the tolerant load / peer-sync
	// paths warn so an already-persisted or peer-synced config still BOOTS
	// (#1960) — the resolver still emits both instances' independent
	// ExportConfigs, so eligible flows duplicate to both instances rather than
	// bricking the load. Same doctrine as lenientFlowServerTemplateRef.
	lenientSamplingInstanceConflicts bool
	// lenientApplicationSetMembers (#2217 Finding B) downgrades the
	// application-set member cross-reference gate
	// (validateApplicationSetMembersStrict) from a hard compile error to a
	// cfg.Warnings entry. An application-set member referencing neither a
	// defined application (user / junos-* predefined) nor a defined nested
	// application-set was previously unvalidated: a policy matching such a set
	// silently failed to match the intended traffic (the unresolved member
	// never matches — an effective no-op term, fail-open). The strict commit /
	// commit-check path hard-rejects; the tolerant load / peer-sync paths warn
	// so an already-persisted or peer-synced config carrying a dangling member
	// still BOOTS (#1960) — the dataplane drops the unresolved member
	// independently, so it is already inert. Same doctrine as
	// lenientApplicationSpecs.
	lenientApplicationSetMembers bool
	// lenientRibGroupRefs (#2226) downgrades the rib-group import-rib
	// cross-reference gate (validateRibGroupImportRibReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. An `import-rib` naming a rib
	// that resolves to no real routing table (a typo, a non-existent instance,
	// or unparseable garbage) was previously unvalidated: the applier mapped
	// the unresolvable name to a bare table 0, which differs from any
	// instance's (>= 100) source table, so it spuriously installed an `ip rule
	// from all lookup <sourceTable>` — a silent mis-leak of the source table
	// into the main lookup. The strict commit / commit-check path hard-rejects
	// so the typo is operator-visible; the tolerant load / peer-sync paths warn
	// so an already-persisted or peer-synced config carrying a dangling
	// import-rib still BOOTS (#1960) — the applier's resolveRibTable ok=false
	// guard skips the phantom rib and installs no rule, so a leniently-loaded
	// config is already inert. Same doctrine as lenientRoutingExportRef.
	lenientRibGroupRefs bool
	// lenientDHCPStaticBindings (#2243 review) downgrades the DHCP-server
	// static (fixed/reserved) host-binding gate (validateDHCPStaticBindingsStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a binding whose fixed-address is malformed,
	// family-mismatched, outside the enclosing pool subnet, or duplicates another
	// binding's MAC/address in the same pool. The tolerant load / peer-sync paths
	// downgrade to a warning so an already-persisted or peer-synced config
	// carrying a bad binding still BOOTS (#1960 no-brick) — without the gate the
	// whole config-load HARD-REJECTED, unlike every sibling validator. The Kea
	// renderer skips an empty/unparseable binding independently (and canonicalizes
	// the MAC), so a leniently-loaded bad binding is inert. Same doctrine as
	// lenientPolicyMatchAddress.
	lenientDHCPStaticBindings bool
	// lenientWireguardPeers (#1434 multi-peer) downgrades the WireGuard
	// per-peer gate (validateWireguardPeersStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a WG tunnel with zero peers, a duplicate peer
	// pubkey, a malformed (non-64-hex) pubkey/PSK, or endpoint-bearing
	// peers that disagree on outer transport family (one UDP socket = one
	// outer family). The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still BOOTS
	// (#1960 no-brick) — the Rust hydrate path independently drops a WG
	// row with a malformed key (hydrate_wg_identity) and the engine
	// reconcile is dup-pubkey-safe, so a leniently-loaded bad config is
	// inert. Same doctrine as lenientNATHostMask.
	lenientWireguardPeers bool
	// lenientPolicyZoneRefs (#2401) downgrades the security-policy
	// zone-pair reference gate (validatePolicyZoneReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a `from-zone`/`to-zone` policy stanza
	// that names a security zone the config never defines. Such a rule is
	// compiled and kept, but the dataplane resolves its from/to zone name to
	// no zone-id and so never indexes it into the zone-pair lookup
	// (userspace-dp/src/policy.rs unknown-zone branch — "rule kept, but not
	// indexed"); the zone pair then falls through to the default action,
	// silently failing OPEN under a permit default (or blackholing under a
	// deny default). ValidateConfig only WARNED on this, so the commit
	// succeeded with an unenforceable rule. The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced
	// config carrying a stale zone reference still BOOTS (#1960 no-brick) —
	// the dataplane drops the unindexed rule independently, so a leniently-
	// loaded bad config is inert. Same doctrine as lenientPolicyMatchAddress.
	lenientPolicyZoneRefs bool
	// lenientZoneCount (#2391) downgrades the security-zone count cap gate
	// (validateZoneCountStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects a config that
	// defines more than MaxUsableZoneID (255) security zones — the 256th+ zone
	// ids overflow the u8 event-stream wire field and were silently dropped by
	// the userspace forwarding builder, collapsing the affected interfaces to
	// zone 0 ("unknown") instead of failing the commit. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or peer-
	// synced config an older binary accepted still BOOTS (#1960 no-brick) — the
	// dataplane independently fails closed on every overflowing zone, so a
	// leniently-loaded over-cap config is inert (the overflow zones do not
	// forward) rather than mis-attributed. Same doctrine as lenientPolicyZoneRefs.
	lenientZoneCount bool
	// lenientZoneInterfaceMembership (#3072) downgrades the zone-interface
	// membership gate (validateZoneInterfaceMembershipStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a config that assigns the same interface to more than
	// one security zone — pkg/dataplane/userspace.buildInterfaceZoneMap resolves
	// such a duplicate first-writer-wins over the SORTED zone names, so the
	// interface silently lands in whichever zone sorts first and traffic is
	// evaluated against the wrong zone's policy. The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// an older binary accepted still BOOTS (#1960 no-brick) — buildInterfaceZoneMap
	// keeps its deterministic first-writer-wins resolution, so the leniently-
	// loaded config forwards exactly as before, just with an operator-visible
	// warning. Same doctrine as lenientPolicyZoneRefs.
	lenientZoneInterfaceMembership bool
	// lenientDestNATAddresses (#2396) downgrades the destination-NAT
	// destination-address gate (validateDestinationNATAddressesStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a DNAT rule whose `match
	// destination-address` resolves to NO parseable host IP at all — every
	// configured destination is malformed/empty. The Go snapshot builder skips
	// each unparseable destination (#2395) and the Rust DNAT table `continue`s
	// on a destination it cannot parse, so such a rule emits NO table entry and
	// silently translates NOTHING — an operator who fat-fingered the only
	// destination gets a committed-but-inert rule with no feedback (the #2396
	// (c) silent-drop). Hard-rejecting it at commit makes the mistake visible.
	// The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying a bad destination still
	// BOOTS (#1960 no-brick) — the dataplane drops the rule independently, so a
	// leniently-loaded bad config is inert. Same doctrine as
	// lenientPolicyZoneRefs / lenientNATHostMask.
	lenientDestNATAddresses bool
	// lenientRPMSourceAddress (#2492) downgrades the RPM test
	// source-address gate (validateRPMSourceAddressStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects an RPM test whose `source-address`
	// is non-empty but unparseable, or whose source address-family does
	// not match an IP-literal target. A malformed source silently turns
	// the tcp-ping/http-get probe dialer into a wildcard/kernel-chosen
	// source bind (net.ParseIP -> nil -> TCPAddr{IP:nil}), so the probe
	// measures the DEFAULT uplink instead of the pinned source path and
	// publishes PASS/FAIL for the wrong path — and RPM feeds
	// event-options / ip-monitoring failover. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying a bad source still BOOTS (#1960
	// no-brick); the runtime probeDialer guard returns ErrProbeSetup for
	// the same malformed source, so the leniently-loaded test HOLDS
	// state rather than actuating routes off a wildcard measurement.
	// Same doctrine as lenientDestNATAddresses / lenientNATHostMask.
	lenientRPMSourceAddress bool
	// lenientRPMLinkLocalZone (#2494) downgrades the bare-link-local RPM
	// target gate (validateRPMLinkLocalZoneStrict) from a hard compile
	// error to a cfg.Warnings entry. An IPv6 link-local target with no
	// `%zone` and no destination-interface has no egress-link scope, so
	// the kernel cannot pick the link and the probe is dead. Strict on
	// commit / commit-check (hard reject so the gap is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick; the runtime
	// probeICMP guard returns ErrProbeSetup for the same scopeless
	// link-local, so the leniently-loaded test HOLDS state rather than
	// actuating off a dead measurement). Same doctrine as
	// lenientRPMSourceAddress.
	lenientRPMLinkLocalZone bool
	// lenientRPMHTTPGetScheme (#2495) downgrades the http-get target
	// scheme gate (validateRPMHTTPGetSchemeStrict) from a hard compile
	// error to a cfg.Warnings entry. An http-get target that carries a
	// scheme other than http/https (ftp://, gopher://, …) makes
	// http.NewRequestWithContext error before a packet is sent, so the
	// probe never runs and publishes a permanent FAIL into event-options
	// / ip-monitoring failover. Strict on commit / commit-check (hard
	// reject so the bad scheme is operator-visible); lenient on load /
	// peer-sync (warn — #1960 no-brick; the runtime canonicalizeHTTPTarget
	// guard returns the same error for the bad scheme, so the
	// leniently-loaded test HOLDS state rather than actuating off a probe
	// that can never run). Same doctrine as lenientRPMLinkLocalZone.
	lenientRPMHTTPGetScheme bool
	// lenientRPMRoutingInstance (#2496) downgrades the RPM test
	// routing-instance cross-reference gate
	// (validateRPMRoutingInstanceStrict) from a hard compile error to a
	// cfg.Warnings entry. An RPM test whose `routing-instance` names a
	// nonexistent instance makes the runtime bind the probe DATA socket to
	// a synthesized vrf-<name> device (SO_BINDTODEVICE) that does not exist
	// → ENODEV → the probe never sends a packet and the test HOLDS its
	// state forever (no PASS, no FAIL), starving any event-options /
	// ip-monitoring policy keyed off it of a failover signal. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick; the runtime bind
	// returns ENODEV for the same nonexistent instance, so the leniently-
	// loaded test HOLDS state rather than actuating off a dead measurement).
	// Same doctrine as lenientRPMHTTPGetScheme.
	lenientRPMRoutingInstance bool
	// lenientBGPNeighborPeerAS (#2963) downgrades the BGP neighbor peer-as
	// gate (validateBGPNeighborPeerASStrict) from a hard compile error to a
	// cfg.Warnings entry. A BGP neighbor whose effective peer-as (remote-as)
	// is missing/0 (or out of [1, 4294967295]) was previously unvalidated:
	// peer-as is optional in the parser/compiler, so a neighbor authored
	// without one keeps the zero value and the FRR renderer (policy_render.go)
	// emitted `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and
	// FRR/vtysh rejects it, failing the whole frr-reload (a single vtysh -f
	// add-batch exits non-zero on any CMD_WARNING_CONFIG_FAILED) and leaving
	// dynamic routing in a broken/stale state — a commit-accepted config the
	// routing daemon cannot load. The strict commit / commit-check path
	// hard-rejects so the missing peer-as is operator-visible, naming the
	// neighbor; the tolerant load / peer-sync paths warn so an
	// already-persisted or peer-synced config carrying such a neighbor still
	// BOOTS (#1960 fail-closed-on-load class) — the render path now skips a
	// remote-as-0 neighbor (defense-in-depth), so AS 0 never reaches frr.conf
	// and a leniently-loaded bad neighbor is inert. Same doctrine as
	// lenientRoutingExportRef.
	lenientBGPNeighborPeerAS bool
	// lenientRouterID (#2980) downgrades the OSPF/OSPFv3/BGP router-id gate
	// (validateRouterIDStrict) from a hard compile error to a cfg.Warnings
	// entry. router-id is parsed as a raw string with no validation, so a
	// malformed value (not a 32-bit IPv4 dotted-quad — e.g. garbage, an
	// out-of-range octet, or an IPv6 address) flowed verbatim into frr.conf.
	// FRR/vtysh requires an IPv4 router-id for ALL routing protocols
	// (including the IPv6 protocols OSPFv3 and BGP) and rejects anything else,
	// failing the whole frr-reload (a single vtysh -f add-batch exits non-zero
	// on any CMD_WARNING_CONFIG_FAILED) and leaving dynamic routing
	// broken/stale — a commit-accepted config the routing daemon cannot load.
	// The strict commit / commit-check path hard-rejects so the bad value is
	// operator-visible, naming the scope and protocol; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config
	// carrying such a router-id still BOOTS (#1960 fail-closed-on-load class)
	// — the render path now skips an invalid router-id (defense-in-depth), so
	// the malformed value never reaches frr.conf and a leniently-loaded bad
	// router-id is inert. Same doctrine as lenientBGPNeighborPeerAS.
	lenientRouterID bool
	// lenientSNMPTrapGroup (#2990) downgrades the SNMP trap-group commit gate
	// (unknown trap-group child key, e.g. a `tragets` typo, and an
	// enabled-but-zero-target trap group) from a hard compile error to a
	// cfg.Warnings entry. Before #2990 the trap-group schema had children:nil
	// and the compiler silently dropped every child but `targets`, so a typo'd
	// or zero-target trap group COMMITTED CLEANLY and persists in active.json.
	// The #2990 strict gate rejects such a group at commit (operator-visible,
	// naming the offending key) — but on the tolerant load / peer-sync path it
	// MUST warn, not error, or an already-persisted bad trap group would fail
	// CompileConfigLenient and blackout the boot / alarm-loop HA sync (the
	// exact #1960 fail-closed-on-load class compileTreeLenient exists to
	// prevent). Runtime is already inert for both cases — sendLinkTraps skips a
	// zero-target group and never reads an unknown key — so a leniently-loaded
	// bad group is harmless. Same doctrine as lenientRouterID.
	lenientSNMPTrapGroup bool
	// lenientPolicyTerminalAction (#3043) downgrades the security-policy
	// terminal-action gate (validatePolicyTerminalActionStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a policy that does not name EXACTLY one
	// terminal action: a log-only / count-only or typo'd policy compiled with
	// Action == PolicyPermit (the zero value) and silently PERMITTED all
	// matching traffic — a fail-OPEN security hole — while a policy naming
	// more than one terminal action resolved last-wins by parse order. The
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config that an older binary accepted
	// still BOOTS (#1960 no-brick); the runtime is independently safe because
	// compilePolicy defaults an actionless policy's Action to PolicyDeny (NOT
	// permit), so a leniently-loaded actionless policy DENIES rather than
	// fails open. Same doctrine as lenientPolicyZoneRefs / lenientPolicyMatchAddress.
	lenientPolicyTerminalAction bool
	// lenientPolicyLogAction (#3060) downgrades the security-policy `then log`
	// gate (validatePolicyLogActionStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// policy whose `then log` names neither session-init nor session-close: a
	// bare `then log` compiles to pol.Log = &PolicyLog{} with both flags false,
	// so the policy REPORTS logging enabled over REST/gRPC/CLI yet emits NO
	// session records — audit looks active while producing nothing (a silent
	// gap on a security appliance). Junos requires at least one of
	// session-init/session-close. The tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config an older binary
	// accepted still BOOTS (#1960 no-brick); a leniently-loaded bare-log policy
	// is harmless (it logs nothing, the pre-existing behavior). Same doctrine as
	// lenientPolicyTerminalAction.
	lenientPolicyLogAction bool
	// lenientScreenProfileRefs (#3066) downgrades the zone screen-profile
	// reference gate (validateScreenProfileReferencesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a security zone whose `screen <name>` references a
	// screen-ids-option profile the config never defines. Before this gate the
	// reference was warned only, so the commit succeeded; at runtime the
	// userspace dataplane fails OPEN (screen/mod.rs returns ScreenVerdict::Pass
	// for a missing profile), silently skipping every screen check for the zone
	// while the operator believes screening is active. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config that an older binary accepted still BOOTS (#1960
	// no-brick). Unlike the policy gates, the dataplane is NOT independently
	// safe on the lenient path (a missing profile fails open), so the strict
	// commit gate — keeping a bad reference from ever reaching the dataplane —
	// is the real fix; the warning is the only signal on a leniently-loaded
	// config. Same doctrine as lenientPolicyZoneRefs.
	lenientScreenProfileRefs bool
	// lenientReservedZoneNames (#3055) downgrades the reserved zone-name
	// definition gate (validateReservedZoneNamesStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `security zones security-zone <name>` whose name is a
	// reserved sentinel ("junos-global", "any", "junos-host"). A zone named
	// "junos-global" is reclassified by the userspace dataplane
	// (userspace-dp/src/policy.rs) as a device-wide global fallback evaluated
	// for every flow, so its zone-scoped policies silently permit traffic for
	// unrelated zone pairs — a security-boundary escape. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick).
	// Same doctrine as lenientPolicyZoneRefs.
	lenientReservedZoneNames bool
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
		lenientIKEPolicyChainRef:           true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
		lenientRoutingExportRef:            true,
		lenientFRRAuthValues:               true,
		lenientRouteFilterMatchTypes:       true,
		lenientApplicationSpecs:            true,
		lenientFilterProtocols:             true,
		lenientFilterActions:               true,
		lenientNPTv6:                       true,
		lenientFirewallRefs:                true,
		lenientFlowServerTemplateRef:       true,
		lenientSamplingInstanceConflicts:   true,
		lenientApplicationSetMembers:       true,
		lenientRibGroupRefs:                true,
		lenientDHCPStaticBindings:          true,
		lenientWireguardPeers:              true,
		lenientPolicyZoneRefs:              true,
		lenientZoneCount:                   true,
		lenientZoneInterfaceMembership:     true,
		lenientDestNATAddresses:            true,
		lenientRPMSourceAddress:            true,
		lenientRPMLinkLocalZone:            true,
		lenientRPMHTTPGetScheme:            true,
		lenientRPMRoutingInstance:          true,
		lenientBGPNeighborPeerAS:           true,
		lenientRouterID:                    true,
		lenientSNMPTrapGroup:               true,
		lenientPolicyTerminalAction:        true,
		lenientPolicyLogAction:             true,
		lenientScreenProfileRefs:           true,
		lenientReservedZoneNames:           true,
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
		lenientIKEPolicyChainRef:           true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
		lenientRoutingExportRef:            true,
		lenientFRRAuthValues:               true,
		lenientRouteFilterMatchTypes:       true,
		lenientApplicationSpecs:            true,
		lenientFilterProtocols:             true,
		lenientFilterActions:               true,
		lenientNPTv6:                       true,
		lenientFirewallRefs:                true,
		lenientFlowServerTemplateRef:       true,
		lenientSamplingInstanceConflicts:   true,
		lenientApplicationSetMembers:       true,
		lenientRibGroupRefs:                true,
		lenientDHCPStaticBindings:          true,
		lenientWireguardPeers:              true,
		lenientPolicyZoneRefs:              true,
		lenientZoneCount:                   true,
		lenientZoneInterfaceMembership:     true,
		lenientDestNATAddresses:            true,
		lenientRPMSourceAddress:            true,
		lenientRPMLinkLocalZone:            true,
		lenientRPMHTTPGetScheme:            true,
		lenientRPMRoutingInstance:          true,
		lenientBGPNeighborPeerAS:           true,
		lenientRouterID:                    true,
		lenientSNMPTrapGroup:               true,
		lenientPolicyTerminalAction:        true,
		lenientPolicyLogAction:             true,
		lenientScreenProfileRefs:           true,
		lenientReservedZoneNames:           true,
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
			// #3065: fail-CLOSED no-match default. The PolicyAction zero
			// value is PolicyPermit (iota==0), so an unset default-policy
			// would otherwise ship as permit-all — the opposite of the
			// Junos SRX default-security-policy (deny-all). Initialize the
			// fallback to PolicyDeny here so an absent
			// `security policies default-policy` stanza denies unmatched
			// zone-pair traffic. An operator opts back into permit-all
			// explicitly via `set security policies default-policy
			// permit-all` (handled in compilePolicies).
			DefaultPolicy: PolicyDeny,
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
			if err := compileSystem(node, &cfg.System, cfg, opts); err != nil {
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
			if err := compileSNMP(node, &cfg.System, cfg, opts.lenientSNMPTrapGroup); err != nil {
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

	// #2401 security-policy zone-pair reference fail-open gate. Strict on
	// commit / commit-check (hard-reject a `from-zone`/`to-zone` policy
	// stanza naming an undefined security zone — such a rule was only warned,
	// then compiled and KEPT, but the dataplane never indexes it into the
	// zone-pair lookup so the pair falls through to the default action,
	// failing OPEN under a permit default); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config with a stale zone
	// reference still boots — #1960 no-brick; the dataplane drops the
	// unindexed rule on its own, so a leniently-loaded bad config is inert).
	// Exempts the `any` / `junos-host` / empty special tokens and does not
	// touch global policies. Runs AFTER the policy match-address gate so a
	// structural CoS/policer/device-map error and a bad match-address still
	// win the first-error slot before a zone-reference error.
	if err := validatePolicyZoneReferencesStrict(cfg); err != nil {
		if opts.lenientPolicyZoneRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy zone reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #3043 security-policy terminal-action fail-open gate. Strict on commit /
	// commit-check (hard-reject a policy that does not name exactly one of
	// permit/deny/reject — a log-only/count-only or typo'd policy compiled to
	// the PolicyPermit zero value and silently PERMITTED all matching traffic,
	// and multiple terminal actions resolved last-wins by parse order);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; compilePolicy defaults an actionless
	// policy to DENY, so a leniently-loaded bad config fails closed rather than
	// open). Runs AFTER the policy zone-reference gate so a structural error, a
	// bad match-address, and a bad zone reference still win the first-error slot.
	if err := validatePolicyTerminalActionStrict(cfg); err != nil {
		if opts.lenientPolicyTerminalAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy terminal action (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #3060 security-policy `then log` accepted-but-inert gate. Strict on commit
	// / commit-check (hard-reject a policy whose `then log` names neither
	// session-init nor session-close — a bare `then log` compiles to a non-nil
	// PolicyLog with both flags false, so the policy REPORTS logging enabled
	// over REST/gRPC/CLI yet emits NO session records; Junos requires at least
	// one of session-init/session-close). Lenient on load / peer-sync (warn so
	// an already-persisted or peer-synced config still boots — #1960 no-brick; a
	// leniently-loaded bare-log policy simply logs nothing, the pre-existing
	// behavior). Covers both per-zone-pair and global policies. Runs after the
	// terminal-action gate so a missing/conflicting terminal action still wins
	// the first-error slot.
	if err := validatePolicyLogActionStrict(cfg); err != nil {
		if opts.lenientPolicyLogAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy log action (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #3066 zone screen-profile reference fail-open gate. Strict on commit /
	// commit-check (hard-reject a zone whose `screen <name>` references a
	// screen-ids-option profile the config never defines — at runtime the
	// dataplane fails OPEN for a missing profile, silently skipping every
	// screen check for that zone); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick).
	// Unlike the policy gates the runtime is NOT independently safe on the
	// lenient path, so the strict commit gate is the real fix.
	if err := validateScreenProfileReferencesStrict(cfg); err != nil {
		if opts.lenientScreenProfileRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone screen profile reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #3055 reserved zone-name definition gate. Strict on commit / commit-check
	// (hard-reject a `security zones security-zone <name>` whose name is a
	// reserved sentinel — "junos-global" is reclassified by the userspace
	// dataplane as a device-wide global fallback evaluated for every flow, so a
	// zone of that name silently turns its zone-scoped policies into global
	// permits across unrelated zone pairs; "any"/"junos-host" are reserved
	// policy context tokens); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config an older binary accepted still
	// boots — #1960 no-brick).
	if err := validateReservedZoneNamesStrict(cfg); err != nil {
		if opts.lenientReservedZoneNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved zone name (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2391 security-zone count cap. Strict on commit / commit-check
	// (hard-reject a config with more than MaxUsableZoneID zones — the overflow
	// zone ids exceed the u8 event-stream wire field and were silently dropped
	// by the dataplane, collapsing the affected interfaces to zone 0); lenient
	// on load / peer-sync (warn so an already-persisted or peer-synced over-cap
	// config still boots — #1960 no-brick; the dataplane fails closed on every
	// overflowing zone, so a leniently-loaded over-cap config is inert). This is
	// the PRIMARY gate: bounding the zone count guarantees no out-of-range id is
	// ever produced. Runs AFTER the policy zone-reference gate so a structural
	// error and a bad zone reference still win the first-error slot.
	if err := validateZoneCountStrict(cfg); err != nil {
		if opts.lenientZoneCount {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone count (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #3072 zone-interface membership gate. Strict on commit / commit-check
	// (hard-reject a config that assigns the same interface to more than one
	// security zone — the userspace interface->zone map resolves a duplicate
	// first-writer-wins over the SORTED zone names, so the interface silently
	// lands in whichever zone sorts first and traffic is evaluated against the
	// wrong zone's policy); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960 no-brick; the
	// interface->zone map keeps its deterministic first-writer-wins resolution,
	// so a leniently-loaded duplicate forwards exactly as before). Runs AFTER the
	// zone-count gate so a structural / policy / zone-count error still wins the
	// first-error slot.
	if err := validateZoneInterfaceMembershipStrict(cfg); err != nil {
		if opts.lenientZoneInterfaceMembership {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone interface membership (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2396(c) destination-NAT destination-address gate. Strict on commit /
	// commit-check (hard-reject a DNAT rule whose `match destination-address`
	// resolves to NO parseable host IP — every configured destination is
	// empty/malformed); lenient on load / peer-sync (downgrade to a warning so
	// an already-persisted or peer-synced config still boots — #1960 no-brick;
	// the snapshot builder skips each bad destination and the Rust DNAT table
	// drops the rule on its own, so a leniently-loaded bad config is inert).
	// Without this gate such a rule committed cleanly and then silently
	// translated nothing — the operator had no feedback that the only
	// destination address was a typo. Runs AFTER the policy gates so a
	// structural/policy error still wins the first-error slot.
	if err := validateDestinationNATAddressesStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat address (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2396(a)/(3) destination-NAT match-protocol gate. The DNAT `match
	// protocol <token>` reaches the wire VERBATIM (nodeVal -> rule.Match.Protocol
	// -> snapshot, with no validation), and the Rust DNAT table drops a token
	// ip_proto::proto_number cannot resolve (the dataplane backstop). So an
	// unresolvable `match protocol` (a typo, or a junos-* alias the DNAT path
	// does not pre-resolve) committed cleanly and then silently translated
	// nothing — the #2396 silent-drop class. Strict on commit / commit-check
	// (hard-reject); lenient on load / peer-sync (downgrade to a warning so a
	// config persisted before this gate existed still boots — #1960 no-brick;
	// the dataplane drops the inert rule on its own). Shares the
	// lenientDestNATAddresses flag (same #2396 DNAT silent-drop doctrine). Runs
	// after the address gate so a malformed-destination error wins first.
	if err := validateDestinationNATProtocolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2243 DHCP-server static (fixed/reserved) host bindings. Strict on
	// commit / commit-check (hard-reject a fixed-address that is malformed,
	// family-mismatched, outside the enclosing pool subnet, or duplicates
	// another binding's MAC/address in the same pool); lenient on load /
	// peer-sync (warn so an already-persisted or peer-synced config carrying a
	// bad binding still boots — #1960 no-brick). Moved OUT of the strictErrs
	// accumulator (#2243 review): like every sibling fail-open gate it must
	// downgrade on the tolerant path, not hard-reject the whole config-load.
	// The Kea renderer skips an empty/unparseable binding independently, so a
	// leniently-loaded bad binding is inert. Runs AFTER the accumulator so a
	// structural CoS/policer/device-map/policy error still wins the first-error
	// slot.
	if err := validateDHCPStaticBindingsStrict(cfg); err != nil {
		if opts.lenientDHCPStaticBindings {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("DHCP static binding (downgraded to warning on tolerant path): %v", err))
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

	// #2399 (032-16) firewall-filter `then` action fail-open gate. Strict on
	// commit / commit-check (hard-reject a term whose `then` block carries a
	// token that is neither a recognized terminating action nor a recognized
	// modifier). Before this gate such a token was silently DROPPED by
	// compileFilterThen, leaving Action == "", which the dataplane compiler and
	// the Rust filter (parse_term) both map to ACCEPT — a fail-open permit for
	// a term the operator meant to deny. Lenient on load / peer-sync (warn so
	// an already-persisted or peer-synced config carrying an unknown action
	// still BOOTS — #1960 no-brick). Runs on the fully-compiled *Config so the
	// typed term list (with UnknownActions populated by compileFilterThen) is
	// available.
	if err := validateFilterActionsStrict(cfg); err != nil {
		if opts.lenientFilterActions {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter action (downgraded to warning on tolerant path): %v", err))
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

	// #2270 IKE (Phase 1) gateway -> ike-policy -> ike-proposal cross-
	// reference. A gateway that names an ike-policy whose chain does not
	// resolve (the policy is undefined, or its `proposals` reference
	// dangles) made resolveIKESettings return an empty proposal, which
	// renderConfig omitted — strongSwan then negotiated phase-1 with its
	// compiled-in default set instead of the configured crypto (a silent
	// downgrade). Strict on commit / commit-check (hard reject so the
	// operator gets a diagnostic); lenient on load / peer-sync (warn so a
	// pre-fix or peer-synced config still boots — #1960 fail-closed-on-load
	// class; the render belt in pkg/ipsec skips the unrenderable VPN rather
	// than negotiating with defaults). Runs on the fully-compiled *Config so
	// both ike{} and ipsec{} gateway/policy/proposal definitions are present
	// regardless of stanza authoring order. Mirrors
	// validateIPsecPolicyProposalReferencesStrict (its Phase-2 sibling).
	if err := validateIKEPolicyChainReferencesStrict(cfg); err != nil {
		if opts.lenientIKEPolicyChainRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ike-policy chain reference (downgraded to warning on tolerant path): %v", err))
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

	// #2963: BGP neighbor peer-as gate. peer-as (remote-as) is optional in
	// the parser/compiler, so a neighbor authored without one keeps a zero
	// PeerAS and the FRR renderer emitted `neighbor <addr> remote-as 0`. AS 0
	// is reserved (RFC 7607); FRR/vtysh rejects it, failing the whole
	// frr-reload and leaving dynamic routing broken — a commit-accepted config
	// the routing daemon cannot load. Strict on commit / commit-check (hard
	// reject naming the neighbor); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960; the render
	// path now skips a remote-as-0 neighbor so AS 0 never reaches frr.conf).
	// Runs on the fully-compiled *Config (group peer-as already inherited).
	// Mirrors validateRoutingExportReferencesStrict.
	if err := validateBGPNeighborPeerASStrict(cfg); err != nil {
		if opts.lenientBGPNeighborPeerAS {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("BGP neighbor peer-as (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2980: OSPF/OSPFv3/BGP router-id gate. router-id is parsed as a raw
	// string with no validation, so a malformed value (not a 32-bit IPv4
	// dotted-quad) flowed verbatim into frr.conf. FRR/vtysh requires an IPv4
	// router-id for ALL routing protocols (including the IPv6 protocols OSPFv3
	// and BGP) and rejects anything else, failing the whole frr-reload and
	// leaving dynamic routing broken — a commit-accepted config the routing
	// daemon cannot load. Strict on commit / commit-check (hard reject naming
	// the scope and protocol); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960; the render
	// path now skips an invalid router-id so it never reaches frr.conf). Runs
	// on the fully-compiled *Config. Mirrors validateBGPNeighborPeerASStrict.
	if err := validateRouterIDStrict(cfg); err != nil {
		if opts.lenientRouterID {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("router-id (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2889: FRR auth-value gate. A BGP neighbor password or an
	// OSPF/RIP/IS-IS authentication key containing whitespace cannot be
	// rendered as a single FRR/vtysh token (FRR's command lexer has no
	// quoted-string and no rest-of-line token — it splits on whitespace), so
	// it would be truncated at the first space or inject trailing words as
	// extra vtysh args at frr.conf load. Strict on commit / commit-check
	// (hard reject, naming the field, so the operator sees it); lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 fail-closed-on-load class; the render path strips
	// control chars so the malformed line stays inert). Runs on the fully-
	// compiled *Config. Mirrors validateRoutingExportReferencesStrict.
	if err := validateFRRAuthValuesStrict(cfg); err != nil {
		if opts.lenientFRRAuthValues {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("FRR auth value (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2525: route-filter match-type gate. `through` has no lossless FRR
	// prefix-list mapping (a two-prefix containment path, not a length range)
	// and `prefix-length-range` must carry a well-formed /low-/high within the
	// family / base-prefix bounds. Both committed unnoticed before this gate
	// and the FRR renderer silently degraded them to an open-ended `le maxLen`,
	// leaking / dropping the configured constraint. Strict on commit /
	// commit-check (hard reject so the unsupported / malformed match-type is
	// operator-visible); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960; the renderer then
	// skips the offending entry, match-nothing). Runs on the fully-compiled
	// *Config. Mirrors validateRoutingExportReferencesStrict.
	if err := validateRouteFilterMatchTypesStrict(cfg); err != nil {
		if opts.lenientRouteFilterMatchTypes {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("route-filter match-type (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2217 Finding A: firewall-filter `then policer <name>` cross-reference.
	// A term naming a policer that is not defined under `firewall policer` /
	// `firewall three-color-policer` compiled cleanly and the rate-limit
	// silently never applied (fail-open — the term's traffic passed
	// unpoliced). Strict on commit / commit-check (hard reject so the typo is
	// operator-visible); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960). Runs on the
	// fully-compiled *Config so the policer maps are populated regardless of
	// authoring order. Mirrors validateRoutingExportReferencesStrict.
	if err := validateFirewallPolicerReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall policer reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2506: firewall-filter `from source-prefix-list <name>` /
	// `destination-prefix-list <name>` cross-reference. A term naming a
	// prefix-list not defined under `policy-options prefix-list` compiled
	// cleanly and the userspace snapshot builder contributed no prefixes for
	// it, silently losing the address scope (fail-open or fail-closed depending
	// on the action). Strict on commit / commit-check (hard reject so the typo
	// is operator-visible); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960; the resolver then
	// contributes no prefixes for the unresolved reference). Mirrors the policer
	// gate above.
	if err := validateFirewallPrefixListReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall prefix-list reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2416: NAT `match source-address-name <book-entry>` cross-reference. A
	// source / destination NAT rule naming an address-book entry not defined
	// under `security address-book` compiled cleanly; the snapshot builder
	// resolves the name to no prefixes and (per the fail-closed backstop) the
	// rule matches NOTHING. That is safe but silent — the operator's intended
	// source scoping is gone with no signal. Strict on commit / commit-check
	// (hard reject so the typo is operator-visible); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960;
	// the dataplane then fails closed for the unresolved reference). Mirrors the
	// firewall prefix-list gate above.
	if err := validateNATSourceAddressNameReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT source-address-name reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2217 Finding C: firewall-filter `then routing-instance <name>` (FBF)
	// cross-reference. A term naming a routing-instance not defined under
	// `routing-instances` compiled cleanly and the dataplane steered matched
	// packets toward a routing table that does not exist — a silent blackhole
	// / fall-through to the default table. Strict on commit / commit-check;
	// lenient on load / peer-sync (warn — #1960). Mirrors the policer gate
	// above.
	if err := validateFirewallRoutingInstanceReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall routing-instance reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2461: per-flow-server NetFlow v9 / IPFIX template cross-reference. A
	// flow-server `version9 { template <name> }` / `version-ipfix { template
	// <name> }` (or the flat `version9-template` / `version-ipfix-template`)
	// naming a template not defined under `services flow-monitoring`
	// compiled cleanly; the live exporter ignored the reference and used the
	// first map-iteration template, so the collector silently received a
	// template (timeouts / export-extensions) it never requested and the
	// choice flipped across restarts. Strict on commit / commit-check (hard
	// reject so the typo is operator-visible); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots —
	// #1960; the resolver drops a group with an undefined template, exporting
	// nothing for that collector rather than the wrong template). Mirrors
	// validateLogProfileStreamReferencesStrict.
	if err := validateFlowServerTemplateReferencesStrict(cfg); err != nil {
		if opts.lenientFlowServerTemplateRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("flow-server template reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2462: multi-sampling-instance conflict. Two `forwarding-options
	// sampling instance` blocks that each export the same (export-version,
	// address-family) pair are genuinely ambiguous — there is no per-interface
	// sampling-instance selector, so the runtime cannot attribute a flow of
	// that family to one instance — and were previously silently flattened
	// into one global policy (first-nonzero map-order rate, merged collectors;
	// flows crossing from one instance's policy to another's collectors).
	// Strict on commit / commit-check (hard reject so the operator sees it);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960; the resolver emits both instances'
	// independent ExportConfigs, duplicating eligible flows rather than
	// bricking). Mirrors validateFlowServerTemplateReferencesStrict.
	if err := validateSamplingInstanceConflictsStrict(cfg); err != nil {
		if opts.lenientSamplingInstanceConflicts {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("sampling instance conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2217 Finding B: application-set member cross-reference. An
	// `applications application-set <set>` member referencing neither a defined
	// application (user / junos-* predefined) nor a defined nested
	// application-set compiled cleanly; a policy matching the set silently
	// failed to match the intended traffic (the unresolved member never
	// matches — an effective no-op term, fail-open). Strict on commit /
	// commit-check; lenient on load / peer-sync (warn — #1960; the dataplane
	// drops the unresolved member independently, so it is already inert).
	// Reuses ExpandApplicationSet, the same resolver the compiler already uses,
	// so no new definedness table is introduced. Mirrors
	// validateApplicationSpecsStrict.
	if err := validateApplicationSetMembersStrict(cfg); err != nil {
		if opts.lenientApplicationSetMembers {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application-set member (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2226: rib-group `import-rib <rib>` cross-reference. An import-rib naming
	// a rib that resolves to no real routing table (a typo, a non-existent
	// instance, or unparseable garbage) compiled cleanly; the applier mapped
	// the unresolvable name to table 0, which differs from the (>= 100) source
	// table, and spuriously installed an `ip rule from all lookup <sourceTable>`
	// — a silent mis-leak of the source table into the main lookup. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the applier's resolveRibTable
	// ok=false guard skips the phantom rib so it is already inert). Mirrors
	// validateRoutingExportReferencesStrict.
	if err := validateRibGroupImportRibReferencesStrict(cfg); err != nil {
		if opts.lenientRibGroupRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rib-group import-rib reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2492: RPM test source-address gate. A malformed `source-address`
	// (non-empty but unparseable) silently degrades the tcp-ping/http-get
	// probe dialer to a wildcard/kernel-chosen source bind, so the probe
	// measures the DEFAULT uplink instead of the pinned source path —
	// publishing PASS/FAIL for the wrong path while RPM feeds
	// event-options / ip-monitoring failover. A v6 source with a v4
	// IP-literal target (or vice-versa) is likewise unpinnable. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the runtime probeDialer
	// guard returns ErrProbeSetup for the same malformed source, so the
	// leniently-loaded test HOLDS state instead of actuating routes off a
	// wildcard measurement). Hostname targets skip the family check
	// (the target family is unknown until DNS resolves). Mirrors
	// validateRibGroupImportRibReferencesStrict.
	if err := validateRPMSourceAddressStrict(cfg); err != nil {
		if opts.lenientRPMSourceAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm source-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2493 scoped-hostname gate REMOVED in #2614: a scoped RPM test
	// (routing-instance / destination-interface / next-hop) against a
	// hostname target now resolves IN the probe's VRF/path scope — the
	// runtime resolver (rpm.resolveProbeTarget / probeDialer.Resolver)
	// binds the DNS socket to the same SO_BINDTODEVICE / SO_MARK as the
	// probe socket, so the lookup egresses the VRF and hits the VRF's DNS.
	// The combination is therefore legitimate and no longer rejected at
	// commit (see docs/multi-wan.md).

	// #2494: IPv6 link-local RPM target zone gate. A link-local target
	// (fe80::/10) needs an egress-link scope — an explicit `%zone` on the
	// literal or a destination-interface — or the kernel cannot pick the
	// link and the ICMP echo is dead. A bare link-local with neither is
	// refused so the operator sees the gap at commit instead of a silently
	// dead probe driving ip-monitoring failover. Strict on commit /
	// commit-check (hard reject); lenient on load / peer-sync (warn —
	// #1960; the runtime probeICMP guard returns ErrProbeSetup for the
	// same scopeless link-local, so the leniently-loaded test HOLDS state
	// instead of actuating off a dead measurement).
	if err := validateRPMLinkLocalZoneStrict(cfg); err != nil {
		if opts.lenientRPMLinkLocalZone {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm link-local zone (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2495: http-get target scheme gate. An http-get target that carries
	// a scheme other than http/https (ftp://, gopher://, …) makes
	// http.NewRequestWithContext error before a packet is sent, so the
	// probe never runs and publishes a permanent FAIL into event-options /
	// ip-monitoring failover. A schemeless target (bare host / IP /
	// host:port) is fine — the runtime prepends http://. Strict on commit /
	// commit-check (hard reject so the bad scheme is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the runtime
	// canonicalizeHTTPTarget guard returns the same error, so the
	// leniently-loaded test HOLDS state instead of actuating off a probe
	// that can never run).
	if err := validateRPMHTTPGetSchemeStrict(cfg); err != nil {
		if opts.lenientRPMHTTPGetScheme {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm http-get scheme (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2496: RPM test routing-instance cross-reference gate. A test whose
	// `routing-instance` names a nonexistent instance makes the runtime
	// bind the probe DATA socket to a synthesized vrf-<name> device
	// (SO_BINDTODEVICE) that does not exist → ENODEV → the probe never runs
	// and the test HOLDS its state forever, starving any event-options /
	// ip-monitoring policy keyed off it of a failover signal. An empty
	// routing-instance is the default (master) context and is accepted.
	// Strict on commit / commit-check (hard reject so the typo is
	// operator-visible); lenient on load / peer-sync (warn — #1960; the
	// runtime bind returns ENODEV for the same nonexistent instance, so the
	// leniently-loaded test HOLDS state instead of actuating off a dead
	// measurement). Mirrors the ip-monitoring preferred-route
	// routing-instance check in validateIPMonitoringStrict.
	if err := validateRPMRoutingInstanceStrict(cfg); err != nil {
		if opts.lenientRPMRoutingInstance {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm routing-instance (downgraded to warning on tolerant path): %v", err))
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

	// #1434 multi-peer WireGuard: per-peer commit gate. Strict (commit /
	// commit-check): hard-reject a WG tunnel with zero peers, a duplicate
	// or malformed (non-64-hex) peer pubkey, a malformed PSK, or
	// endpoint-bearing peers that disagree on outer transport family.
	// Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config still boots — the Rust hydrate path drops a row
	// with a malformed key independently and the engine reconcile is
	// dup-safe, so a leniently-loaded bad config is inert.
	wgPeerWarnings, err := validateWireguardPeersStrict(cfg, opts.lenientWireguardPeers)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, wgPeerWarnings...)

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
