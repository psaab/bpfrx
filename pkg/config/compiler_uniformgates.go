package config

import "fmt"

// runUniformGates runs the P6b "uniform fail-open gate" phase of config
// compilation — the long contiguous run of ~75 independent validation gates
// extracted from compileExpanded as step 4 of the #4406 god-orchestrator
// decomposition (ps-review-011 / codex-173 #4).
//
// Every gate in this phase has the SAME shape: it validates one typed
// sub-struct of the compiled *Config and either (a) returns its first error on
// the strict commit / commit-check path, or (b) downgrades to a warning
// appended to cfg.Warnings on its per-gate tolerant flag (load / peer-sync,
// #1960 no-brick). The phase performs NO cfg mutation — it only reads the
// compiled config, threads warnings, and dispatches the first strict error.
// (validateEventOptionsWithinAST is an AST pre-walk, so this phase also reads
// the group-expanded, inactive-pruned *ConfigTree; it is read-only there.)
//
// Behavior-preserving invariants (do NOT reorder relative to master): the
// source order of every gate is observable — on the strict path the FIRST
// failing gate wins the returned error slot (invariant #6), and on the
// tolerant path all gates run and their warnings accumulate in this exact
// sequence (invariant #7). This is a verbatim contiguous lift of the gate run;
// it runs AFTER P6a's early-strict + folds accumulator and BEFORE the P7 tail
// gates. Covered by the reusable golden-output gate in
// compile_golden_4406_test.go.
func runUniformGates(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// class-of-service scheduler-map -> scheduler cross-reference gate.
	// Strict on commit / commit-check (hard-reject a scheduler-map entry
	// naming an undefined scheduler — such a reference was only warned,
	// then compiled and KEPT, and the userspace dataplane resolved the
	// dangling name to no scheduler: the class silently lost its
	// guarantee and, pre-fix, won the MAXIMUM best-effort surplus share).
	// Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config with a stale scheduler reference still boots —
	// #1960 no-brick; the dataplane applies the scheduler-unresolved SAFE
	// default on that boot). Runs AFTER the strict accumulator +
	// device-map so a structural CoS/policer/device-map error still wins
	// the first-error slot.
	if err := validateClassOfServiceSchedulerMapRefsStrict(cfg.ClassOfService); err != nil {
		if opts.lenientSchedulerMapRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service scheduler-map reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3995 class-of-service loss-priority value gate. Strict on commit /
	// commit-check (hard-reject an unrecognized loss-priority such as an
	// operator typo `medum-low`, which the dataplane would otherwise apply
	// as the SAFE default LOW / wildcard — silently wrong QoS). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 no-brick; the dataplane applies the SAFE default
	// on that boot).
	if err := validateClassOfServiceLossPriorityStrict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSLossPriority {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service loss-priority (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4594 class-of-service forwarding-class queue-range gate. Strict on
	// commit / commit-check (hard-reject a queue outside 0..255, which the
	// userspace helper deserializes via a checked u8::try_from and
	// fail-closes the WHOLE CoS snapshot on — CosQueueIdOutOfRange #2410 —
	// while silently keeping stale CoS forwarding state). Lenient on load /
	// peer-sync (warn so an already-persisted config that only warned +
	// committed under an older binary, or a peer-synced config, still boots
	// — #1960 no-brick; the dataplane's CosQueueIdOutOfRange fail-close is
	// the stale-but-safe backstop on that boot).
	if err := validateClassOfServiceForwardingClassQueueStrict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSForwardingClassQueue {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service forwarding-class queue (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
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
			return err
		}
	}

	// #4047 web-management REST-auth gate. Strict on commit / commit-check
	// (hard-reject a web-management config that binds the unauthenticated REST /
	// config API off-loopback without api-auth — exposing the mutating config
	// endpoints to the network); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960; the daemon's
	// runtime bind path clamps such a bind back to loopback, so the leniently-
	// loaded config is preserved but not left exposed).
	if err := validateWebManagementAuthStrict(cfg); err != nil {
		if opts.lenientWebManagementAuth {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("web-management auth (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
	// Exempts the `any` / `junos-host` / empty special tokens. Validates
	// zone-pair from/to zones AND (as of #3148) a global policy's optional
	// `match from-zone`/`match to-zone` context. Runs AFTER the policy match-address gate so a
	// structural CoS/policer/device-map error and a bad match-address still
	// win the first-error slot before a zone-reference error.
	if err := validatePolicyZoneReferencesStrict(cfg); err != nil {
		if opts.lenientPolicyZoneRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy zone reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3090: the from-zone/to-zone `any` wildcard is now properly indexed and
	// enforced by the userspace dataplane (PolicyState's from-any / to-any /
	// both-any tiers, evaluated in Junos most-specific-first precedence before
	// global/default — userspace-dp/src/policy.rs). The #3018 interim commit
	// reject (validatePolicyWildcardZoneStrict) is therefore lifted: a
	// from-zone/to-zone `any` policy commits AND is enforced. The undefined-zone
	// gate (validatePolicyZoneReferencesStrict) still exempts `any` via
	// policyZoneSpecialTokens, so the wildcard is accepted without being mistaken
	// for an undefined zone, and a `security zone` named `any` is still rejected
	// by validateReservedZoneNamesStrict.

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
			return err
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
			return err
		}
	}

	// #3473 duplicate-policy-name gate. Strict on commit / commit-check
	// (hard-reject two security policies that share a name within the same
	// from/to-zone zone-pair, or within the global rulebase — Junos requires
	// unique policy names within a context). xpf accepted duplicates silently;
	// the name-keyed userspace hit counter then coalesces the duplicates onto one
	// counter, so hit-count observability breaks (the two rules cannot be told
	// apart) and removing one duplicate transfers its accumulated hits to the
	// survivor. Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; first-match enforcement is
	// still correct, only the shared-counter observability bug remains). The
	// validator reads the already-aggregated typed Policies/GlobalPolicies slices,
	// so a duplicate split across two `security {}` blocks is still caught
	// (compileSecurity runs for every `security` root). Runs after the policy
	// log-action gate so an earlier policy-structural error still wins the
	// first-error slot.
	if err := validateDuplicatePolicyNamesStrict(cfg); err != nil {
		if opts.lenientDuplicatePolicyNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("duplicate policy name (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3317 screen numeric-value gate. Strict on commit / commit-check
	// (hard-reject a screen threshold / count leaf whose explicitly-provided
	// value is not a positive integer). Before this gate compileScreen swallowed
	// the strconv.Atoi error and silently fell back to a Junos default or to
	// zero/disabled — a typo'd threshold disabled or weakened the protection
	// (fail-open). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; compileScreen applies the
	// default for the bad value independently on that path). Runs on the
	// fully-compiled *Config so the typed profile list (with BadNumeric
	// populated by compileScreen) is available.
	if err := validateScreenNumericStrict(cfg); err != nil {
		if opts.lenientScreenNumeric {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("screen numeric value (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3318 unknown-screen-leaf gate. Strict on commit / commit-check
	// (hard-reject a screen leaf the dataplane does NOT support). The screen
	// schema subtrees are open and compileScreen had no default case, so a
	// misspelled or unsupported leaf committed cleanly and was silently dropped
	// — the operator believed a protection was enabled when it was absent.
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the dataplane never represented the
	// leaf, so the profile runs without it independently). Runs on the
	// fully-compiled *Config so the typed profile list (with UnknownLeaves
	// populated by compileScreen) is available.
	if err := validateScreenUnknownStrict(cfg); err != nil {
		if opts.lenientScreenUnknown {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("screen unknown leaf (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3332 trailing-token gate. Strict on commit / commit-check (hard-reject
	// a token that rode past a leaf's value arity in a shape the generic
	// schema-walk scalar gate cannot reach — multi:true address-book
	// `address` entries and the compact-hierarchical `dynamic hostname`
	// form). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the dropped token
	// never reached the dataplane). Runs on the fully-compiled *Config so the
	// recorded TrailingTokens / DynamicHostnameExtras are available.
	if err := validateTrailingTokensStrict(cfg); err != nil {
		if opts.lenientTrailingTokens {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("trailing token (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3440 H2 flow-aging gate. Strict on commit / commit-check (hard-reject
	// an unknown `security flow aging` leaf or a low-watermark >=
	// high-watermark cross-field violation that the opaque untyped subtree
	// used to accept silently). Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick;
	// watermark aging is not enforced on the userspace dataplane anyway,
	// #3440 H1). Runs on the fully-compiled *Config (AgingUnknownLeaves and
	// the watermark ints populated by compileFlow).
	if err := validateFlowAgingStrict(cfg); err != nil {
		if opts.lenientFlowAging {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("flow aging (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4434 chassis-cluster heartbeat wire-width gate. Strict on commit /
	// commit-check (hard-reject a redundancy-group cardinality or id that
	// exceeds the single-byte heartbeat count / GroupID fields — 256 RGs
	// advertise as a count of 0 and desync the wire, an id > 255 truncates
	// and collides with another group). Lenient on load / peer-sync (warn so
	// an already-persisted or peer-synced config still boots — #1960
	// no-brick; the heartbeat marshaler independently caps the group section
	// to the wire limit, marshalHeartbeatBody, so a leniently-loaded
	// over-size config is bounded, not a panic). Runs on the fully-compiled
	// *Config (RedundancyGroups populated by compileChassis).
	if err := validateChassisClusterStrict(cfg); err != nil {
		if opts.lenientChassisRG {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("chassis cluster redundancy-group (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4573 VRRP VRID wire-width gate. Strict on commit / commit-check
	// (hard-reject a `vrrp-group <id>` outside the RFC 5798 VRID range 1..255 —
	// the id is truncated onto a single wire byte, so 256 wraps to the reserved
	// VRID 0 and the VIP never masters, and 257 aliases VRID 1 onto another
	// group). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the pkg/vrrp runtime
	// range check independently refuses to advertise an out-of-range VRID, so a
	// leniently-loaded bad id is bounded, not a wrong-VRID advert). Runs on the
	// fully-compiled *Config (VRRPGroups populated by parseVRRPGroups).
	if err := validateVRRPGroupIDStrict(cfg); err != nil {
		if opts.lenientVRRPGroupID {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("vrrp-group id (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// Security-zone count cap (#2391 SUPERSEDED by #3075). After #3075 zone ids
	// are a stable name-hash in a u16 space, so this is a cheap pigeonhole belt:
	// a config cannot define more than MaxUsableZoneID (65533) distinct zones.
	// The StableZoneID collision gate above is the real duplicate-id protection.
	// Strict on commit / commit-check (hard-reject); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960
	// no-brick). Runs AFTER the policy zone-reference gate so a structural error
	// and a bad zone reference still win the first-error slot.
	if err := validateZoneCountStrict(cfg); err != nil {
		if opts.lenientZoneCount {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone count (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3200 host-inbound-traffic token gate. Strict on commit / commit-check
	// (hard-reject an unknown/typo system-services or protocols token that
	// would commit but enforce inconsistently — nft kernel mirror fails OPEN
	// for an all-unknown stanza while the Rust classifier fails CLOSED, a
	// split-brain posture); lenient on load / peer-sync (downgrade to a warning
	// so an already-persisted or peer-synced config carrying a stale token
	// still boots — #1960 no-brick; both enforcement layers ignore the unknown
	// token and the nft path now fails CLOSED for a zero-match zone, so a
	// leniently-loaded bad config is inert and consistent). Runs AFTER the zone
	// gates so a structural/zone-reference error still wins the first-error slot.
	if err := validateHostInboundTokensStrict(cfg); err != nil {
		if opts.lenientHostInboundTokens {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("host-inbound-traffic token (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3718 (Option B) duplicate host-local-address gate. Strict on commit /
	// commit-check (hard-reject a firewall-local interface address or VRRP VIP
	// that is host-inbound-reachable from more than one security zone with
	// DIFFERING host-inbound service/protocol sets — the kernel host-inbound
	// nftables chain matches destination address only over a single global input
	// chain, so the admission verdict is decided order-dependently by whichever
	// zone sorts first and can disagree with the ingress-scoped userspace-dp path
	// (split-brain)); lenient on load / peer-sync (warn so an already-persisted
	// or peer-synced config still boots — #1960 no-brick; the runtime reporter
	// AmbiguousHostInboundAddresses + the xpf_host_inbound_ambiguous_addresses
	// metric surface the ambiguity, which is NOT self-healing on that path). Runs
	// AFTER the host-inbound token gate so a token typo still wins the
	// first-error slot. Option A (kernel iifname ingress-scope) and Option C
	// (per-VRF host-inbound chains) are deferred follow-ons — see
	// docs/host-inbound-traffic.md.
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		if opts.lenientDuplicateHostLocalAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("duplicate host-local address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
			return err
		}
	}

	// #3446 source/destination-NAT match destination-port gate. The DNAT/SNAT
	// `match destination-port` parser used a bare strconv.Atoi with no bound
	// check and the builders cast straight to uint16, so a 0/out-of-range
	// (70000→4464, -1→65535) or non-numeric (`http`) port wrapped to the wrong
	// port or collapsed the whole match to the wildcard port (translating every
	// port). Static NAT already validates its typed destination-port leaf
	// (#2491); this closes the same gap for the source/destination NAT match
	// grammar. Strict on commit / commit-check (hard-reject); lenient on load /
	// peer-sync (downgrade to a warning so a config persisted before this gate
	// existed still boots — #1960 no-brick; the snapshot builders independently
	// fail CLOSED). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the protocol gate.
	if err := validateNATMatchDestinationPortStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("nat match destination-port (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3450 destination-NAT pool port/address gate. The DNAT pool `port` parser
	// used a bare strconv.Atoi with no bound check and the snapshot builder cast
	// straight to uint16, so `port 70000` wrapped to 4464 / `-1` to 65535 (wrong
	// backend port) and `port 0`/`port httpp` collapsed to 0 = preserve-dest-port
	// (silent no-op of the rewrite). The pool `address` was stored verbatim: a
	// non-host CIDR (10.0.0.0/24) was coerced to the network base and an
	// address-book name (web-server) was dropped by the Rust parser, leaving the
	// VIP untranslated. Strict on commit / commit-check (hard-reject); lenient on
	// load / peer-sync (downgrade to a warning so a config persisted before this
	// gate existed still boots — #1960 no-brick; the snapshot builder
	// independently fails CLOSED, skipping the rule rather than wrapping the port
	// or coercing the address). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the destination-port
	// gate.
	if err := validateDNATPoolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("destination-nat pool (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3906 source-NAT pool port-range gate. The pool `port range <low> to
	// <high>` was parsed with the wrong keyword shape and silently ignored (the
	// pool defaulted to 1024-65535 PAT), so an operator narrowing the range got
	// the full default range and a reversed/out-of-range range committed green
	// then dropped the rule at runtime. Reject a reversed (low > high) or
	// out-of-range (not 1-65535) explicitly-configured range. Strict on commit /
	// commit-check (hard-reject); lenient on load / peer-sync (downgrade to a
	// warning so a config persisted before this gate existed still boots — #1960
	// no-brick; the snapshot builder independently fails CLOSED via
	// sourceNATPoolPortRange). Shares the lenientDestNATAddresses flag (same NAT
	// silent-drop / wrong-translate doctrine). Runs after the DNAT pool gate.
	if err := validateSourceNATPoolStrict(cfg); err != nil {
		if opts.lenientDestNATAddresses {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("source-nat pool (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
	// same config-layer validators that produced the warning, so this gate adds no
	// new alias table of its own.
	//
	// #3372: a clarification on the divergence the dataplane DOES keep. The
	// runtime #2124 capability gate (pkg/dataplane/userspace
	// userspacePortSpecRepresentable, mirroring Rust parse_port_spec) matches the
	// 15 literal service aliases CASE-SENSITIVELY, whereas validatePortSpec here is
	// case-INSENSITIVE. That asymmetry would be a commit/apply split (a mixed-case
	// `destination-port HTTPS` accepted here but unrepresentable at apply) EXCEPT
	// that compileApplications / parseApplicationTerms run every application port
	// spec through resolveAppPort FIRST, which canonicalizes any recognized service
	// name (case-insensitively, against the single-source-of-truth
	// junosServicePorts catalog) to its NUMERIC form. So by the time this gate or
	// the userspace gate runs, a recognized mixed-case name is already a number and
	// the case-sensitive gate never sees a raw alias.
	//
	// The "apply" failure mode is the #3261 class-(i) unrepresentable-content
	// path, NOT a disarm/fail-open. Were the resolveAppPort case-fold removed, the
	// raw mixed-case alias would reach the userspace gate, the policy term would be
	// class-(i) unrepresentable, buildOneRuleSnapshot would emit the
	// __unsupported__ sentinel term and record snap.Capabilities.PolicyContentRejected
	// (collectPolicyContentRejections), and a current preflight-capable helper would
	// REJECT the whole snapshot while STAYING ARMED: a running node keeps its
	// previous-good policy state, a fresh boot lands on default-deny. It does NOT
	// disarm or XDP_PASS to the kernel for a current helper — disarm here is only
	// the narrow pre-preflight-protocol-version backstop
	// (pkg/dataplane/userspace/manager_ha.go class-(i) handling;
	// capabilities.go:53 documents that this cfg-only gate decides ONLY class-(ii)
	// semantics, never class-(i) content). So the regression a removed case-fold
	// would cause is broken APPLY (the new config silently does not take effect /
	// the snapshot is rejected), not a fail-open admit. The 15-name lists in
	// validatePortSpec and userspacePortSpecRepresentable are belt-and-suspenders
	// backstops kept consistent with junosServicePorts by the drift canary
	// TestNamedPortAliasTablesDoNotDrift.
	if err := validateApplicationSpecsStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application spec (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3352/#3353: syntactic application errors (an unknown leaf inside an
	// opaque inline `term`, or an unsupported `alg` name) are rejected for ALL
	// user-defined applications — referenced or not — unlike the
	// reference-scoped semantic specs above. These are grammar / enum
	// violations Junos rejects at commit regardless of policy wiring; a typo'd
	// term-leaf silently widens a term and a bogus `alg` silently no-ops from
	// the moment the app is defined, so they must be caught at definition.
	// Lenient-downgrade on the tolerant load / peer-sync path, identical to
	// validateApplicationSpecsStrict (#1960 no-brick).
	if err := validateApplicationSyntaxStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application syntax (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3366: structural application errors (a direct match body mixed with
	// `term` sub-blocks, or a duplicate single-valued leaf inside one term) are
	// rejected for ALL user-defined applications — referenced or not — like the
	// #3352/#3353 syntactic gate above. Mixing a direct body with terms silently
	// dropped the direct match (the term-store branch keeps only the terms), and
	// a repeated scalar term leaf was last-writer-wins; both are Junos config
	// errors caught at definition. Lenient-downgrade on the tolerant load /
	// peer-sync path (#1960 no-brick).
	if err := validateApplicationStructureStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application structure (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3723 firewall-filter cross-field satisfiability gate. Strict on commit /
	// commit-check (hard-reject a term whose `from` block combines a port with a
	// non-port protocol, tcp-flags with a non-TCP protocol, or icmp-type/code with
	// a non-ICMP protocol — or an icmp-code with no icmp-type). Such a term
	// compiles cleanly but the dataplane matcher (userspace-dp engine/matching.rs)
	// can NEVER satisfy the cross-field pair, so a `then discard`/`reject` term
	// silently never matches and the traffic is admitted by the implicit accept
	// (fail-OPEN) — the stateless-filter mirror of the application cross-field gate
	// #3373/#3348. Runs AFTER validateFilterProtocolsStrict so a truly unknown
	// protocol token is reported by that gate first. Lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960
	// no-brick; the Rust UnsatisfiableFilterCrossField backstop then fails the
	// whole snapshot closed independently). Runs on the fully-compiled *Config so
	// the typed term list (Protocols + ports + tcp-flags + icmp populated by
	// compileFilterFrom, covering both `protocol` and `next-header`) is available.
	if err := validateFilterCrossFieldStrict(cfg); err != nil {
		if opts.lenientFilterCrossField {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter cross-field (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3205 (agy-070 #07/#08) firewall-filter symbolic-match-value gate. Strict
	// on commit / commit-check (hard-reject a term whose icmp-type/icmp-code
	// name or named port could not be resolved to a number by compileFilterFrom).
	// Before this gate such a value was silently dropped: an unresolved icmp-type
	// left the type set empty and matched ALL ICMP (a policy bypass for an
	// `accept` term), and an unresolved named port made a `*-port-except` term
	// match ALL ports (fail open — it permitted the excluded port). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the dataplane fails CLOSED on the kept-verbatim
	// token independently). Runs on the fully-compiled *Config so the typed term
	// list (with UnknownICMPTypes/UnknownICMPCodes/UnknownPorts populated by
	// compileFilterFrom) is available.
	if err := validateFilterMatchValuesStrict(cfg); err != nil {
		if opts.lenientFilterMatchValues {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter match value (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3203 (agy-070 #02/#03/#04) firewall-filter flexible-match-range gate.
	// Strict on commit / commit-check (hard-reject a term whose byte-offset/
	// bit-length/match-value/match-mask could not be parsed or fell outside the
	// representable range). Before this gate such a token was silently ignored
	// by compileFilterFrom, leaving the field at its zero default — a malformed
	// or >32-bit match-value became 0x0 and the rule matched the WRONG (zero)
	// pattern with a clean commit. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick).
	// Runs on the fully-compiled *Config so the typed term list (with
	// UnknownFlexMatch populated by compileFilterFrom) is available.
	if err := validateFilterFlexMatchStrict(cfg); err != nil {
		if opts.lenientFlexMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter flexible-match-range (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3297 firewall-filter positive-vs-except port mutual-exclusion gate.
	// Strict on commit / commit-check (hard-reject a term carrying BOTH a
	// positive port match and the negated *-port-except list in the same
	// direction — Junos rejects this as ambiguous). Before this gate xpf
	// accepted the term and the Rust matcher silently applied positive-wins,
	// dropping the except side. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// dataplane's positive-wins fallback keeps that direction fail-safe). Runs
	// on the fully-compiled *Config so the typed term list (with
	// SourcePorts/DestinationPorts and SourcePortsExcept/DestPortsExcept
	// populated by compileFilterFrom) is available.
	if err := validateFilterPortExceptStrict(cfg); err != nil {
		if opts.lenientFilterPortExcept {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter port-except (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3359 firewall-filter positive-vs-except ADDRESS mutual-exclusion gate.
	// Strict on commit / commit-check (hard-reject a term that mixes a positive
	// address match — literal source/destination-address or a non-except
	// prefix-list — with an `except` prefix-list in the same direction; Junos
	// rejects this as ambiguous). Before this gate xpf accepted the term and the
	// userspace lowering FOLDED the except prefixes into the positive set,
	// dropping the except modifier — a silent fail-OPEN for a discard/reject
	// term. Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the dataplane's
	// positive-wins fallback keeps that direction fail-safe). Sibling of the
	// #3297 port-except gate above.
	if err := validateFilterAddressExceptStrict(cfg); err != nil {
		if opts.lenientFilterAddressExcept {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter address-except (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3307 firewall-filter unenforced-`from`-leaf gate. Strict on commit /
	// commit-check (hard-reject a term whose `from` block carries a match leaf
	// the dataplane does NOT enforce — ttl / source-mac-address / ip-options /
	// fragment-offset / hop-limit / ...). The schema gate is opt-in, so such a
	// leaf passed commit and was silently DROPPED by compileFilterFrom (no
	// default arm), leaving the term matching MORE broadly than authored — an
	// accept over-permits (fail open), a discard/reject over-drops. Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the dataplane never represented the leaf, so the
	// term matches without it independently). Runs on the fully-compiled *Config
	// so the typed term list (with UnknownFrom populated by compileFilterFrom) is
	// available.
	// #3433 firewall-filter literal-address gate. Strict on commit / commit-check
	// (hard-reject a term whose literal source/destination-address is malformed or
	// of the wrong family for the filter). The address leaves were untyped at
	// commit, so a bad literal reached the kernel lo0 nft mirror verbatim and
	// either failed the atomic `nft -f -` load (breaking a legitimate commit) or,
	// on the lenient path, left the kernel mirror ABSENT while userspace stayed
	// armed — a host-protection divergence. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// lowering's family-filter and the userspace matcher both fail closed for the
	// bad token independently). Runs on the fully-compiled *Config so the typed
	// term address slices are available. Sibling of the #3307 from-match gate.
	if err := validateFilterAddressLiteralsStrict(cfg); err != nil {
		if opts.lenientFilterAddressLiterals {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter address literal (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	if err := validateFilterFromMatchStrict(cfg); err != nil {
		if opts.lenientFilterFromMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter from-match (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3308 firewall-filter routing-instance-vs-discard/reject mutual-exclusion
	// gate. Strict on commit / commit-check (hard-reject a term that co-locates
	// `then routing-instance <x>` with a terminating `then discard`/`then
	// reject`). Such a term is contradictory: it asks the dataplane to BOTH steer
	// the packet into <x> AND drop/reject it. Both forwarding paths now resolve
	// the contradiction to the DENY — the userspace PBR runtime
	// (ingress_route_table_override) returns RouteOverride::Drop (#4392) and the
	// kernel `ip rule` mirror (buildPBRFromFilter, pkg/routing) skips the steering
	// rule (#4534). This gate stays strict at commit so the operator never
	// authors the contradiction, but is lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; both
	// runtimes drop the term independently). Runs on the fully-compiled *Config so
	// the typed term list (RoutingInstance + Action populated by compileFilterThen)
	// is available.
	if err := validateFilterRoutingInstanceConflictStrict(cfg); err != nil {
		if opts.lenientFilterRoutingInstanceConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter routing-instance conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4375 (avo-review-007 H3) firewall-filter conflicting-terminal-actions gate.
	// Strict on commit / commit-check (hard-reject a term that specifies more than
	// one DISTINCT terminating action — accept/reject/discard are mutually
	// exclusive in Junos). Before this gate compileFilterThen wrote each keyword
	// onto the single-valued term.Action (last-write-wins), so a term with `then
	// accept` AND `then reject` silently compiled to whichever came last — the
	// operator's intent was ambiguous. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// last-wins Action drives the dataplane independently). Runs on the
	// fully-compiled *Config so the typed term list (TerminalActions populated by
	// compileFilterThen) is available.
	if err := validateFilterTerminalConflictStrict(cfg); err != nil {
		if opts.lenientFilterTerminalConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter terminal-action conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3309 firewall-filter DSCP / traffic-class range gate. Strict on commit /
	// commit-check (hard-reject a `from dscp`/`from traffic-class` match or a
	// `then dscp`/`then traffic-class` rewrite token that is neither a known
	// code-point name nor an integer 0..63). Before this gate such a token was
	// appended raw and SILENTLY DROPPED by the snapshot builder
	// (pkg/dataplane/userspace/filters.go) — a dropped match value left the term
	// matching ALL DSCPs (a policy widening) and a dropped rewrite no-opped.
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the snapshot builder drops the bad
	// token independently). Runs on the fully-compiled *Config so the typed term
	// list (DSCPs + DSCPRewrite populated by compileFilterFrom/compileFilterThen)
	// is available.
	if err := validateFilterDSCPStrict(cfg); err != nil {
		if opts.lenientFilterDSCP {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter dscp (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
			return err
		}
	}

	// #3751: event-options within/trigger numerics. compileEventOptions
	// parsed the within time-interval and the trigger count with strconv.Atoi
	// and SILENTLY dropped the error, so a typo (`within bogus`, `trigger on
	// typo`) coerced the field to 0. The engine then treated a 0 threshold as
	// an unconditional match — a threshold-gated remediation silently became
	// ALWAYS-FIRE (fail-open). This gate rejects a non-numeric / negative /
	// zero / out-of-range value and a within clause carrying both `trigger on`
	// and `trigger until` (contradictory). It is an AST pre-walk (the raw
	// typo'd token is lost once compileEventOptions coerces it to 0) run on
	// the group-expanded, inactive-pruned tree so an apply-groups-inherited
	// clause is caught and an inactive one is ignored. Strict (commit /
	// commit-check): hard-reject naming the policy and value. Lenient (load /
	// peer-sync): warn so an already-persisted or peer-synced config an older
	// binary silently accepted still boots (#1960) — the engine's withinMatches
	// then fails CLOSED on the leftover 0 threshold rather than over-firing.
	withinWarnings, werr := validateEventOptionsWithinAST(tree.Children, opts.lenientEventWithinTrigger)
	if werr != nil {
		return werr
	}
	cfg.Warnings = append(cfg.Warnings, withinWarnings...)

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
			return err
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
			return err
		}
	}

	// #4298 (V-2): reject an IPsec proposal with `protocol ah`. AH is
	// integrity-only and xpf has no AH render path, so a `protocol ah`
	// proposal used to render as ESP with a fabricated cipher — a crypto
	// misrepresentation. Strict on commit / commit-check (hard reject);
	// lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — the render belt skips the VPN rather
	// than emitting the fabricated ESP tunnel).
	if err := validateIPsecProposalProtocolStrict(cfg); err != nil {
		if opts.lenientIPsecProposalProtocol {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec proposal protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4300 (V-4): reject an IPsec VPN configuring a `manual { ... }`
	// manual-key SA. xpf has no manual-key path; the block was silently
	// dropped, leaving a dead tunnel that committed OK. Strict on commit /
	// commit-check (hard reject with a clear "use an IKE-negotiated VPN"
	// message); lenient on load / peer-sync (warn — the block was already
	// inert, so the boot is fail-safe).
	if err := validateIPsecManualKeyStrict(cfg); err != nil {
		if opts.lenientIPsecManualKey {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec manual-key SA (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3349 follow-up, #3409 implemented: event-mode log-format compatibility.
	// The top-level `security log format` is schema-validated to a known format
	// in any mode. As of #3409 the EVENT-mode local-file writer honors the full
	// set — binary, standard/syslog text, `structured` (Junos RT_FLOW), and
	// `sd-syslog` (RFC 5424 envelope) — so nothing silently falls back, and this
	// validator accepts the entire schema enum in either mode. It is retained as
	// a cross-field gate (the per-leaf SchemaValidate walker cannot express a
	// mode-dependent rule) and default-rejects only a hypothetical future schema
	// value not yet wired into the writer fanout. Strict on commit / commit-check;
	// lenient on load / peer-sync — now inert for the four known formats.
	if err := validateLogEventModeFormatStrict(cfg); err != nil {
		if opts.lenientLogEventModeFormat {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("security log event-mode format (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3300 residual: an endpoint-less dynamic-address feed-server (no url
	// AND no hostname) is SKIPPED by feeds.Manager.Apply (resolveBaseURL ==
	// "" registers none of its feeds), so an address-name bound to it
	// resolves to an empty match-nothing book and a feed-backed deny policy
	// silently denies nothing — the #3300 symptom at the feed-server root.
	// Reject it so the runtime-nonfunctional config fails at commit. This
	// must run BEFORE the feed-name cross-reference gate below so the
	// declared-feed set the latter trusts is exact (no skipped servers in
	// it). Strict on commit / commit-check; lenient on load / peer-sync
	// (warn — the runtime already drops the server, so a bound address-name
	// is fail-closed rather than bricking the load — #1960 / #3261).
	if err := validateDynamicAddressFeedServerEndpointStrict(cfg); err != nil {
		if opts.lenientDynamicAddressFeedRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("dynamic-address feed-server endpoint (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3300 dynamic-address feed cross-reference gate. A
	// `security dynamic-address address-name <addr> profile feed-name <feed>`
	// whose feed-name resolves to no declared feed-server feed records an
	// empty (match-nothing) address book at runtime, so a feed-backed deny
	// policy silently denies nothing with no commit error — a typo is
	// indistinguishable from a not-yet-fetched feed. Strict on commit /
	// commit-check (hard reject so the typo is operator-visible); lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 / #3261; the runtime stays fail-closed match-none
	// for the unknown feed). Runs on the fully-compiled *Config so the
	// feed-server map is populated regardless of authoring order. Mirrors
	// validateLogProfileStreamReferencesStrict.
	if err := validateDynamicAddressFeedReferencesStrict(cfg); err != nil {
		if opts.lenientDynamicAddressFeedRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("dynamic-address feed reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #2881: policy community cross-reference gate. A policy term's
	// `from community <name>` (rendered `match community <name>`) and
	// `then community delete <name>` (rendered `set comm-list <name> delete`,
	// added in #2848) both reference an FRR `bgp community-list <name>` that xpf
	// renders ONLY from a defined `policy-options community <name>`. An
	// undefined name committed unnoticed, then at FRR render time a dangling
	// `match community` / `set comm-list ... delete` is rejected by frr-reload,
	// failing the WHOLE reload (a single vtysh -f add-batch exits non-zero on
	// any CMD_WARNING_CONFIG_FAILED) and leaving dynamic routing stale. Strict
	// on commit / commit-check (hard reject naming the policy, term, and missing
	// community); lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960). Runs on the fully-compiled
	// *Config so the community map is populated regardless of authoring order.
	// Mirrors validateRoutingExportReferencesStrict.
	if err := validatePolicyCommunityReferencesStrict(cfg); err != nil {
		if opts.lenientPolicyCommunityRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy community reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
			return err
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
			return err
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
			return err
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
			return err
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
			return err
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
				fmt.Sprintf("NAT address-name reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4290: reject a static-NAT rule that would install with an EMPTY
	// translation target — an unresolvable `then static-nat prefix-name` or a
	// misspelled / unhandled target keyword the free-form static-nat leaf
	// accepted. Both silently installed a 1:1 NAT with no translation. Strict on
	// commit / commit-check (hard reject so the broken target is operator-
	// visible); lenient on load / peer-sync (warn — #1960; the dataplane then
	// fails closed on the empty prefix). Reuses lenientFirewallRefs, the same
	// opt the NAT address-name gate above uses.
	if err := validateStaticNATThenTargetStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT translation target (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
		}
	}

	// #3296: interface/unit (and lo0) `family inet|inet6 filter input|output
	// <name>` cross-reference. A filter hook naming a filter not defined under
	// `firewall family inet|inet6 filter` compiled cleanly with only a
	// warning, and the userspace filter compiler left the per-interface
	// fast-path map empty for the missing key, so the hot path returned the
	// default Accept — the security hook was silently disarmed and the
	// interface forwarded unfiltered (a fail-OPEN on a typo'd firewall hook).
	// Strict on commit / commit-check (hard reject so the typo is operator-
	// visible); lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960; the helper's snapshot-integrity
	// backstop then refuses to publish a snapshot whose interface references an
	// undefined filter, preserving prior good state rather than degrading the
	// hook to Accept). Supersedes the warn-only interface filter-reference loop
	// in ValidateConfig. Mirrors validateFirewallPrefixListReferencesStrict.
	if err := validateFirewallFilterReferencesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3432: an OUTPUT-attached firewall filter carrying a `then
	// routing-instance <x>` (FBF) term compiled cleanly but was a silent
	// no-op: the userspace route-override path only consults the INPUT
	// filter's affects_route_lookup flag (the Rust filter compiler sets it
	// only on the input attach branch), so an output attach never steers the
	// traffic. Reject the unsupported direction at commit so the dead steering
	// action is operator-visible. Strict on commit / commit-check; lenient on
	// load / peer-sync (warn — #1960; the runtime already treats the output
	// steering term as inert). Mirrors the filter-reference gate above.
	if err := validateFilterRoutingInstanceDirectionStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter routing-instance direction (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
			return err
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
			return err
		}
	}

	// #3144 security-policy match-application definedness gate. A policy
	// `match application <name>` token resolving to no predefined junos-*
	// application, no user-defined application, and no application-set was
	// previously only WARNED at commit — yet the userspace capability gate
	// (resolveUserspaceApplicationNames) resolves the SAME name set and returns
	// false for an unknown name, so the dataplane REFUSES to arm security
	// policies. The operator gets a green commit and a silently DISARMED policy
	// engine on the firewall's allow/deny path (a commit/apply split,
	// fail-open). Strict on commit / commit-check (hard reject naming the
	// policy scope, the policy, and the undefined app); lenient on load /
	// peer-sync (warn — #1960; the dataplane independently refuses the policy,
	// so a leniently-loaded bad config is no worse off, now flagged). Resolves
	// via ResolveApplication / ResolveApplicationSet — the EXACT name set the
	// runtime gate uses — so commit and runtime cannot diverge. Covers
	// zone-pair + global policies and the multi-value application list. Runs
	// AFTER the application-set member gate (#2217) so a dangling member of a
	// DEFINED set still wins the first-error slot; this gate catches a wholly
	// undefined top-level reference that #2217's ExpandApplicationSet never
	// sees.
	if err := validatePolicyMatchApplicationsStrict(cfg); err != nil {
		if opts.lenientPolicyMatchApplications {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match application (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3434 (Codex audit 095 H07/H08): source/destination-NAT match-application
	// definedness gate, the NAT analog of validatePolicyMatchApplicationsStrict
	// (#3144/#3146). A NAT `match application <name>` resolving to no
	// predefined/user application and no non-empty application-set previously
	// committed cleanly — yet the DNAT snapshot builder then fell through to a
	// wildcard match-all term and published the pool VIP for every flow to the
	// destination (fail-open). Strict on commit / commit-check (hard reject
	// naming the NAT kind, rule-set, rule, and the undefined app); lenient on
	// load / peer-sync (warn — #1960; the dataplane now fails such a rule closed
	// via a never-match term, so a leniently-loaded bad config is no worse off,
	// now flagged). Resolves via ResolveApplication / ResolveApplicationSet —
	// the EXACT name set the SNAT/DNAT snapshot builders use — so commit and
	// runtime cannot diverge. Covers source and destination NAT rule-sets
	// (static NAT carries no application match).
	if err := validateNATMatchApplicationsStrict(cfg); err != nil {
		if opts.lenientNATMatchApplications {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT match application (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3149 (folds #3147): policy match address-set member / empty-set
	// fail-open gate. A security-policy source/destination address naming a
	// DEFINED address-book entry whose members dangle, or a defined-but-empty
	// address-set / prefix-less address, was only WARNED at commit
	// (compiler_validate_warn.go) — yet the runtime address resolver returns
	// false for the same name and the userspace gate then REFUSES to arm
	// security policies, silently disarming the allow/deny path (commit/apply
	// split, fail-open; address-book sibling of #3144/#3146). Strict on commit /
	// commit-check (hard reject); lenient on load / peer-sync (warn — #1960; the
	// dataplane independently refuses such a policy, so a leniently-loaded bad
	// config is no worse off, now flagged). Runs AFTER the #2008 token gate
	// (which catches a wholly-undefined token) so a defined-name resolution
	// failure is this gate's first-error.
	if err := validatePolicyMatchAddressSetMembersStrict(cfg); err != nil {
		if opts.lenientPolicyMatchAddressSetMembers {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match address-set members (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
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
			return err
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
			return err
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
			return err
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
			return err
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
			return err
		}
	}

	return nil
}
