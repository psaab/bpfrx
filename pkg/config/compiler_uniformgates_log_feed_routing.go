package config

import "fmt"

// runUniformGatesLogFeedRouting runs the log feed routing sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesLogFeedRouting(tree *ConfigTree, cfg *Config, opts compileOpts) error {
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
	// "" registers none of its feeds), so an address-name bound to it is
	// unresolvable and fails CLOSED at runtime (#5645: omitted ->
	// __unsupported_address__ -> whole-snapshot preflight reject ->
	// previous-good/default-deny) — historically the #3300 fail-open symptom
	// at the feed-server root, now caught. Reject it so the
	// runtime-nonfunctional config fails at commit instead of silently
	// default-denying. This must run BEFORE the feed-name cross-reference gate
	// below so the declared-feed set the latter trusts is exact (no skipped
	// servers in it). Strict on commit / commit-check; lenient on load /
	// peer-sync (warn — the runtime already drops the server, so a bound
	// address-name is fail-closed rather than bricking the load — #1960 / #3261).
	if err := validateDynamicAddressFeedServerEndpointStrict(cfg); err != nil {
		if opts.lenientDynamicAddressFeedRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("dynamic-address feed-server endpoint (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4913 dynamic-address feed-name uniqueness gate. feeds.Manager keys its
	// worker map + enforcement snapshot by the effective feed name, so two
	// feed-servers declaring the same name raced on m.feeds[name] — orphaning a
	// refresh loop (goroutine leak) and backing enforcement with a
	// nondeterministic provider. Reject the collision so the operator fixes the
	// typo. Runs AFTER the endpoint gate so the surviving servers are exactly
	// the ones Apply would register (endpoint-less servers are skipped by both).
	// Strict on commit / commit-check; lenient on load / peer-sync (warn — the
	// runtime now de-dups deterministically per #4913 rather than leaking).
	if err := validateDynamicAddressFeedNameUniquenessStrict(cfg); err != nil {
		if opts.lenientDynamicAddressFeedRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("dynamic-address feed name uniqueness (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3300 dynamic-address feed cross-reference gate. A
	// `security dynamic-address address-name <addr> profile feed-name <feed>`
	// whose feed-name resolves to no declared feed-server feed is UNRESOLVABLE
	// at runtime and fails CLOSED (#5645: omitted -> __unsupported_address__ ->
	// whole-snapshot preflight reject -> previous-good/default-deny), with no
	// commit error — a typo is indistinguishable from a not-yet-fetched feed.
	// Strict on commit / commit-check (hard reject so the typo is
	// operator-visible); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 / #3261; the
	// runtime stays fail-closed for the unknown feed). Runs on the
	// fully-compiled *Config so the feed-server map is populated regardless of
	// authoring order. Mirrors validateLogProfileStreamReferencesStrict.
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

	// #6659: a multi-policy `routing-options forwarding-table export` chain.
	// The leaf is declared `multi: true` and Junos accepts a chain, but the FRR
	// renderer honours exactly one policy (resolveECMP derives ecmpMaxPaths from
	// a single policy-statement). The compiler read the leaf with nodeVal, so a
	// chain silently collapsed to the first policy AND the dropped names escaped
	// the reference gate directly above — a dangling policy in slot 2 committed
	// clean on the very scenario that gate exists to catch. The compiler now
	// accumulates all values (so the gate above checks every one) and this gate
	// rejects the multi-valued case so the collapse is loud instead of silent.
	// Strict on commit / commit-check; lenient on load / peer-sync (warn —
	// #1960; ForwardingTableExport still carries the first policy, so rendering
	// on the tolerant path is exactly pre-#6659). Reuses lenientRoutingExportRef
	// like the sibling gate above.
	if err := validateForwardingTableExportSingleStrict(cfg); err != nil {
		if opts.lenientRoutingExportRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("forwarding-table export chain (downgraded to warning on tolerant path): %v", err))
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

	// #5116: reserved route-map-suffix gate. The FRR renderer derives a
	// per-use-site fail-closed redistribute alias `name + "-xpf-redist"`
	// (redistFailClosedRouteMap) into FRR's GLOBAL name-keyed route-map
	// namespace to keep a BGP-default-accept policy's trailing permit from
	// leaking into an IGP redistribute (#4481). An operator policy-statement
	// literally named `<X>-xpf-redist` collides with that generated alias and
	// can silently undo the fail-closed separation, reintroducing route
	// redistribution leakage under a config that passes validation. Reserve the
	// suffix: strict on commit / commit-check (hard reject so the reserved name
	// is operator-visible), lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config an older binary accepted still
	// boots — #1960; the render path carries the redistAliasCollision guard that
	// fails the apply CLOSED on the tolerant path). Runs on the fully-compiled
	// *Config so the policy-statement map is populated regardless of authoring
	// order. Mirrors validateRoutingExportReferencesStrict.
	if err := validatePolicyReservedRedistNameStrict(cfg); err != nil {
		if opts.lenientPolicyReservedRedistName {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved route-map suffix (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5442: reserved composed-chain route-map-suffix gate. #5277 composes an
	// ordered BGP import/export policy chain (length >= 2) into a single FRR
	// route-map named `join(chain, "-") + "-xpf-chain"` (composedChainName,
	// pkg/frr) in FRR's GLOBAL name-keyed route-map namespace. An operator
	// policy-statement literally named `<X>-xpf-chain` collides with that
	// generated composed route-map and FRR MERGES same-named route-maps,
	// silently altering the operator's BGP filtering. Reserve the suffix: strict
	// on commit / commit-check (hard reject so the reserved name is
	// operator-visible), lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config an older binary accepted still
	// boots — #1960; the render path carries the bgpComposedChainCollision guard
	// that fails the apply CLOSED on the tolerant path). Runs on the
	// fully-compiled *Config so the policy-statement map is populated regardless
	// of authoring order. Mirrors validatePolicyReservedRedistNameStrict.
	if err := validatePolicyReservedChainNameStrict(cfg); err != nil {
		if opts.lenientPolicyReservedChainName {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved route-map suffix (downgraded to warning on tolerant path): %v", err))
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

	return nil
}
