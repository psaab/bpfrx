package config

import "fmt"

// runUniformGatesFirewallNAT2 runs the firewall nat2 sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesFirewallNAT2(tree *ConfigTree, cfg *Config, opts compileOpts) error {
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

	// #3076 / #4953: firewall-filter `from tcp-flags` enforceability gate.
	// An expression the conjunctive dataplane matcher cannot represent
	// (disjunction, negated group, unknown flag, dangling negation, or a
	// required/forbidden contradiction) compiled cleanly before #3076 and the
	// constraint was silently dropped on the wire (fail-open — the term
	// matched every TCP segment). Strict on commit / commit-check (hard reject
	// so the operator error is visible); lenient on load / peer-sync (warn so a
	// config an older binary persisted, or a peer authored, before the reject
	// existed still boots — #1960 no-brick). On the leniently-loaded boot the
	// term keeps its raw TCPFlags and the userspace snapshot builder marks it
	// TCPFlagsUnparseable, failing the term CLOSED (#3367) rather than widening
	// it. This reject previously lived inline in compileFirewall, which the P4
	// dispatch calls with no compileOpts — so it could not be mode-gated and an
	// upgraded / peer-synced node blacked out or alarm-looped HA sync.
	if err := validateFirewallTCPFlagsStrict(cfg); err != nil {
		if opts.lenientFirewallTCPFlags {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("firewall filter tcp-flags (downgraded to warning on tolerant path): %v", err))
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

	// #5456: firewall-filter term rule-expansion advisory. A term whose
	// source×destination×dest-port×src-port cross-product (prefix-list prefixes
	// folded into src/dst) exceeds MaxFilterTermExpansion is COMMITTED, not
	// rejected: the live userspace dataplane enforces it natively (prefix-set
	// membership + name-keyed per-term counters) and never materializes the
	// cross-product, so rejecting would false-reject a legitimate config. The
	// silent uint32 truncation this issue fixes is already closed by
	// FilterTermExpansionCount's checked-uint64 clamp; this advisory only flags
	// that per-rule `show firewall filter` counts on the RETIRED-eBPF counter
	// path (unused on this build) would be clamped/inexact for such a term. Runs
	// on the fully-compiled *Config so the prefix-list maps are populated
	// regardless of authoring order. Emitted on BOTH the strict commit and the
	// tolerant load / peer-sync paths (it never blocks either — #1960 no-brick).
	warnFilterTermExpansionOverBound(cfg)

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

	// #5859: reject a static-NAT rule whose target is the NAT64 keyword `then
	// static-nat inet`. The compiler accepts the keyword but the userspace
	// snapshot emits the literal string "inet" into the same-family static_nat
	// address slot; the Rust parse of "inet" fails and the rule is SILENTLY
	// SKIPPED — a strict-valid config claims NAT64 but installs nothing. No
	// dataplane lowering of `static-nat inet` exists (the supported IPv6->IPv4
	// path is the native `security nat nat64` rule-set). Strict on commit /
	// commit-check (hard reject so the inert rule is operator-visible, naming
	// the native alternative); lenient on load / peer-sync (warn — #1960; the
	// snapshot builder then DROPS the rule so the sentinel never reaches Rust).
	// Reuses lenientFirewallRefs, the same opt the target gates above use.
	if err := validateStaticNATInetTargetStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT inet (NAT64) target (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6659: a static-NAT `match destination-address` list. The leaf is
	// declared `multi: true`, but the compiler read it with nodeVal and kept
	// only the first prefix — so the remaining prefixes were neither translated
	// NOR validated (a malformed prefix in any slot but the first committed
	// clean). The compiler now accumulates every value; this gate rejects the
	// multi-valued case because a static-NAT rule lowers to exactly ONE
	// dataplane row. Strict on commit / commit-check (hard reject so the
	// previously-silent collapse is operator-visible); lenient on load /
	// peer-sync (warn — #1960 no-brick; Match still carries the first prefix, so
	// the tolerant path behaves exactly as it did pre-#6659). Reuses
	// lenientFirewallRefs like the sibling static-NAT gates above.
	if err := validateStaticNATMatchAddressesStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT `match destination-address` LIST FORM IS NOT SUPPORTED — "+
					"only the FIRST prefix is honoured and the rest carry no translation; "+
					"author one rule per external prefix (support for the list form is tracked "+
					"in #6674). Downgraded to a warning on the tolerant load / peer-sync path "+
					"so an already-persisted config still boots: %v", err))
		} else {
			return err
		}
	}

	// #5628 (codex-review-181 M16): a source / destination NAT rule's complete
	// `then` block must carry EXACTLY ONE NAT-terminal translation action. A
	// rule with ZERO actions installs no translation (an intended `off`
	// exemption silently disappears, revealing a later broader rule); a rule
	// with TWO+ mutually-exclusive actions inside one block let the compiler
	// silently pick one by packed-key/child order (an exemption can publish as a
	// translation — the inverse of the authored action). Strict on commit /
	// commit-check (hard reject so the malformed rule is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick; the dataplane is no
	// worse than before the gate). Preserves #3850 duplicate-`then`-CONTAINER
	// last-wins (the count reflects the winning block only).
	if err := validateNATTerminalActionCardinalityStrict(cfg); err != nil {
		if opts.lenientNATTerminalAction {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("NAT terminal-action cardinality (downgraded to warning on tolerant path): %v", err))
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

	return nil
}
