package config

import "strings"

// compiler_nat_then_packed_contradiction_7033.go — #7033.
//
// A `then` block carrying two mutually-exclusive translation actions is meant to
// be rejected at strict commit (#5628). When the two are PACKED as tokens on one
// run rather than lowered as two fields, only one is lowered, the cardinality
// counter — which counts RESOLVED fields — sees `n == 1`, and the contradiction
// commits under STRICT with no diagnostic:
//
//	then { source-nat pool P off; }      -> {PoolName:"P"}   `off` DROPPED
//	then { source-nat off pool P; }      -> {Off:true}       `pool P` dropped
//	then { source-nat { pool P off; } }  -> {PoolName:"P"}   `off` DROPPED
//	set … then source-nat pool P off     -> {PoolName:"P"}   `off` DROPPED
//
// The rows where `off` is the casualty are the severe ones: the operator
// authored a no-NAT EXEMPTION and the compiler publishes a TRANSLATION in its
// place — the inverse of the authored action, which is the outcome the #5628
// rejection text says it prevents.
//
// WHY THIS IS A DETECTION FIX AND NOT AN ACCUMULATING LOWERING FIX. Two rounds
// of #6820 tried to make the lowering read every packed token, and each
// introduced a commit-reachable regression in the ACCEPTING direction — round 5
// made `then { destination-nat interface pool PD; }` newly resolve as a pool
// translation, round 6 fabricated an exemption out of
// `then { source-nat { frobnicate { off; } } }`. Both were reverted. Nothing
// here changes what a rule RESOLVES to: the authored actions are recorded
// alongside the resolved NATThen (the #7013 record, extended with modes) and the
// gate reads that. A config that commits today either commits unchanged or is
// rejected; none resolves differently.
//
// ORDERING: this runs AFTER the resolved-field count, deliberately. A block that
// LOWERS two actions is already rejected there, with a message this project has
// iterated on across #6820, #7034 and #7035. Running first would replace that
// message for every such config. Running after means the only configs that reach
// this check are the ones the field count cannot see, so no currently-rejected
// config's diagnostic changes and the change is purely additive.
//
// WHAT STAYS ACCEPTED, each pinned by a test:
//
//   - `pool off` — a pool legitimately NAMED `off`. `pool` consumes exactly one
//     value token, so this is one pool, not a pool plus an exemption.
//   - `pool P persistent-nat permit any-remote-host` — #4313's open-world
//     trailing grammar. The scan stops at the first unrecognised token instead of
//     reading the tail as actions.
//   - `then { source-nat { frobnicate { off; } } }` — still rejected, but as the
//     ZERO-action rule it is. The walk does not descend past an unrecognised
//     container, so this never becomes a fabricated `off`.

// natThenPackedContradictionModes returns the distinct terminal action MODES one
// `then` container authored, when there are two or more of them AND the rule
// resolved to exactly one action — that is, precisely the contradiction the
// resolved-field count cannot see. It returns nil in every other case.
//
// ONE PREDICATE, TWO CALLERS. The strict gate rejects on it and
// natTerminalActionCardinalityOffenders enumerates on it, for the same reason
// #7640 gave for the field count: a gauge that counted rules a commit would
// accept, or missed ones it would refuse, is worse than no gauge.
// TestLenientNATOffendersMatchThePackedGate_7033 binds the agreement for this
// class rather than trusting it.
func natThenPackedContradictionModes(rule *NATRule) []string {
	if rule == nil {
		return nil
	}
	// Only the n == 1 class. n == 0 and n >= 2 are the field count's, and it
	// reports them with its own text.
	if natThenTerminalActionCount(rule.Then) != 1 {
		return nil
	}
	modes := rule.thenAuthored.distinctModes()
	if len(modes) < 2 {
		return nil
	}
	return modes
}

// natPackedContradictionDetail renders the operator-facing explanation for a
// packed contradiction: which mode takes effect, which are discarded, and — when
// `off` is among the casualties — that the published behaviour is the INVERSE of
// what was authored.
func natPackedContradictionDetail(modes []string) string {
	survivor := modes[0]
	dropped := modes[1:]
	var b strings.Builder
	b.WriteString("`" + survivor + "` is the one that takes effect and ")
	b.WriteString("`" + strings.Join(dropped, "`, `") + "` ")
	if len(dropped) == 1 {
		b.WriteString("is silently discarded")
	} else {
		b.WriteString("are silently discarded")
	}
	for _, d := range dropped {
		if d == "off" {
			b.WriteString(". `off` is an EXEMPTION from translation, so what the " +
				"dataplane enforces here is the INVERSE of what was authored: a " +
				"translation where the configuration asks for none")
			break
		}
	}
	return b.String()
}
