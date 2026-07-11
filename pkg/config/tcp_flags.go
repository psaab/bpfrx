package config

import (
	"fmt"
	"strings"
)

// tcpFlagBits maps Junos firewall-filter TCP-flag mnemonics (and the Junos
// `push` alias for `psh`) to their bit position in the TCP flags byte. Bit
// order matches userspace-dp/src/tcp_flags.rs and the dataplane snapshot
// builder in pkg/dataplane/userspace/filters.go.
var tcpFlagBits = map[string]uint8{
	"fin":  0x01,
	"syn":  0x02,
	"rst":  0x04,
	"psh":  0x08,
	"push": 0x08, // Junos alias for psh
	"ack":  0x10,
	"urg":  0x20,
}

// ParseTCPFlagsExpression parses a Junos firewall-filter `tcp-flags` value into
// a required-bits mask and a forbidden-bits mask over the TCP flags byte. A TCP
// segment matches the term when:
//
//	(flags & required) == required && (flags & forbidden) == 0
//
// The elements of parts are joined with a space before parsing, so every shape
// the parser can hand us is covered uniformly:
//
//   - bracket / flat list of flag names: ["syn","ack"]   → required = SYN|ACK
//   - a quoted space list:               ["syn ack"]     → required = SYN|ACK
//   - a quoted conjunction:              ["syn & ack"]   → required = SYN|ACK
//   - negation:                          ["syn & !ack"]  → required = SYN,
//     forbidden = ACK
//   - redundant grouping parentheses around a pure conjunction:
//     ["(syn & !ack)"]                                   → required = SYN,
//     forbidden = ACK
//
// The conjunctive (AND-only) dataplane matcher can represent a single set of
// required bits and a single set of forbidden bits, so the following forms are
// NOT representable and are REJECTED with an error rather than silently dropped
// (#3076 — a dropped security constraint must never silently match every
// packet):
//
//   - disjunction with '|' (e.g. "ack | rst")
//   - a negated parenthesized group (e.g. "!(syn & ack)") which is a
//     disjunction by De Morgan's law
//   - an unrecognized flag token
//   - a flag that is both required and forbidden (a contradiction)
//   - a dangling negation '!' with no flag operand (e.g. "!", "syn & !",
//     "! & ack") — the '!' would otherwise be silently dropped, weakening the
//     term (#4714, fail-open); reject it so the operator's intent is never
//     silently lost
//   - a '&' conjunction with no flag operand on one side, i.e. a leading,
//     trailing, or duplicated separator (e.g. "&", "syn &", "& ack",
//     "syn && ack"), and any non-empty expression that sets no flag bits at all
//     (e.g. "&", "()") — such an operator-only / empty-operand expression would
//     otherwise return "no constraint" (or silently drop the dangling '&') and
//     the term would match EVERY TCP segment (#5455, fail-open widening of a
//     security filter); reject it so a malformed value never commits
//
// An input that carries no flag at all (empty / whitespace only) returns
// ok=false with no error: the caller leaves the wire field nil, i.e. no
// tcp-flags constraint. This "absent" case is distinct from a NON-EMPTY value
// that parses to no flag bits (rejected above): the former is "operator wrote
// nothing", the latter is "operator wrote something malformed".
func ParseTCPFlagsExpression(parts []string) (required, forbidden uint8, ok bool, err error) {
	expr := strings.TrimSpace(strings.Join(parts, " "))
	if expr == "" {
		return 0, 0, false, nil
	}

	// Lex into tokens: the operators '&' '|' '!' '(' ')' plus flag-name words.
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range expr {
		switch r {
		case '&', '|', '!', '(', ')':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()

	// Only a conjunction of (optionally negated) flag names is representable by
	// the dataplane matcher. A '|' anywhere, or a '!' applied to a parenthesized
	// group, yields a disjunction that the conjunctive matcher cannot enforce —
	// reject it (fail-closed) instead of dropping the constraint.
	pendingNeg := false
	// segHasFlag tracks whether the current '&'-delimited segment has yet
	// contributed a flag operand. A conjunction separator ('&') is binary: it
	// requires a flag operand on BOTH sides. A '&' reached while the current
	// segment is still empty is a leading or duplicated separator (e.g. "& ack",
	// "syn && ack"); the trailing check after the loop catches a segment left
	// empty at the end (e.g. "&", "syn &"). Either way the operator wrote a '&'
	// with no flag operand — reject it so the malformed value never commits and
	// silently matches all TCP (#5455, fail-open).
	segHasFlag := false
	for _, t := range toks {
		switch t {
		case "&":
			// A conjunction separator carries no negation across itself. A '!'
			// standing immediately before the separator has no flag operand —
			// that is a dangling negation (e.g. "! & ack"). Reject it rather
			// than silently discarding the '!' (#4714, fail-open).
			if pendingNeg {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: dangling negation \"!\" with no flag operand", expr)
			}
			// A '&' with no flag operand to its left is a leading or duplicated
			// separator (e.g. "& ack", "syn && ack") — reject it (#5455).
			if !segHasFlag {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: \"&\" conjunction with no flag operand", expr)
			}
			pendingNeg = false
			segHasFlag = false
			continue
		case "|":
			return 0, 0, false, fmt.Errorf(
				"tcp-flags %q: logical OR (\"|\") is not representable by the firewall dataplane; split the disjuncts into separate terms", expr)
		case "!":
			pendingNeg = !pendingNeg
			continue
		case "(", ")":
			if pendingNeg {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: a negated group is a disjunction (De Morgan) and is not representable by the firewall dataplane", expr)
			}
			continue
		}
		bit, found := tcpFlagBits[strings.ToLower(t)]
		if !found {
			return 0, 0, false, fmt.Errorf("tcp-flags %q: unrecognized flag %q", expr, t)
		}
		if pendingNeg {
			forbidden |= bit
		} else {
			required |= bit
		}
		pendingNeg = false
		segHasFlag = true
	}

	// A negation left pending after the last token is a dangling '!' with no
	// flag operand (e.g. "!", "syn & !"). Without this guard the trailing '!'
	// is silently dropped and the term matches more than the operator intended
	// (#4714, fail-open) — reject it so a malformed expression fails at commit.
	if pendingNeg {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: dangling negation \"!\" with no flag operand", expr)
	}

	// The final '&'-delimited segment must also carry a flag operand. A segment
	// left empty at the end is a trailing '&' (e.g. "syn &"), a whole expression
	// that is operator-only (e.g. "&"), or an empty-operand group (e.g. "()").
	// Each sets no flag bits for that segment, so accepting it would silently
	// drop the constraint and match every TCP segment (#5455, fail-open). This
	// is the NON-EMPTY-but-no-flag-bits case that must ERROR, distinct from the
	// legitimately-absent (expr == "") case handled above which returns "no
	// constraint" with no error.
	if !segHasFlag {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: expression has no flag operand (operator-only, empty operand, or trailing \"&\")", expr)
	}

	if required&forbidden != 0 {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: a flag is both required and forbidden (the term can never match)", expr)
	}
	// segHasFlag implies at least one bit was set, so required|forbidden != 0
	// here — the historical "required == 0 && forbidden == 0 → no constraint"
	// fall-through is unreachable for a non-empty expression. Guard it as a
	// fail-closed backstop rather than silently returning match-all (#5455).
	if required == 0 && forbidden == 0 {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: expression sets no flag bits", expr)
	}
	return required, forbidden, true, nil
}
