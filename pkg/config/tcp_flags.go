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
//
// An input that carries no flag at all (empty / whitespace only) returns
// ok=false with no error: the caller leaves the wire field nil, i.e. no
// tcp-flags constraint.
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
	for _, t := range toks {
		switch t {
		case "&":
			// A conjunction separator carries no negation across itself.
			pendingNeg = false
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
	}

	if required&forbidden != 0 {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: a flag is both required and forbidden (the term can never match)", expr)
	}
	if required == 0 && forbidden == 0 {
		return 0, 0, false, nil
	}
	return required, forbidden, true, nil
}
