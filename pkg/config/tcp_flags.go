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
//   - an unbalanced or reversed parenthesis (e.g. "(syn", "syn)", "syn)(") —
//     a ')' with no matching '(' or a '(' left unclosed. The parens are
//     redundant grouping only, so without balance tracking they were stripped
//     unconditionally and the malformed value committed as if the parens were
//     absent (C180-024); reject it so the grammar is auditable. Balanced
//     groups, including nested ones ("((syn & !ack))"), remain accepted.
//   - a balanced-but-malformed group (C180-024 completion): an EMPTY group
//     that contributes no flag operand (e.g. "syn()", "x()", or a bare "()"
//     inside a larger expression); a '&' or other dangling operator standing
//     immediately before a ')' with no right operand in the group (e.g.
//     "(syn&)"); and a ')' immediately followed by another operand — a bare
//     flag, a '!', or a '(' — with no intervening '&' operator (e.g.
//     "(syn)ack", "(syn&)ack", "(syn)(ack)"). Balancing the parens alone did
//     not catch these — the flag bits still parsed and the malformed value
//     committed — so reject them via per-group flag-presence tracking plus an
//     "a closed group must be followed by an operator, not another operand"
//     rule. Legitimate grouping — "(syn)", "(syn & ack)", "((syn & !ack))",
//     "(!fin)", and "(syn) & (ack)" — remains accepted with identical masks.
//   - the MIRROR of the closed-group-then-operand misorder: a flag operand
//     immediately followed by a '(' group with no intervening '&' operator
//     (e.g. "syn(ack)", "ack(syn)", "syn (ack)", "syn(&ack)"). A group is an
//     operand, so juxtaposing it against a preceding flag is the same
//     operand-then-operand misorder as "(syn)ack" — it must be written
//     "syn & (ack)". The earlier justClosedGroup rule only covered the
//     ')'-then-operand direction, so these were WRONGLY ACCEPTED (the flag
//     bits parsed as a plain conjunction); reject them so the grammar is
//     symmetric. "syn(&ack)" is caught here at the '(' — before this guard the
//     outer flag's flag-presence leaked into the inner group and let its
//     leading '&' pass.
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
	// parenDepth tracks the balance of grouping parentheses. A ')' reached at
	// depth 0 is an unbalanced or reversed close (e.g. "syn)", "syn)("); a
	// nonzero depth after the last token is an unclosed group (e.g. "(syn").
	// Without this tracking the parser stripped every paren unconditionally and
	// committed "(syn", "syn)", "syn)(" as plain "syn" — strict-grammar debt
	// that admits malformed values (C180-024). The packet mask is not widened
	// (the flag bits still parse), so this is auditability/grammar hardening,
	// not an admission bypass.
	parenDepth := 0
	// groupHasFlag is a per-group stack (one frame per open '('): the top frame
	// records whether the CURRENT group has contributed a flag operand yet. A
	// '(' pushes a fresh false frame; a flag sets the top frame true; a ')' pops
	// and REJECTS an empty frame (e.g. "syn()", "()") — parenDepth balance alone
	// accepted these because segHasFlag was global (a preceding "syn" left it
	// true). A non-empty group is transitively non-empty for its parent, so on a
	// clean pop the flag is propagated to the enclosing frame ("((syn))" is
	// accepted). This is the empty/misordered-group completion of C180-024.
	var groupHasFlag []bool
	// justClosedGroup is set immediately after a ')' and cleared by the '&'
	// conjunction operator. A closed group is an operand; the grammar requires
	// the next token to be an operator ('&'), another ')' (closing an outer
	// group), or end — NOT another operand. So a flag, a '!', or a '(' seen
	// while justClosedGroup is set is a ')'-followed-by-operand misorder (e.g.
	// "(syn)ack", "(syn)(ack)", "(syn)!ack") and is rejected. Without this an
	// expression like "(syn)ack" parsed as the plain conjunction "syn ack"
	// (C180-024).
	justClosedGroup := false
	for _, t := range toks {
		// A closed group ')' is an operand: the only tokens that may follow it
		// are the conjunction operator '&', another ')' closing an enclosing
		// group, or end of input. Any operand-introducing token — a flag, '!',
		// or '(' — is a ')'-followed-by-operand misorder ("(syn)ack",
		// "(syn)!ack", "(syn)(ack)"). Reject it here in ONE place so the guard
		// is a single load-bearing check rather than three partly-shadowed
		// per-token checks. '|' is excluded so it keeps its specific
		// disjunction diagnostic below; it is rejected there regardless.
		if justClosedGroup && t != "&" && t != ")" && t != "|" {
			return 0, 0, false, fmt.Errorf(
				"tcp-flags %q: a closed group \")\" must be followed by \"&\" or the end of the expression, not %q", expr, t)
		}
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
			// A conjunction operator legitimately follows a closed group
			// ("(syn) & ack"), so the operand-after-close guard is cleared.
			justClosedGroup = false
			continue
		case "|":
			return 0, 0, false, fmt.Errorf(
				"tcp-flags %q: logical OR (\"|\") is not representable by the firewall dataplane; split the disjuncts into separate terms", expr)
		case "!":
			pendingNeg = !pendingNeg
			continue
		case "(":
			// A '!' immediately before '(' is a negated group ("!(...)"), a
			// disjunction by De Morgan's law that the conjunctive matcher cannot
			// enforce — reject it (#3076).
			if pendingNeg {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: a negated group is a disjunction (De Morgan) and is not representable by the firewall dataplane", expr)
			}
			// A '(' opens a group, which is itself an operand. An operand may not
			// directly follow another operand without a '&' conjunction between
			// them. This is the MIRROR of the justClosedGroup guard (which rejects
			// a closed ')' operand directly followed by another operand). Here
			// segHasFlag is true exactly when a bare flag already appeared in the
			// current '&'-segment with no intervening '&' — a preceding closed
			// ')' would have set justClosedGroup instead, and the top-of-loop
			// guard already rejects a '(' after ')'. So a '(' seen while
			// segHasFlag is set is a flag-then-group misorder ("syn(ack)",
			// "syn (ack)", and "syn(&ack)" — the outer flag's segHasFlag is what
			// let the inner group-leading '&' pass before this guard). Reject it;
			// a group must be joined to a preceding flag with '&' ("syn & (ack)").
			// This also guarantees segHasFlag is false at the start of every
			// freshly-opened group, so a group that itself leads with '&' or ')'
			// ("(&ack)", "(&)", "((&syn))") is still caught by the existing
			// segHasFlag left-operand checks below.
			if segHasFlag {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: a flag operand may not be directly followed by a \"(\" group; separate them with \"&\"", expr)
			}
			groupHasFlag = append(groupHasFlag, false)
			parenDepth++
			continue
		case ")":
			// A '!' immediately before ')' has no flag operand — dangling
			// negation (e.g. "syn & !)"); reject it (#4714, fail-open).
			if pendingNeg {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: dangling negation \"!\" with no flag operand", expr)
			}
			// A ')' at depth 0 has no matching '(' — an unbalanced or reversed
			// close (e.g. "syn)", "syn)(") — reject it (C180-024).
			if parenDepth == 0 {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: unbalanced parenthesis: \")\" with no matching \"(\"", expr)
			}
			// Pop this group's flag-presence frame. An empty frame is a group
			// that contributed no flag operand (e.g. "syn()", "()") — reject it
			// (C180-024 completion); parenDepth balance alone accepted it.
			had := groupHasFlag[len(groupHasFlag)-1]
			groupHasFlag = groupHasFlag[:len(groupHasFlag)-1]
			if !had {
				return 0, 0, false, fmt.Errorf(
					"tcp-flags %q: empty group \"()\" with no flag operand", expr)
			}
			// A dangling '&' immediately before this ')' (e.g. "(syn&)") leaves
			// segHasFlag false with no path to acceptance: the only tokens that
			// may follow the ')' are '&' (rejected by the "&"-no-operand guard,
			// segHasFlag is false), another operand (rejected by the
			// top-of-loop operand-after-close guard), another ')' (segHasFlag
			// stays false), or end (rejected by the post-loop trailing-'&'
			// guard). So it is rejected downstream — no dedicated in-')'
			// segHasFlag check is needed here, and adding one would be a
			// non-load-bearing shadow.
			// A non-empty group is transitively an operand of its parent, so
			// propagate the flag to the enclosing frame ("((syn))" is accepted).
			if len(groupHasFlag) > 0 {
				groupHasFlag[len(groupHasFlag)-1] = true
			}
			parenDepth--
			justClosedGroup = true
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
		// Record that the current group (if any) now has a flag operand, so a
		// later ')' does not reject it as empty.
		if len(groupHasFlag) > 0 {
			groupHasFlag[len(groupHasFlag)-1] = true
		}
	}

	// A negation left pending after the last token is a dangling '!' with no
	// flag operand (e.g. "!", "syn & !"). Without this guard the trailing '!'
	// is silently dropped and the term matches more than the operator intended
	// (#4714, fail-open) — reject it so a malformed expression fails at commit.
	if pendingNeg {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: dangling negation \"!\" with no flag operand", expr)
	}

	// A nonzero paren depth after the last token is an unclosed group (e.g.
	// "(syn", "((syn)"). Without this the trailing '(' was silently stripped
	// and the malformed value committed (C180-024). Balanced groups —
	// including nested ones like "((syn & !ack))" — leave depth at 0 and are
	// still accepted.
	if parenDepth != 0 {
		return 0, 0, false, fmt.Errorf(
			"tcp-flags %q: unbalanced parenthesis: %d unclosed \"(\"", expr, parenDepth)
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
