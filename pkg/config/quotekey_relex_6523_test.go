package config

// Structural round-trip tests for quoteKey's bare-emission predicate (#6523).
//
// quoteKey used to emit a key bare whenever every byte satisfied isIdentChar.
// isIdentChar is the LEXER'S ident set — it admits `/`, `*` and `:` — and is
// not the set of texts that survive a serialize/re-parse cycle. Three
// ident-char-only CLASSES are re-interpreted STRUCTURALLY on the way back in.
// Two are SILENT — no parse error, no warning. The unterminated block comment
// is the exception: it returns a TokenError, so it corrupts loudly rather than
// quietly, which makes it the least dangerous of the three:
//
//	//x        line comment  -> the key and everything after it on that line
//	                            silently VANISH
//	/*x*/      block comment -> swallowed silently
//	/*x        block comment -> swallows the rest of the config (Parse errors)
//	inactive:  deactivation marker -> leading, deactivates an unrelated
//	                            statement; inline, TRUNCATES the key list
//
// Every serialize-then-reparse path is affected: HA config sync, rollback,
// archive, rescue. This file pins the fix at three levels — the predicate
// itself, the hierarchical Format->Parse path, and the `| display set`
// Format->ParseSetVerb path — plus two anti-rot devices: a brute-force
// property sweep that re-derives the hazard set from the real lexer, so a
// comment syntax added later cannot quietly reopen the hole, and
// TestParserMarkerVocabulary6523, which covers the half the lexer cannot
// derive (a word-shaped parser marker).
//
// Not every test here is a fail-on-revert BINDER, and the ones that are not
// say so in their own doc comment. TestQuoteKeyNoOverReach6523 and
// TestQuoteKeyBareEmissionIsZeroAlloc6523 are GUARDS — green under revert by
// design. TestQuoteKeySetFormHazards6523 and TestBareKeySafeAgreesWithLexer6523
// bind only PARTIALLY: their `inactive:` cases pass under revert, because that
// hazard bites at the PARSER and those two assertions stop short of it. The
// parse-level binder for `inactive:` is TestQuoteKeyStructuralHazards6523.

import (
	"fmt"
	"strings"
	"testing"
)

// structuralHazards are the texts that must NOT be emitted bare. Each is made
// entirely of isIdentChar bytes, so the pre-#6523 predicate emitted every one
// of them unquoted.
var structuralHazards = []struct {
	name  string
	value string
}{
	{"line-comment", "//x"},
	{"line-comment-bare", "//"},
	{"line-comment-only-slashes", "///"},
	{"block-comment-terminated", "/*x*/"},
	{"block-comment-unterminated", "/*x"},
	{"block-comment-bare", "/*"},
	{"block-comment-empty", "/**/"},
	{"inactive-marker", "inactive:"},
}

// hazardKeyShapes places a candidate at each structurally distinct position in
// a node's key list: leading (where the `inactive:` marker is lifted onto
// Node.Inactive), inline (where it truncates the key list), and trailing
// (the usual home of a config VALUE, e.g. an IKE pre-shared-key).
var hazardKeyShapes = []struct {
	name string
	// keys builds the node key list around the candidate, and idx is where
	// the candidate lands.
	keys func(v string) []string
	idx  int
}{
	{"leading", func(v string) []string { return []string{v, "trailer"} }, 0},
	{"inline", func(v string) []string { return []string{"description", v, "trailer"} }, 1},
	{"trailing", func(v string) []string { return []string{"pre-shared-key", "ascii-text", v} }, 2},
}

// formatParseKeys round-trips a single-leaf tree through Format and Parse and
// returns the recovered key list. Errors are returned rather than fataled so
// callers can report the candidate that produced them.
func formatParseKeys(keys []string) ([]string, bool, error) {
	tree := &ConfigTree{Children: []*Node{{Keys: keys, IsLeaf: true}}}
	text := tree.Format()
	parsed, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		return nil, false, fmt.Errorf("parse errors %v in:\n%s", errs, text)
	}
	if len(parsed.Children) != 1 {
		return nil, false, fmt.Errorf("expected 1 top-level node, got %d in:\n%s",
			len(parsed.Children), text)
	}
	n := parsed.Children[0]
	return n.Keys, n.Inactive, nil
}

// TestQuoteKeyStructuralHazards6523 is the primary fail-on-revert assertion:
// a key that re-lexes as a comment or a deactivation marker must survive
// Format->Parse byte-identically, in every key position.
//
// On revert of the quoteKey change every subtest fails with an assertion (a
// wrong key list, a spurious Inactive flag, or a Parse error) — not a build
// break.
func TestQuoteKeyStructuralHazards6523(t *testing.T) {
	for _, hz := range structuralHazards {
		for _, shape := range hazardKeyShapes {
			t.Run(hz.name+"/"+shape.name, func(t *testing.T) {
				want := shape.keys(hz.value)
				got, inactive, err := formatParseKeys(want)
				if err != nil {
					t.Fatalf("value %q at %s position did not round-trip: %v",
						hz.value, shape.name, err)
				}
				if inactive {
					t.Fatalf("value %q at %s position was re-read as a deactivation "+
						"marker: Node.Inactive set on an active statement",
						hz.value, shape.name)
				}
				if len(got) != len(want) {
					t.Fatalf("value %q at %s position changed the key list: want %q, got %q",
						hz.value, shape.name, want, got)
				}
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("value %q at %s position corrupted key %d: want %q, got %q "+
							"(full key list %q)", hz.value, shape.name, i, want[i], got[i], got)
					}
				}
			})
		}
	}
}

// TestQuoteKeyHazardsAreQuoted6523 pins the predicate itself: each hazard must
// be emitted WITH quotes, so the token the parser sees on re-read is a
// TokenString. That token kind is what makes parseStatement treat `inactive:`
// as a literal rather than a marker (#4348), and what keeps the lexer from
// ever starting a comment inside the value.
func TestQuoteKeyHazardsAreQuoted6523(t *testing.T) {
	for _, hz := range structuralHazards {
		t.Run(hz.name, func(t *testing.T) {
			out := quoteKey(hz.value)
			if !strings.HasPrefix(out, `"`) || !strings.HasSuffix(out, `"`) {
				t.Fatalf("quoteKey(%q) = %s, want a quoted string — bare emission "+
					"re-parses as a comment or deactivation marker", hz.value, out)
			}
			tok := NewLexer(out).Next()
			if tok.Type != TokenString {
				t.Fatalf("quoteKey(%q) = %s re-lexed as %s, want a string token",
					hz.value, out, tok.Type)
			}
			if tok.Value != hz.value {
				t.Fatalf("quoteKey(%q) = %s re-lexed to %q", hz.value, out, tok.Value)
			}
		})
	}
}

// TestQuoteKeyNoOverReach6523 is the over-reach GUARD. It is deliberately not
// a fail-on-revert binder: it stays GREEN under a revert of bareKeySafe, which
// is exactly what an over-reach guard must do, because the pre-#6523 predicate
// also emitted all of these bare. What it catches is the opposite regression —
// a predicate tightened too far.
//
// Tightening must not start quoting values that were never at risk: doing so
// would churn every archived config and every HA config-sync diff, and would
// show up as spurious noise in `show | compare`.
//
// `/` in particular appears legitimately in prefixes (10.0.0.0/24), interface
// names (ge-0/0/0) and wildcards, so a predicate that rejected any value
// containing `/` would be wrong — and this test is what catches it.
func TestQuoteKeyNoOverReach6523(t *testing.T) {
	for _, v := range bareKeyValues {
		t.Run(v, func(t *testing.T) {
			if got := quoteKey(v); got != v {
				t.Fatalf("quoteKey(%q) = %q — value quoted unnecessarily; "+
					"over-quoting churns archives and HA config-sync diffs", v, got)
			}
			// Bare emission must still be correct, not merely unchanged.
			want := []string{"description", v, "trailer"}
			got, inactive, err := formatParseKeys(want)
			if err != nil {
				t.Fatalf("bare value %q did not round-trip: %v", v, err)
			}
			if inactive || len(got) != len(want) || got[1] != v {
				t.Fatalf("bare value %q corrupted: want %q (inactive=false), got %q (inactive=%v)",
					v, want, got, inactive)
			}
		})
	}
}

// TestQuoteKeySetFormHazards6523 covers the second serializer. `show
// configuration | display set` renders through joinQuotedKeys (ast_format.go)
// and is replayed through ParseSetVerb, which drives the same Lexer — so the
// COMMENT forms are re-read as comments there too. configstore LoadSet /
// LoadMerge replay this form.
//
// The `inactive:` subtest is a consistency case, not a binder: it stays GREEN
// under a revert of bareKeySafe. ParseSetVerb reads a structural verb from the
// FIRST token only (parser.go); a later `inactive:` identifier is appended to
// the path literally, so even the old bare output round-trips in set form. It
// is asserted anyway because both serializers must agree on what gets quoted —
// a text quoted in hierarchical output and bare in set output would make `show
// | compare` and `| display set` disagree about the same tree. The parse-level
// binder for `inactive:` is TestQuoteKeyStructuralHazards6523.
func TestQuoteKeySetFormHazards6523(t *testing.T) {
	for _, hz := range structuralHazards {
		t.Run(hz.name, func(t *testing.T) {
			want := []string{"description", hz.value, "trailer"}
			line := "set " + joinQuotedKeys(want)
			verb, path, err := ParseSetVerb(line)
			if err != nil {
				t.Fatalf("ParseSetVerb(%q) failed: %v", line, err)
			}
			if verb != "set" {
				t.Fatalf("ParseSetVerb(%q) verb = %q, want set", line, verb)
			}
			if len(path) != len(want) {
				t.Fatalf("set-form round-trip of %q changed the path: want %q, got %q",
					hz.value, want, path)
			}
			for i := range want {
				if path[i] != want[i] {
					t.Fatalf("set-form round-trip of %q corrupted element %d: want %q, got %q",
						hz.value, i, want[i], path[i])
				}
			}
		})
	}
}

// TestQuoteKeyZoneInterfaceHazard6523 is the concrete operator-visible end
// state from the issue: a security zone whose interface name is a
// comment-introducing text loses the interface entirely on the receiving side
// of an HA config sync / rollback reload. The zone still compiles — it just
// has nothing in it.
func TestQuoteKeyZoneInterfaceHazard6523(t *testing.T) {
	for _, hz := range structuralHazards {
		if strings.HasPrefix(hz.value, "/*") {
			// A block comment swallows the following statement too, which is a
			// different (also fixed) end state; the line-comment and marker
			// forms are the ones that silently empty the zone.
			continue
		}
		t.Run(hz.name, func(t *testing.T) {
			tree := &ConfigTree{Children: []*Node{
				{Keys: []string{"security"}, Children: []*Node{
					{Keys: []string{"zones"}, Children: []*Node{
						{Keys: []string{"security-zone", "trust"}, Children: []*Node{
							{Keys: []string{"interfaces", hz.value}, IsLeaf: true},
							{Keys: []string{"interfaces", "ge-0/0/1.0"}, IsLeaf: true},
						}},
					}},
				}},
			}}
			text := tree.Format()
			parsed, errs := NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("zone with interface %q failed to re-parse: %v\n%s", hz.value, errs, text)
			}
			zone := parsed.FindChild("security").
				FindChild("zones").
				FindChild("security-zone")
			if zone == nil {
				t.Fatalf("security-zone vanished after round-trip:\n%s", text)
			}
			ifaces := zone.FindChildren("interfaces")
			if len(ifaces) != 2 {
				t.Fatalf("zone lost interfaces: want 2, got %d (%v)\n%s",
					len(ifaces), ifaces, text)
			}
			if len(ifaces[0].Keys) != 2 || ifaces[0].Keys[1] != hz.value {
				t.Fatalf("interface %q corrupted to %q\n%s", hz.value, ifaces[0].Keys, text)
			}
		})
	}
}

// parserMarkerCandidates is the realistic vocabulary of WORD-shaped texts a
// future parser might promote to a structural marker: the Junos configuration
// verbs and edit directives, plus `inactive:`'s obvious siblings. Every entry
// is made entirely of isIdentChar bytes, so each one is emitted bare today.
var parserMarkerCandidates = []string{
	inactiveMarker,
	"active:", "replace:", "protect:", "unprotect:", "delete:", "rename:",
	"insert:", "annotate:", "deactivate:", "activate:", "apply:", "set:",
	"copy:", "edit:", "update:", "load:", "merge:", "override:",
}

// TestParserMarkerVocabulary6523 gates the one obligation bareKeySafe cannot
// derive from the lexer. A parser-level marker is handed back by the lexer as
// an ordinary identifier, so the predicate has to be TOLD about it
// (parserMarkers, parser.go) — and the sweep in
// TestQuoteKeyRelexProperty6523 cannot discover an unregistered one either,
// because its candidates are short and punctuation-shaped, not words.
//
// For each candidate word this asserts exactly one of two things holds:
//
//   - it IS registered in parserMarkers -> quoteKey must quote it, and the
//     quoted form must survive Format->Parse in every key position. (A binder:
//     the `inactive:` leg goes RED on a revert of bareKeySafe.)
//   - it is NOT registered -> the parser must still treat it as an ordinary
//     key, i.e. bare emission round-trips unchanged. (A guard: green today,
//     green under revert.)
//
// The point is the pairing. If a future parseStatement change gives one of
// these words structural meaning and nobody adds it to parserMarkers, the
// second leg goes RED — the word stops round-tripping as an ordinary key.
// That is the anti-rot device for the marker half of the predicate, and its
// scope is exactly this list: a marker outside this vocabulary is still
// caught only by whoever honours the parserMarkers contract.
func TestParserMarkerVocabulary6523(t *testing.T) {
	registered := make(map[string]bool, len(parserMarkers))
	for _, m := range parserMarkers {
		registered[m] = true
	}

	for _, cand := range parserMarkerCandidates {
		t.Run(cand, func(t *testing.T) {
			emitted := quoteKey(cand)
			if registered[cand] && emitted == cand {
				t.Fatalf("quoteKey(%q) = %s — a registered parser marker MUST be "+
					"quoted, or the next Parse reads it back as structure", cand, emitted)
			}
			if !registered[cand] && emitted != cand {
				t.Fatalf("quoteKey(%q) = %s — %q is not in parserMarkers, so quoting "+
					"it is over-reach", cand, emitted, cand)
			}
			// Whichever branch applied, the text must survive Format->Parse as
			// exactly this key. For an UNREGISTERED candidate this is the
			// gate: it goes RED if the parser starts treating the word
			// structurally without parserMarkers being extended.
			for _, shape := range hazardKeyShapes {
				want := shape.keys(cand)
				got, inactive, err := formatParseKeys(want)
				if err != nil {
					t.Fatalf("%q at %s position did not round-trip: %v", cand, shape.name, err)
				}
				if inactive {
					t.Fatalf("%q at %s position set Node.Inactive — the parser now treats "+
						"it as a marker; add it to parserMarkers (parser.go)", cand, shape.name)
				}
				if len(got) != len(want) || got[shape.idx] != cand {
					t.Fatalf("%q at %s position corrupted: want %q, got %q — if the parser "+
						"now treats it structurally, add it to parserMarkers (parser.go)",
						cand, shape.name, want, got)
				}
			}
		})
	}
}

// bareKeyValues are values that MUST keep being emitted WITHOUT quotes. The
// #6523 predicate tightened what may go bare, and over-quoting is its own
// regression: it would churn every archived config and every HA config-sync
// diff for values that were never at risk. Note that `/` is legitimate and
// common here (prefixes, interface names, wildcards) — a predicate that
// rejected any value containing `/` would be wrong, and this slice is what
// catches it.
var bareKeyValues = []string{
	// Structural keys.
	"security", "zones", "security-zone", "pre-shared-key", "ascii-text",
	// Prefixes and addresses — `/` mid-value.
	"10.0.0.0/24", "192.168.1.1", "2001:db8::1", "2001:db8::/32", "::/0",
	// Interface names — `/` and `-`.
	"ge-0/0/0", "ge-0/0/0.100", "reth0.50", "xe-1/0/0:3", "fxp0",
	// MAC addresses — all-`:`, the same byte that makes `inactive:` a marker.
	"00:11:22:33:44:55", "02:bf:72:00:00:01",
	// Application and policy names — the operand of the `permit junos-http`
	// widening this issue demonstrated.
	"junos-http", "junos-ssh", "my-app", "allow-trust-to-untrust",
	// Wildcards and group syntax — `*`, `<`, `>`.
	"*", "<*>", "<ge-*>", "any", "any-ipv4",
	// Times, ranges, numbers, percentages, equals — the rest of isIdentChar.
	"00:00:00", "1024-65535", "3600", "50%", "a=b", "a,b",
	// `/` and `*` present but NOT as a leading comment introducer. `/` alone
	// and `/x` are safe: the introducer needs `/` followed by `/` or `*`.
	"a//b", "a/*b", "a*/b", "*/", "*/x", "x//", "/x", "/", "/-", "/0",
	// Near-misses on the parser marker: only the exact text is a marker.
	"inactive", "inactive::", ":inactive:", "Inactive:", "inactive:x",
}

// relexAlphabet is every byte the lexer accepts inside a bare identifier —
// read from isIdentChar itself, so it tracks the lexer rather than a copy.
var relexAlphabet = func() []byte {
	var out []byte
	for c := 0; c < 256; c++ {
		if isIdentChar(byte(c)) {
			out = append(out, byte(c))
		}
	}
	return out
}()

// relexPunctuation is the non-alphanumeric part of the alphabet plus two
// filler bytes. Structural meaning only ever comes from punctuation, so this
// is the subset worth sweeping to greater depth.
var relexPunctuation = []byte{'%', '*', '+', ',', '-', '.', '/', ':', '<', '=', '>', '_', 'a', '0'}

// TestQuoteKeyRelexProperty6523 is the anti-rot device. Rather than trusting a
// fixed list of three known-bad texts, it sweeps the lexer's own ident
// alphabet and asserts the round-trip invariant for every candidate: whatever
// quoteKey emits must read back as exactly the key it was given.
//
// SCOPE — what this does and does not catch. A comment syntax or an ident-char
// addition is punctuation-shaped and short, so the sweep below sees it the
// moment it lands and goes RED. A WORD-shaped parser marker (a future
// `replace:` / `protect:`) is NOT in the swept space and would not be caught
// here; that obligation lives on parserMarkers (parser.go) and is gated
// separately by TestParserMarkerVocabulary6523. The parserMarkers leg below
// only asserts that the markers already registered survive — it cannot
// discover an unregistered one.
//
// Coverage, exactly:
//
//   - every 1-byte and every 2-byte text over the full ident alphabet — i.e.
//     every possible two-byte introducer, exhaustively;
//   - every 2-byte alphabet prefix followed by each of four tails (`abc`,
//     `*/`, `x*/y`, `inactive:`), for introducers that need trailing text to
//     bite. Exhaustive in the 2-byte prefix, NOT in the resulting length;
//   - every 3-byte text over the 14-byte punctuation subset (structural
//     meaning only ever comes from punctuation), plus each punctuation pair
//     embedded mid-value (`abc??def`) and at the tail (`abcd??`), which must
//     NOT trigger;
//   - every registered parserMarkers entry at full length.
//
// There is no exhaustive 3-byte sweep over the FULL alphabet and no 5-byte
// punctuation sweep. Each candidate is checked in all three key positions;
// the total round-trip count is logged.
func TestQuoteKeyRelexProperty6523(t *testing.T) {
	checked := 0
	check := func(t *testing.T, v string) {
		for _, shape := range hazardKeyShapes {
			want := shape.keys(v)
			got, inactive, err := formatParseKeys(want)
			checked++
			if err != nil {
				t.Errorf("candidate %q at %s position did not round-trip: %v",
					v, shape.name, err)
				return
			}
			if inactive {
				t.Errorf("candidate %q at %s position set Node.Inactive", v, shape.name)
				return
			}
			if len(got) != len(want) || got[shape.idx] != v {
				t.Errorf("candidate %q at %s position corrupted: want %q, got %q",
					v, shape.name, want, got)
				return
			}
		}
	}

	buf := make([]byte, 3)
	// Every 1- and 2-byte text, and every 2-byte prefix with a tail.
	tails := []string{"", "abc", "*/", "x*/y", inactiveMarker}
	for _, c0 := range relexAlphabet {
		buf[0] = c0
		check(t, string(buf[:1]))
		for _, c1 := range relexAlphabet {
			buf[1] = c1
			for _, tl := range tails {
				check(t, string(buf[:2])+tl)
			}
		}
	}
	// Every 3-byte punctuation text, plus the same embedded mid-value and at
	// the tail of a longer value (interior sequences must NOT trigger).
	for _, c0 := range relexPunctuation {
		buf[0] = c0
		for _, c1 := range relexPunctuation {
			buf[1] = c1
			check(t, "abc"+string(buf[:2])+"def")
			check(t, "abcd"+string(buf[:2]))
			for _, c2 := range relexPunctuation {
				buf[2] = c2
				check(t, string(buf[:3]))
			}
		}
	}
	// Every registered parser marker at full length. The sweep's own candidates
	// never reach `inactive:` unprefixed (the marker only appears there as a
	// TAIL after two alphabet bytes), so without this leg a marker added to
	// parserMarkers would be swept only in prefixed form.
	for _, m := range parserMarkers {
		check(t, m)
	}
	t.Logf("swept %d round-trips over %d ident bytes and %d parser markers",
		checked, len(relexAlphabet), len(parserMarkers))
}

// TestBareKeySafeAgreesWithLexer6523 asserts two things about the predicate:
// that it agrees with quoteKey (accepting a text iff quoteKey emits it bare),
// and that whatever quoteKey emitted re-LEXES back to exactly that text. This
// is what keeps a future "optimization" from widening the predicate without
// widening what actually survives a re-lex.
//
// The assertion is LEXER-level, which is why this test is not named for a
// round-trip: its `inactive:` case stays GREEN under a revert of bareKeySafe,
// because bare `inactive:` lexes to an identifier equal to itself — the marker
// bites at the PARSER, one layer up, where this test does not look.
// Format→Parse coverage for the same corpus already exists and is where that
// case binds: TestQuoteKeyStructuralHazards6523 (the hazards) and
// TestQuoteKeyNoOverReach6523 (bareKeyValues) both run formatParseKeys over
// it, so a parse leg here would duplicate rather than add.
func TestBareKeySafeAgreesWithLexer6523(t *testing.T) {
	cases := []string{}
	for _, hz := range structuralHazards {
		cases = append(cases, hz.value)
	}
	cases = append(cases, bareKeyValues...)
	cases = append(cases, "", " ", "a b", "{", "}", ";", `"`, `a"b`, "#x", "a#b",
		"[a]:1", "[2001:db8::1]:51820", "${node}", "10.0.0.0/24")

	for _, v := range cases {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			emitted := quoteKey(v)
			bare := bareKeySafe(v)
			if bare != (emitted == v) {
				t.Fatalf("bareKeySafe(%q)=%v disagrees with quoteKey(%q)=%q", v, bare, v, emitted)
			}
			// Whatever was emitted must re-lex to exactly this value.
			l := NewLexer(emitted)
			tok := l.Next()
			if tok.Type == TokenError {
				t.Fatalf("quoteKey(%q)=%s lexed to error %q", v, emitted, tok.Value)
			}
			if tok.Value != v {
				t.Fatalf("quoteKey(%q)=%s lexed back to %q", v, emitted, tok.Value)
			}
			if next := l.Next(); next.Type != TokenEOF {
				t.Fatalf("quoteKey(%q)=%s produced a trailing %s token", v, emitted, next.Type)
			}
		})
	}
}

// TestQuoteKeyBareEmissionIsZeroAlloc6523 keeps the predicate off the heap.
// quoteKey runs once per key on every Format, and Format serializes the whole
// candidate configuration on each commit, archive, rollback slot write and HA
// config sync. Asking the real lexer is only affordable because the Lexer does
// not escape; this fails if a future edit makes it allocate.
//
// This is a PERFORMANCE guard, not a correctness binder: it stays GREEN under
// a revert of bareKeySafe to the old identifier scan (that predicate does not
// allocate either).
//
// It is also escape-analysis dependent by construction — the zero comes from
// the Lexer being stack-allocated. Under `-gcflags=all=-l` (inlining off) it
// reports 41 allocs, one NewLexer per bareKeyValues entry, and FAILS. That is
// the disabled optimizer, not a regression: the default build and `-race` both
// report 0, and neither CI nor `make test` passes `-l`.
func TestQuoteKeyBareEmissionIsZeroAlloc6523(t *testing.T) {
	avg := testing.AllocsPerRun(1000, func() {
		for _, v := range bareKeyValues {
			if !bareKeySafe(v) {
				t.Fatalf("bareKeySafe(%q) = false", v)
			}
		}
	})
	if avg != 0 {
		t.Fatalf("bareKeySafe allocates %.1f times per call batch, want 0", avg)
	}
}
