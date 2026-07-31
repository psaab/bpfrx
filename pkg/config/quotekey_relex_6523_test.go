package config

// Structural round-trip tests for quoteKey's bare-emission predicate (#6523).
//
// quoteKey used to emit a key bare whenever every byte satisfied isIdentChar.
// isIdentChar is the LEXER'S ident set — it admits `/`, `*` and `:` — and is
// not the set of texts that survive a serialize/re-parse cycle. Three
// ident-char-only texts are re-interpreted STRUCTURALLY on the way back in,
// with no parse error and no warning:
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
// Format->ParseSetVerb path — plus an over-reach guard (ordinary values must
// keep emitting bare) and a brute-force property sweep that re-derives the
// hazard set from the real lexer so a comment syntax added later cannot
// quietly reopen the hole.

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

// TestQuoteKeyNoOverReach6523 is the over-reach guard. Tightening the
// predicate must not start quoting values that were never at risk: doing so
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
// same three texts are re-read as comments or markers there too. configstore
// LoadSet / LoadMerge replay this form.
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
// A comment syntax, an ident-char addition, or a new parser marker introduced
// later reopens this hole the moment it lands, and this sweep goes RED then —
// not when someone remembers to extend a denylist.
//
// Coverage: all 1- and 2-byte texts over the full alphabet (every possible
// two-byte introducer), every 2-byte prefix followed by a tail (introducers
// that need trailing text to bite), and all 3-byte texts over the punctuation
// subset. Each candidate is checked in all three key positions.
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
	t.Logf("swept %d round-trips over %d ident bytes", checked, len(relexAlphabet))
}

// TestBareKeySafeAgreesWithRoundTrip6523 asserts the predicate is not merely
// sufficient but honest: every text bareKeySafe accepts must round-trip when
// emitted bare, and every text it rejects must round-trip when emitted quoted.
// This is what keeps a future "optimization" from widening the predicate
// without widening what actually survives a re-parse.
func TestBareKeySafeAgreesWithRoundTrip6523(t *testing.T) {
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
