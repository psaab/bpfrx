package config

import "strings"

// Group-key wildcards — #9423.
//
// A Junos configuration group can key a stanza on a WILDCARD instead of an
// instance name, so one template covers every matching instance:
//
//	groups { G { interfaces { <ge-*> { description UPLINK; } } } }
//
// Before this, only the bare `<*>` was recognised. `keysContainWildcard`
// compared the token for exact equality with `"<*>"`, so `<ge-*>` was not a
// wildcard at all — it fell through to the ordinary container path in
// `mergeNodes`, found no destination with that literal name, and was ADOPTED
// AS A NEW INSTANCE. The compiled config then carried an interface literally
// named `<ge-*>`:
//
//	pattern <*>        interfaces=[ge-0/0/0]           ge-0/0/0 description="FROM-GROUP"
//	pattern <ge-*>     interfaces=[ge-0/0/0 <ge-*>]    ge-0/0/0 description=""
//	pattern <*-0/0/0>  interfaces=[ge-0/0/0 <*-0/0/0>] ge-0/0/0 description=""
//
// So the template did not merely fail to apply — it manufactured a config
// object the daemon then reconciles. xpfd owns every interface on the box and
// reconciles the configured set against the kernel, and a zone or a policy can
// reference the phantom by name.
//
// # Which channel refused it, and which did not
//
// The channels do not agree, and the INTERFACE example is the one that hides
// the defect. Measured on the base revision:
//
//	slot                          CompileConfig   configstore.CheckText (operator commit)
//	interfaces <ge-*>             ACCEPT+phantom  REJECT
//	security-zone <tr*>           ACCEPT+phantom  ACCEPT + phantom zone `<tr*>`
//
// `CheckText` catches the interface case only because the typed interface-name
// validator rejects `<` as a character in an interface NAME — an incidental
// downstream refusal, not the group matcher doing its job. A slot whose
// instance-name has no such validator (`security-zone` is one) carries the
// phantom all the way through the operator commit path with zero warnings.
// A probe on the interfaces slot alone would have concluded the commit path was
// safe.
//
// # The remedy, and why it removes the phantom by construction
//
// `keysContainWildcard` now recognises any `<...>`-shaped token, so EVERY
// wildcard-shaped group key takes the wildcard branch in `mergeNodes` — the
// branch that merges into each matching destination and never appends. A
// pattern that matches nothing therefore applies nothing, which is what Junos
// does, instead of inventing an instance named after the pattern.
//
// `keysMatchWildcard` then glob-matches the pattern rather than accepting only
// the universal token, so `<ge-*>` reaches the interfaces it names.
//
// Supported metacharacter: `*`, matching any run of characters INCLUDING `/` —
// which `path.Match` would not do, and every interface name in this product
// contains `/`. `?` is not supported because it cannot be authored: the lexer
// rejects it (`unexpected character: ?`), so there is no spelling to support.
// A `[...]` character class survives lexing as part of the token and is matched
// literally; it therefore selects nothing rather than mis-selecting, and no
// phantom is created either way.

// groupKeyPattern returns the wildcard pattern inside a `<...>` group key.
//
// The shape test is deliberately structural (leading `<`, trailing `>`, at
// least one character between) rather than "contains a `*`": the phantom-
// instance outcome this exists to stop comes from a key that LOOKS like a
// wildcard and is not treated as one, so recognition has to be by shape. A key
// with no metacharacter (`<foo>`) is then a pattern matching exactly `foo`,
// which is what Junos means by it — and, either way, it can no longer be
// adopted under its bracketed spelling.
func groupKeyPattern(key string) (string, bool) {
	if len(key) < 3 || !strings.HasPrefix(key, "<") || !strings.HasSuffix(key, ">") {
		return "", false
	}
	return key[1 : len(key)-1], true
}

// globMatch reports whether s matches pattern, where `*` matches any run of
// characters including `/`. Iterative with backtracking, so it is linear in the
// common case and cannot recurse on a pathological pattern.
func globMatch(pattern, s string) bool {
	var (
		p, i       int
		star       = -1
		startMatch int
	)
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star = p
			startMatch = i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			// Backtrack: let the last `*` absorb one more character.
			p = star + 1
			startMatch++
			i = startMatch
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
