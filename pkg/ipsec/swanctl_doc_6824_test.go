package ipsec

import (
	"fmt"
	"sort"
	"strings"
)

// swanctl_doc_6824_test.go -- #6824.
//
// The render tests asserted on generated swanctl configuration with
// strings.Contains. A containment assertion cannot distinguish valid output from
// output that merely contains the right substrings in the WRONG STRUCTURE: a
// `remote_addrs = 203.0.113.1` line satisfies it whether it sits under the
// connection it belongs to, under a sibling connection, or outside every
// section entirely.
//
// # What this file claims, and what it does NOT
//
// strongSwan is not installed here (`which swanctl charon ipsec` finds nothing),
// so the rendered document cannot be checked against the real parser. This file
// therefore does NOT implement a swanctl grammar, and nothing in it should be
// read as one -- that would be a proxy for a grammar with nothing to check it
// against, which is the containment defect again with more code.
//
// What it asserts instead are properties of OUR OWN RENDERER, which we control
// and can state exactly: brace nesting balances, every setting sits at a known
// path, one key per line, no duplicate key within a section, no duplicate
// section within a parent. One thing they are NOT: byte-exact. Both the line
// and the two halves of a setting are trimmed, so trailing whitespace on a
// value is normalised away and an equality assertion here does not reject it,
// where a needle ending in "\n" did. That is a deliberate trade -- the old
// needles were pinning the renderer's whitespace, not its structure -- but it
// is a real difference and not a strengthening.
//
// Those are facts about generateConfig, not claims
// about strongSwan. Conformance to the real parser is a separate and stronger
// property that needs the package installed, and remains worth doing.

// swanctlTB is the narrow slice of *testing.T this checker uses.
//
// It exists so the checker's OWN tests can drive it with a capturing fake and
// assert that it rejects a malformed document -- without a deliberately-failing
// sub-test appearing in the suite output, which would make a healthy run
// indistinguishable from a broken one. testing.TB cannot be implemented outside
// the testing package (it has an unexported method), hence a local interface.
//
// *testing.T satisfies this by construction.
type swanctlTB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// swanctlNode is one parsed section of a rendered document.
type swanctlNode struct {
	name     string
	settings map[string][]string // key -> values; a slice so duplicates stay visible
	children map[string]*swanctlNode
	order    []string // child insertion order, for stable messages
}

// parseSwanctlDoc parses a rendered document into a section tree.
//
// Two line shapes are ambiguous, and the first cut of this parser got both
// wrong in a way that did NOT fail loudly, contrary to what its comment claimed:
//
//   - a SETTING whose value ends in an open brace (`local_ts = 10.0.0.0/24 {`)
//     read as a section opener, and
//   - a SECTION whose name begins '#' (a connection named "#b") skipped as a
//     comment.
//
// Either alone unbalances the document and the end-of-parse check fires. TOGETHER
// they CANCEL: the phantom open from the first is closed by the real brace of the
// second, the stack balances, and the tree silently lacks a section the renderer
// emitted -- so hasNoChild("#b") passes on a document that contains it. Both
// values are reachable from authored quoted tokens (pkg/config/schema_security.go,
// copied through compiler_ipsec.go, rendered at policy.go); sanitizeSwanctlValue
// strips control bytes, not braces or hashes.
//
// Both are now classified on content rather than on a single suffix: a section
// opener carries no '=', and a comment is neither a section opener nor a setting.
func parseSwanctlDoc(t swanctlTB, doc string) *swanctlNode {
	t.Helper()
	root := &swanctlNode{name: "<root>", settings: map[string][]string{}, children: map[string]*swanctlNode{}}
	stack := []*swanctlNode{root}

	for i, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// AMBIGUOUS SHAPES ARE REFUSED, NOT CLASSIFIED.
		//
		// Two line shapes cannot be told apart from the line alone: one
		// starting '#' and ending '{' (a comment, or a section whose name
		// begins '#'), and one containing '=' and ending '{' (a setting whose
		// value ends in a brace, or a section whose name contains '=').
		//
		// The first cut of this parser guessed at each, and the guesses
		// CANCELLED: a fake open from one was closed by a real brace from the
		// other, the stack balanced, and the tree silently lacked a section the
		// renderer emitted. Fixing the guesses only moved the pair -- reversing
		// which half is misread reproduces the cancellation exactly.
		//
		// Neither shape is reachable from this renderer (generateConfig emits
		// one fixed header comment and section names come from config object
		// names). So the honest response is to fail on them rather than to pick
		// an interpretation: a parser that guesses can cancel its guesses, and a
		// parser that refuses cannot.
		if strings.HasSuffix(line, "{") && strings.HasPrefix(line, "#") {
			t.Fatalf("line %d: %q both opens a section and looks like a comment. This "+
				"parser refuses ambiguous shapes rather than guessing -- two guesses "+
				"can cancel and leave a balanced document with a wrong tree:\n%s",
				i+1, line, doc)
		}
		if strings.HasSuffix(line, "{") && strings.Contains(line, "=") {
			t.Fatalf("line %d: %q both opens a section and looks like a setting. Same "+
				"refusal as above; see the doc comment:\n%s", i+1, line, doc)
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		cur := stack[len(stack)-1]

		switch {
		case line == "}":
			if len(stack) == 1 {
				t.Fatalf("line %d: closing brace with no open section:\n%s", i+1, doc)
			}
			stack = stack[:len(stack)-1]

		case strings.HasSuffix(line, "{"):
			name := strings.TrimSpace(strings.TrimSuffix(line, "{"))
			if name == "" {
				t.Fatalf("line %d: section opened with no name:\n%s", i+1, doc)
			}
			if _, dup := cur.children[name]; dup {
				t.Errorf("line %d: section %q declared twice under %q -- one of them "+
					"wins and the other's settings are silently lost", i+1, name, cur.name)
			}
			child := &swanctlNode{name: name, settings: map[string][]string{}, children: map[string]*swanctlNode{}}
			cur.children[name] = child
			cur.order = append(cur.order, name)
			stack = append(stack, child)

		case strings.Contains(line, "="):
			k, v, _ := strings.Cut(line, "=")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "" {
				t.Fatalf("line %d: setting with an empty key:\n%s", i+1, doc)
			}
			if _, dup := cur.settings[k]; dup {
				// Stated as a parse invariant in this file's doc comment, so it
				// must fire HERE. Detecting it only when setting() happens to
				// be called leaves a path-only test green on a document with a
				// duplicated, unqueried key -- which is the containment defect
				// with extra steps.
				t.Errorf("line %d: section %q declares %q more than once (%v, now %q); "+
					"which one applies is left to the parser", i+1, cur.name, k,
					cur.settings[k], v)
			}
			cur.settings[k] = append(cur.settings[k], v)

		default:
			t.Fatalf("line %d: unrecognised line %q -- the renderer emitted a shape no "+
				"structural test describes. Extend this parser rather than letting it "+
				"pass, or the check degrades to containment:\n%s", i+1, line, doc)
		}
	}
	if len(stack) != 1 {
		var open []string
		for _, n := range stack[1:] {
			open = append(open, n.name)
		}
		t.Fatalf("document ends with %d section(s) still open: %s\n%s",
			len(stack)-1, strings.Join(open, " > "), doc)
	}
	return root
}

// at walks a path of section names, failing with the deepest section it DID
// reach -- so a misnested setting reports where the tree actually put it, not
// merely that the path was absent.
func (n *swanctlNode) at(t swanctlTB, path ...string) *swanctlNode {
	t.Helper()
	cur := n
	for i, p := range path {
		next, ok := cur.children[p]
		if !ok {
			t.Fatalf("no section %q under %q (reached %v of %v); sections there: %v\n%s",
				p, cur.name, path[:i], path, cur.childNames(), n)
		}
		cur = next
	}
	return cur
}

func (n *swanctlNode) childNames() []string {
	out := append([]string(nil), n.order...)
	sort.Strings(out)
	return out
}

// setting returns the single value of key in THIS section, failing if it is
// absent or DUPLICATED. The duplicate case is the one containment cannot see at
// all: two `remote_addrs` lines in one section satisfy any Contains check while
// leaving which one applies to the parser.
func (n *swanctlNode) setting(t swanctlTB, key string) string {
	t.Helper()
	vals, ok := n.settings[key]
	if !ok {
		t.Fatalf("section %q has no setting %q; keys present: %v", n.name, key, n.settingNames())
	}
	if len(vals) != 1 {
		t.Fatalf("section %q declares %q %d times (%v); which one applies is left to "+
			"the parser", n.name, key, len(vals), vals)
	}
	return vals[0]
}

// hasNoSetting asserts a key is absent HERE -- how a test says "this value must
// not have landed in the wrong section".
func (n *swanctlNode) hasNoSetting(t swanctlTB, key string) {
	t.Helper()
	if vals, ok := n.settings[key]; ok {
		t.Errorf("section %q unexpectedly declares %q = %v", n.name, key, vals)
	}
}

func (n *swanctlNode) settingNames() []string {
	out := make([]string, 0, len(n.settings))
	for k := range n.settings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String renders the tree back as an indented outline, so a failure shows
// STRUCTURE rather than the raw document a containment failure would dump.
func (n *swanctlNode) String() string {
	var b strings.Builder
	var walk func(*swanctlNode, int)
	walk = func(node *swanctlNode, depth int) {
		pad := strings.Repeat("  ", depth)
		for _, k := range node.settingNames() {
			fmt.Fprintf(&b, "%s%s = %v\n", pad, k, node.settings[k])
		}
		for _, name := range node.order {
			fmt.Fprintf(&b, "%s%s {\n", pad, name)
			walk(node.children[name], depth+1)
			fmt.Fprintf(&b, "%s}\n", pad)
		}
	}
	walk(n, 0)
	return b.String()
}

// hasNoChild asserts a section is absent HERE -- how a test says "this
// connection must not have been rendered at all", replacing a
// `strings.Contains(out, "tun-bad {")` needle that depends on brace placement
// and would also match the string appearing inside a value.
func (n *swanctlNode) hasNoChild(t swanctlTB, name string) {
	t.Helper()
	if c, ok := n.children[name]; ok {
		t.Errorf("section %q unexpectedly contains a %q section:\n%s", n.name, name, c)
	}
}

// requireSetting is the common conversion of `!strings.Contains(got, "k = v")`:
// it names the PATH the setting must sit at, so the same rendered value under a
// different section is a failure rather than a pass.
func (n *swanctlNode) requireSetting(t swanctlTB, key, want string) {
	t.Helper()
	if got := n.setting(t, key); got != want {
		t.Errorf("%s.%s = %q, want %q", n.name, key, got, want)
	}
}

// settingMembers splits a comma-joined setting value (swanctl's proposal
// lists) into its members.
//
// It exists because containment on a member token is doubly unsound: `3des-sha1`
// is a substring of `3des-sha1-modp1024`, so a Phase-2 assertion written as
// Contains(doc, "3des-sha1") is satisfied by the PHASE-1 line and passes even if
// esp_proposals is missing entirely. Membership in the split value of a named
// setting cannot be satisfied by a different line or a longer token.
func (n *swanctlNode) settingMembers(t swanctlTB, key string) []string {
	t.Helper()
	raw := n.setting(t, key)
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// requireMembers asserts every want is a member of the comma-joined value of
// key -- an exact token match, not a substring of a longer one.
func (n *swanctlNode) requireMembers(t swanctlTB, key string, want ...string) {
	t.Helper()
	got := n.settingMembers(t, key)
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("%s.%s = %v, missing member %q", n.name, key, got, w)
		}
	}
}

// hasNoSettingAnywhere asserts no section in the whole tree declares key.
//
// This is how a test says "an injected directive never became a live setting",
// and it is strictly stronger than scanning for a line that trims to the exact
// injected text: it fires whatever VALUE the injection carried, and at whatever
// nesting depth the render placed it.
func (n *swanctlNode) hasNoSettingAnywhere(t swanctlTB, key string) {
	t.Helper()
	var walk func(*swanctlNode, string)
	walk = func(node *swanctlNode, path string) {
		if vals, ok := node.settings[key]; ok {
			t.Errorf("setting %q became live at %s = %v; nothing in this fixture "+
				"renders that key, so it can only have been injected", key, path, vals)
		}
		for _, name := range node.order {
			walk(node.children[name], path+"."+name)
		}
	}
	walk(n, n.name)
}

// hasNoSettingValuePrefixAnywhere asserts no section declares key with a value
// STARTING with forbidden.
//
// This is the faithful structural form of a deleted
// `strings.Contains(doc, "<key> = <forbidden>")` needle. Exact equality is NOT
// faithful: the renderer emits comma-joined lists, so
// `esp_proposals = default,aes256` contains the old needle and FAILED it, while
// an equality check passes. Five restorations were written as equality and were
// all weaker than the checks they replaced for exactly that reason.
func (n *swanctlNode) hasNoSettingValuePrefixAnywhere(t swanctlTB, key, forbidden string) {
	t.Helper()
	var walk func(*swanctlNode, string)
	walk = func(node *swanctlNode, path string) {
		for _, v := range node.settings[key] {
			if strings.HasPrefix(v, forbidden) {
				t.Errorf("%s = %q at %s, which begins with the forbidden %q. The needle "+
					"this replaced matched the rendered LINE, so a comma list starting "+
					"with the forbidden value failed it too.", key, v, path, forbidden)
			}
		}
		for _, name := range node.order {
			walk(node.children[name], path+"."+name)
		}
	}
	walk(n, n.name)
}

// hasNoValueSubstringAnywhere asserts no setting value anywhere CONTAINS substr.
//
// The faithful form of a deleted bare-token needle -- one that named no key, so
// it matched the token anywhere in the document, including as a member of a
// comma list. `Contains(doc, "sha256-modp2048")` is that shape: an equality
// check on one key misses `esp_proposals = aes128-sha256-modp2048` entirely.
func (n *swanctlNode) hasNoValueSubstringAnywhere(t swanctlTB, substr string) {
	t.Helper()
	var walk func(*swanctlNode, string)
	walk = func(node *swanctlNode, path string) {
		for _, k := range node.settingNames() {
			for _, v := range node.settings[k] {
				if strings.Contains(v, substr) {
					t.Errorf("%s.%s = %q contains the forbidden %q; the needle this "+
						"replaced named no key, so it matched the token ANYWHERE "+
						"including inside a comma list", path, k, v, substr)
				}
			}
		}
		for _, name := range node.order {
			walk(node.children[name], path+"."+name)
		}
	}
	walk(n, n.name)
}
