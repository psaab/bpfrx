package config

import (
	"strconv"
	"strings"
	"testing"
)

// sentinel6625 is the secret every case plants. One distinctive token so the
// assertion can be "the error does not contain this" — the only shape a partial
// redaction cannot satisfy by looking tidy.
const sentinel6625 = "MY-CLUSTER-PSK-SENTINEL"

// leafChain6625 builds a nested single-key chain ending in a leaf whose LAST
// key is the value. This is the AST shape the validators walk; ParseSetCommand
// cannot be used because the lexer treats a tab as whitespace and strips the
// very byte under test.
func leafChain6625(keys ...string) []*Node {
	var head, cur *Node
	for _, k := range keys {
		n := &Node{Keys: []string{k}}
		if head == nil {
			head = n
		} else {
			cur.Children = []*Node{n}
		}
		cur = n
	}
	cur.IsLeaf = true
	return []*Node{head}
}

// secretLeaf6625 is one secret leaf shape, with the sentinel carrying a leading
// tab — the realistic trigger: a value pasted from a password manager, a
// terminal or a file.
func secretLeaf6625(path ...string) []string {
	return append(append([]string(nil), path...), "\t"+sentinel6625)
}

// secretLeafCases6625 covers every disambiguation class in secretIndices, not
// just one keyword: distinctive keywords, the format-qualifier case, and all
// three CONTEXT-gated generic keywords. A single-case test would pass while the
// generic keywords — the ones whose secrecy depends on ancestor context — kept
// leaking.
func secretLeafCases6625() map[string][]string {
	return map[string][]string{
		"authentication-key (distinctive keyword)": secretLeaf6625("chassis", "cluster", "authentication-key"),
		"pre-shared-key with a format qualifier":   secretLeaf6625("security", "ike", "policy", "p1", "pre-shared-key", "ascii-text"),
		"tsig-secret":                              secretLeaf6625("system", "services", "dynamic-dns", "provider", "p1", "tsig-secret"),
		"private-key (wireguard)":                  secretLeaf6625("interfaces", "wg0", "unit", "0", "private-key"),
		"password under dynamic-dns (context)":     secretLeaf6625("system", "services", "dynamic-dns", "provider", "p1", "password"),
		"key under authentication md5 (context)":   secretLeaf6625("protocols", "ospf", "area", "0", "interface", "ge-0/0/0", "authentication", "md5", "1", "key"),
		"community under snmp (context)":           secretLeaf6625("system", "snmp", "community"),
	}
}

// TestSecretLeafValueNeverRendered_6625 is the fail-on-revert gate for the
// STRICT commit path.
//
// The #1798 control-character validator rendered the offending leaf's VALUE
// into its error — and for a Secret leaf that published the key to commit
// output, the daemon log and the audit journal at once. It appeared TWICE: once
// quoted as the value, and once as a component of the rendered path, because
// for `authentication-key <PSK>` the secret IS part of the path that names it.
//
// The trigger is narrow but entirely routine: a PSK pasted with a leading or
// trailing tab or CR. The operator does the ordinary thing and the refusal
// message discloses the key they were trying to set.
func TestSecretLeafValueNeverRendered_6625(t *testing.T) {
	for name, keys := range secretLeafCases6625() {
		t.Run(name, func(t *testing.T) {
			err := validateNodesControlChars(leafChain6625(keys...), "")
			if err == nil {
				t.Fatal("expected the control character to be rejected; if it is now ACCEPTED " +
					"this case no longer exercises an error render and must be re-chosen")
			}
			if strings.Contains(err.Error(), sentinel6625) {
				t.Fatalf("the secret reached the error string:\n%v", err)
			}
			// The diagnostic must still be USABLE: an operator has to be able to
			// find the byte without being shown the value.
			if !strings.Contains(err.Error(), "0x09") {
				t.Fatalf("the error must name the offending byte class so the input can be "+
					"corrected without echoing it, got:\n%v", err)
			}
		})
	}
}

// TestSecretLeafValueNeverRenderedLenient_6625 is the same gate for the LENIENT
// twin, and it is not redundant.
//
// `sanitizeNodesControlChars` returns a path per modified node and the caller
// logs it. That path is built from `n.Keys`, which for a secret leaf INCLUDES
// the secret. Sanitizing the control characters made it printable, not safe.
//
// This surface is worse in one respect: the strict validator fires once, on the
// operator's commit, while this one runs on `Store.Load` at BOOT and on
// `Store.SyncApply` for every HA peer-sync — so an already-persisted key with a
// stray tab was re-published to the log on every single boot. Fixing only the
// strict side is the "one of several symmetric surfaces" failure this project
// keeps hitting.
func TestSecretLeafValueNeverRenderedLenient_6625(t *testing.T) {
	for name, keys := range secretLeafCases6625() {
		t.Run(name, func(t *testing.T) {
			tree := &ConfigTree{Children: leafChain6625(keys...)}
			got := SanitizeTreeControlChars(tree)
			if len(got) == 0 {
				t.Fatal("expected a sanitize warning; if nothing was sanitized this case no " +
					"longer exercises a path render and must be re-chosen")
			}
			for _, p := range got {
				if strings.Contains(p, sentinel6625) {
					t.Fatalf("the secret reached a logged sanitize path: %q", p)
				}
			}
		})
	}
}

// TestNonSecretLeafStillRendersValue_6625 is the over-reach guard the issue
// asks for by name. A validator that stopped echoing EVERY value would satisfy
// both tests above completely, and would destroy a genuinely useful diagnostic:
// for a description or a hostname the offending value is exactly what the
// operator needs to see.
func TestNonSecretLeafStillRendersValue_6625(t *testing.T) {
	const plain = "PLAIN-DESCRIPTION-VALUE"
	err := validateNodesControlChars(
		leafChain6625("interfaces", "ge-0/0/0", "description", "\t"+plain), "")
	if err == nil {
		t.Fatal("expected the control character to be rejected")
	}
	// Assert on the QUOTED form, not a bare substring. The rendered PATH also
	// contains the value (sanitized, tab -> space), so `Contains(plain)` is
	// satisfied whether or not the value branch ran — it passed against a
	// mutation that withheld EVERY value. Only the %q value render produces the
	// escaped, quoted spelling.
	if want := strconv.Quote("\t" + plain); !strings.Contains(err.Error(), want) {
		t.Fatalf("a NON-secret leaf must still render its value as %s — blanket suppression "+
			"is not a fix, it is a lost diagnostic. got:\n%v", want, err)
	}

	tree := &ConfigTree{Children: leafChain6625("interfaces", "ge-0/0/0", "description", "\t"+plain)}
	got := SanitizeTreeControlChars(tree)
	if len(got) != 1 || !strings.Contains(got[0], plain) {
		t.Fatalf("the lenient path must still name a NON-secret value: %q", got)
	}
}

// TestSecretRedactionUsesTheSharedSecretSet_6625 pins that the validator's
// notion of "secret" is the SAME one the raw-AST display paths use.
//
// A validator that carried its own list would drift from the renderer the
// moment either gained a keyword, and the drift would be silent in the
// direction that matters — a leaf redacted in `show configuration` but echoed
// by a commit error.
func TestSecretRedactionUsesTheSharedSecretSet_6625(t *testing.T) {
	for name, keys := range secretLeafCases6625() {
		t.Run(name, func(t *testing.T) {
			// The shared resolver must mark the LAST token (the value) secret.
			if !isSecretIndex(keys, len(keys)-1) {
				t.Fatalf("secretIndices does not mark the value token of %v as secret; the "+
					"validator and the display redactor disagree about this leaf", keys)
			}
			if got := renderNodePath(keys); strings.Contains(got, sentinel6625) {
				t.Fatalf("renderNodePath leaked the secret: %q", got)
			}
		})
	}
}

// TestControlCharDetail_6625 covers the detail renderer directly: it must name
// the byte and offset and carry no input.
func TestControlCharDetail_6625(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\tSECRET", "0x09 at offset 0"},
		{"SECRET\n", "0x0a at offset 6"},
		{"SEC\x7fRET", "0x7f at offset 3"},
		{"clean", "none"},
	} {
		if got := controlCharDetail(tc.in); got != tc.want {
			t.Fatalf("controlCharDetail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
