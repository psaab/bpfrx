package config

import (
	"strings"
	"testing"
)

// #1798 regression tests: a free-text config value carrying an embedded
// newline (the lexer maps the "\n" escape inside a quoted string to a
// real newline) must be rejected by the strict commit-path compile and
// sanitized-with-warning by the lenient load/peer-sync compile.

// newlineDescTree builds a tree via the flat-set path (ParseSetCommand +
// SetPath, per the project testing rule) whose interface description
// contains a real newline.
func newlineDescTree(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(`set interfaces ge-0-0-0 description "lan\nDHCP=ipv4"`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	// The lexer must have produced a REAL newline in the value — that
	// is the injection primitive under test.
	if want := "lan\nDHCP=ipv4"; path[len(path)-1] != want {
		t.Fatalf("lexer escape mapping changed: got %q, want %q", path[len(path)-1], want)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

// findDescriptionValue walks the tree and returns the first key
// containing the injected marker, independent of how SetPath grouped
// the flat-set tokens into nodes.
func findDescriptionValue(nodes []*Node) string {
	for _, n := range nodes {
		for _, k := range n.Keys {
			if strings.Contains(k, "DHCP=ipv4") {
				return k
			}
		}
		if v := findDescriptionValue(n.Children); v != "" {
			return v
		}
	}
	return ""
}

func TestCompileConfigRejectsNewlineDescription(t *testing.T) {
	tree := newlineDescTree(t)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig must reject a description containing a newline")
	}
	if !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("error should mention control characters: %v", err)
	}
	if !strings.Contains(err.Error(), "description") {
		t.Fatalf("error should name the offending path: %v", err)
	}
}

func TestCompileConfigForNodeRejectsNewlineDescription(t *testing.T) {
	tree := newlineDescTree(t)
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatal("strict CompileConfigForNode must reject a description containing a newline")
	}
}

// TestCompileConfigRejectsHierarchicalQuotedNewline exercises the
// issue's exact reproduction path: hierarchical config text whose
// quoted string carries the "\n" escape through the parser/lexer.
func TestCompileConfigRejectsHierarchicalQuotedNewline(t *testing.T) {
	text := "interfaces {\n" +
		"    ge-0-0-0 {\n" +
		"        description \"lan\\nDHCP=ipv4\";\n" +
		"    }\n" +
		"}\n"
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject the hierarchical quoted-newline description")
	}
}

func TestCompileConfigRejectsControlCharAnnotation(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set interfaces ge-0-0-0 mtu 1500")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	tree.Children[0].Annotation = "note\nAddress=10.0.0.1/24"
	_, err = CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig must reject an annotation containing a newline")
	}
	if !strings.Contains(err.Error(), "annotation") {
		t.Fatalf("error should mention the annotation: %v", err)
	}
}

// #3900: node annotations are emitted verbatim into `/* */` comments,
// so an annotation containing `*/` closes the comment early and the
// trailing text is re-lexed as configuration on the next Format→Parse
// round-trip (HA config sync, rollback/archive reload). The strict
// commit path must reject the delimiter; the lenient path must scrub it
// so a Format→Parse round-trip cannot inject.

const injectAnnotation = `note */ set system host-name pwned; /* end`

// mtuTreeWithAnnotation builds a one-leaf tree and sets its annotation.
func mtuTreeWithAnnotation(t *testing.T, annotation string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set interfaces ge-0-0-0 mtu 1500")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	tree.Children[0].Annotation = annotation
	return tree
}

// sameStructure compares two node slices by Keys, IsLeaf, and Children,
// ignoring Annotation (which the lexer discards on parse) — so it detects
// injected or dropped configuration nodes.
func sameStructure(a, b []*Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IsLeaf != b[i].IsLeaf || len(a[i].Keys) != len(b[i].Keys) {
			return false
		}
		for j := range a[i].Keys {
			if a[i].Keys[j] != b[i].Keys[j] {
				return false
			}
		}
		if !sameStructure(a[i].Children, b[i].Children) {
			return false
		}
	}
	return true
}

func TestCompileConfigRejectsCommentDelimAnnotation(t *testing.T) {
	tree := mtuTreeWithAnnotation(t, injectAnnotation)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig must reject an annotation containing a '*/' comment delimiter")
	}
	if !strings.Contains(err.Error(), "comment delimiter") {
		t.Fatalf("error should mention the comment delimiter: %v", err)
	}
	if !strings.Contains(err.Error(), "annotation") {
		t.Fatalf("error should mention the annotation: %v", err)
	}
	// The leading `/*` half of the pair must be rejected too.
	openTree := mtuTreeWithAnnotation(t, "danger /* swallow the next stanza")
	if _, err := CompileConfig(openTree); err == nil {
		t.Fatal("strict CompileConfig must reject an annotation containing a '/*' comment delimiter")
	}
}

// TestAnnotationCommentDelimInjection is the #3900 RED-on-revert proof:
// without the fix, a malicious annotation round-trips through Format→Parse
// into an INJECTED config node; with the fix, the lenient sanitize breaks
// the delimiter so the round-trip is inert, and the strict compile rejects
// the annotation outright.
func TestAnnotationCommentDelimInjection(t *testing.T) {
	// Baseline: the same tree WITHOUT any annotation, formatted and
	// re-parsed, is the reference structure a safe round-trip must match.
	clean := mtuTreeWithAnnotation(t, "")
	clean.Children[0].Annotation = ""
	refParsed, errs := NewParser(clean.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("baseline parse errors: %v", errs)
	}

	// Demonstrate the injection primitive is real: the malicious
	// annotation, emitted verbatim, escapes the comment on re-parse. This
	// is what a revert of the sanitize would leave live.
	malicious := mtuTreeWithAnnotation(t, injectAnnotation)
	injected, errs := NewParser(malicious.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("malicious parse errors: %v", errs)
	}
	if sameStructure(injected.Children, refParsed.Children) {
		t.Fatal("expected the un-sanitized malicious annotation to INJECT nodes on Format→Parse (injection primitive precondition)")
	}

	// The lenient migration path (Store.Load / peer-sync) must scrub the
	// delimiter in place so the SAME tree now round-trips inert.
	warnings := SanitizeTreeControlChars(malicious)
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one sanitize warning, got %d: %v", len(warnings), warnings)
	}
	if hasCommentDelim(malicious.Children[0].Annotation) {
		t.Fatalf("annotation still holds a comment delimiter after sanitize: %q", malicious.Children[0].Annotation)
	}
	sanitizedParsed, errs := NewParser(malicious.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("sanitized parse errors: %v", errs)
	}
	if !sameStructure(sanitizedParsed.Children, refParsed.Children) {
		t.Fatalf("sanitized annotation still injected/altered config on Format→Parse: %v", sanitizedParsed.Children)
	}

	// And the strict commit path rejects the malicious annotation outright,
	// so it can never be committed on the primary in the first place.
	if _, err := CompileConfig(mtuTreeWithAnnotation(t, injectAnnotation)); err == nil {
		t.Fatal("strict CompileConfig must reject the malicious annotation")
	}
}

// TestNormalAnnotationRoundTrips confirms a benign annotation is inert:
// it neither injects nor drops real configuration on Format→Parse and is
// accepted by both the strict and lenient paths.
func TestNormalAnnotationRoundTrips(t *testing.T) {
	clean := mtuTreeWithAnnotation(t, "")
	clean.Children[0].Annotation = ""
	ref, errs := NewParser(clean.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("baseline parse errors: %v", errs)
	}

	normal := mtuTreeWithAnnotation(t, "primary firewall MTU note")
	if _, err := CompileConfig(normal); err != nil {
		t.Fatalf("strict CompileConfig must accept a normal annotation: %v", err)
	}
	if w := SanitizeTreeControlChars(normal); len(w) != 0 {
		t.Fatalf("normal annotation must not be sanitized, got %v", w)
	}
	parsed, errs := NewParser(normal.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("normal parse errors: %v", errs)
	}
	if !sameStructure(parsed.Children, ref.Children) {
		t.Fatalf("normal annotation altered config structure on Format→Parse: %v", parsed.Children)
	}
}

func TestSanitizeCommentDelim(t *testing.T) {
	cases := []struct{ in, want string }{
		{"clean note", "clean note"},
		{"a */ b", "a * / b"},
		{"a /* b", "a / * b"},
		{"a */ b /* c", "a * / b / * c"},
		{"*/*", "* / *"}, // chained: split must not leave a delimiter
		{"/*/", "/ * /"},
		{"/**/", "/ ** /"}, // /**/ -> /* and */ both broken, inner ** untouched
	}
	for _, c := range cases {
		got := sanitizeCommentDelim(c.in)
		if got != c.want {
			t.Errorf("sanitizeCommentDelim(%q) = %q, want %q", c.in, got, c.want)
		}
		if hasCommentDelim(got) {
			t.Errorf("sanitizeCommentDelim(%q) = %q still contains a delimiter", c.in, got)
		}
	}
}

func TestValidateAnnotationText(t *testing.T) {
	if err := ValidateAnnotationText("a normal note"); err != nil {
		t.Errorf("normal annotation should validate: %v", err)
	}
	if err := ValidateAnnotationText("bad */ inject"); err == nil {
		t.Error("annotation with '*/' must be rejected")
	} else if !strings.Contains(err.Error(), "comment delimiter") {
		t.Errorf("error should mention comment delimiter: %v", err)
	}
	if err := ValidateAnnotationText("open /* here"); err == nil {
		t.Error("annotation with '/*' must be rejected")
	}
	if err := ValidateAnnotationText("line\nbreak"); err == nil {
		t.Error("annotation with a control character must be rejected")
	} else if !strings.Contains(err.Error(), "control characters") {
		t.Errorf("error should mention control characters: %v", err)
	}
}

func TestCompileConfigLenientSanitizesNewlineDescription(t *testing.T) {
	tree := newlineDescTree(t)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must tolerate a persisted newline description: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil {
		t.Fatal("interface ge-0-0-0 missing from compiled config")
	}
	if ifc.Description != "lan DHCP=ipv4" {
		t.Errorf("description not sanitized: got %q", ifc.Description)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "control characters") && strings.Contains(w, "#1798") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile should surface a #1798 warning, got %v", cfg.Warnings)
	}
	// The caller's tree must be untouched (compile works on a clone);
	// scrubbing the stored tree is the configstore's job.
	if got := findDescriptionValue(tree.Children); got != "lan\nDHCP=ipv4" {
		t.Errorf("lenient compile must not mutate the caller's tree, got %q", got)
	}
}

func TestSanitizeTreeControlChars(t *testing.T) {
	tree := newlineDescTree(t)
	tree.Children[0].Annotation = "x\ry"
	warnings := SanitizeTreeControlChars(tree)
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings (value + annotation nodes), got %d: %v", len(warnings), warnings)
	}
	if got := findDescriptionValue(tree.Children); got != "lan DHCP=ipv4" {
		t.Errorf("tree value not sanitized in place: %q", got)
	}
	if tree.Children[0].Annotation != "x y" {
		t.Errorf("annotation not sanitized in place: %q", tree.Children[0].Annotation)
	}
	// Idempotent: a second pass finds nothing.
	if again := SanitizeTreeControlChars(tree); len(again) != 0 {
		t.Errorf("second sanitize pass should be a no-op, got %v", again)
	}
	// A clean tree compiles strictly after sanitization.
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("sanitized tree must pass strict compile: %v", err)
	}
}

func TestControlCharHelpers(t *testing.T) {
	cases := []struct {
		in       string
		has      bool
		sanitize string
	}{
		{"plain description", false, "plain description"},
		{"lan\nDHCP=ipv4", true, "lan DHCP=ipv4"},
		{"a\rb", true, "a b"},
		{"a\tb", true, "a b"},
		{"del\x7fchar", true, "del char"},
		{"nul\x00byte", true, "nul byte"},
		// Multi-byte UTF-8 must pass through untouched (no byte of a
		// UTF-8 continuation sequence is below 0x80).
		{"héllo — wörld", false, "héllo — wörld"},
		{"", false, ""},
	}
	for _, c := range cases {
		if got := hasControlChars(c.in); got != c.has {
			t.Errorf("hasControlChars(%q) = %v, want %v", c.in, got, c.has)
		}
		if got := sanitizeControlChars(c.in); got != c.sanitize {
			t.Errorf("sanitizeControlChars(%q) = %q, want %q", c.in, got, c.sanitize)
		}
	}
}
