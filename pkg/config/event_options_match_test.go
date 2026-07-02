package config

import (
	"strings"
	"testing"
)

// Tests for #2008 M7 — event-options attributes-match is a regex match
// (Junos `matches` semantics), validated at commit time.

func TestEventAttributesMatch_ParseLine(t *testing.T) {
	cases := []struct {
		in        string
		wantEvent string
		wantField string
		wantPat   string
		wantOK    bool
	}{
		{`ping_test_failed.test-owner matches ^Comcast$`, "ping_test_failed", "test-owner", "^Comcast$", true},
		{`ping_test_failed.test-name matches .*down`, "ping_test_failed", "test-name", ".*down", true},
		// no separator
		{`ping_test_failed.test-owner Comcast`, "", "", "", false},
		// no dot in field spec
		{`testowner matches Comcast`, "", "", "", false},
		// empty pattern
		{`ping_test_failed.test-owner matches `, "", "", "", false},
	}
	for _, c := range cases {
		event, field, pat, ok := ParseEventAttributesMatch(c.in)
		if ok != c.wantOK || event != c.wantEvent || field != c.wantField || pat != c.wantPat {
			t.Errorf("ParseEventAttributesMatch(%q) = (%q,%q,%q,%v); want (%q,%q,%q,%v)",
				c.in, event, field, pat, ok, c.wantEvent, c.wantField, c.wantPat, c.wantOK)
		}
	}
}

// A valid regex pattern compiles cleanly at commit.
func TestEventAttributesMatch_ValidPatternCompiles(t *testing.T) {
	cfg := compileSetLines(t, []string{
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 attributes-match "ping_test_failed.test-owner matches ^Comcast.*$"`,
	})
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("want 1 event policy, got %d", len(cfg.EventOptions))
	}
	if len(cfg.EventOptions[0].AttributesMatch) != 1 {
		t.Fatalf("attributes-match not stored: %#v", cfg.EventOptions[0].AttributesMatch)
	}
}

// CRITICAL (#2008 M7 / SMR flag): an invalid regex must be REJECTED at
// commit time, not silently accepted and dropped at runtime. This is the
// commit-time pattern validation that backs the literal->regex switch.
func TestEventAttributesMatch_InvalidPatternRejectedAtCommit(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		`set event-options policy p1 events ping_test_failed`,
		// Unbalanced "[" is not a valid RE2 pattern.
		`set event-options policy p1 attributes-match "ping_test_failed.test-owner matches [unterminated"`,
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an invalid attributes-match regex; want commit error")
	}
	if !strings.Contains(err.Error(), "invalid regex pattern") {
		t.Fatalf("commit error %q does not mention the invalid regex", err)
	}
	if !strings.Contains(err.Error(), "p1") {
		t.Fatalf("commit error %q does not identify the offending policy", err)
	}
}

// #2141: a malformed (non-match) line is REJECTED at strict commit (it was
// previously silently dropped at runtime — a fail-open that broadens the
// policy). The lenient-load path downgrades it to a warning.
func TestEventAttributesMatch_MalformedLineRejectedAtCommit(t *testing.T) {
	tree := setTree(t,
		`set event-options policy p1 events ping_test_failed`,
		// No " matches " separator: not a match expression.
		`set event-options policy p1 attributes-match "garbage with no separator"`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a malformed attributes-match line; want commit error")
	}
	if !strings.Contains(err.Error(), "malformed match expression") {
		t.Fatalf("commit error %q does not flag the malformed line", err)
	}
	if !strings.Contains(err.Error(), "p1") {
		t.Fatalf("commit error %q does not identify the offending policy", err)
	}
	// Lenient load boots through with a warning.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("CompileConfigLenient hard-errored on a malformed line; want boot-through: %v", lerr)
	}
	if !hasAttributesMatchWarning(cfg.Warnings) {
		t.Fatalf("lenient load did not warn on the malformed line; got %v", cfg.Warnings)
	}
}

// #2141: an unknown <field> name is REJECTED at strict commit (it can never be
// satisfied against an rpm.Event, so the matcher dropped it and broadened the
// policy). The lenient-load path downgrades to a warning.
func TestEventAttributesMatch_UnknownFieldRejectedAtCommit(t *testing.T) {
	tree := setTree(t,
		`set event-options policy p1 events ping_test_failed`,
		// "test-ower" is a typo for "test-owner".
		`set event-options policy p1 attributes-match "ping_test_failed.test-ower matches ^x$"`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an unknown attributes-match field; want commit error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("commit error %q does not flag the unknown field", err)
	}
	if !strings.Contains(err.Error(), "test-ower") {
		t.Fatalf("commit error %q does not name the offending field", err)
	}
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("CompileConfigLenient hard-errored on an unknown field; want boot-through: %v", lerr)
	}
	if !hasAttributesMatchWarning(cfg.Warnings) {
		t.Fatalf("lenient load did not warn on the unknown field; got %v", cfg.Warnings)
	}
}

// ValidateEventAttributesMatchStrict rejects malformed/unknown lines directly
// (unit-level) and accepts a well-formed known-field line.
func TestValidateEventAttributesMatchStrict_Direct(t *testing.T) {
	good := &Config{EventOptions: []*EventPolicy{
		{Name: "ok", Events: []string{"ev"}, AttributesMatch: []string{`ev.test-owner matches ^a+b*$`}},
	}}
	if err := ValidateEventAttributesMatchStrict(good); err != nil {
		t.Fatalf("valid line rejected by strict validator: %v", err)
	}

	malformed := &Config{EventOptions: []*EventPolicy{
		{Name: "m", Events: []string{"ev"}, AttributesMatch: []string{`no separator here`}},
	}}
	if err := ValidateEventAttributesMatchStrict(malformed); err == nil {
		t.Fatal("strict validator accepted a malformed line")
	}

	unknown := &Config{EventOptions: []*EventPolicy{
		{Name: "u", Events: []string{"ev"}, AttributesMatch: []string{`ev.bogus matches ^x$`}},
	}}
	if err := ValidateEventAttributesMatchStrict(unknown); err == nil {
		t.Fatal("strict validator accepted an unknown field")
	}

	// #3756 H14: the three new static per-test fields are accepted at strict
	// commit. RED-on-revert: without them in EventAttributesKnownFields the
	// strict validator rejects a policy keyed on target / routing-instance /
	// destination-interface as an unknown field.
	for _, field := range []string{"target", "routing-instance", "destination-interface"} {
		newField := &Config{EventOptions: []*EventPolicy{
			{Name: "n", Events: []string{"ev"}, AttributesMatch: []string{`ev.` + field + ` matches ^x$`}},
		}}
		if err := ValidateEventAttributesMatchStrict(newField); err != nil {
			t.Fatalf("strict validator rejected known field %q (#3756 H14): %v", field, err)
		}
		if !EventAttributesFieldKnown(field) {
			t.Errorf("field %q missing from EventAttributesKnownFields SSOT (#3756 H14)", field)
		}
	}
}

// #3753: an attributes-match line scoped to an event the policy does NOT
// declare is rejected at strict commit (it can never apply, and the old
// prefix-dropping parse silently gated the wrong event). RED-on-revert:
// without the eventNameInPolicy check the out-of-scope constraint is accepted.
func TestValidateEventAttributesMatchStrict_EventNameScope(t *testing.T) {
	// event_b IS declared: accepted.
	inScope := &Config{EventOptions: []*EventPolicy{{
		Name:            "p",
		Events:          []string{"ping_test_failed", "ping_test_completed"},
		AttributesMatch: []string{`ping_test_completed.test-owner matches ^x$`},
	}}}
	if err := ValidateEventAttributesMatchStrict(inScope); err != nil {
		t.Fatalf("in-scope event prefix rejected: %v", err)
	}

	// ping_probe_failed is NOT one of the policy's events: rejected.
	outOfScope := &Config{EventOptions: []*EventPolicy{{
		Name:            "p",
		Events:          []string{"ping_test_failed", "ping_test_completed"},
		AttributesMatch: []string{`ping_probe_failed.test-owner matches ^x$`},
	}}}
	err := ValidateEventAttributesMatchStrict(outOfScope)
	if err == nil {
		t.Fatal("strict validator accepted an attributes-match scoped to an event not in the policy")
	}
	if !strings.Contains(err.Error(), "ping_probe_failed") {
		t.Fatalf("commit error %q does not name the out-of-scope event", err)
	}
}

func setTree(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func hasAttributesMatchWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "attributes-match") && strings.Contains(w, "tolerant path") {
			return true
		}
	}
	return false
}

// The validator helper rejects an uncompilable pattern and accepts valid
// ones directly (unit-level, independent of the full compile pipeline).
func TestValidateEventAttributesMatch_Direct(t *testing.T) {
	good := &Config{EventOptions: []*EventPolicy{
		{Name: "ok", AttributesMatch: []string{`ev.test-owner matches ^a+b*$`}},
	}}
	if err := ValidateEventAttributesMatch(good); err != nil {
		t.Fatalf("valid pattern rejected: %v", err)
	}

	bad := &Config{EventOptions: []*EventPolicy{
		{Name: "bad", AttributesMatch: []string{`ev.test-owner matches a(b`}},
	}}
	if err := ValidateEventAttributesMatch(bad); err == nil {
		t.Fatal("invalid pattern accepted by ValidateEventAttributesMatch")
	}
}

// #2063 review: the strict commit-time rejection must DOWNGRADE to a warning
// on the tolerant load path. A config persisted under the pre-#2008
// literal-equality matcher can hold a non-RE2 attributes-match pattern; an
// upgrading node must boot through it (CompileConfigLenient) rather than fail
// to load, mirroring every sibling lenient validator.
func TestEventAttributesMatch_InvalidPatternLenientDowngrade(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 attributes-match "ping_test_failed.test-owner matches [unterminated"`,
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	// Strict commit still rejects (guards against the downgrade leaking to commit).
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted an invalid pattern; commit must stay strict")
	}
	// Tolerant load boots through with a warning.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-errored on an invalid persisted pattern; want boot-through: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "attributes-match") && strings.Contains(w, "tolerant path") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load did not emit the attributes-match downgrade warning; got %v", cfg.Warnings)
	}
}
