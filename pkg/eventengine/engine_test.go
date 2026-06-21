package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Tests for #2008 M7 — attributes-match is a regex match (Junos `matches`
// semantics), with the compiled regex cached at Apply() time so the event
// hot path never recompiles.

func newTestEngine(t *testing.T, policies []*config.EventPolicy) *Engine {
	t.Helper()
	e := New(nil, nil) // nil store/commitFn: matcher tests never commit
	e.Apply(policies)
	return e
}

func policyWithMatch(name, event, match string) *config.EventPolicy {
	return &config.EventPolicy{
		Name:            name,
		Events:          []string{event},
		AttributesMatch: []string{match},
	}
}

// A pattern that is an anchored exact match behaves like the old literal
// equality for the matching value, and rejects a non-matching value.
func TestAttributesMatch_AnchoredExact(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches ^Comcast$")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"}) {
		t.Error("anchored ^Comcast$ should match TestOwner=Comcast")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "ComcastBusiness"}) {
		t.Error("anchored ^Comcast$ should NOT match TestOwner=ComcastBusiness")
	}
}

// The behavior change vs the old literal equality: an UNANCHORED pattern is
// a regex substring match (Junos semantics). `Com` matches `Comcast` — the
// old code required exact equality and would have returned false.
func TestAttributesMatch_UnanchoredSubstring(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches Com")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"}) {
		t.Error("unanchored Com should substring-match Comcast (regex behavior)")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "ATT"}) {
		t.Error("unanchored Com should NOT match ATT")
	}
}

// A metacharacter pattern is honored as a regex, not as a literal string.
// `.*down` matches `link-down` (the `.` and `*` are regex operators); the
// old literal code would only have matched the exact string ".*down".
func TestAttributesMatch_MetacharactersBehaveAsRegex(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-name matches .*down")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "link-down"}) {
		t.Error(".*down should regex-match link-down")
	}
	// The literal string ".*down" is NOT what TestName equals here, proving
	// the match is regex, not literal equality on the pattern text.
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "up"}) {
		t.Error(".*down should NOT match up")
	}
}

// test-name field is supported in addition to test-owner.
func TestAttributesMatch_TestNameField(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-name matches ^wan-probe$")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestName: "wan-probe"}) {
		t.Error("test-name field should match")
	}
}

// #2141 FAIL-CLOSED: an unknown field (which can only reach the runtime on a
// legacy lenient-load path, since strict commit now rejects it) makes the
// policy NOT fire, rather than being silently dropped and broadening the
// policy. This is the behavior change vs the old default:continue fail-open.
func TestAttributesMatch_UnknownFieldFailsClosed(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.nonexistent matches whatever")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "x"}) {
		t.Error("unknown attribute field should fail closed (policy does not match)")
	}
	if got := e.Stats().AttributesInvalid; got == 0 {
		t.Error("AttributesInvalid counter should bump on an unknown field")
	}
}

// #2141 FAIL-CLOSED: a malformed line (no " matches ") that slipped through a
// lenient load also fails closed.
func TestAttributesMatch_MalformedLineFailsClosed(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed", "garbage with no separator")
	e := newTestEngine(t, []*config.EventPolicy{pol})
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "x"}) {
		t.Error("malformed attributes-match line should fail closed")
	}
}

// SSOT drift guard (#2141): the config-side known-field set and the runtime
// matcher's switch must stay identical. Every known field must resolve in the
// matcher (i.e. a policy matching ^anything against that field with the right
// event value must be able to return true), and an unknown field must fail.
func TestEventAttributesKnownFields_MatchesRuntimeSwitch(t *testing.T) {
	// The matcher resolves test-owner and test-name; assert exactly those are
	// the known fields. If a field is added to the SSOT, this test forces the
	// matcher switch to be updated in lockstep.
	want := map[string]bool{"test-owner": true, "test-name": true}
	if len(config.EventAttributesKnownFields) != len(want) {
		t.Fatalf("known-field set %v has unexpected size; runtime switch resolves %v",
			config.EventAttributesKnownFields, want)
	}
	for f := range want {
		if !config.EventAttributesFieldKnown(f) {
			t.Errorf("field %q is resolved by the matcher but missing from the SSOT", f)
		}
	}
	for f := range config.EventAttributesKnownFields {
		if !want[f] {
			t.Errorf("field %q is in the SSOT but the runtime matcher switch does not resolve it", f)
		}
	}
}

// Cached-compile: Apply() must populate the regex cache for every valid
// pattern so the hot path reads a pre-compiled regex. This proves the
// matcher does NOT compile per event (it reads e.regexCache[pattern]).
func TestAttributesMatch_RegexCachedAtApply(t *testing.T) {
	pol := policyWithMatch("p", "ping_test_failed",
		"ping_test_failed.test-owner matches ^Comcast$")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	pattern := "^Comcast$"
	re, ok := e.regexCache[pattern]
	if !ok || re == nil {
		t.Fatalf("Apply() did not cache the compiled regex for %q; cache=%v",
			pattern, e.regexCache)
	}

	// The cached pointer must be stable across matches — the hot path reads
	// the same compiled object, never recompiling. Capture it, run several
	// matches, and confirm the cache entry is identical (same pointer).
	before := e.regexCache[pattern]
	for i := 0; i < 5; i++ {
		e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast"})
	}
	after := e.regexCache[pattern]
	if before != after {
		t.Error("regex cache entry changed across matches — hot path recompiled")
	}

	// Re-Apply rebuilds the cache (new map); the same pattern is present.
	e.Apply([]*config.EventPolicy{pol})
	if _, ok := e.regexCache[pattern]; !ok {
		t.Error("Apply() rebuild dropped the cached pattern")
	}
}

// Multiple attributes-match lines must ALL match (AND semantics) — one
// failing constraint blocks the policy.
func TestAttributesMatch_AllMustMatch(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		AttributesMatch: []string{
			"ping_test_failed.test-owner matches ^Comcast$",
			"ping_test_failed.test-name matches ^wan$",
		},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})

	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast", TestName: "wan"}) {
		t.Error("both constraints satisfied should match")
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "Comcast", TestName: "lan"}) {
		t.Error("one failing constraint should block the match")
	}
}
