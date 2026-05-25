package config

import (
	"errors"
	"strings"
	"testing"
)

// TestCompileMultipleStrictErrorsAccumulated verifies that #1538's
// accumulator surfaces ONE error per independent strict-validator
// family in a single `CompileConfig` response — saving operator
// round-trips on first-touch upgrades that carry several dormant
// findings at once.
//
// Fixture (parser-reachable):
//   - CoS family: `class-of-service schedulers <name>
//     equal-flow-enforcement` without `transmit-rate exact`
//     triggers validateClassOfServiceStrict at the
//     equal-flow-enforcement guard in compiler.go.
//   - Policer family: `firewall three-color-policer <name>
//     single-rate color-blind` (with the schema-clean `then
//     discard` action) leaves CIR=0, triggering
//     validateThreeColorPolicersStrict at the
//     committed-information-rate guard in compiler.go.
//
// The `set system dataplane-type userspace` line is harmless
// explicitness: unset == userspace via effectiveDataplaneType
// and validateDataplaneTypeStrict only rejects explicit `dpdk`.
// Keeping the line self-documents the test and guards against
// future default-dataplane behavior changes.
//
// The DPDK precheck stays fail-fast (#1526 contract pinned by
// TestDataplaneTypeDPDKRejectedAtCommitFiresFirst); this test
// proves the *post-precheck* accumulator block does the right
// thing.
func TestCompileMultipleStrictErrorsAccumulated(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
		"set class-of-service schedulers bad-sched equal-flow-enforcement",
		"set firewall three-color-policer bad-pol single-rate color-blind",
		"set firewall three-color-policer bad-pol then discard",
	}
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

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; expected accumulated strict-validator errors")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "equal-flow-enforcement") {
		t.Errorf("error missing CoS-family substring 'equal-flow-enforcement': %q", errStr)
	}
	if !strings.Contains(errStr, "committed-information-rate") {
		t.Errorf("error missing policer-family substring 'committed-information-rate': %q", errStr)
	}
	// Exactly one '\n' separator because this fixture fires exactly
	// two validator families (CoS + policer). errors.Join places
	// one '\n' between N joined errors, so N-errors → N-1 newlines.
	// A regression to fail-fast (one family silently swallowed)
	// drops the count to 0; full-accumulation leak (all sub-errors
	// from inside a single family) raises it above 1.
	if nc := strings.Count(errStr, "\n"); nc != 1 {
		t.Errorf("newline count = %d, want 1 (one '\\n' between two joined errors): %q", nc, errStr)
	}
	// Defense-in-depth: DPDK sentinel must not surface — DPDK was
	// not in the fixture, so the precheck cannot fire.
	if errors.Is(err, ErrDPDKDataplaneRetired) {
		t.Errorf("errors.Is(err, ErrDPDKDataplaneRetired) = true; DPDK was not in fixture: %q", errStr)
	}
}

// TestCompileSingleStrictErrorJoinPath pins errors.Join's
// single-element byte-identity semantics: when only ONE strict-
// validator family fires under compileExpanded's accumulator,
// the returned error's Error() must be byte-identical to the
// underlying validator's return — no leading/trailing newline,
// no header framing, no '\n' separators. This protects against
// any future helper-wrapper drift (custom multierror type, added
// prefix, etc.) that would silently change operator-facing error
// text on the single-error path.
//
// Exercises the PRODUCTION path through CompileConfig so the
// assertion fails if compileExpanded later wraps or reformats
// the single-error result (Codex code-review round-1 finding —
// the prior version of this test inlined the accumulator and
// would not have caught that class of regression).
//
// Fixture only triggers the CoS family (no policer config), so
// the accumulator slice ends up length-1 and errors.Join must
// emit byte-identical bytes per Go 1.20+ std lib spec (see
// `joinError.Error()` in the std errors package).
func TestCompileSingleStrictErrorJoinPath(t *testing.T) {
	// Single-family fixture: only CoS equal-flow-enforcement.
	// No firewall stanza means three-color policers map is empty
	// and validateThreeColorPolicersStrict returns nil; same for
	// the policy-scheduler-references validator.
	lines := []string{
		"set system dataplane-type userspace",
		"set class-of-service schedulers bad-sched equal-flow-enforcement",
	}
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

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; expected single CoS strict-validator error")
	}

	// Reference: what does the underlying validator return when
	// called directly on the same configured value? Build an
	// equivalent CoSScheduler stub matching the fixture.
	want := validateClassOfServiceStrict(&ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"bad-sched": {
				Name:                 "bad-sched",
				EqualFlowEnforcement: true,
				// TransmitRateExact=false, TransmitRateBytes=0
			},
		},
	})
	if want == nil {
		t.Fatal("validateClassOfServiceStrict returned nil for the reference fixture; test setup is broken")
	}

	// Byte-identity assertion: errors.Join with exactly one
	// non-nil child must emit the child's text verbatim.
	gotStr, wantStr := err.Error(), want.Error()
	if gotStr != wantStr {
		t.Errorf("single-element errors.Join in compileExpanded produced framing drift:\n  got  = %q\n  want = %q",
			gotStr, wantStr)
	}

	// Defense-in-depth: no '\n' separator on the single-family
	// path. Catches any regression where compileExpanded begins
	// emitting framing around single-element joins.
	if n := strings.Count(err.Error(), "\n"); n != 0 {
		t.Errorf("single-error path has %d '\\n' separators, want 0: %q", n, err.Error())
	}

	// Defense-in-depth: errors.Is must still traverse from the
	// CompileConfig return through to ErrDPDKDataplaneRetired ==
	// false (DPDK not in this fixture). This is incidental
	// coverage of the wrap-chain traversal for the single-element
	// join path.
	if errors.Is(err, ErrDPDKDataplaneRetired) {
		t.Errorf("errors.Is(err, ErrDPDKDataplaneRetired) = true; DPDK not in fixture: %q", err.Error())
	}
}

// TestCompileAllThreeStrictValidatorsAccumulated closes the coverage
// gap identified in the Copilot code review: the 2-family test
// (TestCompileMultipleStrictErrorsAccumulated) does not exercise
// validatePolicySchedulerReferencesStrict, so a silent removal of
// that validator's append call from the accumulator would go
// undetected. This test fires all three independent strict-validator
// families simultaneously and pins the count of accumulated errors.
//
// Fixture:
//   - CoS: equal-flow-enforcement without transmit-rate exact
//     (validateClassOfServiceStrict).
//   - Policer: single-rate color-blind with CIR=0
//     (validateThreeColorPolicersStrict).
//   - Scheduler-ref: a zone policy referencing a scheduler name not
//     present in the compiled schedulers map
//     (validatePolicySchedulerReferencesStrict).
//
// All three set commands are parser-reachable (same path as
// the existing single-family tests in parser_ast_test.go).
func TestCompileAllThreeStrictValidatorsAccumulated(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
		// CoS family
		"set class-of-service schedulers bad-sched equal-flow-enforcement",
		// Policer family
		"set firewall three-color-policer bad-pol single-rate color-blind",
		"set firewall three-color-policer bad-pol then discard",
		// Scheduler-reference family: zone policy referencing a
		// scheduler that is not defined in the compiled config.
		"set security policies from-zone trust to-zone untrust policy sched-test match source-address any",
		"set security policies from-zone trust to-zone untrust policy sched-test match destination-address any",
		"set security policies from-zone trust to-zone untrust policy sched-test match application any",
		"set security policies from-zone trust to-zone untrust policy sched-test then permit",
		"set security policies from-zone trust to-zone untrust policy sched-test scheduler-name missing-sched",
	}
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

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; expected all three strict-validator families to error")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "equal-flow-enforcement") {
		t.Errorf("error missing CoS-family substring 'equal-flow-enforcement': %q", errStr)
	}
	if !strings.Contains(errStr, "committed-information-rate") {
		t.Errorf("error missing policer-family substring 'committed-information-rate': %q", errStr)
	}
	if !strings.Contains(errStr, "references undefined scheduler") {
		t.Errorf("error missing scheduler-ref-family substring 'references undefined scheduler': %q", errStr)
	}
	// Three errors → two '\n' separators (N errors → N-1 newlines
	// per errors.Join semantics). A regression that drops one
	// append call reduces this to 1; a fail-fast regression reduces
	// it to 0.
	if nc := strings.Count(errStr, "\n"); nc != 2 {
		t.Errorf("newline count = %d, want 2 (two '\\n' between three joined errors): %q", nc, errStr)
	}
}
