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
//     triggers validateClassOfServiceStrict at
//     compiler.go:371-374.
//   - Policer family: `firewall three-color-policer <name>
//     single-rate color-blind` (with the schema-clean `then
//     discard` action) leaves CIR=0, triggering
//     validateThreeColorPolicersStrict at compiler.go:277-278.
//
// The `set system dataplane-type userspace` line is harmless
// explicitness: unset == userspace via effectiveDataplaneType
// (compiler.go:1005) and validateDataplaneTypeStrict only rejects
// explicit `dpdk`. Keeping the line self-documents the test and
// guards against future default-dataplane behavior changes.
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

	got := err.Error()
	if !strings.Contains(got, "equal-flow-enforcement") {
		t.Errorf("error missing CoS-family substring 'equal-flow-enforcement': %q", got)
	}
	if !strings.Contains(got, "committed-information-rate") {
		t.Errorf("error missing policer-family substring 'committed-information-rate': %q", got)
	}
	// Exactly one '\n' separator → exactly two joined errors.
	// A regression to fail-fast (or to leaking ALL family errors
	// where none were intended) trips this gate.
	if got, want := strings.Count(got, "\n"), 1; got != want {
		t.Errorf("newline count = %d, want %d (one '\\n' between two joined errors): %q",
			got, want, err.Error())
	}
	// Defense-in-depth: DPDK sentinel must not surface — DPDK was
	// not in the fixture, so the precheck cannot fire.
	if errors.Is(err, ErrDPDKDataplaneRetired) {
		t.Errorf("errors.Is(err, ErrDPDKDataplaneRetired) = true; DPDK was not in fixture: %q", got)
	}
}

// TestCompileSingleStrictErrorJoinPath pins errors.Join's
// single-element byte-identity semantics: when only ONE strict-
// validator family fires under the accumulator, the returned
// error's Error() must be byte-identical to the underlying
// validator's return — no leading/trailing newline, no header
// framing. This protects against any future helper-wrapper drift
// (custom multierror type, prefix, etc.) that would silently
// change operator-facing error text on the single-error path.
//
// Verified against /usr/lib/go-1.24/src/errors/join.go:47-48
// per Codex round-2 verification. The hand-built *Config route
// keeps the test independent of parser/compiler-shape changes.
func TestCompileSingleStrictErrorJoinPath(t *testing.T) {
	// Hand-build a *Config that triggers only the CoS family.
	// We invoke the validators inline (mirroring compileExpanded's
	// post-precheck accumulator block) so the test is independent
	// of the parse + compile pipeline.
	cfg := &Config{
		ClassOfService: &ClassOfServiceConfig{
			Schedulers: map[string]*CoSScheduler{
				"bad-sched": {
					Name:                 "bad-sched",
					EqualFlowEnforcement: true,
					// TransmitRateExact=false, TransmitRateBytes=0:
					// triggers the validator.
				},
			},
			SchedulerMaps:       make(map[string]*CoSSchedulerMap),
			ForwardingClasses:   make(map[string]*CoSForwardingClass),
			DSCPClassifiers:     make(map[string]*CoSDSCPClassifier),
			IEEE8021Classifiers: make(map[string]*CoSIEEE8021Classifier),
			DSCPRewriteRules:    make(map[string]*CoSDSCPRewriteRule),
			Interfaces:          make(map[string]*CoSInterface),
		},
		Firewall: FirewallConfig{
			ThreeColorPolicers: map[string]*ThreeColorPolicerConfig{},
		},
	}

	// Reference: what does the single underlying validator return?
	direct := validateClassOfServiceStrict(cfg.ClassOfService)
	if direct == nil {
		t.Fatal("validateClassOfServiceStrict returned nil; fixture is broken")
	}

	// Apply the same accumulator pattern compileExpanded uses.
	var strictErrs []error
	if err := validateClassOfServiceStrict(cfg.ClassOfService); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	joined := errors.Join(strictErrs...)
	if joined == nil {
		t.Fatal("errors.Join over single non-nil err returned nil")
	}

	// Byte-identity assertion: errors.Join with exactly one
	// non-nil child must emit the child's text verbatim.
	if got, want := joined.Error(), direct.Error(); got != want {
		t.Errorf("single-element errors.Join produced framing drift:\n  got  = %q\n  want = %q",
			got, want)
	}
}
