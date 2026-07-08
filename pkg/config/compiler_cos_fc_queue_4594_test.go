package config

import (
	"strings"
	"testing"
)

// #4594: a class-of-service forwarding-class whose queue is outside 0..255
// must be HARD-REJECTED on the strict commit / commit-check path. Before the
// gate the out-of-range queue was warn-only (ValidateConfig) and COMMITTED,
// while the userspace helper fail-closes the WHOLE CoS snapshot on
// CosQueueIdOutOfRange (#2410) and silently keeps stale CoS forwarding state.
//
// RED on revert: without validateClassOfServiceForwardingClassQueueStrict
// wired into runUniformGates, CompileConfig (strict) returns nil and the bad
// queue commits.
func TestCoSForwardingClassQueueOutOfRange_StrictReject_4594(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service forwarding-classes queue 999 iperf-video",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected strict commit to reject out-of-range forwarding-class queue 999")
	}
	if !strings.Contains(err.Error(), "queue 999") ||
		!strings.Contains(err.Error(), "0..255") {
		t.Fatalf("error should name the out-of-range queue and the 0..255 range, got: %v", err)
	}
}

// A queue inside 0..255 (including the boundaries) commits clean on the strict
// path — the gate is scoped to out-of-range values, not a blanket reject.
func TestCoSForwardingClassQueueValid_StrictAccept_4594(t *testing.T) {
	for _, q := range []string{"0", "7", "255"} {
		tree := flatTreeFromSets(t,
			"set class-of-service forwarding-classes queue "+q+" iperf-video",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid forwarding-class queue %s wrongly rejected on strict commit: %v", q, err)
		}
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on
// an already-persisted out-of-range queue — it downgrades to a warning so an
// upgrading node still boots (#1960 no-brick). RED on revert: with the gate
// unconditional (no lenient flag) the lenient path would return an error.
func TestCoSForwardingClassQueueOutOfRange_LenientWarns_4594(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service forwarding-classes queue 999 iperf-video",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of out-of-range queue must not brick, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "forwarding-class queue") && strings.Contains(w, "queue 999") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must warn about the out-of-range queue, warnings: %v", cfg.Warnings)
	}
}

// Unit-level guard on the validator itself: a NEGATIVE queue (only reachable
// via a constructed / externally-assembled config, since the grammar has no
// minus token on the operator set path) is rejected too.
func TestValidateCoSForwardingClassQueue_NegativeRejected_4594(t *testing.T) {
	cos := &ClassOfServiceConfig{
		ForwardingClasses: map[string]*CoSForwardingClass{
			"bad": {Name: "bad", Queue: -1},
		},
	}
	if err := validateClassOfServiceForwardingClassQueueStrict(cos); err == nil {
		t.Fatal("expected negative forwarding-class queue to be rejected")
	}
	ok := &ClassOfServiceConfig{
		ForwardingClasses: map[string]*CoSForwardingClass{
			"ef": {Name: "ef", Queue: 5},
		},
	}
	if err := validateClassOfServiceForwardingClassQueueStrict(ok); err != nil {
		t.Fatalf("in-range forwarding-class queue wrongly rejected: %v", err)
	}
}
