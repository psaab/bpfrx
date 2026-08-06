package logging

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6851 MAJOR 1: the SEVENTH policy-name resolver.
//
// `EventReader.resolvePolicyName` resolves RT_FLOW record names independently of
// the six session-row builders #4626 routed through `dataplane.SessionPolicyName`,
// and it indexed `er.policyNames` directly. Reserved id 0 is also the id of the
// FIRST configured policy, so every host-inbound / fabric / tunnel / pre-#3056 /
// older-peer-synced record named that policy.
//
// This surface matters more than the interactive ones: RT_FLOW records go to
// syslog and ship off-box to a collector, so the wrong attribution is DURABLE —
// it lands in the record an auditor reads months later, not in a row an operator
// can re-run.
//
// FIXTURE NOTE: id 0 must be OCCUPIED by a real policy, exactly as
// compilePolicies emits it. A fixture with no entry at 0 passes against the
// unfixed code and proves nothing.
func policyNamesWithFirstPolicy6851() map[uint32]string {
	return map[uint32]string{
		0: "trust-to-untrust/allow-web",
		1: "trust-to-untrust/allow-dns",
	}
}

func TestResolvePolicyNameZeroIsNotTheFirstPolicy_6851(t *testing.T) {
	er := &EventReader{}
	er.SetPolicyNames(policyNamesWithFirstPolicy6851())

	got := er.resolvePolicyName(0)

	if got == "trust-to-untrust/allow-web" {
		t.Fatalf("RT_FLOW record names policy %q for policy_id 0 — that is the FIRST "+
			"configured policy, which never admitted the session. This record is "+
			"shipped to a collector, so the misattribution is durable (#6851)", got)
	}
	if got != dataplane.UnattributedPolicyName {
		t.Errorf("resolvePolicyName(0) = %q, want %q", got, dataplane.UnattributedPolicyName)
	}
}

// Over-rejection controls. A fix that blanked or reserved everything would pass
// the test above and destroy the surface.
func TestResolvePolicyNameUnreservedStillResolves_6851(t *testing.T) {
	er := &EventReader{}
	er.SetPolicyNames(policyNamesWithFirstPolicy6851())

	if got, want := er.resolvePolicyName(1), "trust-to-untrust/allow-dns"; got != want {
		t.Errorf("resolvePolicyName(1) = %q, want %q — a real policy must still name "+
			"itself on its own records", got, want)
	}

	// #3057 must not regress: the implicit-default sentinel keeps its name.
	if got, want := er.resolvePolicyName(dataplane.DefaultPolicySentinelID),
		dataplane.DefaultPolicyName; got != want {
		t.Errorf("default sentinel = %q, want %q", got, want)
	}

	// An unreserved id absent from the map keeps the pre-existing numeric
	// fallback rather than becoming "unattributed" — the guard must be scoped to
	// the RESERVED id, not to "anything the map cannot resolve".
	if got, want := er.resolvePolicyName(4242), "4242"; got != want {
		t.Errorf("absent unreserved id = %q, want the numeric fallback %q", got, want)
	}
}

// The reserved rendering must not depend on a published map: a record emitted
// before the first apply must still not alias policy 0.
func TestResolvePolicyNameZeroWithNoPublishedMap_6851(t *testing.T) {
	er := &EventReader{}

	if got, want := er.resolvePolicyName(0), dataplane.UnattributedPolicyName; got != want {
		t.Errorf("resolvePolicyName(0) with no policyNames map = %q, want %q", got, want)
	}
}
