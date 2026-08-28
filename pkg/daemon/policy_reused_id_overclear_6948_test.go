package daemon

// policy_reused_id_overclear_6948_test.go — #6948.
//
// Runtime policy ids are POSITIONAL (policySetID*MaxRulesPerPolicy +
// ruleIndex), so deleting a policy renumbers every later one:
//
//	C1 = [A, B, C]  ->  A=0, B=1, C=2
//	delete B
//	C2 = [A, C]     ->  A=0, C=1        <- C INHERITED B's id
//	deletion set     =  { B's old id } = { 1 }
//
// The commit path publishes the new policy set inside applyConfigLocked and
// only runs the invalidation sweep after the WHOLE apply returns — tail
// included. The dataplane admits under the new numbering from the moment of
// publication, so a session admitted in that window under C carries policy_id 1
// and is swept as though it were B: a correctly-permitted session dropped by an
// unrelated policy's deletion.
//
// d.policyActivationSecs is stamped immediately before publication, and the
// sweep skips rows Created strictly after it. Created is "seconds since boot"
// on the BPF side and CLOCK_MONOTONIC seconds on the Go side — the same clock.
//
// RESIDUAL, asserted below rather than left to prose: Created has ONE-SECOND
// granularity, so a session created in the same integer second as the stamp is
// ambiguous and is still cleared. This narrows the over-clear from the entire
// post-activation apply to at most one second; it does not eliminate it.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// reusedIDFixture builds the worked example: p-web deleted, p-ssh inherits its
// runtime id. It asserts the inheritance rather than assuming it — if the id
// allocator ever stopped renumbering, every cell here would pass for the wrong
// reason.
func reusedIDFixture6948(t *testing.T) (oldCfg, newCfg *config.Config, deletedID uint32) {
	t.Helper()
	o := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	n := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)

	oldIDs := dpuserspace.PolicyIDsByStableKey(o)
	newIDs := dpuserspace.PolicyIDsByStableKey(n)
	webOld := oldIDs["trust->untrust/p-web"]
	sshNew := newIDs["trust->untrust/p-ssh"]

	if webOld != sshNew {
		t.Fatalf("precondition: this cell needs p-ssh to INHERIT deleted p-web's "+
			"runtime id, which is what makes the over-clear possible. "+
			"p-web(old)=%d p-ssh(new)=%d — ids are no longer positional, so "+
			"re-derive #6948 before trusting these cells", webOld, sshNew)
	}
	return o, n, webOld
}

// TestFreshSessionOnInheritedIDIsNotSwept6948 is the defect.
//
// FAIL-ON-REVERT: drop the admittedAfterActivation guard from
// clearSessionsForPolicyIDs and this reds — the post-activation session is
// deleted although p-ssh, which admitted it, still exists.
func TestFreshSessionOnInheritedIDIsNotSwept6948(t *testing.T) {
	oldCfg, newCfg, reusedID := reusedIDFixture6948(t)

	const activation = 1000
	// Admitted AFTER the new policy set went live: this is a p-ssh session that
	// merely inherited the id p-web used to hold.
	fresh := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 9}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 41001, DstPort: 22, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			fresh: {State: dataplane.SessStateEstablished, PolicyID: reusedID, Created: activation + 5},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.policyActivationSecs = activation

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForDeletedPolicies: %v", err)
	}

	if _, ok := dp.v4[fresh]; !ok {
		t.Fatal("a session admitted AFTER the new policy set went live was swept by an " +
			"OLD-numbering deletion set: it carries the deleted policy's id only " +
			"because a surviving policy inherited that id. A correctly-permitted " +
			"session was dropped by an unrelated policy's deletion (#6948)")
	}
}

// TestPreActivationSessionIsStillSwept6948 is the OVER-REACH cell, and the
// reason it exists is that the previous cell alone is satisfied by a guard that
// refuses to clear ANYTHING.
//
// A session admitted BEFORE activation under the genuinely-deleted policy must
// still be cleared. Failing to clear it is a STALE-AUTHORIZATION gap — traffic
// the new config no longer permits keeps forwarding — which is strictly worse
// than the over-clear this change fixes.
func TestPreActivationSessionIsStillSwept6948(t *testing.T) {
	oldCfg, newCfg, deletedID := reusedIDFixture6948(t)

	const activation = 1000
	stale := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			stale: {State: dataplane.SessStateEstablished, PolicyID: deletedID, Created: activation - 30},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.policyActivationSecs = activation

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForDeletedPolicies: %v", err)
	}

	if _, ok := dp.v4[stale]; ok {
		t.Fatal("a session admitted BEFORE activation under the DELETED policy survived " +
			"the sweep. The #6948 guard is over-broad: it is refusing to clear " +
			"sessions the deletion-clear exists to remove, which is a stale-" +
			"authorization gap and worse than the over-clear it was added to fix")
	}
}

// TestSameSecondSessionIsStillSwept6948 pins the RESIDUAL rather than leaving it
// to a comment that a later change could quietly invalidate.
//
// Created has one-second granularity, so a session created in the same integer
// second as the activation stamp cannot be placed on either side of it. It is
// still cleared — the direction this code already chose, since over-clear is
// fail-safe for security and under-clear is a stale-authorization gap.
//
// If someone later switches the predicate to `>=`, this cell reds and tells
// them they have traded a bounded availability bug for a security one.
func TestSameSecondSessionIsStillSwept6948(t *testing.T) {
	oldCfg, newCfg, deletedID := reusedIDFixture6948(t)

	const activation = 1000
	ambiguous := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 7}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40007, DstPort: 80, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			ambiguous: {State: dataplane.SessStateEstablished, PolicyID: deletedID, Created: activation},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.policyActivationSecs = activation

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForDeletedPolicies: %v", err)
	}

	if _, ok := dp.v4[ambiguous]; ok {
		t.Fatal("a session created in the SAME second as the activation stamp survived. " +
			"Created has one-second granularity so that session is genuinely " +
			"ambiguous, and the ambiguous case must fail SAFE (cleared): an " +
			"under-clear is a stale-authorization gap. Switching the predicate to " +
			">= trades a bounded availability bug for a security one (#6948)")
	}
}

// TestUnstampedActivationClearsAsBefore6948 is the compatibility floor.
//
// policyActivationSecs is zero on any path that reaches the sweep without going
// through applyConfigLocked (tests, and any future caller). Zero must mean "no
// boundary known", falling back to the pre-#6948 behaviour of clearing every
// matching id — NOT to skipping everything, which would silently disable the
// deletion-clear wherever the stamp is missing.
func TestUnstampedActivationClearsAsBefore6948(t *testing.T) {
	oldCfg, newCfg, deletedID := reusedIDFixture6948(t)

	sess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			// A Created far in the future: with no stamp it must be irrelevant.
			sess: {State: dataplane.SessStateEstablished, PolicyID: deletedID, Created: 999999},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	// policyActivationSecs deliberately left 0.

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForDeletedPolicies: %v", err)
	}

	if _, ok := dp.v4[sess]; ok {
		t.Fatal("with no activation stamp the deletion-clear skipped a matching session. " +
			"An unstamped boundary must degrade to the pre-#6948 behaviour (clear " +
			"everything matching), or the guard silently disables the deletion-clear " +
			"on every path that does not set it (#6948)")
	}
}
