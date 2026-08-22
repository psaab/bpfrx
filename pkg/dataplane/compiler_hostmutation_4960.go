package dataplane

import (
	"fmt"
	"sort"
	"strings"
)

// #4960 — reporting the host mutation that an aborted apply leaves behind.
//
// `pkg/dataplane.CompileConfig` performs live netlink host mutation in Phase 2
// (compileZones -> mapZoneInterface -> ensureVLANSubInterface /
// reconcileInterfaceAddresses), and there is no undo log anywhere. Three
// fallible steps still run after that point on the live AF_XDP path:
//
//	CompileConfig's own later phases
//	preflightCheckIfindexCaps   (loader.go, #5836)
//	attachUserspaceShimXDP      (loader.go) — the reachable one
//
// A failure in any of them returns an error, CompileUserspaceShim returns
// before publishing, and the Rust dataplane keeps its PREVIOUS snapshot. The
// host has moved; the forwarding plane has not.
//
// This does NOT fix that. An apply transaction with a real undo path is a
// redesign (#4960's own "split pure planning from host+shim actuation" and
// "restore the prior host plan" clauses), it has a stranded plan branch with
// two PLAN-NEEDS-MAJOR review rounds, and none of it is reachable without first
// deciding what an abort does to a host that has already been mutated.
//
// What it fixes is that the split state was INVISIBLE. The operator saw
//
//	apply failed: attach userspace shim XDP: ...
//
// and had every reason to read it as "the apply did nothing". They would then
// retry, or roll back the config, on a box whose VLAN sub-interfaces and
// interface addresses had already been moved by the failed attempt. Now the
// error says which classes of host state changed and that the dataplane is
// still running the previous snapshot.
//
// WHY THE FLAG IS PER-ACTION AND NOT A BARE BOOL. A bool would answer "did an
// apply of a VLAN config run", which is true on essentially every apply and
// carries no information. The mutation helpers therefore report whether they
// ACTUALLY changed the host — ensureVLANSubInterface only when it added a link,
// reconcileInterfaceAddresses only on a successful AddrDel/AddrAdd — so a
// converged re-apply records nothing and the message stays worth reading.

// markHostMutated records that a live host-state change was performed during
// this compile. action is a short, stable classification (not a per-interface
// detail): the message is an operator instruction to go look, and enumerating
// every interface would bury it.
//
// Idempotent per action, so N interfaces reconciled produce one entry.
func (r *CompileResult) markHostMutated(action string) {
	if r == nil {
		return
	}
	if r.hostMutations == nil {
		r.hostMutations = map[string]bool{}
	}
	r.hostMutations[action] = true
}

// HostMutated reports whether this compile changed live host state.
//
// Exported because the decision to annotate an error belongs to the caller that
// knows the abort happened AFTER the mutation point (CompileUserspaceShim), not
// to the compiler.
func (r *CompileResult) HostMutated() bool {
	return r != nil && len(r.hostMutations) > 0
}

// hostMutationSummary renders the recorded actions in a stable order.
func (r *CompileResult) hostMutationSummary() string {
	if !r.HostMutated() {
		return ""
	}
	actions := make([]string, 0, len(r.hostMutations))
	for a := range r.hostMutations {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	return strings.Join(actions, ", ")
}

// annotateHostMutationOnAbort wraps err with the host state this compile
// already changed, for a caller aborting AFTER the Phase-2 mutation point.
//
// Returns err unchanged when nothing was mutated — a converged apply that fails
// for an unrelated reason must not be decorated with a warning about state that
// did not move, or the annotation stops meaning anything.
//
// It is a no-op on a nil error by design: the success path publishes the new
// snapshot, at which point the host and the dataplane agree again and the
// mutation is not a split state but the intended outcome.
func annotateHostMutationOnAbort(result *CompileResult, err error) error {
	if err == nil || !result.HostMutated() {
		return err
	}
	return fmt.Errorf("%w — this apply ALREADY changed live host state (%s) and "+
		"there is no undo: the host is now configured for the new config while the "+
		"dataplane is still running the PREVIOUS snapshot. Re-apply a working "+
		"config to converge them; a plain rollback restores the config but not the "+
		"host state this attempt changed (#4960)",
		err, result.hostMutationSummary())
}

// runPostMutationSteps runs the fallible steps of the userspace-shim apply that
// execute AFTER pkg/dataplane.CompileConfig has already mutated live host
// state, annotating any failure with what moved (#4960).
//
// It exists as a named region rather than two inline `if err != nil` blocks in
// CompileUserspaceShim for two reasons:
//
//  1. It is the ONLY place the post-mutation abort contract is expressed, so a
//     step added to this window cannot be wired without inheriting it. Adding
//     one anywhere else in CompileUserspaceShim is then a visible choice rather
//     than an omission nobody notices.
//  2. It makes the contract testable. CompileUserspaceShim itself needs netlink
//     and root; this takes its steps as parameters, so
//     TestPostMutationStepsAnnotateBothAbortPaths drives both failure paths
//     unprivileged. The call site is compile-enforced — delete it and the
//     preflight and attach simply do not run.
//
// Steps run in order and short-circuit, matching the original control flow.
func runPostMutationSteps(result *CompileResult, steps ...func(*CompileResult) error) error {
	for _, step := range steps {
		if err := step(result); err != nil {
			return annotateHostMutationOnAbort(result, err)
		}
	}
	return nil
}
