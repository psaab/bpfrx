package dataplane

import "sync"

// #8285 — the evidence that an aborted apply left host state behind must
// survive the RETRY, and today it does not.
//
// THE DEFECT. `CompileResult.hostMutations` (#4960/#7288) is per-COMPILE and
// is recorded only when the host ACTUALLY changed — `markHostMutated` fires
// from `if vlanCreated` and from `reconcileInterfaceAddresses` returning true,
// and its own doc gives the reason: "a converged re-apply records nothing and
// the message stays worth reading". `annotateHostMutationOnAbort` then returns
// the error UNCHANGED when nothing was mutated. Both are correct in isolation
// and together they lose the evidence exactly when it is needed:
//
//	apply #1  creates the VLAN child, reconciles addresses, aborts at the
//	          attach -> hostMutations non-empty -> the operator gets the full
//	          "this apply ALREADY changed live host state ... and there is no
//	          undo" annotation.
//	apply #2  the operator RETRIES. Phase 2 is now converged, so nothing is
//	          recorded, so hostMutations is EMPTY, so the abort returns a bare
//	          "attach userspace shim XDP: ..." with no mention that the box is
//	          still diverged.
//
// The divergence is identical across the two attempts — the host is on the new
// topology and the dataplane on the previous snapshot either way. Only the
// evidence disappears, and it disappears on the attempt the operator is most
// likely to be looking at: retrying is the expected response to a failed
// commit, and #7289's r1 established that the reachable trigger (a driver
// refusing an XDP attach) is PERSISTENT, so the un-annotated retry is the
// steady state after the first failure rather than an edge case.
//
// WHY A MANAGER CELL AND NOT A WIDER CARRIER. The question "what carries abort
// evidence" was chased through the whole apply path first (#8285's own body
// proposed threading `hostMutations` into `ApplyResult`, which is unreachable:
// an aborted apply never constructs one). Enumerated instead of assumed, the
// carrier already exists and is already consumed — the ERROR is returned
// unchanged through `manager_compile.go:246` and `manager.go:496` to
// `daemon_apply_dataplane.go`, which both joins it into the commit the
// operator sees AND stores it via `recordCompileFailure` ->
// `compileLastError` -> `CompileHealthSnapshot` -> `/health`. So nothing new
// has to be plumbed or rendered: the fix is to stop the EXISTING annotation
// from evaporating, and its consumers are the ones already reading it.
//
// The state is per-BOX because that is what the operator's question is ("is
// this box diverged"), while `hostMutations` answers a per-COMPILE question
// ("did this compile move anything"). Both are wanted; conflating them is what
// produced the gap.

// hostDivergenceCell is the sticky per-Manager record. Its own mutex: it is
// written from the abort path and read at the head of the next compile, and
// neither holds applyMu.
type hostDivergenceCell struct {
	mu sync.Mutex
	// actions are the hostMutations classes of the apply that aborted, kept so
	// the retry's message names what actually moved rather than degrading to a
	// generic "something changed". Empty means converged (or never diverged).
	actions map[string]bool
}

// recordHostDivergence remembers the host state this ABORTING apply leaves
// unconverged, so a later retry can still report it.
//
// Merges rather than replaces: two successive aborts can move different
// classes, and the box carries the union until a successful apply converges it.
func (m *Manager) recordHostDivergence(result *CompileResult) {
	if m == nil || !result.HostMutated() {
		return
	}
	m.hostDivergence.mu.Lock()
	defer m.hostDivergence.mu.Unlock()
	if m.hostDivergence.actions == nil {
		m.hostDivergence.actions = map[string]bool{}
	}
	for a := range result.hostMutations {
		m.hostDivergence.actions[a] = true
	}
}

// inheritHostDivergence stamps a retained divergence onto THIS compile's
// result, so `annotateHostMutationOnAbort` — which reads only the result —
// annotates a retry whose own Phase 2 found the host already converged.
//
// Stamping the result rather than adding a second annotator is deliberate:
// there is exactly one place that renders this fact, so the operator cannot
// read it twice in two formats, and a step added to the post-mutation window
// keeps inheriting the contract from `runPostMutationSteps` unchanged.
func (m *Manager) inheritHostDivergence(result *CompileResult) {
	if m == nil || result == nil {
		return
	}
	m.hostDivergence.mu.Lock()
	retained := make([]string, 0, len(m.hostDivergence.actions))
	for a := range m.hostDivergence.actions {
		retained = append(retained, a)
	}
	m.hostDivergence.mu.Unlock()
	for _, a := range retained {
		result.markHostMutated(a)
	}
}

// clearHostDivergence records that an apply COMPLETED, so the host and the
// dataplane agree again and the retained evidence must stop firing.
//
// Called only from the success tail of a compile. Clearing anywhere else — on
// an abort, or at the head of an apply — would drop the fact while it is still
// true, which is the defect this file exists to fix, inverted.
func (m *Manager) clearHostDivergence() {
	if m == nil {
		return
	}
	m.hostDivergence.mu.Lock()
	m.hostDivergence.actions = nil
	m.hostDivergence.mu.Unlock()
}

// debugHostDivergence reports the retained classes (test-only).
func (m *Manager) debugHostDivergence() []string {
	m.hostDivergence.mu.Lock()
	defer m.hostDivergence.mu.Unlock()
	out := make([]string, 0, len(m.hostDivergence.actions))
	for a := range m.hostDivergence.actions {
		out = append(out, a)
	}
	return out
}
