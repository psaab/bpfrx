// Package memlockcensus gates the set of tests that go INERT without the
// privilege to raise the memlock rlimit (#8371).
//
// THE DEFECT. 42 test sites across 19 files call `rlimit.RemoveMemlock()` and
// `t.Skipf` when it fails. Without CAP_SYS_RESOURCE the tests SKIP, the package
// still reports `ok`, and the guards they encode provide no protection. A
// reviewer greps, finds `TestApplyHelperStatusRejectsQueueIDBeyondStride`, and
// reasonably concludes the #4894 aliasing defect is guarded — and whether it is
// depends entirely on where the suite ran.
//
// This is the codebase's recurring failure shape — a check that fails to a
// value indistinguishable from healthy — applied to the checks themselves.
//
// MEASURED, because #8371 asks for the measurement before the fix and names it
// the first task. On the development host these guards do NOT run:
//
//	$ id -u        -> 1000        (not root)
//	$ ulimit -l    -> 8192        (8 MiB, cannot be raised unprivileged)
//	$ go test ./pkg/dataplane/userspace/ -run QueueIDBeyondStride -count=1 -v
//	    RemoveMemlock: failed to set memlock rlimit: operation not permitted
//	  --- SKIP: TestApplyHelperStatusRejectsQueueIDBeyondStride (0.00s)
//	  ok  github.com/psaab/xpf/pkg/dataplane/userspace  0.005s
//
// So this is not a CI-only concern deferred to a machine nobody watches. It is
// the primary development environment, where `make test-go` runs and where
// every change is first validated. All 42 are inert here, today.
//
// WHAT THIS PACKAGE DOES, and what it deliberately does not.
//
// It does NOT make the suite red when memlock is unavailable. That would turn
// every developer's `make test-go` red for an environment property they cannot
// change, and a gate everyone learns to ignore is worse than the silence it
// replaced.
//
// It makes the SET a gated quantity instead. The census below is a registry:
// a new memlock-gated guard cannot be added without appearing here, and a
// removed one cannot linger. That closes the reviewer-grep harm, because the
// registry names every guard whose protection is conditional, in one place, and
// the count cannot drift silently.
//
// And it makes the inertness LOUD where it matters: when memlock is
// unavailable, TestMemlockGuardsAreInertHere reports exactly which guards did
// not run, by name. Under XPF_REQUIRE_MEMLOCK_GUARDS=1 — for a privileged CI
// leg — it FAILS instead, so an environment that is supposed to execute them
// cannot silently stop.
package memlockcensus
