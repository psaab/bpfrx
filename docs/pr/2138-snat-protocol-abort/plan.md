# #2138 — persistent-SNAT protocol mismatch must abort the commit

**Status:** v3 — IMPLEMENTED. Codex r1 PLAN-NEEDS-MINOR (premise holds,
no brick regression, all claims independently verified; 3 minors folded
into v2 + code). Gemini companion is decommissioned ("no longer
supported for individuals, migrate to Antigravity") — AGY is the
substitute second reviewer, dispatched at code-review time. Fix + tests
committed; `go test ./pkg/dataplane/... ./pkg/daemon/...` green;
`go build ./...` clean; abort/predicate tests confirmed
non-tautological (FAIL against a scheduler-only abort set).

## Codex r1 minor findings (folded into v2)

1. **Unused `errors` import.** After `compileErrorMustAbortApply`
   delegates to `dpuserspace.IsRequiredProtocolGateError`, `errors` is
   no longer referenced in `daemon_apply.go` (its only use was the
   `errors.Is` at line 1325). The implementation MUST remove the
   `"errors"` import or `go build` fails. — Added to the design.
2. **"Abort commit" wording is imprecise.** `Store.Commit*` /
   `Store.SyncApply` promote+persist BEFORE `applyConfigLocked` runs
   (store.go:1169 / store.go:621), and existing comments
   (daemon_apply.go:349) rely on that ordering. The fix aborts the
   **apply/commit-RPC result** the operator sees — it does not roll
   back store promotion. This is the accepted scheduler-gate contract.
   Wording tightened below + in the new code comments.
3. **Comments name only the scheduler sentinel.** daemon_apply.go:351
   and daemon_snmp_reconcile_test.go:74 reference only
   `ErrPolicySchedulerProtocolIncompatible`. After this change they must
   read "required userspace protocol gate" (or name both sentinels). —
   Added to the design.

## Issue framing

Severity HIGH (codex-review-016, verified against master `12becabc4`).

When the Rust AF_XDP helper's `ConfigSnapshotProtocolVersion` is below
the version required to honor a feature in the config, the userspace
`Manager.ApplyConfig` correctly **fail-closes**: it disarms the helper
(`set_forwarding_state Armed=false`) and returns a protocol-incompatible
sentinel error. The daemon's commit pipeline
(`pkg/daemon/daemon_apply.go:693-696`) only **aborts the commit** when
`compileErrorMustAbortApply(err)` is true.

`compileErrorMustAbortApply` (daemon_apply.go:1324-1326) currently checks
**only** `dpuserspace.ErrPolicySchedulerProtocolIncompatible`. The
sibling sentinel `ErrPersistentSourceNATProtocolIncompatible` is NOT in
the abort set.

Consequence: commit a persistent-source-NAT config against a too-old
helper →

1. `ApplyConfig` returns `ErrPersistentSourceNATProtocolIncompatible`
   and disarms the helper (forwarding off).
2. `compileErrorMustAbortApply` returns false → the commit is treated as
   non-aborting.
3. The candidate is **promoted and persisted** while the dataplane is
   fail-closed/disarmed. The operator sees a "successful" commit against
   a dead dataplane. **Silent data-path outage.**

The persistent-SNAT protocol gate is the exact same semantic class as
the policy-scheduler gate (both: "this config cannot be committed against
this helper protocol version"). The fix is to treat **all** required
protocol-gate sentinels as commit-aborting, and to make the set
table-driven so the next protocol gate cannot repeat the omission.

## Honest scope/value framing

This is a one-omission control-plane correctness bug. The win is
operator-visible fail-closed semantics: a commit that would silently
kill forwarding instead fails loudly with a clear message, so the
operator does not promote a config the helper cannot honor. The blast
radius of the fix is tiny (one predicate + a shared sentinel list +
tests). There is no perf dimension.

If reviewers conclude the fix is wrong (e.g. that persistent-SNAT should
NOT be commit-aborting, or that the lenient-load path would be broken),
PLAN-KILL is an acceptable verdict.

## What's already shipped / partially in place

- `ErrPolicySchedulerProtocolIncompatible` and
  `ErrPersistentSourceNATProtocolIncompatible` are both defined in
  `pkg/dataplane/userspace/manager.go:31-32`.
- `ensureRequiredSnapshotProtocolLocked` (manager.go:1098-1103) chains
  `ensurePolicySchedulerProtocolLocked` then
  `ensurePersistentSourceNATProtocolLocked`. Both return their sentinel
  (wrapped) when the helper protocol is too old AND the config uses the
  feature. **No change needed in the manager** — it already produces the
  right sentinel and already disarms.
- `compileErrorMustAbortApply` only matches the scheduler sentinel —
  this is the single line to fix.
- Existing tests that establish the pattern to mirror:
  - `pkg/daemon/compile_error_policy_test.go` — predicate unit test.
  - `pkg/daemon/policy_scheduler_apply_test.go` — `applyConfigLocked`
    abort tests with an injectable-`compileErr` test DP.
  - `pkg/daemon/daemon_snmp_reconcile_test.go` — documents that the SNMP
    reconcile runs BEFORE the aborting dataplane apply.
  - `pkg/dataplane/userspace/manager_test.go:2939` —
    `TestEnsureRequiredSnapshotProtocolRejectsOldHelperForPersistentSourceNAT`
    already proves the manager returns the sentinel.

## Lenient-load doctrine (#1960) — preserved by construction

The critical invariant: a too-old helper must **fail the commit loudly**
(operator sees it) but must **NOT brick a node on boot or peer-sync**
(an already-persisted or peer-synced persistent-SNAT config still boots
through — warn, not fail-closed-on-load).

This is already guaranteed by *which apply wrapper* each caller uses, and
the fix does not change any of that:

| Caller | Wrapper | Error handling | Effect of fix |
|---|---|---|---|
| HTTP/gRPC/CLI commit | `commitAndApply` / `commitConfirmedAndApply` | **returns err** → commit fails | **commit now aborts (the fix)** |
| Boot apply (`daemon_run.go:671`) | `applyConfig` (void) | `slog.Warn` + **swallow** | unchanged — boots through, warns |
| Peer config-sync recv (`daemon_ha_sync.go:368`) | `syncAndApply` → caller logs `slog.Error` + returns | store already promoted; logs, continues | unchanged — node stays consistent with peer, helper disarmed + alarm, no brick |
| DHCP/feed/event/poll re-apply | `applyConfig` (void) | `slog.Warn` + swallow | unchanged |
| commit-confirmed auto-rollback (`executeConfirmedRollback`) | `applyConfigLocked` directly | `slog.Error` + continue | unchanged |

The protocol mismatch is **not** an `ErrConfigCompile` — the config
compiles fine; the helper is simply too old at apply time. So it never
flows through the #1960 `classifyLoadError` / `computeBootClass`
fail-closed-on-COMPILE-failure path. The boot path applies the persisted
config via the **swallowing** `applyConfig` wrapper, which logs and
continues regardless of the abort predicate. The abort predicate only
changes behavior for callers that *propagate* the error — and the only
such caller that surfaces to an operator is the commit path. That is
exactly the desired fail-closed-at-commit / lenient-at-load split.

## Required vs optional protocols

Only **required** protocol gates abort. The two existing sentinels are
both required gates produced by `ensureRequiredSnapshotProtocolLocked`
(the function name encodes it): the helper literally cannot honor the
config, so committing it is meaningless. There is no "optional protocol"
sentinel in this set today; the table is scoped to the
`ensureRequired*` family. Optional/best-effort capabilities are surfaced
via `UnsupportedReasons` / capabilities, not via these sentinels, and are
out of scope.

## Concrete design

Single source of truth lives next to the sentinels, in
`pkg/dataplane/userspace`. The daemon delegates.

### 1. Exported sentinel set + predicate (manager.go)

Add, immediately after the two sentinel `var` declarations:

```go
// requiredProtocolGateSentinels enumerates every "this config cannot be
// committed against the helper's current ConfigSnapshotProtocolVersion"
// sentinel produced by ensureRequiredSnapshotProtocolLocked. A commit
// that hits any of these MUST abort (fail-closed at commit) rather than
// promote a config the helper cannot honor. The boot/peer-sync apply
// paths use the swallowing apply wrapper, so a node still boots through
// an already-persisted/peer-synced config (warn, not brick) — see
// docs/pr/2138-snat-protocol-abort/plan.md.
//
// Every future ensureRequiredSnapshotProtocolLocked gate MUST add its
// sentinel here so the commit-abort policy can never silently omit it.
var requiredProtocolGateSentinels = []error{
	ErrPolicySchedulerProtocolIncompatible,
	ErrPersistentSourceNATProtocolIncompatible,
}

// IsRequiredProtocolGateError reports whether err is (or wraps) any
// required helper-protocol gate sentinel — the set that must abort a
// commit. Used by the daemon commit policy (compileErrorMustAbortApply).
func IsRequiredProtocolGateError(err error) bool {
	for _, sentinel := range requiredProtocolGateSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}
```

`errors` is already imported in manager.go.

### 2. Daemon delegates (daemon_apply.go)

```go
func compileErrorMustAbortApply(err error) bool {
	return dpuserspace.IsRequiredProtocolGateError(err)
}
```

This keeps the existing single call site (daemon_apply.go:695)
unchanged, preserves the existing function name (referenced in three
test files + comments), and removes the omission hazard: a new gate is
covered the moment its sentinel is added to the list beside the gate.

**Remove the now-unused `"errors"` import** from daemon_apply.go (Codex
r1 #1): the delegation drops the only `errors.Is` use in the file.

### Precise abort semantics (Codex r1 #2)

"Abort" here means **the apply/commit-RPC result returned to the
operator becomes non-nil**, so the HTTP/gRPC/CLI commit reports failure.
`Store.Commit` / `Store.CommitConfirmed` / `Store.SyncApply` have ALREADY
promoted+persisted the compiled config before `applyConfigLocked` runs
(store.go:1169 / store.go:621), so the abort does NOT unwind store
promotion — identical to the existing scheduler-gate behavior and the
contract the daemon_apply.go:349 SNMP-reconcile-ordering comment already
documents. The operator-visible signal is the failed commit + the
disarmed helper; the store row is the accepted post-condition for this
gate class (out of scope to change — see OQ-6).

### Comment generalization (Codex r1 #3)

Update the two comments that name only the scheduler sentinel to name
the gate CLASS:
- daemon_apply.go:351 — "...returns early on a required userspace
  protocol gate error (compileErrorMustAbortApply: policy-scheduler OR
  persistent-source-NAT protocol incompatibility)".
- daemon_snmp_reconcile_test.go:74 — same generalization.

### Why the list lives in `pkg/dataplane/userspace`, not a new package

The issue suggests `pkg/daemon/applyerrors` or
`pkg/dataplane/userspace/protocolgate`. Putting the list *next to the
sentinels and the `ensureRequired*` gate that emits them* is the
strongest anti-omission placement: a developer adding a third gate edits
one file and sees the list. A separate package adds an import edge and a
second place to forget. No new package is warranted for a 2-element
list.

## Public API preservation

- `compileErrorMustAbortApply(error) bool` — signature unchanged, still
  the single decision point in the commit pipeline.
- New exported `dpuserspace.IsRequiredProtocolGateError(error) bool` —
  additive.
- `requiredProtocolGateSentinels` — unexported; the public surface is
  the predicate.
- `ApplyConfig`, `ensureRequiredSnapshotProtocolLocked`,
  `disarmSnapshotProtocolFailureLocked` — all unchanged.

## Hidden invariants the change must preserve

1. **Side-effect ordering at commit**: `Store.Commit()` promotes/persists
   BEFORE `applyConfigLocked` runs. The fix does not move the abort
   relative to the store promotion — the candidate is already promoted
   when the abort fires, identical to the existing scheduler abort. The
   commit RPC still returns the error to the operator. (This is the same
   shape the SNMP-reconcile-before-abort comment at daemon_apply.go:349
   already documents and relies on; no regression.)
2. **Helper already disarmed before the abort**: `ApplyConfig` disarms
   (Armed=false) before returning the sentinel; the abort propagates the
   disarm result via `errors.Join` if the disarm itself failed. The
   daemon's abort does not re-arm. Fail-closed end-to-end.
3. **Lenient load/boot/peer-sync**: unchanged (table above). No node is
   bricked on restart with an already-committed persistent-SNAT config
   against an old helper.
4. **No double-abort / no new early-return site**: the call site
   (daemon_apply.go:695) is unchanged; only the predicate's match set
   widens.
5. **`deferWorkers` clear-on-abort**: the existing
   `TestApplyConfigClearsDeferWorkersOnAbortCompileError` proves the
   defer-state is still cleared on an aborting compile error; persistent-
   SNAT now takes the same abort branch, so the same cleanup applies.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (control plane) | LOW | Single predicate widens its match set; commit path already handled the scheduler sentinel identically. |
| Lifetime / borrow (N/A Go) | N/A | Go; no ownership change. |
| Performance regression | NONE | Commit-time only; not a data-path change. |
| Architectural mismatch | LOW | This is the issue's own suggested fix (table-driven abort set, single predicate). Not a speculative pattern. |
| Lenient-load brick-on-restart | LOW | Verified: boot/peer-sync use swallowing wrappers; protocol mismatch is not ErrConfigCompile. |

## Test plan

- `go build ./...` clean.
- `pkg/daemon/compile_error_policy_test.go`: extend
  `TestCompileErrorMustAbortApply` to assert
  `ErrPersistentSourceNATProtocolIncompatible` (bare + wrapped) aborts,
  and a non-protocol error does not.
- New daemon apply test (mirror the scheduler ones) asserting a
  persistent-SNAT protocol mismatch through the **commit-style**
  `applyConfigLocked` path RETURNS the sentinel (commit aborts), while a
  **lenient** call through the void `applyConfig` wrapper SWALLOWS it
  (returns/continues without surfacing). Reuse the existing
  `policySchedulerApplyTestDP` (injectable `compileErr`). The test must
  be non-tautological: it must FAIL against pre-fix code (where the
  persistent-SNAT sentinel is not in the abort set, so
  `applyConfigLocked` would NOT return it / would continue past the
  dataplane apply).
- New `pkg/dataplane/userspace` unit test for
  `IsRequiredProtocolGateError`: true for both sentinels (bare +
  wrapped), false for an unrelated error.
- `go test ./pkg/dataplane/... ./pkg/daemon/...` green.
- Full `go test ./...` (30 Go packages) green.

### Why no CoS/iperf smoke matrix

This is a Go control-plane commit-policy change. It does not touch the
Rust dataplane, the AF_XDP fast path, the CoS classifier/shaper, or any
forwarding code. The loss-cluster CoS smoke matrix exercises none of the
changed lines. The validation that matters here is the unit-test gate
above (commit aborts / load is lenient), which is deterministic and
hermetic. A throughput smoke would be theater. (Stated explicitly per
the skill's smoke requirement — declining it with a reason, not
skipping silently.)

## Out of scope (explicitly)

- Re-arming the helper after a protocol mismatch (the disarm is correct
  fail-closed behavior).
- Any change to the manager's gate logic or the sentinels themselves.
- Surfacing the disarm as a distinct CLI/commit-check warning beyond the
  error message (the error message already names the required vs current
  protocol version).
- A `commit check` (dry-run) path change. `commit check` compiles but
  does not apply, so it does not hit `ApplyConfig`; the protocol gate is
  an apply-time runtime check, not a compile-time one. Surfacing the
  protocol mismatch at `commit check` would require querying the live
  helper status during dry-run and is a separate enhancement — noted as
  a possible follow-up, not done here.

## Open questions for adversarial review

1. **Is delegating `compileErrorMustAbortApply` to a userspace-package
   predicate the right layering?** The daemon already imports
   `dpuserspace` and references its sentinels directly, so the import
   edge exists. Is there a reason the abort-set SSOT should instead live
   in `pkg/daemon`? (PLAN-KILL if the layering is wrong.)
2. **Does any boot or peer-sync path actually propagate this error
   fatally?** I traced boot→`applyConfig` (swallow) and
   peer-sync→`syncAndApply`→caller `slog.Error`+return (non-fatal, store
   already promoted). Is there a startup path I missed that would now
   brick a node carrying a persisted persistent-SNAT config against an
   old helper?
3. **Is persistent-SNAT genuinely a REQUIRED gate (must abort), or
   should it degrade gracefully?** The manager already disarms forwarding
   on this mismatch, so "continue with forwarding disabled" is strictly
   worse than aborting. Is there an operational scenario where promoting
   the config while the helper is disarmed is the desired behavior?
4. **`commit check` gap.** Should the protocol mismatch be surfaced at
   `commit check` (dry-run) too, or is apply-time abort sufficient? I
   scoped it out (commit check doesn't apply). Is that acceptable, or is
   a too-old helper a config error that `commit check` must catch?
5. **Are there OTHER `ensureRequired*`-class mismatches that disarm but
   don't abort** beyond these two sentinels, that this table should also
   cover today? (I found exactly the two chained in
   `ensureRequiredSnapshotProtocolLocked`.)
6. **Store-promotion ordering.** The candidate is promoted/persisted
   before the abort fires (same as the scheduler gate). Is a promoted-but-
   aborted store a problem on its own, or is the existing scheduler-gate
   behavior the accepted contract? (If the former, that is a pre-existing
   issue beyond #2138's scope, but call it out.)
