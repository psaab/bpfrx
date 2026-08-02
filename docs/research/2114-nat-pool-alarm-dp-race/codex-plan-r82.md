# Codex hostile plan-review — round 82 (plan v83 @ c3c4cad42)

Task: task-msb5i7ke-k75npa (session 019fc031-69ad-7a91-bb96-768ba09689b8).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — the registry canary still neither exact nor aligned with the real publisher (the named writer is the wrapper; the writes live in loadUserspaceShimObjectsOnce; no allowed-shapes enumeration; the Lock→hook→Unlock→access anti-pattern passes); the whole-batch lock interval contradictory (a body-wide hold self-deadlocks on the :154 selector) — 5 MINOR: hook protocol; retained-oracle privilege split; summary carve-out erasures; closure wording; qualification propagation + stale scope text). 'Repairable specification defects, not grounds for PLAN-KILL.' Raw companion output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 2 major, 5 minor

Yes. Findings 1–2 are entirely inside PR-1 and block `PLAN-READY` for #2114. They are repairable specification defects, not grounds for `PLAN-KILL`. G+H+H2 were not reviewed or scored.

### Findings

1. **MAJOR — the registry canary is still neither exact nor aligned with the real publisher.**

   The allegedly exact allowlist names “the registry helper function” without giving it an identifier or signature, and names `loadUserspaceShimObjects` as the writer ([plan.md:4735](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4735)). In the real code:

   - `loadUserspaceShimObjects` is only a wrapper ([loader_userspace_shim.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:95)).
   - The registry writes are in `loadUserspaceShimObjectsOnce`, beginning at [line 106](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:106), with writes at [185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185), [187](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:187), and [190](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:190).

   Therefore the stale-allowlist self-check immediately rejects the named writer, while the actual writer is forbidden.

   The plan also never enumerates the helper/writer’s allowed read/write shapes, receiver matching, or counts. A canary plus hook still passes the invalid implementation `Lock → hook → Unlock → m.maps[name]`: the access remains in the allowlisted helper and the hook observes ownership, but the access is unlocked.

   The syscall-only seam rule at [plan.md:4749](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4749) is directionally correct, but no concrete acquisition/publication boundary or lower-level injection points are specified. V83 must name the helper and choose either:

   - acquisition returning a bundle followed by a small named locked publisher; or
   - the actual `...Once` writer, with structural call-site/lock enforcement.

   **Answer:** the canary is not implementable as currently specified.

2. **MAJOR — the whole-batch lock interval remains contradictory; one interpretation self-deadlocks.**

   V83 says the hold spans `LoadUserspaceShim`’s “body” ([plan.md:3217](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3217), [5310](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:5310)), but elsewhere only requires it to span the loader call and Store ([plan.md:4743](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4743)).

   A body-wide hold deadlocks: `LoadUserspaceShim` calls `SelectUserspaceXDPShimEntryProgram` at [loader.go:154](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:154), while A3 makes that public selector acquire the same non-reentrant mutex ([plan.md:3854](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3854)).

   The cleanup calls at [loader.go:155](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:155) and [158](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:158) touch no registry. They perform `ReadDir`/`Remove` and pinned-link load/Unpin/Close operations ([loader.go:267](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:267), [288](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:288)). If included, they block every proposed registry/XDP accessor, including status calls at [maps_sync.go:481](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:481) and [947](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/maps_sync.go:947).

   Moreover, holding around the entire loader call puts collection construction and pinning under the mutex, contradicting the explicit “construction and pinning stay outside” rule at [plan.md:3753](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3753).

   **Answer:** the cleanups must be explicitly outside. At minimum, locking begins after the selector and both successful cleanups. To preserve the stated short-hold invariant, acquisition must also occur outside, followed by one locked publication+Store section. The current Store is at [loader.go:164](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:164), not `:163`.

3. **MINOR — the helper-ownership primitive can be deterministic, but the complete proof protocol is underspecified.**

   The referenced `:632` pattern permits an in-section `TryLock` assertion ([plan.md:4684](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4684)); choosing that branch gives a deterministic ownership check. Merely observing that a racing writer has not completed, however, can false-green if it has not reached `Lock`.

   The helper hook and batch hook also cannot both be awaited while the first holds `m.mu`: the second cannot execute. Specify instance-scoped hooks, arm only one ownership hook per test, and require either `TryLock()==false` inside the actual access interval or a before-lock/after-acquire handshake. As written, the two-hook coordinator is not pinned.

4. **MINOR — the all-entry retained oracle overclaims what unprivileged tests can prove.**

   The plan says runtime tests drive all entries ([plan.md:3623](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3623)) and that retained mutations reach retained maps ([plan.md:4704](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4704)). Sentinel/absent registries can prove classification and blocking for every entry, but not real mutation semantics: registry values are concrete `*ebpf.Map` values ([loader.go:37](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:37)), and existing tests skip real-map semantics without BPF privileges ([maps_session_clear_test.go:14](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_session_clear_test.go:14)).

   Split this into always-on all-entry classification/ownership tests plus privileged semantic mutation legs, or add a map-operation seam.

5. **MINOR — the loaded-check carve-out remains erased in later summaries.**

   The detailed rule is correct at [plan.md:3634](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3634) and [3688](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3688), matching `AttachXDP`, `AttachTC`, and `CompileConfig` ([loader.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:490), [1082](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1082), [compiler.go:182](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go:182)).

   But [plan.md:3886](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3886), [4407](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4407), and the fresh oracle at [4625](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4625) again say class 1 simply returns the typed error. Fold m1 is only partial.

6. **MINOR — the closure wording remains internally false.**

   Section 4.7 still says two windows are “NARROWED without closure” and then says registry selection is **CLOSED**, with narrowing applying only to teardown ([plan.md:4032](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4032)).

   It also calls the Close-entry Store a narrowing of “fresh-state admission” ([plan.md:4034](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4034), although Close retains a nonempty registry and ordinary methods therefore classify as retained and proceed. The actual narrowing is limited to the loaded-check set. Fold m3 is incomplete.

7. **MINOR — oracle qualifications are present but not consistently propagated.**

   The detailed §9 fold correctly names nil config, canceled context, cleanup failures, pin removal, and the two-invocation shape ([plan.md:4660](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4660)). But §7 omits the canceled-context precedence, and §9 repeats the unconditional “rejection fires whenever `loaded==false`” at [plan.md:4673](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4673). `ApplyConfig` checks cancellation first ([apply.go:238](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:238)).

8. **MINOR — convergence inventory still has stale scope text.**

   Section 4.7 still calls the enforcement a “canary pair” ([plan.md:4023](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4023)) after adding the registry canary. It also retains the old “ship it all” escape hatch ([plan.md:4056](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4056)), contradicting the executed PR-1-only split at [4065](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4065). I found no technical PR-1 dependency on G/H/H2; this is textual leakage only.

Fold m4 passes: the `UpdateFabricFwd` citation and higher-precedence qualification now match the tree. No files were changed.

Codex session ID: 019fc031-69ad-7a91-bb96-768ba09689b8
Resume in Codex: codex resume 019fc031-69ad-7a91-bb96-768ba09689b8
