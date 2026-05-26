# #1528 Reviewer IDs

## Plan review

### Round 1 — 2026-05-25, plan v1 (45a74d79)

- Codex: task-mplct48n-8mmrjq (dispatched 08:35Z, FAILED 08:36Z — sandbox missing, ENV-BLOCKED)
- Codex retry 2: task-mplcwinw-aayd43 (dispatched 08:40Z, FAILED — sandbox missing, ENV-BLOCKED)
- Antigravity: adversarial-review-mplctf86-k90pc7 (dispatched 08:35Z, completed 09:08Z — PLAN-NEEDS-MAJOR)
  - Q2 YES: Option A stored-config rolling-upgrade bug verified
  - Q5 socket-mem keep+rewrite preferred (folded into v2 §4.4)
  - Q10 hallucinated PR #1553 canary as master-side — corrected in v2 §9

### Round 2 — 2026-05-25, plan v2 (b645259a)

- Codex r3: task-mpld4f7u-l7ixka (dispatched 09:20Z, completed) — **PLAN-NEEDS-MAJOR**
  - Finding 1: rewrite walks raw tree, misses apply-groups + ${node} expansion
  - Finding 2: v2 Q11 HA-sync claim is wrong (SyncApply uses compileTree, rejects DPDK cleanly)
  - Finding 3: ConfigTree.FindPath doesn't exist publicly
  - Finding 4: rewrite leaves orphan DPDK sub-stanza (cores/memory/rx-mode/ports)
  - Informational: pkg/dataplane/runtime/import_canary_test.go:47 still has dpdk forbidden-backend
- Antigravity r2: adversarial-review-mpld4tso-19877w (dispatched 09:20Z, completed) — **PLAN-READY**
  - Confirmed v2 Q11 HA-sync is correct behavior (compile rejects, no flap)
  - Confirmed DeletePath is right public API; placement OK; no audit-journal phantom
  - Self-corrected r1 Q10 hallucination (no master-side leakage canary file)
  - **Missed findings 1, 3, 4** — Codex r3 is strictly superior here

### Round 3 — 2026-05-25, plan v3 (f8b4caf4)

- Codex r4: task-mplgjwea-goeioj (dispatched 10:30Z, FAILED — sandbox missing, expired from job queue before result fetch)
- Codex r5 retry: task-mpm3bsbi-hsom0r (dispatched 21:10Z, LOST from companion job-history wipe — see feedback_codex_session_loss_continuation)
- Codex r5 inline-diff retry: task-mpm7n2n2-ty9kjd (completed) — **PLAN-NEEDS-MINOR**
  - Confirmed apply-groups + ${node} fix is correct (bypass after ExpandGroups)
  - Confirmed 4-function API is appropriate for current scope
  - **MINOR (blocking)**: schema-validate edge — Store.Load runs schemaValidateExpandedTree before compileTreeForLoad. If cmdtree.SchemaValidate ever expands to walk `system dataplane`, the load-blackout returns.
  - Verified against actual source (pkg/cmdtree/schema_validate.go:35-57): SchemaValidate is currently scoped to class-of-service schedulers only, so the concern is unfounded TODAY. v3.2 adds explicit tests + §4.7 contract to lock in the scope.

### Round 4 — 2026-05-26, plan v3.2 (54020dda)

- Codex r6: task-mpm8d1qz-9bj4nh (dispatched ~00:35Z, inline-content workaround)
- Antigravity r4: adversarial-review-mpm8dgta-xdoziu (dispatched ~00:35Z)
- Antigravity r3: adversarial-review-mplgkdgz-ikpdw1 (completed 17:08Z) — **PLAN-READY**
  - All 4 Codex r3 findings correctly addressed by load-mode bypass
  - Confirmed only validateDataplaneTypeStrict is gated; siblings run regardless
  - Confirmed orphan sub-stanza walkthrough: effectiveDataplaneType("dpdk") returns "dpdk", no case matches in §4.3-deleted switch, sub-stanza silently dropped (consistent semantic)
  - Confirmed daemon_run.go:247 sentinel-Is path now reachable
  - Confirmed SyncApply rejects DPDK at compile (no flap)
  - Confirmed four-function API > variadic options
  - Minor: add TestCompileConfigForLoad_BypassesDPDKRejectViaApplyGroups for explicit apply-groups coverage (folded into plan)
  - Self-corrected r2: didn't trace ExpandGroups + SyncApply paths separately; now done

### Round 4 — 2026-05-26, plan v3.2 (54020dda)

- Codex r6: task-mpm8d1qz-9bj4nh (completed, inline-content workaround) — **PLAN-NEEDS-MINOR**
  - One finding: TestSchemaValidate_AcceptsLegacyDPDKSubStanza fixture has no class-of-service subtree, so the test only proves the early-return behavior. A future PR adding a top-level system-dataplane walker independently of the cos early-return would silently bypass the gate.
  - Confirmed apply-groups + ${node} fix, 4-function API, mechanical-removal scope all clean
- Antigravity r4: adversarial-review-mpm8dgta-xdoziu (completed) — **PLAN-READY**
  - Did not flag the fixture-strength minor

### Round 5 — 2026-05-26, plan v3.3 (3328cc49)

- Codex r7: task-mpmbxohf-mft8dk (dispatched ~02:00Z, inline-content workaround)
- Antigravity r5: adversarial-review-mpmby226-tvzsfa (completed) — **PLAN-READY**

## Code review

### PR #1560 (HEAD ecc4d5b8 — PRE-REBASE)

- Codex: task-mpmf8tph-0dwkmf (FAILED sandbox)
- Codex inline retry: task-mpmfed3l-q8pe15 (CANCELLED — rebase required)
- Antigravity: adversarial-review-mpmf9e1k-p2wray (completed) — **MERGE-READY** (pre-rebase semantics; load-mode bypass)
- Copilot: COMMENTED with one inline nit on retirement-phase wording (addressed in 90ef4637)
- Claude SMR: posted as PR comment (issuecomment-4542722009) — **MERGE-READY** (pre-rebase semantics)

### PR #1560 (HEAD 4f348ee9 — POST-REBASE onto master 13fa1009)

Rebase folds master's `rewriteRetiredDataplaneType` (#1558) and removes this PR's load-mode bypass machinery in favor of the master-provided bridge. Also drops PR #1553's `cfg.System.DPDKDataplane = nil` runtime nil-clear + leakage canary file since the field is now compile-time gone.

- Codex: task-mpmfvd7r-ez277q (dispatched ~03:30Z, inline-content workaround)
- Antigravity: adversarial-review-mpmfusl5-is2lz8 (dispatched ~03:30Z)
- Copilot: re-triggered via `@copilot review` comment after rebase (~03:30Z)
- Claude SMR: posted as PR comment (issuecomment-4542908276) — **MERGE-READY** (post-rebase semantics; master rewrite path verified)
