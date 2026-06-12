# #1873 reviewer task-id ledger

| Round | Reviewer | Task id | Verdict |
|---|---|---|---|
| 1 | Claude SMR | (in-conversation) claude-smr-plan-r1.md | PLAN-NEEDS-REVISION (R1 config-domain assignment) |
| 1 | Codex | task-mqa4p6jy-k0oi3a (first dispatch task-mqa4mj62-tndk1i lost in shared runtime, never registered) | PLAN-NEEDS-REVISION (3 MAJOR: collision probing, eligibility determinism, live-validation gaps) |
| 1 | AGY | adversarial-review-mqa4memd-n0t6xo | PLAN-NEEDS-REVISION (CRITICAL slow-path plaintext leak refutes v1 fail-safe claim; eligibility gates; GRE-origin staleness) |
| 2 | Claude SMR | (in-conversation) claude-smr-plan-r2.md | PLAN-NEEDS-REVISION (R-C cold-path rescope; R-B groups union) |
| 2 | Codex | task-mqa5478t-h5yale | PLAN-NEEDS-REVISION (R-C must be slow-path-boundary invariant; full caller enumeration) |
| 2 | AGY | adversarial-review-mqa540ex-4eud0g | PLAN-NEEDS-REVISION (retry_pending_neigh plaintext MAJOR; Q1-Q8 ratified) |
| 3 | Claude SMR | (in-conversation) claude-smr-plan-r3.md | PLAN-READY-conditional, then SELF-RETRACTED anti-blanket argument (wg_control.rs:592) |
| 3 | Codex | task-mqa5gfj5-ceos57 | PLAN-READY (ratified conditional gate on refuted premise — superseded by v4) |
| 3 | AGY | adversarial-review-mqa5g6f6-abtkjf | PLAN-NEEDS-REVISION (verified admin-down plaintext trace kills conditional gate; netlink/oper-state revisions REJECTED as superseded by blanket) |
| 4 | Claude SMR | (in-conversation) claude-smr-plan-r4.md | PLAN-READY |
| 4 | Codex | task-mqa5sc25-bz2mkx | PLAN-READY |
| 4 | AGY | adversarial-review-mqa5s52d-b8j1xm | PLAN-READY |

Converged: PLAN-READY 3-of-3 at round 4 on plan v4 (blanket R-C gate).

## PR #1882 code review

| Round | Reviewer | Task id | Verdict |
|---|---|---|---|
| code-1 | Copilot | (review requested) | COMMENTED — quota limit, retry 1 documented |
| code-1 | Claude SMR | claude-smr-code-r1.md | MERGE-READY after self-found MAJOR fix 73f61b1db797 (reverse-only purge) |
| code-1 | AGY | adversarial-review-mqa9m9r0-p48whc (timed out) → retry adversarial-review-mqa9u6b2-lq3y1y | MERGE-READY at 73f61b1db797 |
| code-1 | Codex | task-mqa9mk6f-2etcct | MERGE-NEEDS-MAJOR (re-owned-id publication window) → fixed in 8909f3ac0e70 (purge-before-store + defer + rotation barrier) |
| code-2 | Copilot | (review re-requested at 70206ae04 — retry 2; retry 3 requested before round-2 push) | COMMENTED — quota limit |
| code-2 | AGY | review-mqaam2as-a3fgqq (job state under gemini state/1873-engineer-0721a2dc90c4f2cd/) | needs-attention (2 med 2 low, no verified counter-example) — mediums superseded by the r2 redesign; low (engine-Arc pin) FOLDED |
| code-2 | Codex | task-mqaaoq6a-6afsma | MERGE-NEEDS-MAJOR (1: private fabric-overlay Arc defeats the rotation barrier, worker/loop_body/mod.rs:617; 2: 250ms timeout fail-open) → fixed in 140f310bd (structural owner check: stored egress_ifindex vs row logical_ifindex at re-resolve + both encap builders; new-appearance purge arm; defer/barrier deleted) |
| code-2 | Claude SMR | claude-smr-code-r2.md | Confirmed both Codex findings; found+fixed the write-back erasure (gated resolution must PRESERVE stale egress_ifindex) and the first-apply purge guard; MERGE-READY pending Codex r3 ratification |
| code-3 | Codex | task-mqac5g2t-gzsjhm | MERGE-NEEDS-MAJOR (1: disarmed same-plan refresh purges boot-time synced sessions; 2: owner_rg_for_resolution re-homes gated sessions under the new owner's RG); CONFIRMED the r2 mis-encap traces are closed → both fixed in 59f6a0180 |
| code-3 | AGY | review-mqac445n-5cc54g (wrapper JSON-parse failed; full content in the job log) | needs-attention (medium: NoRoute->HAInactive reclassification — REFUTED, enforce_ha_resolution_snapshot early-returns non-{FC,MN,LD} dispositions at forwarding/mod.rs:542-549; low: first-apply guard vs soft resets — CONFIRMED, root-caused to stop_inner defaulting forwarding+validation; fixed in 59f6a0180 via PreservedReconcileState owners capture) |
| code-3 | Claude SMR | (in-conversation, this round) | Root-caused AGY's low to the reconcile-boundary inert-diff; found the preserved-replay resurrection hazard; verified owner-RG guard safety across all 19 call sites |
| code-4 | Codex | task-mqacrbqj-iot5f9 | MERGE-NEEDS-MAJOR (replay filter resurrects the derived reverse companion of a purged forward — verified trace via ha.rs:344 + coordinator/mod.rs:473); CONFIRMED both r3 MAJORs closed → fixed in 6cac0bec4 (filter_replayed_synced_sessions collects purge KEYS incl. reverse_session_key of dropped forwards — exactly Codex's prescription, independently implemented from AGY r4's identical finding before the Codex result landed) |
| code-4 | AGY | review-mqacrm2m-vflatf | no-ship (HIGH: same companion-resurrection hazard, NAT-companion counter-example) → fixed in 6cac0bec4 + pin replay_filter_drops_purged_forward_and_derived_reverse_companion |
| code-4 | Claude SMR | (in-conversation) | Verified the filter mirrors delete_synced_session companion semantics exactly (reverse-marked drops standalone; forward drop derives reverse key); gates clean at 6cac0bec4 (full 2027/0 rc0) |
| code-5 | Codex | task-mqad0msy-8t7xrh | MERGE-READY, no findings — verified 6cac0bec4 implements its r4 prescription faithfully (re-ran the F/R trace; key-semantic retention ratified; pin judged not-weak); r2-r4 fold chain re-confirmed closed |
| code-5 | AGY | review-mqad0vbm-nvew2i | MERGE-READY — companion fix mirrors delete_synced_session semantics; pin adequate; no new hazard from key-based retention |
| code-5 | Copilot | (re-requested at 2a4670695 and c4527957f — retries 4 and 5) | COMMENTED — quota limit; proceeding 3-of-4 per protocol |
| code-5 | Claude SMR | (in-conversation) | MERGE-READY at 24ca330c1 |

Converged: MERGE-READY 3-of-4 at code round 5 (Codex + AGY + Claude SMR; Copilot quota-blocked through 5 documented retries).

## Live validation round 2 (head 24ca330c1, 2026-06-12)

Deployed 24ca330c1 to both loss userspace nodes (rolling deploy, both
report g24ca330c1). wg-interop configure (wg0 endpoint id 16091 — the
hash-freeze pin value; control thread spawned once). Under
with-cluster.sh lock: REMOVED gr-0/0/0 (+sfmix zone+VR, 8 statements)
then RE-ADDED via rollback 1, with a continuous inner ping from the
kernel-WG peer across both commits:

- wg0 telemetry FROZEN across both commits: initiations 2,
  completions 2/1, session_confirmed 1 — no rebuild, no re-handshake.
- Journal: zero wg-control stop/spawn lines at either commit (only the
  original configure spawn for endpoint 16091).
- Inner ping: 263/263, 0% loss through remove+re-add.
- gr-0-0-0 netdev restored after rollback; cluster RG0/1/2 primary on
  node0, failover count 0; fw1 journal error-free.
- Teardown PASS (--keep peer kept for parent smoke); CoS re-applied
  (apply-cos-config atomic commit + verification OK).
