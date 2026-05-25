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

### Round 3 — 2026-05-25, plan v3 (pending push)

- Codex r4: (to be dispatched on v3 HEAD)
- Antigravity r3: (to be dispatched on v3 HEAD)

## Code review

(none yet)
