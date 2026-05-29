# #1630 cause-1 credit carry — reviewer task IDs

Branch: `fix/1630-cause1-credit-carry` (off origin/master)
PR: #1650
Head SHA: f9563b9a8 (code frozen at 7e6f7115f; post-Copilot delta is docs-only)

4-way code review seats — CLEAN 4-of-4 at HEAD f9563b9a8:
- **Claude SMR**: `docs/pr/1630-cause1-credit-carry/claude-smr-code-r1.md` — MERGE-READY
- **Codex r1**: direct companion task (fresh, session a8c1b014) — 1 Major + 1 Medium (floored-boundary), both FIXED in 4a2b998f7.
- **Codex r2 RE-CONFIRM**: fresh thread `019e7204-d7b4-7d93-8c9d-d22f73d15da8`, checked out HEAD f9563b9a8 directly — **MERGE-READY**. Verified with quoted lines: (a) the boundary MAJOR is resolved by the exact-ns thresholds (`(K+1)*EPOCH-1ns > K*EPOCH` → regime 2, not a near-(K+1) regime-1 grant); (b) the `(2K-1)*rate*EPOCH` per-rotation bound holds at BOTH the `(K+1)*EPOCH-1ns` and `STALL*EPOCH+1ns` boundaries and for ANY repeated regime-2-bank → regime-1-drain sequence (carry clamped at carry_max via `.min(carry_max)`, drain ≤ K-1 epochs); (c) the worst-case ceiling test exercises the tight maximum (fill to CARRY_MAX, rotate at exactly K*EPOCH = regime 1, assert exactly K+(K-1) epochs). No remaining counter-example.
- **AGY**: `review-mpqel5m5-2skf6n` — MERGE-READY across 6 axes, no findings.
- **Copilot**: formal `copilot-pull-request-reviewer` review on PR #1650 — same boundary Major (fixed 4a2b998f7) + plan.md doc nit (fixed 7e6f7115f).

Cluster validation: scoped Gate-1 SOLO v4 100m 95.0% / 1g 95.3% PASS;
`make test-failover` 13/0. cause-2 resolved-as-physics → `Closes #1630`.

Merge gate: 4-of-4 MERGE-READY + scoped Gate-1 (100m/1g ≥95% SOLO) +
full smoke matrix + `make test-failover`. 3-of-4 allowed only with a
documented Codex/Copilot-infra-blocked exception
(feedback_codex_infra_must_retry).
