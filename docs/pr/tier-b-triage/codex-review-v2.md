# Codex round-2 PLAN review — Tier B triage v2

Task ID: task-most74ue-n3nz7b
Codex session ID: 019df8d9-4584-7b31-b1a4-304308454fee

---

**Verdict: PLAN-NEEDS-MINOR**

Do not execute until the citations are cleaned up. The recommendations are substantively right, but v2 still contains reference errors that will mislead future closeout comments.

**Findings**

- `#917` slot-floor rationale is correct, but the min-scan citation is wrong. plan.md:146 cites `shared_cos_lease.rs:95` for min-scan. That line is `PaddedVtimeSlot::publish`; the Release store is line 100. The actual peer min-scan is `shared_cos_lease.rs:171`, especially lines 177-184, and it excludes the caller's own worker slot. Fix both #793 and #917 references to cite `49/95-100/132` for slot/publish/storage and `171-185` for min-scan.

- `#837` is fixed semantically, but line refs are stale. The "Do not retire #837" evidence is at `findings.md:145`, not `:142`. The defer-back-to-#837 evidence is at `plan.md:619`, not `:617`.

- `feedback_cross_binding_impossible.md` is not present in this repo. Either qualify it as external project memory or replace it with checked-in sources like `shared-umem-plan.md:58` and `shared-umem-plan.md:246`.

**Round-1 Status**

All three round-1 findings are addressed substantively:

- `#837`: now keep parked/gated, not wontfix.
- `#917`: now close as shipped via slot-floor design, not CAS-global atomic.
- `#793`: now close as superseded/absorbed by `#917`, not literal duplicate.

The close/keep set is sound: close `#786/#793/#794/#917`; keep `#837/#936/#937`. Clean the citations, then execute.
