# AGY adversarial plan-review — round 29 (plan v29 @ 9e6bef427)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (7/7 folds FOLDED; 3 fresh attacks FAILED). Structure confirmed ((A) dissent preserved). Raw output follows verbatim.

---

 sight of section 4.7 is required. Let's call `view_file`.
(A) Fold verification:
1. FOLDED: No-create `readMasterKey` primitive and active-side gate cover all repair producers ((w-a), (w-b)/(w-c), R (a), R (c), D tombstone) while ordinary arm keeps create-on-first-use (`db.go:207-217`, `crypto.go:262-270,443-479`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:971-978,2360-2378`).
2. FOLDED: Runbook serializes key remediation, clear-time path re-read compares key bytes, and ENOENT provenance assumption for active/confirm slots is documented (`db.go:302-330`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:978-990,2379-2394`).
3. FOLDED: Per-state `ConfirmDebtKeyClassMask` and `ConfirmRecordKeyClass` snapshot fields render per-level causes accurately across coexisting debts and boot latches (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:991-1000,2745-2808`).
4. FOLDED: x24 pins zero write/delete under swapped valid K′ and qualifies bad nonce encoding/length (pre-AEAD non-key-class) vs tampered nonce (`gcm.Open` key-class) (`pkg/configstore/crypto.go:328-356`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1003-1008,4262-4279`).
5. FOLDED: Successful-arm D clear is pinned as arm's own supersession independent of D gate/preconditions, with D inert absent such an arm (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1000-1003,2039-2051,4247-4254`).
6. FOLDED: Stale copies swept; normative snapshot definition, x14/x21/v-history copies, (x4e') exemption legs, next-SUCCESSFUL-W wording, and §9 x22-x24 test list are aligned (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1008-1014,3090-3145`).
7. FOLDED: §4.7 PR-1 core (A1 + site conversions + canaries) stands alone without G/H/H2 dependencies or master regressions (`pkg/daemon/daemon.go:73,211-223`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1014-1023,3309-3348`).

(B) Fresh attacks:
- Clear-time key-path re-read: FAILED (attack closed). Transient EACCES at re-read safely retains the debt for the next retry pass; byte comparison (`bytes.Equal`) checks key content equality, which passes if an operator rewrites the key file with identical bytes (`pkg/configstore/crypto.go:443-455`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2389-2394`).
- Per-debt key-class rendered cause: FAILED (attack closed). Setting/clearing the debt's key-class cause bit on raise/retain accurately reflects the active cause currently blocking debt processing when `/health` renders (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:2750-2756,2792-2808`).
- Arm path auto-create vs repair paths: FAILED (attack closed). Ordinary arm (`writeConfirmState`) explicitly retains `readOrCreateMasterKey` for fresh-box setup (#1894), while all repair/resolution paths use `readMasterKey` no-create primitive; no contradiction exists (`pkg/configstore/crypto.go:457-481`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:976-978,2375-2378`).

(C) Structure confirmation or dissent:
Confirmed: §4.7 accurately records the 2-of-3 split packaging structure (PR-1 core + G/H/H2 follow-up) while preserving AGY's single-PR (A) dissent and leaving final packaging to user approval (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:3309-3353`).

Verdict:
PLAN-READY
