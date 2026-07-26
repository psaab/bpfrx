# AGY adversarial plan-review — round 30 (plan v30 @ 63ace2bdc)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (7/7 folds FOLDED; 3 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED: DEBT-origin process-local debt termination verified at `store_persist.go:397-401`; hash-match re-arm/expired-revert on restart verified at `store_persist.go:149-165,231-255`; plan provenance split documented at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2453-2472`.
2. FOLDED: Per-debt derived `ConfirmDebtKeyClassMask` OR-by-kind semantics and sticky/cleared cause update verified at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2854-2860,2894-2915`.
3. FOLDED: `readMasterKey()` error branch behavior verified against `pkg/configstore/crypto.go:443-455`; exact-bytes comparison and UNVERIFIABLE journal logging verified at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2477-2486`.
4. FOLDED: Full non-arm producer enumeration `(w-a), (w-b)/(w-c), (w-u), R (a), R (c), D tombstone` verified at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1066,2419-2436,4400-4402`.
5. FOLDED: Arm-supersession D clear barrier choice `(x22a)` and SyncApply pre-rename suppression `(x22b)` verified consistent across `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1067-1070,2668-2676,3216-3234,4386-4397`.
6. FOLDED: Pre-AEAD nonce validation `crypto.go:328-353` (non-key-class) vs `gcm.Open` auth failure `crypto.go:354-356` (key-class) verified across `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1011-1012,1074-1075,2354-2359,3253-3256,4410-4412`.
7. FOLDED: Delivery partition `[CORE]/[FOLLOW-UP]` at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:4002-4015`, five response texts at `plan.md:2870-2915`, and operator provenance scope outside `factory_reset.go:252-268` at `plan.md:2390-2398`.

(B) Fresh attacks:
- Debt-origin live-restore with incorrect key $K''$: Hypothesis: Operator restores valid $K''$ while $xpfd$ runs after slot was written under auto-created key $K'$ during compromised window. Outcome: FAILED. Re-reading slot under $K''$ fails AEAD authentication at `crypto.go:354-356`, returning `ErrMasterKeyAuth` / `ConfirmRecordKeyClassError`. The R-kind/W-kind retry loop retains debt, stays 503 degraded, and refrains from laundering active state (`plan.md:2078-2086,2300-2315`).
- Per-debt latest-cause flip-flopping: Hypothesis: Retained failure cause alternating across passes causes status message oscillations. Outcome: FAILED. Re-evaluation per pass (`errors.As` against `ConfirmRecordKeyClassError`) reflects real-time actionable cause at `plan.md:2894-2905`, while exact per-pass attempt trace is logged to journal.
- Arm-supersession D clear barrier choice: Hypothesis: Arm lands on slot with pending D debt, and arm's write fails post-rename, leaving visible record $B$ and raising $W_B$. Outcome: FAILED. D is suppressed whenever a live window or $W$ debt exists (`plan.md:2099-2111`). Furthermore, D's mandatory re-read observes readable $B$, triggering (d-iii) moot clear.

(C) Structure confirmation:
- §4.7 delivery structure stands (PR-1 core + Follow-up issue G+H+H2; r28 AGY (A) dissent recorded at `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3431-3470`).

Verdict: PLAN-READY
