# Codex hostile plan-review — round 32 (plan v32 @ 28505e6e0)

Task: task-ms1uin0x-1t4tuu (session 019f9ea8-08a2-7f53-9953-42c158c13c5e).
Verdict: NEEDS-REVISION (2 MAJOR, 2 MINOR; fold verification 3 FOLDED / 2 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — WRITE-UNVERIFIED has explicit ENTER/HOLD/EXIT semantics, including wrong-K″ authentication failure and missing-key no-auto-create behavior, at docs/research/2114-nat-pool-alarm-dp-race/plan.md:2582-2623 and formal x25 at :4667-4682.
2. PARTIAL — Restored-K same-pass validation and healing is non-circular at plan.md:2613-2618, but EXIT is exclusively decrypt-positive at :2607-2612; sanctioned removal at :2479-2481 and :2981-2985 has no corresponding state transition.
3. FOLDED — The early precheck examines candidate-active OR confirm-PrevTree encryption before any write at plan.md:2624-2637,4683-4687. This matches pkg/configstore/store_commit.go:437-524 and pkg/configstore/db.go:199-214; dropping master-password makes active plaintext while an encrypted PrevTree still encrypts confirm.json.
4. PARTIAL — plan.md:3039-3044 still assigns per-debt keyClass solely through errors.As, contradicting the corrected errors.As-OR-explicit-mismatch definition at :3089-3097. The x14/x21/§5.1 copies are corrected at :3325-3328,3399-3402,3812-3815,4514-4517,4596-4599.
5. FOLDED — Current W tables are FOUR-LEGGED at plan.md:2100-2166 and :3767-3774; x23/x24 include (w-u) and the re-read taxonomy at :3443-3473 and :4631-4666; formal x25 contains all requested legs at :4667-4693.

New findings:

MAJOR — WRITE-UNVERIFIED’s EXIT relation is neither sufficient nor total. It may exit after decrypting “an” active or confirm record, without requiring every other present encrypted generation to validate or be overwritten before the state becomes globally clear (plan.md:2607-2611). The exact walked R_A case does HOLD because its confirm re-read fails authentication at :2613-2619, but that example is not a database-wide invariant. Conversely, after a pre-rename write-side EACCES/invalid-length failure over a plaintext DB, or after sanctioned removal of the final unreadable K′ record, no ciphertext remains capable of POSITIVE validation. Future encrypted commits are early-refused at :2631-2636, the retry loop may exit with no debt/latch at :3313, and WRITE-UNVERIFIED is absent from the health aggregate at :3047-3061. Define action-scoped/all-present-record validation, keep this state observable and actively probed, and add an explicit confirmed-empty/sanctioned-removal exit with the required data-loss warning.

MAJOR — The pass-N/pass-N+1 claim is false under a second key swap. The plan exits under K during pass N but defers active healing until pass N+1 while claiming zero hazard (plan.md:2637-2642,4688-4691). Its clear-time comparison protects only the pass-N debt action (:2647-2652). If K is replaced with valid K″ afterward, the active retry reads the then-installed key through pkg/configstore/store_persist.go:414-420 and pkg/configstore/crypto.go:262-270,457-465, re-encrypting active.json under unvalidated K″. The active write must consume/compare the retained validation snapshot or perform a fresh same-snapshot validation immediately before encryption; x25 needs this second-swap leg.

MINOR — The keyClass copy sweep remains contradictory beyond the fold line: plan.md:2994-2995 also says the health cause comes only from errors.As, omitting explicit byte-mismatch assignment.

MINOR — Missing/unreadable-key remediation is inconsistent. The W/D copies prescribe “master.key restoration” for any missing/unreadable key at plan.md:2173-2176,2820-2824,3300-3302, while the normative taxonomy says EACCES/ENOENT/mount-I/O is UNVERIFIABLE with no restoration claim at :2659-2664. Implementors cannot derive one operator message from both rules.

Structure confirmation: CONFIRMED — origin/master...28505e6e0 changes documentation only; §4.7’s PR-1 core versus G+H+H2 follow-up split remains coherent at plan.md:3652-3695.

NEEDS-REVISION

Codex session ID: 019f9ea8-08a2-7f53-9953-42c158c13c5e
Resume in Codex: codex resume 019f9ea8-08a2-7f53-9953-42c158c13c5e
