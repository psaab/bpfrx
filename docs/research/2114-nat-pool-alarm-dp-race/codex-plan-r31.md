# Codex hostile plan-review — round 31 (plan v31 @ 445cbd2b1)

Task: task-ms1tdjd4-6rk1gq (session 019f9e8a-c5eb-79c0-abe6-469e802c7b3e).
Verdict: NEEDS-REVISION (2 MAJOR, 3 MINOR; fold verification 1 FOLDED / 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The steady wrong-K″ case is blocked by docs/research/2114-nat-pool-alarm-dp-race/plan.md:2531-2557, but the gate depends on the latest failure remaining key-class; UNVERIFIABLE failures clear that classification and reopen the active-first split described below.
2. FOLDED — Any nonzero live debt mask forces running/wait, only mask zero permits stopped restore, and BOOT latch + W is explicitly pinned at plan.md:2515-2530; the scenario matches pkg/configstore/store_commit.go:437-524,530-553.
3. PARTIAL — The taxonomy and both x24 copies are correct at plan.md:2563-2582,3377-3383,4545-4551, but health still defines keyClass solely through errors.As at plan.md:2955-2960,3005-3009,3309-3312,3710-3712, excluding the explicitly non-wrapped byte-mismatch outcome.
4. FOLDED — D survives either arm-barrier failure, remains W-suppressed, and clears with successful (w-a) durability at plan.md:2765-2787,3331-3341,4511-4519, consistent with pkg/fsatomic/fsatomic.go:342-369; resolution-owned tombstone/deletion plus fresh D reclassification prevents orphaning at plan.md:1861-1897,2181-2195.
5. PARTIAL — Both x23/x24 copies, v20 annotation, §9 tags, and FOLLOW-UP comment block are corrected at plan.md:526-530,3353-3391,3861-3864,4127-4134,4526-4575, but current H2 and §5.1 still retain three-state W copies omitting (w-u) at plan.md:2056-2072,3667-3672.

New findings:

MAJOR — The safety gate is not closed under its own taxonomy. It blocks writes only while the latest retained failure is key-class (plan.md:2539-2557,2955-2963), while ENOENT/EACCES/mount-I/O explicitly retain debt as non-key-class UNVERIFIABLE state (plan.md:2568-2580). After such reclassification, the next pass processes active first (pkg/configstore/store_persist.go:414-428); encrypted persistence invokes readOrCreateMasterKey, which creates K′ on ENOENT or accepts any installed 32-byte K″ (pkg/configstore/crypto.go:262-270,457-479). Active is therefore rewritten under K′/K″ before confirm detects authentication failure, leaving confirm under K. The write-safety state must remain closed through UNVERIFIABLE outcomes and clear only after positive same-snapshot validation.

MAJOR — The restoration transition is circular. Existing W/R healing requires encrypted WriteConfirm operations (plan.md:2094-2118; pkg/configstore/db.go:199-219), yet every encrypted write is blocked while that debt’s key-class bit remains set (plan.md:2539-2552,2955-2963). A successful read after restoring K has no specified transition that clears the bit before the same-snapshot repair: retaining it deadlocks healing, while clearing it on a generic non-key outcome creates the split above. The plan needs an explicit positive-validation transition and ordering/self-exemption.

MINOR — State-neutral commit refusal is not pinned. CommitConfirmed writes active before promotion, then performs its best-effort arm after promotion (pkg/configstore/store_commit.go:437-524,530-553); a plaintext candidate with an encrypted PrevTree can therefore pass a per-write plaintext exemption and encounter the encrypted gate only after promotion. The plan promises refusal at plan.md:2541-2547 but specifies neither an early Store-level precheck nor a regression for this case; x23/x24 at plan.md:4526-4562 do not test active withholding, commit refusal, or the pass-N/pass-N+1 transition.

MINOR — The health-state source of truth remains contradictory: plan.md:2571-2575 explicitly assigns keyClass for byte mismatch, while plan.md:2955-2960,3005-3009,3309-3312,3710-3712 permit assignment only through errors.As. An implementation following the latter cannot render the promised restoration-required outcome.

MINOR — The claimed copy sweep is false: plan.md:2056-2072 and 3667-3672 still describe a three-state W table and omit (w-u), contradicting the normative four-legged table at plan.md:2091-2128.

Structure confirmation: CONFIRMED — §4.7’s core/follow-up split and §9 delivery partition remain structurally coherent, and commit 445cbd2b1 contains plan documentation only.

NEEDS-REVISION

Codex session ID: 019f9e8a-c5eb-79c0-abe6-469e802c7b3e
Resume in Codex: codex resume 019f9e8a-c5eb-79c0-abe6-469e802c7b3e
