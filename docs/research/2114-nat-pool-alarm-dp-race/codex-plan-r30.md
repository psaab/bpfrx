# Codex hostile plan-review — round 30 (plan v30 @ 63ace2bdc)

Task: task-ms1rki0f-26dqob (session 019f9e5c-7961-7d21-807a-d1e8af4f42d5).
Verdict: NEEDS-REVISION (2 MAJOR, 2 MINOR; fold verification 2 FOLDED / 5 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The quiescent DEBT-origin path is sound: restore K live, then R_A re-reads, tombstones, and deletes through its keyed table (plan.md:1959-1979,2453-2472); stopping would abandon it and permit re-arm/revert (pkg/configstore/store_persist.go:149-165,231-255,397-401). Mixed provenance and split-key interleaves below still invalidate the general runbook claim.

2. FOLDED — Each debt owns its latest retained failure class, and the snapshot derives its mask by OR-by-kind over live debts (plan.md:2840-2860,2894-2904). The mixed-R case is pinned. Key-class → EROFS → key-class flip-flopping is correct: it reports the current actionable cause; hysteresis would recreate the sticky-cause defect.

3. PARTIAL — The normative clear-time branch retains on every re-read error, journals the exact error, distinguishes UNVERIFIABLE from mismatch/restoration, and permits same-byte replacement (plan.md:2474-2486). However, the promised x23/x24 legs are absent from both copies (plan.md:3239-3268,4398-4423), and the cause schema cannot render those outcomes consistently; see MINOR 1.

4. PARTIAL — The central matrix and COMPLETE producer inventory include (w-u) (plan.md:2417-2435), but formal x23/x24 omit it at plan.md:3239-3244,3267-3268 and again at plan.md:4398-4403,4421-4423. The current summary also still calls W a “three-state” table and lists only match/differ/absent (plan.md:3540-3549), despite (w-u) being defined at plan.md:2071-2086.

5. FOLDED — A fully durable arm clears D through the arm’s own barrier (plan.md:2668-2675,3216-3224,4386-4391). That barrier is directory fsync, not rename visibility (pkg/fsatomic/fsatomic.go:354-369): a post-rename failure creates W (plan.md:1995-1999) and explicitly leaves D suppressed while (w-a) remains owed (plan.md:2137-2142). The delayed-clear transition still needs the MINOR 2 pin.

6. FOLDED — All current copies distinguish nonce encoding/length failure before AEAD from well-formed tampering reaching gcm.Open (plan.md:2351-2360,3250-3258,4406-4414), matching pkg/configstore/crypto.go:328-356. No unqualified current “bad nonce” classification remains.

7. PARTIAL — G and the §11 prerequisite copy now point to the follow-up (plan.md:1531-1536,4514-4516), §6 names five responses (plan.md:3838-3845), and factory-reset provenance is correctly scoped (plan.md:2390-2400; pkg/configstore/factory_reset.go:252-268). But plan.md:3738-3754 still instructs source-comment changes in “the same PR,” while §9 says build/vet are untagged BOTH-unit gates yet tags them CORE (plan.md:4002-4009); core-only items 3–5 remain unpartitioned at plan.md:4424-4436.

New findings:

MAJOR 1 — The live-restore branch can permanently split active.json and confirm.json across keys. With R_A and persistDegraded both live under original K, install wrong-but-valid K″. The retry explicitly heals active persistence first (plan.md:2023-2025; pkg/configstore/store_persist.go:414-428), and that write encrypts the in-memory active tree using the currently installed K″ (pkg/configstore/crypto.go:262-270,457-465). confirm A remains under K, so its subsequent read fails authentication. Restoring K as instructed (plan.md:2453-2472) then makes active validation fail; retaining K″ makes confirm validation fail. No single key permits convergence. Ordinary commits/arms are likewise admitted during debt (plan.md:2200-2214,2444-2447). The plan must gate active writes/retries during unresolved key verification or define and test a safe two-key/manual recovery protocol.

MAJOR 2 — BOOT-origin is not a stable “no live debts” state, so terminal-first rendering can recommend stopping while process-local debt exists. BOOT-origin starts without a debt (plan.md:2537-2543), but a confirmed commit during that latch can fail its arm pre-rename and create W (plan.md:2694-2705); D failures are also explicitly process-local debts (plan.md:2617-2624). The snapshot can therefore contain TerminalUnreadable plus a nonzero debt mask, yet its precedence is TerminalUnreadable before ConfirmDebt (plan.md:2840-2869,2905-2914). Stopping then abandons the debt (pkg/configstore/store_persist.go:397-401). Any live debt must force the running/wait branch regardless of latch origin, with an explicit mixed-state regression.

MINOR 1 — Clear-time remediation is not representable by the sole keyClass bit. Byte mismatch is restoration-required while every re-read error, including invalid length, is UNVERIFIABLE (plan.md:2474-2486). But keyClass is derived only through errors.As(ConfirmRecordKeyClassError) (plan.md:2844-2860), whose typed sources include invalid length but not byte mismatch (plan.md:2333-2350). Thus invalid length selects the restoration health variant and mismatch selects generic debt text (plan.md:2905-2914), opposite the stated rule; §6 has no UNVERIFIABLE variant (plan.md:3838-3845).

MINOR 2 — Successful (w-a) completion does not explicitly clear D. The durable rewrite clears W (plan.md:2044-2045), but armedArmID remains live and blocks every D clear (plan.md:2620-2625). The only gate-independent D cross-clear names a “successful arm” (plan.md:2668-2675), leaving it ambiguous whether later (w-a) completion counts. Pin post-rename arm → D retained → successful (w-a) dir-fsync → D cleared; otherwise health may remain degraded until window resolution.

Structure confirmation: §4.7 stands; PR-1’s accessor core remains independent, and G+H+H2 still belong together in the follow-up.

NEEDS-REVISION

Codex session ID: 019f9e5c-7961-7d21-807a-d1e8af4f42d5
Resume in Codex: codex resume 019f9e5c-7961-7d21-807a-d1e8af4f42d5
