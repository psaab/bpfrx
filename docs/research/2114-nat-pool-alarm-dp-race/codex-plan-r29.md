# Codex hostile plan-review — round 29 (plan v29 @ 9e6bef427)

Task: task-ms1q5jhe-p56y8a (session 019f9e38-3174-7fd0-8ffa-27affb801ad1).
Verdict: NEEDS-REVISION (2 MAJOR, 5 MINOR; fold verification 1 FOLDED / 7 PARTIAL). Structure: split itself holds; stale packaging copies require correction. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — Master has one production `WriteConfirm` caller, the arm at pkg/configstore/store_commit.go:524,535-553, reaching pkg/configstore/db.go:207-217 and pkg/configstore/crypto.go:262-270,457-479. v29 places all proposed repair producers on the no-create primitive, but its “COMPLETE” inventory and x23/x24 matrices omit the distinct `(w-u)` unreadable-slot restore defined at plan.md:2011-2025; see plan.md:2360-2366,3121-3124,3147-3148,4254-4279.

2. PARTIAL — Exact-byte identity, reread-before-clear, and safe-if-wrong absent-slot barrier are specified at plan.md:2327-2394 and match pkg/configstore/crypto.go:443-454 and pkg/configstore/db.go:297-316. Same-content key replacement correctly passes. However, the offline remediation branch loses process-local debt provenance, and clear-time reread errors are unspecified. Also, “the store NEVER deletes active.json” needs ordinary-lifecycle scoping because operator-triggered factory reset removes the DB at pkg/configstore/factory_reset.go:252-268.

3. PARTIAL — Separate debt/latch causes and rendered-level selection exist at plan.md:2750-2760,2792-2808, so a boot key-class latch without debt is representable. But plan.md:1966-1971 permits multiple same-kind R debts while plan.md:2752-2756 gives them one REMOVAL cause bit with undefined ownership and cause-transition semantics.

4. FOLDED — Both x24 copies assert zero write/delete for plaintext-active/K-encrypted-confirm under K′ at plan.md:3138-3141,4270-4273. Plaintext bypasses key access while confirm decryption reaches authentication at pkg/configstore/crypto.go:262-265,307-356, making the ordering testable.

5. PARTIAL — x24 correctly distinguishes bad nonce encoding/length from well-formed tampering at plan.md:3133-3137,4265-4269, matching pkg/configstore/crypto.go:328-356. The normative classification still says unqualified “bad nonce” is non-key-class at plan.md:2291-2297.

6. PARTIAL — The normative D table now makes successful-arm clearing the arm’s own supersession at plan.md:2576-2584. Ordinary encrypted arms deliberately retain auto-creation at plan.md:2375-2379 and pkg/configstore/crypto.go:457-479. But x22 still requires D to survive a fully durable arm at plan.md:3107-3113,4247-4251—the opposite outcome.

7. PARTIAL — The named health, x4e′, next-successful-W, R-action, and formal x22–x24 copies landed at plan.md:1899-1919,2744-2808,2899-2911,3016-3031,3086-3104,4053-4063,4148-4165,4227-4279. Stale copies remain: the placement-level x23 matrix omits W `(w-a)` and R `(a)/(c)` at plan.md:2350-2354, and §6 still claims exactly three new response texts despite the two key-class variants at plan.md:3717-3720.

8. PARTIAL — The actual split is coherent at plan.md:3319-3352,4312-4319,4720-4736, and G/H/H2 are header-tagged at plan.md:1283-1287,1478-1481,1651-1657. The accessor core is independent of the executor and recovery machinery at pkg/daemon/daemon.go:70-74, pkg/daemon/daemon_apply_commit.go:629-650, and pkg/configstore/store_persist.go:113,136-253. But plan.md:1472-1476 and 4370-4371 still say G ships in the same PR/stack, while plan.md:3879,3940-3997 leaves core, G, and H tests unpartitioned.

New findings:

MAJOR 1 — The “restore with xpfd stopped” runbook deterministically enters H2’s admitted replay residual for debt-origin state. A keep-active confirmation can resolve A in memory while a wrong key makes its tombstone read fail and retain R_A (plan.md:1665-1674,1757-1775,2902-2910). Stopping xpfd abandons that process-local retry (plan.md:2633-2637; pkg/configstore/store_persist.go:397-401). After restoring K and restarting, pending-shaped A still hash-matches and recovery re-arms or expired-reverts an already-confirmed config at pkg/configstore/store_persist.go:149-165,231-255. Offline restoration is safe for boot-origin unresolved state, not process-local resolved debt; debt-origin remediation must restore live and wait for health/debt clearance before stopping.

MAJOR 2 — `ConfirmDebtKeyClassMask` remains unrepresentable for multiple removal debts. `R_A + W_B + R_B` is explicitly allowed at plan.md:1966-1971, but both R entries share one REMOVAL bit whose cause is supposedly cleared with its “owning debt” at plan.md:2752-2756,2792-2795. Clearing one R can erase the other’s live cause. Cause lifetime is also ambiguous: “cleared only with debt” makes it sticky, so after successful key revalidation followed by an EROFS write failure (retained per plan.md:2411-2417), health still incorrectly directs key restoration. Each keyed debt needs its own cause state, with the snapshot mask derived by OR-by-kind, plus an explicit latest-versus-latched transition rule and mixed-R regression.

MINOR 1 — The clear-time key reread has no error branch. plan.md:2389-2394 covers byte mismatch only, while pkg/configstore/crypto.go:445-453 can return EACCES, ENOENT, or invalid length. A post-action reread failure must retain, journal the exact verification error, and avoid falsely asserting that restoration is necessarily required; x23/x24 at plan.md:3119-3148 do not test this. Exact-byte comparison itself is correct and permits a safe same-content file replacement.

MINOR 2 — W `(w-u)` is protected in its local prose but absent from every purported complete producer matrix. Because plan.md:2011-2025 defines a separate unreadable-slot branch, lists at plan.md:2360-2366,3121-3124,3147-3148,4254-4279 need to name and test it explicitly.

MINOR 3 — x22 contradicts the successful-arm rule. plan.md:2576-2584 says the arm’s durable overwrite clears D outside D’s gate, while plan.md:3107-3113 and 4247-4251 expect that same fully durable arm to leave D inert. The regression must assert arm-barrier clearance; suppression applies only absent a successful arm.

MINOR 4 — The nonce taxonomy still has a normative stale copy. plan.md:2291-2297 classifies all “bad nonce” cases as non-key-class, but a correctly encoded, valid-length tampered nonce reaches `gcm.Open` and is authentication-indistinguishable at pkg/configstore/crypto.go:328-356.

MINOR 5 — Delivery instructions still contradict §4.7. The same-PR statements at plan.md:1472-1476,4370-4371 and the unpartitioned test block at plan.md:3879,3940-3997 must be marked follow-up work so PR-1’s implementor is not instructed to ship G/H/H2.

Structure confirmation: §4.7’s split itself holds—PR-1’s accessor/sampler core stands alone without depending on or worsening G/H/H2, and G+H+H2 may trail together—but the stale packaging copies require correction.

NEEDS-REVISION

Codex session ID: 019f9e38-3174-7fd0-8ffa-27affb801ad1
Resume in Codex: codex resume 019f9e38-3174-7fd0-8ffa-27affb801ad1
