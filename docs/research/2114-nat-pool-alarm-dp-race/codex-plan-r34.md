# Codex hostile plan-review — round 34 (plan v34 @ 0e344b03e)

Task: task-ms1za1xi-5cebk4 (session 019f9f22-1320-7431-9392-9b83ebdec223).
Verdict: NEEDS-REVISION (3 MAJOR, 1 MINOR; fold verification 4 FOLDED / 2 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. FOLDED — The asymmetric rule is explicit at plan.md:2712-2732 and carried into (w-u) at plan.md:2250-2271 and D/(d-i) at plan.md:3019-3038. The K-encrypted-active/too-new-confirm scenario can repair D after access restoration. With encrypted active still present, exit is by positive validation; CONFIRMED-EMPTY remains available only when both records become plaintext/absent as specified at plan.md:2743-2775.

2. FOLDED — The authoritative one-snapshot, both-file classification precedes key-probe HOLD at plan.md:2737-2764 and is regression-pinned at plan.md:4957-4961. The required metadata is currently available/discarded at pkg/configstore/crypto.go:301-358 and pkg/configstore/db.go:95-103,242-253. Store-origin writers serialize through s.mu at pkg/configstore/store.go:642-643 and pkg/configstore/store_commit.go:122-134,368-397. The external mid-scan key-swap claim still fails in the state-only case described below.

3. PARTIAL — All identified loop exits now retain the loop at plan.md:3133-3136,3541-3543,4744-4747, and the primary schema is correct at plan.md:3268-3289. However, exact §5.1/x14/x21 copies omit writeUnverified from the aggregate and WriteUnverified from precedence at plan.md:4046-4062,4756-4775,4839-4859; the API precedence copy also omits it at plan.md:4070-4078.

4. FOLDED — Save is explicitly changed from the current RLock at pkg/configstore/store_persist.go:258-274 to s.mu.Lock at plan.md:2825-2834, with the exported-path x25 leg at plan.md:4961-4964.

5. FOLDED — SyncApply promotion plus persistence withholding is pinned at plan.md:2813-2824,4964-4967 and matches its current promote/degrade contract at pkg/configstore/store.go:681-689,722-746. A withheld replacement follows confirmResolvePendingPersist at pkg/configstore/store.go:738-746, and healing rereads current s.active under s.mu at pkg/configstore/store_persist.go:389-428 before finalizing retention. No third admission option is needed.

6. PARTIAL — errors.As-or-explicit-mismatch is fixed at plan.md:3256-3263, and the cited class splits are fixed at plan.md:3524-3530,4729-4735,5289-5294. The cumulative summary still incorrectly assigns master-key I/O the restoration message at plan.md:5367-5371, contradicting plan.md:2860-2869.

New findings:

MAJOR 1 — The own-target classification and repair write are not serialized against the plan’s sanctioned live operator remediation. The plan permits in-process repair-to-valid followed by classification at plan.md:3190-3204, admits there is no filesystem lock at plan.md:3219-3224, and only claims s.mu excludes Store-origin interleavings at plan.md:2761-2764. ReadConfirm performs an ordinary read at pkg/configstore/db.go:242-253, while WriteConfirm later performs an unconditional atomic replacement at pkg/configstore/db.go:207-218 and pkg/fsatomic/fsatomic.go:310-366. An operator can replace the too-new record with a valid K-encrypted record after (d-i) classifies it but before the synthesized tombstone rename; D then overwrites and deletes the repaired record without ever classifying it. The plan needs a cooperative file protocol, identity-bound conditional write, or a requirement to stop xpfd during filesystem remediation.

MAJOR 2 — A mid-scan key swap is not always self-correcting on the next pass. Save can enter WRITE-UNVERIFIED and start the loop without creating any persistence debt at plan.md:2825-2833. A pass may read K, validate both K-encrypted files, then have the unlocked key path replaced by K′ before the positive exit at plan.md:2698-2703. The final key reread applies only to debt clears at plan.md:2853-2872; with no debt, clearing the state satisfies the loop-exit condition at plan.md:3133-3136, so there is no next pass and health becomes green although the installed key cannot decrypt either record. Same-pass actionable debt writes remain protected by fresh validation, but that does not cure this state-only false clear. Positive-validation state exits need their own final key identity comparison and a state-only second-swap regression.

MAJOR 3 — The claimed observability sweep remains contradictory. The normative aggregate and precedence include ConfigWriteUnverified at plan.md:3268-3289, but the concrete implementation inventory and both formal test inventories exclude it at plan.md:4046-4062,4756-4775,4839-4859; plan.md:4070-4078 likewise omits its API precedence position. Following those “exact” copies can produce healthy aggregate/gauge output or select ActivePersist while WRITE-UNVERIFIED remains outstanding.

MINOR 1 — The cumulative remediation summary says master-key I/O retains with the master-key-restoration message at plan.md:5367-5371, while the normative taxonomy assigns ENOENT/EACCES/mount-I/O to key-state UNVERIFIABLE with no restoration claim at plan.md:2860-2869. That stale guidance can send operators toward key replacement when the actual fault is permissions or storage availability.

Structure confirmation: CONFIRMED — commit 0e344b03e remains research-document-only; plan.md:3889-3924 still splits PR-1’s A1 core from the combined G+H+H2 follow-up, with no production implementation in the reviewed delta.

NEEDS-REVISION

Codex session ID: 019f9f22-1320-7431-9392-9b83ebdec223
Resume in Codex: codex resume 019f9f22-1320-7431-9392-9b83ebdec223
