# Codex hostile plan-review — round 33 (plan v33 @ ee4e82ee1)

Task: task-ms1wjm1c-wcx9lw (session 019f9edb-fcf4-7a92-962e-f727dff920ea).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR; fold verification 1 FOLDED / 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The exact K-active/K′-confirm premature-exit case is closed by fresh same-snapshot BOTH-SIDES validation at docs/research/2114-nat-pool-alarm-dp-race/plan.md:2661-2677. However, requiring every encrypted repair to validate its unreadable own target contradicts W-u/D recovery; see MAJOR 1.
2. PARTIAL — CONFIRMED-EMPTY, irrecoverable removal, observability, and active probing appear at plan.md:2678-2710 and :3158-3175, but the exit proof/priority is underspecified and the “exact” health/aggregate copies still omit `ConfigWriteUnverified` at :3435-3454, :3508-3530, :3923-3938, :4624-4647, and :4707-4730.
3. FOLDED — The second-swap leg is explicit at plan.md:2735-2747 and :4806-4812: the active heal freshly validates the K-era confirm generation before encrypting. This closes the current behavior at pkg/configstore/store_persist.go:402-428 and pkg/configstore/crypto.go:262-270,457-465.
4. PARTIAL — The health DETAIL copy is fixed at plan.md:3100-3106, but the normative per-debt definition at :3150-3155 still derives `keyClass` solely through `errors.As`, contradicting the explicit byte-mismatch assignment at :2761-2766 and corrected copy at :3203-3208.
5. PARTIAL — The primary W-u/D blocks are class-split at plan.md:2211-2223 and :2920-2932, but :3411-3417, :4604-4609, :5140-5145, and :5217-5222 still prescribe `.configdb/master.key` restoration for missing/unreadable-key or master-key-I/O cases, contradicting the ENOENT/EACCES UNVERIFIABLE taxonomy at :2761-2771.

New findings:

MAJOR 1 — v33’s own-target validation deadlocks the content-independent W-u/D escape hatch. W-u must overwrite a NON-KEY-CLASS-PERMANENT unreadable confirm slot at plan.md:2211-2229, and D must synthesize a tombstone over one at :2920-2935; too-new envelope, unsupported PRF, and malformed nonce classes explicitly receive this repair-write exemption at :2497-2516. Take a K-encrypted readable active and a too-new encrypted confirm. D’s synthetic `PrevTree` clones active (:2853-2860), so its write is encrypted via crypto.go:262-270. If its key probe first hits EACCES, WRITE-UNVERIFIED enters (:2641-2650). After K access is restored, active validates, but v33 requires validating the unreadable target too (:2665-2675); that target cannot validate under any key, and CONFIRMED-EMPTY cannot fire while it remains unreadable (:2678-2684). W-u has the same loop. Content-independent target replacement needs an explicit own-target exception while retaining opposite-active validation.

MAJOR 2 — CONFIRMED-EMPTY has neither an executable two-file proof nor defined priority over HOLD. Plan.md:2682-2686 says all-plaintext/all-absent exits, while :2717-2718 says a missing-key probe holds; a key-path failure over an all-plaintext DB satisfies both transitions. Current `ReadActiveMeta` exposes no encryption classification (pkg/configstore/db.go:95-103), `ReadConfirm` discards the decrypted flag (:242-253), and both independently reread `master.key` through `maybeDecryptTreeJSON` (db.go:348; crypto.go:307-319). The plan must name one fresh, under-`s.mu`, active-and-confirm classification using one key byte snapshot and define CONFIRMED-EMPTY as authoritative before key-probe HOLD. Such reads add lock-held I/O but no recursive-lock deadlock. Once this scan is pinned under `s.mu`, Store-origin arm interleaving is excluded: CommitConfirmed, SyncApply, and bootstrap’s ordinary commit all serialize there; SyncApply does not itself arm.

MAJOR 3 — The promised probe liveness and health observability remain contradictory. The normative state says WRITE-UNVERIFIED alone keeps the loop alive at plan.md:2698-2710 and joins the aggregate at :3166-3175, but loop copies still exit on no debt/latch at :3030-3034, :3425-3427, and :4617-4618; current code has exactly those two old exit checks at store_persist.go:406-412 and :455-458. The exact snapshot/aggregate copies cited in fold 2 omit the field, and the precedence list at plan.md:3177-3179 has no position for its sixth message. Pin loop startup on every ENTER, include the state in both exit checks and every exact schema/formula, and define its health precedence.

MINOR 1 — The universal write gate lacks a viable `Save` lock placement. `Save()` holds only `s.mu.RLock()` and calls `writeActive`, whose contract permits either lock at store_persist.go:258-274. A failed validation must mutate `ConfigWriteUnverified` and start/retain the retry loop; doing that under the read lock races, while upgrading deadlocks. The x25 inventory at plan.md:4782-4788 omits this exported path. Pin `Save` to the write lock or specify another synchronized transition mechanism.

MINOR 2 — SyncApply’s admission behavior is unresolved. Bootstrap import is covered because it calls `CommitWithDescriptionGen` at pkg/daemon/daemon_apply_commit.go:17-60, but SyncApply bypasses commit gates and promotes before its degrade-not-fail persistence attempt at pkg/configstore/store_commit.go:134-138 and pkg/configstore/store.go:687-738. Plan.md:2722-2734 and :4798-4803 test only commit/confirm early refusal. State explicitly whether encrypted SyncApply promotes and raises persistence debt while the lower write is withheld, or is refused before promotion.

Structure confirmation: CONFIRMED — origin/master...ee4e82ee1 is documentation-only, and §4.7’s PR-1 core versus G+H+H2 follow-up split remains intact at plan.md:3766-3809.

NEEDS-REVISION

Codex session ID: 019f9edb-fcf4-7a92-962e-f727dff920ea
Resume in Codex: codex resume 019f9edb-fcf4-7a92-962e-f727dff920ea
