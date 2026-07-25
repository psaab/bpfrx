# Codex hostile plan-review — round 25 (plan v25 @ 3028893aa)

Task: task-mrzl4988-0rbcj8 (session 019f9681-db28-79e2-b870-a05d5b58f32f).
Verdict: NEEDS-REVISION (2 MAJOR, 4 MINOR). Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The R-only terminalization/W-D exemption and write-retry rule are explicit at plan.md:1851-1879, but the boundary is unsafe for shared-key authentication failures, and x15 still unqualifiedly expects every permanent key/auth error to latch at plan.md:2388-2392,3371-3373.

2. PARTIAL — The corrected oracle at plan.md:1943-1982 matches store_persist.go:166-194 and bootstrap.go:246-273, but plan.md:2217-2219 still falsely says FirstCommit=true trips H “on any reader”; the new reader drops Resolved before H.

3. PARTIAL — fsatomic.go:354-367 supports the immediate PRE/POST distinction, but plan.md:1725-1734 considers only the latest write attempt; it misses a live C already visible from an earlier POST-rename outcome at plan.md:1649-1653.

4. PARTIAL — The principal §5.1/x14/x21 schemas are exact at plan.md:2702-2709,3361-3370,3427-3439, but stale BODY text remains: the generic message omits SLOT_DELETE at plan.md:2178-2183 and §5.1 abbreviates precedence without RestartRecoveryOwed at plan.md:2717-2720.

5. PARTIAL — Store ownership, reclassification, and intentional overwrite are pinned at plan.md:2124-2132, but daemon.go:1042-1053 establishes only one Store per Daemon, not cross-process exclusion; configstore/store.go:296-319 and db.go:37-70 acquire no process lock.

6. PARTIAL — “No post-crash heal” is correct at plan.md:3074-3080 and store_persist.go:397-401, but “seconds-wide” assumes the next W write succeeds; writes can retry indefinitely under plan.md:1784-1800,1873-1879 and store_persist.go:402-465.

New findings:

MAJOR 1 — Master-key failure can be laundered into healthy state. With a W debt created under key K, replacing master.key with another valid 32-byte K′ makes ReadConfirm fail authentication at crypto.go:316-356, yet readOrCreateMasterKey accepts K′ and WriteConfirm rewrites the record under it at crypto.go:457-465 and db.go:207-217. W is exempt from terminalization, so its debt can clear while active.json remains encrypted under K; the aggregate becomes healthy, but the next Load fails closed at store_persist.go:26-35. Sanctioned confirm.json removal similarly clears invalid-length/key-loss latches without validating active.json. Key-related clears require key-identity/current-active validation, not confirm-slot success alone.

MAJOR 2 — D can delete a live window record because the PRE/POST classification is not stateful across attempts. W may already have live C visible from an earlier POST-rename failure (plan.md:1649-1653); after permanent unreadability, a later W restore can fail PRE-rename, leaving C—not the superseded record—standing. Nevertheless plan.md:1725-1729 sends D to (d-i), which synthesizes and deletes at plan.md:1994-2004. Concretely, if C removed master-password while s.armedRecord retains master-password-bearing PrevTree, invalid key length blocks W’s encrypted write but D’s current-C tombstone is plaintext and succeeds (db.go:207-217; crypto.go:262-270,457-465). A crash then silently loses C’s recovery intent. D must remain suppressed whenever W’s desired record may already be visible.

MINOR 1 — R terminalization is conservative, but its rationale is wrong. The payload could be synthesized; blind action is unsafe because permanent unreadability prevents proving the current slot still holds R_K rather than a newer live record, exactly the mismatch case at plan.md:1621-1633. Plan.md:1854-1866 instead says the dependence is record content and the corrupt owner is known.

MINOR 2 — Invalid-master-key remediation is not operator-correct. Plan.md:1873-1879 says repair master.key, but the runbook sanctions repairing/removing confirm.json at plan.md:2117-2134, while the generic 503 merely says retry is pending at plan.md:2178-2183. It must direct operators to the journal and master.key restoration, and warn that deleting a live W record sacrifices crash recovery.

MINOR 3 — The recordless crash exposure is not inherently seconds-wide. Convergence requires a failure-free suffix at plan.md:1784-1800, while deterministic write failures retry until operator repair at plan.md:1873-1879. After deletion, W may remain unable to restore for the rest of the confirm window, so a substantially later crash still materializes the loss; plan.md:3074-3080 understates that residual.

MINOR 4 — The claimed process-wide Store ownership is unsupported. daemon.go:1042-1053 and cmd/xpfd/main.go:490-504 show one Store in the normal daemon run, but configstore/store.go:296-319 has no singleton/flock enforcement. State this as an operational single-xpfd assumption or add enforcement.

NEEDS-REVISION

Codex session ID: 019f9681-db28-79e2-b870-a05d5b58f32f
Resume in Codex: codex resume 019f9681-db28-79e2-b870-a05d5b58f32f
