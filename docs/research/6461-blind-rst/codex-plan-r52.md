PLAN NO

Review pinned to `plan.md` at `b3597980b`; later worktree text was excluded.

1. **BLOCKER — AUTH_PROOF_v2 still lacks one executable byte grammar.**  
   `plan.md@b3597980b:4040-4056` fixes role and record ordering, but does not define capability-field widths, capability-bit layout, whether record lengths are included in each formula term, or whether capability records are hashed as raw transmitted bytes versus reconstructed fields. Lines 4083-4088 retain a conflicting older encoding—individually length-prefixed fields ordered `node_id … nonces`—rather than the formula’s HELLO-first record layout. Lines 4057-4065 promise hexadecimal vectors, but §9 at 4768-4770 contains no actual vector values.  
   Concrete trace: implementation A hashes `u16(length) || raw capability payload`; implementation B decodes and reserializes according to lines 4083-4088. Their HMAC inputs differ, verification fails at [sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:401), the connection closes at `sync_conn.go:106-110`, and the dialer retries indefinitely at `sync_conn.go:435-477`. `readSyncFrameRaw` returning the payload separately from its header at `sync_auth.go:289-310` makes the length-inclusion decision material.  
   **Required change:** define exact widths and offsets; specify `u16-LE(len) || exact raw payload bytes` for every HELLO/capability term—or one complete canonical serialization; remove lines 4083-4088’s alternate grammar; clarify that only the shared record segment is identical while full inputs differ by `prover_role`; and include literal keyed hexadecimal vectors for both roles.

2. **MEDIUM — The plan retains competing v1 capability-negotiation contracts.**  
   The new rule at `plan.md@b3597980b:3990-4007` and §9 at 4773-4780 correctly disables every feature until matching same-connection `CAPABILITY_CONFIRM`s. Elsewhere, §5.2 still puts a capability word in every connection’s HELLO at 3412-3418, lines 4020-4030 say `repair-vN` is independently negotiated and “never masked,” lines 4098-4100 say the HELLO negotiates `repair-vN/reset-vN` before feature frames, and §9 repeats independent repair negotiation at 4764-4767.  
   Concrete trace: A follows the HELLO-negotiation clauses and enters repair-era completion; B follows the total-confirm rule, receives no matching confirmation, and remains in legacy completion. B reconciles at BulkEnd and returns bare BulkAck through [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:205); A requires JOURNAL_ACK, leaving its obligation, cold-prime latch, and readiness unresolved and repeatedly redriven through `sync_conn.go:572-618`.  
   **Required change:** make HELLO only advertise/select the transcript version. On a v1 proof, no capability becomes active except through matching authenticated same-connection CONFIRMs; replace every “HELLO negotiates” or independent-negotiation straggler accordingly.

**Round-51 dispositions**

- **r51-1 — RESOLVED.** `plan.md@b3597980b:3970-3989` now sends v1 AUTH_PROOF immediately when either HELLO is v1 and moves capability exchange post-wrapper. This matches `sync_auth.go:345-376,392,401-404`; the prior reconnect loop is closed.
- **r51-2 — PARTIALLY RESOLVED.** Both capability records and fixed dialer/acceptor ordering are now included, but finding 1 leaves the byte representation ambiguous and internally contradictory.
- **r51-3 — PARTIALLY RESOLVED.** The new normative and §9 confirmation clauses are correct, but finding 2’s older HELLO/independent-negotiation instructions remain operative.

Bottom line: the r51 handshake-order failure is closed, and I found no new demote-gate or NAT-holder-lifetime trace. Final sign-off remains blocked because two conforming implementations can still compute different v2 proofs, while the v1 negotiation text permits asymmetric repair completion. Both lead directly to session-sync unavailability or readiness desynchronization at the cited code paths.
