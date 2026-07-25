### Final Defensive Firewall DoS-Hardening Design Review (#6461 v9.9.7)

1. **Stable Cursor (`(install_epoch, key)` Insertion-Ordered Index)**:
   - **Verified**: Storing an insertion-ordered secondary index ordered by `(install_epoch, key)` alongside `nat_reverse_index` and `forward_wire_index` in `userspace-dp/src/session/mod.rs` and `afxdp/shared_ops.rs` follows the exact existing maintenance discipline.
   - Insertions (`index_forward_nat_key_parts`) and deletions (`index_remove_forward_nat_key_parts`) update the index synchronously under the canonical lock.
   - Chunked iteration (≤1,024 entries per lock span) with cursor resumption on `(install_epoch, key)` guarantees bounded lock-hold times and prevents iteration loops over monotonically assigned epochs.

2. **Wire Identity Matrix (Old-Sender → New-Receiver Fallback)**:
   - **Verified**: The fallback to generation-based delete acceptance (`takeDeleteGen`) for tail-less entries from old senders is safe.
   - Gen-based checks reject stale deletes whenever a re-seeded entry $E_2$ advances its generation ($G_{new} > G_{old}$). 
   - The residual window for tail-less entries is the documented, temporary mixed-version rolling upgrade hazard. Once nodes complete upgrade to new→new, strict `(origin_process_nonce, flow_incarnation_id)` matching disallows all stale/aliased $E_2$ deletions.

**Verdict: PLAN YES**
