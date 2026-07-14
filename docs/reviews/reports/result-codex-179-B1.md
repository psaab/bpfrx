# Codex-review-179 Batch B1 triage ledger
# Worktree ground truth: /tmp/wt-codex179 (HEAD 7208d417a = origin/master)
# Findings C179-001..C179-015

C179-006 Unbound binding status retains stale shared-UMEM/drop counters — REJECTED-duplicate-#5190 — zero_unbound_slot (userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:266-428) never clears shared_umem_mode/group/socket_role/disabled_reason/martian_dropped/ipv6_ext_header_dropped copied at :64-80; #5190 cohort explicitly lists "unbound-slot stale counters".
C179-008 TCP seg promotes bytes beyond IP-declared datagram — REJECTED-duplicate-#5141 — tcp_segmentation.rs:76 `payload=&frame[l3..]` uses physical frame len, no IP total_len clamp; exact match to #5141 "no total_len clamp".
C179-009 First fragments enter segmentation/L4 recompute — REJECTED-duplicate-#5148 — forwarded_tcp_may_need_segmentation (tx/dispatch/mod.rs:1439-1482) gates only is_non_first_fragment; first fragment (offset0/MF) still segments; exact match to #5148.
C179-004 Runtime reset strands legacy shared CoS credits (non-exact queues) — REJECTED-duplicate-#5156 — release_all_cos_queue_leases (cos/token_bucket.rs:421-467) filter is `queue.config.exact` at :430, stranding non-exact shared-lease tokens on reset (loop_body:519/533) and teardown; #5156 explicitly names "teardown (release filter is exact-only)" — same root cause/fix point.
