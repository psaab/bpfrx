# Plan Findings Responses — r1 (#1648)

[CRITICAL-1] ACCEPT. External `ip -ts monitor neigh` is a separate netlink
socket and cannot observe what the daemon socket skipped via the
`nlmsg_seq != next_seq` continue (neighbor.rs:434-437). Gate-R R1 will add
daemon-side throwaway counters: "seq-mismatch skipped NEW/DEL during dump" and
"applied NEW/DEL during dump", plus the dump duration. This is the single most
important instrumentation change — it directly tests AGY's seq=0-multicast-drop
hypothesis, which all three reviewers now converge on as the likely 1.7s
mechanism.

[CRITICAL-2] ACCEPT. `neighbor_generation` is stored `1` on both dump success
(neighbor.rs:516) and failure (neighbor.rs:520) — it is a liar-flag for "seed
complete". 5.B (gate on generation>=1) is unsound. Plan v2 drops 5.B's
generation-gating and notes that any seed-complete gate must key on an explicit
dump-success state. (Already raised as SMR MEDIUM-1; ACCEPT and promote to the
5.B rejection.)

[HIGH-1] ACCEPT. The first SYN is buffered only if
`pending_neigh.len() < MAX_PENDING_NEIGH` (poll_descriptor/mod.rs:2644);
otherwise recycled. Earlier branch exits also recycle on errors. AGY's trace
confirms the dominant path IS buffered, then dropped at the 800ms timeout
(neighbor_dispatch.rs:111) when the seq=0 resolution advert was discarded.
Gate-R R1 will explicitly count "first SYN queued vs recycled" so we know which
drop path produces the RTO.

[HIGH-2] ACCEPT. Standby passive learning (poll_stages.rs:79/92/100/113/183 +
neighbor_dispatch.rs:320) is unguarded and can mask failover cold-start. AGY
refined this: standby only RX's broadcast/multicast (L2 unicast MAC learning
means an idle cold-connect target isn't seen) AND NUD aging + RTM_DELNEIGH
propagation cools the cache, so World 1 (failover cold) is likely. Gate-R R2
will control for passive-learn contamination: measure both a target the standby
HAS seen and one it has NOT, and let the standby cache age before failover.

[HIGH-3] ACCEPT. 5.C.2 warms prior-session on-link peers but the cold-connect
class (new host, no prior session) is exactly what it misses, and
`prewarm_reverse_synced_sessions_for_owner_rgs` (shared_ops.rs:72) already
restores synced-session entries. Plan v2 reframes 5.C.2 as a non-fix and
elevates the first-touch self-heal (5.A.2) as the root fix.

[HIGH-4] ACCEPT. `pending_neigh_timeout_ns` falls back to 2000ms when the sysctl
check fails/exceeds threshold (neighbor_dispatch.rs:99-103;
forwarding_build/mod.rs:433,474). Whether the 1.7s is "260ms schedule + 800ms
timeout + 1s RTO ≈ minus overlap" vs a 2000ms-timeout path materially changes
the trace. Gate-R will record the effective `pending_neigh_timeout_ns` each run.

[MEDIUM-1] ACCEPT. Netlink rcvbuf overflow (ENOBUFS) is a competing explanation
for missed adverts and is not instrumented. Gate-R adds SO_RCVBUF sizing
inspection + drop/overflow accounting on the monitor socket (neighbor.rs:470,
498, 506).

[MEDIUM-2] ACCEPT. R2 testing a single on-link target under-detects if that host
is incidentally warm. Gate-R R2 adds at least one additional on-link host not
recently active (and the aged-standby case).

[MEDIUM-3] ACCEPT (as an alternative to evaluate). Dual-socket design (separate
dump socket vs multicast-subscription socket) eliminates the seq-mixing entirely
and is arguably cleaner than the 5.A.2 seq-filter patch. Plan v2 adds it as
5.A.3 to compare against 5.A.2 before /engineer. The single-socket bind-then-
dump (neighbor.rs:485,514,434) is the root of the seq-skip hazard.

[LOW-1] ACCEPT. Path map error: `update_ha_state` is in
`userspace-dp/src/server/handlers/ha.rs:26`, not under `afxdp/server/...`. The
plan's §2.3 already cites `server/handlers/ha.rs` correctly, but the prose
elsewhere should be consistent. Plan v2 corrects any stale path.

[SECURITY] ACCEPT (noted). Gate-R runbook will mark `ip neigh flush all` and
failover injection as lab-only guardrails.
