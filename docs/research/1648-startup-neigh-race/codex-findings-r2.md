# Plan Findings Responses — r2 (#1648)

[CRITICAL-1] ACCEPT (sharpened the kill bar). Standby passive learn
(`poll_stages.rs:183`, `neighbor_dispatch.rs:320`, `poll_descriptor/mod.rs:501`)
has no forwarding-active guard, so a fast R2 on an incidentally-prelearned
target is a false-negative for "cold failover fixed". v2 already added a
never-seen target B + aged-standby case; v2.1 now makes the kill bar EXPLICITLY
require target B (verified absent from fw1's dynamic_neighbors pre-failover) AND
the aged condition — a fast result is a kill ONLY on the provably-cold target.

[HIGH-1] ACCEPT (already rejected in v2). 5.C.2 is self-limiting for a true
first cold connect; prewarm (`ha.rs:130`, `shared_ops.rs`) only iterates
existing session-indexed keys, so a no-prior-session host is invisible. v2
already REJECTS 5.C.2 on exactly this basis (Codex r1 HIGH-3 / AGY Q3 / SMR
CRITICAL-3). No further change.

[HIGH-2] ACCEPT (already in v2 R1; reinforced). The silent drop branch
(`poll_descriptor/mod.rs:2644` — buffer only if `pending_neigh.len() <
MAX_PENDING_NEIGH`, else recycle) needs explicit instrumentation. v2 R1 step 2
already adds the "first cold SYN queued vs recycled" daemon counter. Confirmed
adequate.

[HIGH-3] ACCEPT (NEW — incorporated). `test/incus/test-failover.sh:188` is an
unclean `reboot` of fw0, not a clean handover. v2.1 adds R2-crash: Gate-R now
measures BOTH clean promote AND crash/reboot promote, and dispositions
production-relevance on the crash result. This is the project's own failover
gate path (CLAUDE.md:106).

[HIGH-4] ACCEPT (already in v2 R1). External `ip monitor` cannot prove what the
daemon socket skipped at `neighbor.rs:434`. v2 R1 step 2 already adds daemon-side
"seq-mismatch skipped during dump" + "applied during dump" counters. This is the
decisive H-0 instrumentation. No further change.

[MEDIUM-1] ACCEPT (already in v2 R1, Codex r1 HIGH-4). Effective
`pending_neigh_timeout_ns` (800ms fast vs 2000ms fallback) recorded per run.
Confirmed.

[MEDIUM-2] ACCEPT (already rejected in v2). 5.B's generation>=1 gate is a
liar-flag (set 1 on success AND failure, `neighbor.rs:516/520`). v2 already
REJECTS 5.B. No further change.

[LOW-1] ACCEPT. Path naming: `loss-userspace-cluster.env` is under
`test/incus/`. v2.1 ensures the plan references it with the `test/incus/` prefix
(the §2.4 reference already does; prose elsewhere made consistent).
