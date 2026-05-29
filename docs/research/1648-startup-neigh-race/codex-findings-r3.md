# Plan Findings Responses — r3 (#1648)

[CRITICAL-1] ACCEPT (confirms v3 — and AGY r3 extends it). Codex independently
verifies that failover does not re-enter `initial_neighbor_dump` (startup-only
at neighbor.rs:514/bringup.rs:339; promote only runs on_rg_promote_active →
queue_warm_pass). v3 already split restart vs failover on exactly this basis.
AGY r3 additionally found a THIRD window: config-reload/reconcile DOES respawn
the monitor (reconcile/mod.rs:98 → teardown.rs:28 → stop_inner sets monitor_stop
None → bringup.rs:330 respawns → new dump). v4 adds Window-3.

[CRITICAL-2] ACCEPT. 5.A.2 needs an explicit ordering/replay design, not just
"process seq=0 immediately": a live seq=0 RTM_DELNEIGH (unconditional remove,
neighbor.rs:359) interleaved with older dump rows could resurrect/remove entries
by arrival order. v4 makes the 5.A.2 implementation contract explicit: process
seq=0 NEW/DEL into a STAGING buffer during the dump and replay it AFTER
NLMSG_DONE so dump rows are applied first then live deltas (or adopt 5.A.3
dual-socket where the multicast socket's ordering is naturally correct). This is
an /engineer design item; the plan flags it as must-resolve.

[HIGH-1] ACCEPT. R1 must attribute the queue-full / pre-buffer drop explicitly
(recycle_now defaults true at poll_descriptor/mod.rs:463; buffer only if
pending_neigh has room at :2644). v4 R1 adds a distinct "MissingNeighbor SYN
dropped because queue full" vs "dropped before buffer" counter so the RTO
conclusion is unambiguous.

[HIGH-2] ACCEPT. R2 needs deterministic cold-state enforcement before each
trial. v4 R2 specifies: before each measured trial, verify (a) fw1
dynamic_neighbors has NO entry for target B, (b) kernel neigh has none, (c) no
session-table entry — a throwaway pre-trial assertion. Otherwise World 2 can be
falsely concluded from passive-learn contamination (poll_descriptor/mod.rs:501,
poll_stages.rs:183).

[HIGH-3] ACCEPT (real contradiction — my bug). §8 still had a 5.C.2 test
(on_rg_promote_active warms prior-session peers) even though 5.C.2 is rejected.
v4 removes that test and replaces it with the 5.A.2 staging-replay test + the
5.E ENOBUFS-resync test.

[MEDIUM-1] ACCEPT. Durable ENOBUFS observability should be an acceptance
criterion, not just Gate-R throwaway: v4 notes that 5.E (if shipped) must add a
permanent ENOBUFS counter/log so overflow-induced desync is detectable in
production (neighbor.rs:527).

[MEDIUM-2] ACCEPT. PLAN-KILL gating sharpened: v4 states World 2 (zero
RTO-signature on the cold target across all windows) → PLAN-KILL the failover
scope. 5.A.2 still ships ONLY if Window-1/Window-3 (restart/config-reload)
independently show the RTO signature — that is a SEPARATE disposition, not a
"ship anyway after a kill". The two scopes are decided independently.
