# PR #1911 (#1902) reviewer ledger

| Reviewer | Round | Task id | Verdict |
|----------|-------|---------|---------|
| Codex | r1 | task-mqbduj72-met6ha | MERGE-READY (no Critical/High/Medium; 1 Low — see below) |
| AGY (Antigravity) | r1 | adversarial-review-mqbduz6e-beyr8h | MERGE-READY (read-only; no writes; verified producer/consumer pairing, #1771 invariants, byte-trace, wire alignment) |
| Copilot | r1 | review requested 2026-06-12 (attempt 1: quota-limited x2) | pending |
| Claude SMR | r1 | in-conversation hostile byte-trace | MERGE-READY |

## Codex r1 Low — adjudicated, no code change

Low: `pending_neigh_decap_drops` increments BEFORE `pending_key` /
`pending_neigh_admission` adjudication, so a decapped duplicate or
over-capacity packet counts as decap-refused rather than
duplicate/capacity-refused. Adjudication: this is the intended
priority-reason semantics and the in-tree wording already matches —
the `BindingLiveState` doc comment (umem/mod.rs) says "Counted only
when the packet would otherwise have been an admission CANDIDATE
(non-tunnel decision with a next_hop, seed not refused)", i.e.
candidate after the seed/tunnel/no-hop gates, NOT "helper would
return Buffer". No wording over-claims admission; no change needed.

## Claude SMR r1 byte-trace (hostile, in-conversation)

Traced: tagged GRE outer (UMEM `desc`, `raw_frame`) →
`stage_native_gre_decap` (mod.rs:126) rebinds `meta` to INNER +
`owned_packet_frame = Some(inner Vec)`; `packet_frame` rebound to the
inner frame at mod.rs:242 → inner forward decision MissingNeighbor →
new first branch (mod.rs:2716): `!seed_install_refused &&
tunnel_endpoint_id == 0 && next_hop.is_some() &&
owned_packet_frame.is_some()` → counter++ only; NO insert; the else-if
(original conditions, no drift — `.is_some()` vs `let Some(hop)` bind
are equivalent) is not entered → `recycle_now` stays true → outer UMEM
frame recycled via `scratch.scratch_recycle.push(desc.addr)`
(mod.rs:2853) → trailing `maybe_reinject_slow_path_from_frame`
(mod.rs:2814) receives `packet_frame` (= INNER frame) + inner meta +
inner decision and hands the correctly-paired inner L3 packet to the
kernel slow path exactly once. Verified the two
`owned_packet_frame.take()` sites (mod.rs:483, mod.rs:2040) are
exclusive to queued-forward/fabric-return TX paths and cannot empty the
Option before the non-forward disposition match. Verified
`pending_neigh.insert` remains a single production site reachable only
through the non-decap else-if. Counter plumbing verified end-to-end:
`BindingLiveState.pending_neigh_decap_drops` →
`Coordinator::pending_neigh_decap_drops_total()` → serde
`pending_neigh_decap_drops_total` (control.rs) → Go
`PendingNeighDecapDropsTotal` (protocol.go) → Prometheus
`xpf_userspace_pending_neigh_decap_drops_total`.

Out-of-scope observation (pre-existing since at least the #1054
extraction, NOT introduced or worsened by this PR): the trailing
`maybe_reinject_slow_path_from_frame` call at mod.rs:2814 runs for ALL
non-forward dispositions in that match (incl. PolicyDenied /
HAInactive), and the `_from_frame` variant has NO disposition filter —
the LocalDelivery|NoRoute|MissingNeighbor|NextTableUnsupported filter
lives only in the desc-based `maybe_reinject_slow_path` wrapper
(slow_path.rs:90). Flagged to the parent for separate triage.
