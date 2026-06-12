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

## Live validation (loss userspace cluster, lock cells, 2026-06-12)

Choreography: branch build deployed to both nodes (rolling, verified
active; CoS re-applied post-deploy). fw0 configured with `gr-0/0/1`
(GRE-to-self over the LAN: tunnel 10.0.61.1 <-> 10.0.61.102) + lan->lan
permit policy; cluster-userspace-host (container) ran the GRE peer
(`gre1902`, required `modprobe ip_gre` on the loss HOST kernel — the
first attempt was vacuous because the container cannot autoload it and
pings silently fell back to direct LAN); inner route 10.0.61.103/32
(xpf-wg-peer) via the tunnel, so inbound GRE-encapped pings decap on
fw0 and the INNER forward egresses ge-0-0-1 toward a neighbor we
flush per round (`ip neigh flush dev ge-0-0-1`). tcpdump taps on the
inner egress receiver (wg-peer eth1) and the outer leg (lanhost eth0).

Results (3 flush rounds x 6 pings, plus an earlier 3-round cell):

- **Gate fires and is observable**: `xpf_userspace_pending_neigh_decap_drops_total`
  0 -> 1 (cell r2 round 1) and 1 -> 2 -> 3 -> 4 (cell r3 rounds 1-3) —
  exactly ONE refusal per cold-neighbor window; nothing decapped was
  ever buffered (`pending_neigh_keys` 0 throughout,
  `pending_neigh_duplicate_drops_total` 0).
- **No corrupt TX on the wire**: 0 proto-47 frames and 0
  truncated/malformed frames on wg-peer eth1 across both captures
  (55 + 51 packets). Pre-fix the neighbor-resolution retry would have
  TXed the mis-rewritten GRE OUTER frame here.
- **First-packet delivery via the decap-aware slow path**: 18/18 inner
  echo requests arrived at wg-peer (gate-refused first packets included)
  and 18/18 replies were generated; kernel ARP probe traffic
  (fw0 10.0.61.1 -> 10.0.61.103 ICMP + who-has) visible as designed.
- **Non-decap buffered-retry regression leg**: #1876 telemetry shows
  `neighbor_pending_dwell_seconds_count 2` with sum 295 us (both
  buffered packets retried in <1 ms), `pending_timeout_drops_total 0`;
  iperf3 through the flushed-neighbor WAN path ran at full CoS class
  rate (98.5/95.3 Mbit/s on the 100M class) with 0 retransmits.
- **Cluster state**: setup/cleanup commits rc=0 in every cell; both
  daemons active; CoS verified applied; locks released.

Observed pre-existing behaviors (NOT this PR — by condition algebra a
tunnel-marked decision, `tunnel_endpoint_id != 0`, skips BOTH the new
decap branch and the admission else-if exactly as it skipped the single
pre-fix branch):

1. Reply-leg blackhole during a cold ENCAP outer next-hop: with
   10.0.61.102 flushed, wg-peer replies entering fw0 for gr-0/0/1 encap
   were dropped for entire 2s ping windows (rounds 2-3: 0/6 received;
   lanhost tap shows ~1/18 reply GRE frames and NO who-has 10.0.61.102
   probe). #1873 R-E's no-buffer choice is by design, but no probe was
   observed driving the outer hop. Follow-up filed.
2. The journal `Invalid argument` match during the run is the known
   benign ifindex-4 (fabric ge-0-0-0, by-design xdpgeneric) native-XDP
   fallback warning at daemon start — not a tunnel-delivery EINVAL.

Known-flaky note (full `cargo test --release`):
`worker_queue::concurrent_recovery_processes_each_command_exactly_once`
failed 2 of 3 full-suite runs under parallel load (scheduling-race
assert, in the documented known-flakies set, source untouched by this
branch); standalone 5/5 pass, and one full-suite run was fully green
(2072 passed / 0 failed). `go test ./...` rc=0 (38 packages ok);
`cargo build --release` rc=0.
