# #1748 Step 1 — reactive cross-worker ntuple rebalance controller (forward-direction, default-OFF)

- **Status**: DRAFT v3 — round-2 NEEDS-MAJOR addressed (two-origin ownership
  transfer), pending round-3 re-review
- **Issue**: #1748

### Round-1 review outcome (verdict: PLAN-NEEDS-MAJOR)
AGY found a **verified correctness kill** that v1 missed (and that R1's 70s
spike was too short to expose): the **stale-owner GC cascade**. When the
controller steers flow F off W_old, W_old keeps F's forward entry with
`origin=ForwardFlow` (NOT peer-synced — confirmed `session/entry.rs:78`). When
that frozen entry ages out, `expire_stale_entries` (`session/mod.rs:431`) takes
the `!is_peer_synced() && !is_transient_local_seed()` branch → pushes a
`SessionDeltaKind::Close` → which deletes the **shared** session map entry and
broadcasts `DeleteSynced` to all workers including W_new — **killing the flow
now active on W_new**. Claude-SMR independently flagged a narrower
session-replication-eligibility gap (NEEDS-MINOR) and v2 folds both. Codex
cleared control-socket + scope (its full verdict was lost to an output-capture
glitch; it re-attacks v2 fresh). v1's claim "no migration code needed; stale
copy ages out silently" was **wrong** and is corrected in §3/§4.5.

### Round-2 review outcome (verdict: PLAN-NEEDS-MAJOR, all three)
Codex + AGY + Claude-SMR all NEEDS-MAJOR, converged on the same design. v2's
single-origin `RebalancedOut` demotion fixed *premature* cleanup but: (Codex #1/
AGY) missed the **conntrack mirror delete** — `delete_session_map_entry_..._with_origin`
deletes conntrack + redirect keys ungated by origin (`bpf_map/mod.rs:952,1032,1037`);
(Codex #2) created a **never-cleanup leak** — W_new's replica is `WorkerLocalImport`
(peer-synced) so *its* eventual real expiry is ALSO Close-suppressed → no worker
owns shared-map/peer cleanup when the flow truly ends; (Codex #3) `RebalancedOut`
leaks through `demote_owner_rg` (`session/mod.rs:1030,1039`),
`refresh_owner_rgs` (`:32,80`), and peer export (`session_glue/mod.rs:420,436`).
v3 resolves all three with a **two-origin ownership transfer** (§4.5).
**Confirmed by reviewers:** ethtool ioctl direction correct + exact UAPI layout
(AGY, §4.1); eligibility gate bypasses the NAT-miss path
(`resolve_flow_session_decision`, `session_glue/mod.rs:886`); selection is
mathematically convergent (cooldown + `≤ gap/2` + ε-band); scope coherent.
- **Branch**: `engineer/1748-ntuple-rebalance`
- **Predecessors**: converged research plan (`research-plan.md`); R1 spike PASS
  (`r1-spike-findings.md`: CoV 16.8%→2.3–4.2%, aggregate preserved, established-
  flow mid-flight re-pin on `ge-0-0-1`).

## 1. Issue framing

The per-flow CoV on shaped ports swings 14–29% (`-P12`) because RSS hashes the
N flows unevenly across the 6 mlx5 VF RX queues → workers serve different flow
counts (`[2,2,1,1,4,2]`), and a worker's capacity splits among *its* flows. The
#1746 equal-flow cap can only clip fast flows down; it can't lift slow flows.
The only lever that lifts slow flows *and* preserves aggregate is moving an
established flow off an overloaded worker onto an idle one — proven in R1 to
take CoV to 2.3–4.2% with aggregate *up*. This PR builds the reactive controller
that does that move automatically.

## 2. Honest scope/value framing

- **Value**: lift `-P12` shaped-port CoV from ~16–29% toward the balanced floor
  (~3–4% measured), WITHOUT the #1746 cap's aggregate loss. This is the only
  mechanism that improves the structural ceiling `Cstruct` rather than operating
  within it.
- **Scope of THIS PR (deliberately bounded)**: a **default-OFF, opt-in**
  forward-direction reactive rebalancer in Rust `userspace-dp`:
  observe per-worker byte-rate imbalance → pick the flow whose move most
  flattens the per-worker byte-rate → install one exact-5-tuple ntuple rule via
  a direct `SIOCETHTOOL`/`ethtool_rxnfc` ioctl → bounded rule budget + hysteresis
  + dwell (≪1 Hz rule churn). Plus the config knob, metrics, and operator docs.
- *If reviewers conclude the perf gain is too small to justify the churn, or
  that R4 (HA) cannot be made safe in this increment, PLAN-KILL is an acceptable
  verdict.*

## 3. What's already shipped / composes-with

- **Session substrate (research §0, verified)**: HA replication pre-installs
  forward+reverse session replicas on every sibling worker
  (`poll_descriptor/mod.rs:1267`/`:1480`); the active-node packet path gates
  forwarding on owner-RG-active, never on which worker owns the session
  (`forwarding/mod.rs:541`, `session_glue/mod.rs:137`). So a flow steered to a
  new RX queue **forwards** correctly — BUT (round-1 correction) the move is NOT
  free of state work: W_old's now-stale `ForwardFlow` entry must be explicitly
  demoted so its GC expiry does not cascade-delete the live flow (§4.5).
- **Origin-aware deletion plumbing already exists**: both
  `delete_session_map_entry_for_removed_session_with_origin(...)` and
  `delete_session_map_redirect_for_session(...)`
  (`worker/loop_body/mod.rs:660-687`) already take `origin`, and
  `bpf_map/mod.rs:3 uses_kernel_local_session_map_entry()` already distinguishes
  local vs shared entries by origin — so the §4.5 fix extends an existing
  origin-gated path, not a new subsystem.
- **Occupancy telemetry**: `coordinator/status.rs:195-206` already aggregates
  per-`(ifindex, queue_id, worker_id)` active-flow counts; per-worker
  `tx_bytes: AtomicU64` (`umem/mod.rs:387`) supplies byte-rate.
- **Flow 5-tuples**: `flow_cache.rs` holds per-flow keys (incl. NAT rewrite
  ports — see R7).
- **ioctl precedent**: `slowpath.rs` already does `libc::ioctl` on an
  `AF_INET`/`SOCK_DGRAM` socket (`SIOCGIFFLAGS`/`SIOCSIFFLAGS`/`TUNSETIFF`).
- **#1746 cap + #1230 lease**: complementary (within-worker levers); this changes
  `{aᵢ}` itself. No conflict (research §6).

## 4. Concrete design

### 4.1 NIC programming — direct ioctl, no shell-out, no genetlink crate
The rust-netlink `ethtool` crate does **not** expose rxnfc/flow-classification
rules (verified on docs.rs: only feature/coalesce/ring/channel/link/pause/FEC/
timestamp). Flow rules are ioctl-only. New module
`userspace-dp/src/afxdp/rebalance/ntuple.rs`:

```rust
// mirrors slowpath.rs's libc::ioctl-on-AF_INET-socket pattern
#[repr(C)] struct EthtoolRxnfc { cmd: u32, flow_type: u32, /* h_u, m_u union */
    data: u64, fs: EthtoolRxFlowSpec, rule_cnt: u32, rule_locs: [u32;0] }
// ETHTOOL_SRXCLSRLINS=0x32, SRXCLSRLDEL=0x31, GRXCLSRLALL=0x30
fn insert_rule(ifname, FlowSpec5Tuple, queue) -> io::Result<u32 /*loc*/>
fn delete_rule(ifname, loc) -> io::Result<()>
fn list_locs(ifname) -> io::Result<Vec<u32>>   // for reconcile/cleanup
```
Single `ioctl(fd, SIOCETHTOOL=0x8946, &ifreq{ifr_name, ifr_data:&rxnfc})`.
Structured `errno` (e.g. `ENOSPC` at the 1024 cap, `EOPNOTSUPP` non-mlx5) — no
text parsing. Programs the **local** node's interface only.

**Exact UAPI layout (AGY-verified against kernel `ethtool.h`, x86-64) — assert
at compile time:**
- `struct ethtool_rx_flow_spec` = **168 B**: `flow_type` u32 @0; `h_u` union @4
  (52 B); `h_ext` @56 (20 B); `m_u` union @76 (52 B); `m_ext` @128 (20 B); pad
  @148 (4 B); `ring_cookie` u64 @152; `location` u32 @160; pad @164 (4 B).
- `struct ethtool_rxnfc` = **192 B**: `cmd` u32 @0; `flow_type` u32 @4; `data`
  u64 @8; `fs` @16 (168 B); `rule_cnt`/`rss_context` u32 @184; pad @188;
  `rule_locs` `[u32;0]` flexible @192.
- For TCP4: `flow_type=TCP_V4_FLOW(0x03)`, `h_u.tcp_ip4_spec{ip4src,ip4dst,
  psrc,pdst}`, masks in `m_u` (0 = match, 0xff..= wildcard — kernel inverts),
  `ring_cookie` = target queue index, `location = RX_CLS_LOC_ANY` to auto-assign.
- `cmd = ETHTOOL_SRXCLSRLINS(0x32)` insert, `0x31` del, `0x30` getall.
- `size_of::<EthtoolRxnfc>() == 192` and field-offset asserts gate the build; a
  live insert→`GRXCLSRLALL`→read-back round-trip test validates wire semantics.

### 4.2 Controller loop (coordinator-level, low cadence)
New `rebalance/controller.rs`, ticked from the existing coordinator status
cadence (NOT per-packet, NOT per-poll — gated to ≤1 decision/dwell-interval):
1. Read per-worker byte-rate over the last window (Δtx_bytes/Δt per worker on the
   target ifindex).
2. If `max_worker / mean > imbalance_threshold` AND it has persisted ≥
   `dwell_ticks` (hysteresis): pick the **heaviest single flow** on the hottest
   worker whose move to the **least-loaded** worker most flattens the per-worker
   byte-rate vector (byte-rate-aware selection — the fix for #1203's count-blind
   defect, research §4 R1).
3. Install one exact-5-tuple rule (forward direction) → least-loaded queue.
   Record (5-tuple→loc,queue) in an in-memory ledger.
4. Stop conditions: byte-rate CoV below target, or rule budget exhausted, or no
   move improves the objective. Never oscillate (a flow re-pinned within
   `cooldown` is ineligible).

Bounded churn: at most one install per `rebalance_interval` (default ≥1 s),
hard cap `max_rules` (≪1024) with graceful RSS fallback for the rest.

**Round-1 refinements to the selection/eligibility logic:**
- **Move-eligibility gate (SMR)**: a flow is eligible only if (a) age >
  `session-sync interval + margin` AND (b) the target worker already holds a
  peer-synced replica (`is_peer_synced()` present). This guarantees the target
  worker's flow-cache miss resolves to the EXISTING session/NAT binding, never
  the `*_on_session_miss` NAT-realloc family (`forwarding/mod.rs:1026-1164`).
- **One move per tick (AGY)** — never move >1 flow per `rebalance_interval`, to
  bound the R3 reorder (the R1 7601-retrans burst was 12 simultaneous moves).
- **Magnitude guard against thrash (AGY)**: abort the move unless the chosen
  flow's byte-rate ≤ (source_worker_rate − dest_worker_rate); i.e. moving it
  must not make the destination the new hottest worker. Plus a per-flow
  `cooldown` ≥ several intervals and an ε-band (move only if projected
  byte-rate CoV improves by > ε). Stop condition: "no single eligible move
  reduces byte-rate CoV by > ε" — terminates (finite flows, monotone objective
  under the ε-band), cannot oscillate.

### 4.5 Move protocol — two-origin ownership transfer (round-2 must-fix)
A move is a genuine **ownership transfer** W_old → W_new. Two new
`SessionOrigin` variants make the handoff correct:
- **`RebalancedOut`** — the abandoned copy on W_old. Suppress-everything: never
  cleans up shared state, never exports/syncs/promotes; ages out local-only.
- **`RebalancedOwner`** — the promoted owner on W_new. Behaves like `ForwardFlow`
  for cleanup/export/sync (emits Close on REAL expiry, deletes shared map +
  conntrack, broadcasts `DeleteSynced`, releases SNAT) — so exactly one worker
  owns end-of-flow cleanup. `is_peer_synced()` stays false for it (it is a
  local owner, not an import) so it is NOT Close-suppressed.

Coordinator sequence (one move per `rebalance_interval`):
1. **Eligibility**: flow age > `session-sync interval + margin` AND a fresh
   target-worker replica-present ack (W_new holds the materialized synced
   replica — `resolve_flow_session_decision`, `session_glue/mod.rs:886` — so the
   first steered packet hits it and bypasses the `*_on_session_miss` NAT-realloc
   family). Magnitude `≤ gap/2`, cooldown clear, projected CoV gain `> ε`.
2. **Promote W_new (before the rule):** `WorkerCommand::PromoteRebalanced{key}`
   sets W_new's existing replica `origin = RebalancedOwner` — **tag flip only,
   no NAT reallocation, no republish**. W_new is now the single cleanup owner.
3. **Demote W_old (before the rule):** `WorkerCommand::DemoteRebalanced{key}`
   sets W_old's forward entry `origin = RebalancedOut`. Doing both demote+promote
   before the rule means a racing GC tick on either side sees safe origins.
4. **Install the ntuple rule** (forward 5-tuple → W_new's queue) via
   `SIOCETHTOOL`. W_new's `RebalancedOwner` entry's `last_seen_ns` advances with
   the arriving packets; W_old's `RebalancedOut` entry freezes and ages out.

**`RebalancedOut` GC/HA suppression — the complete set (all code-verified):**
- **Close delta**: `session/mod.rs:431` gains `&& !origin.is_rebalanced_out()`.
- **Shared session-map redirect + conntrack delete**: early-return guard at the
  top of `delete_session_map_entry_for_removed_session_with_origin`
  (`bpf_map/mod.rs`) — `if origin == RebalancedOut { return; }` (AGY's surgical
  fix; covers both the redirect-key delete `:952` AND the conntrack delete
  `:1032/:1037` in one guard, since W_new owns those entries now).
- **`DeleteSynced` broadcast**: gated off for `RebalancedOut`.
- **SNAT release**: `release_source_nat_allocation` (`worker/loop_body/mod.rs:670`)
  skipped for `RebalancedOut` (W_new releases it on its own close).
- **HA/export path exclusions**: `demote_owner_rg` (`session/mod.rs:1030,1039`)
  must NOT rewrite `RebalancedOut`→`SyncImport`; `refresh_owner_rgs`
  (`:32,80`) must NOT republish it; peer export (`session_glue/mod.rs:420,436`)
  must NOT emit an Open delta for it.

**Ordering + timing invariant (SMR r3 — required):** the controller MUST issue
promote(W_new) → demote(W_old) → rule-install within a SINGLE rebalance tick,
and `rebalance_interval` (and the move-sequence duration) MUST be ≪
`SESSION_GC_INTERVAL_NS` so no GC sweep interleaves the transfer. Per-worker
loop serialization (commands + `expire_stale_entries` run in the same
single-threaded worker loop) then guarantees GC on W_old never observes a stale
`ForwardFlow`, and there is always ≥1 owner (zero-owner impossible; transient
two-owner is harmless — neither expires in the sub-tick window).

**`RebalancedOwner` vs `RebalancedOut` get OPPOSITE HA treatment:**
`RebalancedOut` is inert (excluded from demote/refresh/export). `RebalancedOwner`
is a normal *local owner* — on a real RG failover it MUST demote to `SyncImport`
like `ForwardFlow` (i.e. it participates in `demote_owner_rg`/export/sync
normally; it is excluded only from the *rebalance* suppression, not from HA).
The promote is a tag-flip on `origin` ONLY — no re-publish, no NAT re-resolve
(a unit test asserts the SNAT allocation owner/refcount is unchanged across
promote).

On rule removal / flow close / disable: delete the ntuple rule; the flow
re-hashes back to RSS naturally (W_new's `RebalancedOwner` entry is the
authoritative owner). On **failover**, the standby has no rules → RSS fallback
(correct; fairness re-converges) — documented in operator docs.

### 4.3 Config knob (default-OFF)
`pkg/config/schema.go` typed leaf under `class-of-service` (or `chassis`/
forwarding-options — reviewer Q): `flow-rebalance` with sub-leaves
`imbalance-threshold`, `rebalance-interval`, `max-rules`. Compiles to a
userspace-dp control message; absent ⇒ controller never constructs its ioctl
socket and installs zero rules (byte-identical default path).

### 4.4 Metrics
`xpf_userspace_flow_rebalance_{rules_active, installs_total, deletes_total,
moves_skipped_total{reason}, worker_byterate_cov}` per ifindex.

## 5. Public API preservation
No existing Rust pub-fn signatures change. New module is additive. Go: one new
schema leaf + one control-message field (additive, default zero).

## 6. Hidden invariants to preserve
- **Default-OFF is byte-identical**: no ioctl socket, no rules, no extra
  per-tick work when the knob is unset (gated construction).
- **Control-socket contention** (CLAUDE.md): the controller must NOT add a
  >1 Hz control-socket caller; it reads worker telemetry already collected by
  the status path and programs the NIC directly (not via the control socket).
- **No per-packet/per-poll cost**: decision loop is coordinator-cadence only.
- **ioctl safety**: `ethtool_rxnfc` layout must match the kernel UAPI exactly
  (size/align) — compile-time `size_of` assertion + a parity test.
- **Rule lifecycle**: every installed rule is tracked and deleted on disable,
  flow-close, daemon shutdown, and reconcile (no orphan HW rules across config
  changes — `list_locs` reconcile on startup clears stale xpf-owned rules).

## 7. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW (OFF) / MED (ON) | OFF is byte-identical; ON adds HW steering — R3 transient reorder is the main correctness watch |
| Lifetime/borrow | LOW | additive module, owns its own state/socket |
| Performance regression | LOW | coordinator-cadence, ≪1 Hz rule writes; ~1 ms/rule firmware off the hot path |
| Architectural mismatch | MED | R4 (HA mirroring) deferred — must prove forward-only single-node re-pin is HA-*correct* (not just fairness) this increment, or KILL |

## 8. Test plan
- cargo build + full suite; new `ntuple.rs` UAPI size/parity test + controller
  unit tests (selection objective, hysteresis, budget, oscillation guard) 5×.
- Go suite (schema leaf + compile).
- Deploy on loss cluster. **R1-equivalent live gate**: enable knob, `-P12 -p5210`
  push, confirm controller drives per-worker `{aᵢ}` toward balance and per-flow
  CoV ≤10% with aggregate not regressed and bounded retransmits (incremental
  moves, not the 7601 bulk-move artifact). Default-OFF control run unchanged.
- Full Pass A/B smoke matrix (v4+v6 × push+reverse × CoS-off/on).
- **`make test-failover`** MUST stay clean (touches placement on an HA cluster).

## 9. Out of scope (explicit follow-ups)
- **R2 reverse-direction** rule pair (forward-only this PR; documented).
- **R4 HA peer rule-mirroring** for fairness *continuity* across failover (this
  PR proves correctness; mirroring for sustained post-failover fairness is a
  follow-up). After failover the new primary falls back to RSS until it
  re-converges — fairness, not correctness, regresses.
- Full 1024-rule eviction policy refinement (R5) beyond a simple budget+cooldown.

## 10. Open questions for adversarial review (each invitable to PLAN-KILL)
0. **(v2) Does `RebalancedOut` fully close the GC cascade?** v2 suppresses FOUR
   sites on W_old's stale-entry expiry: Close delta, shared session-map delete,
   `DeleteSynced` broadcast, and SNAT release (all verified as real hazards).
   Re-attack: is there any OTHER GC/sync site that acts on W_old's expiring
   entry and touches shared state W_new depends on — conntrack-map mirror delete
   (`conntrack_v4_fd`/`conntrack_v6_fd` in
   `delete_session_map_entry_for_removed_session_with_origin`), alias/redirect
   cleanup, flow-cache invalidation broadcast, or the reverse-companion entry?
   Name it with a quoted line or confirm the four-point set is complete.
1. **R4 correctness**: with §4.5 demotion in place, does re-pinning ONLY the
   forward 5-tuple on ONLY the active node still break reverse-companion
   resolution or peer session-sync? Find a residual per-worker gate. (v1 KILL
   risk now addressed by §4.5 — re-attack it.)
2. **R3 transient**: is the per-move reorder bounded enough to avoid TCP resets
   under incremental single-flow moves, or does even one move risk a reset?
3. **`ethtool_rxnfc` UAPI**: is the struct/union layout correct across the
   target kernel (7.0.0-rc7+) and is `SIOCETHTOOL` the right path vs the ethtool
   netlink family (confirm flow rules truly aren't in genetlink)?
4. **Selection objective**: is "move the heaviest flow on the hottest worker"
   provably convergent (not oscillating) with hysteresis, or can it thrash like
   #840 (CoV 37.7% vs 18.5%)?
5. **Schema placement**: is `class-of-service flow-rebalance` the right grammar
   home, or does this belong under `chassis`/`forwarding-options`?
6. **Scope honesty**: is a forward-only, single-node, default-OFF increment a
   coherent shippable unit, or does it only become useful once R2+R4 land (→
   ship nothing until then)?
