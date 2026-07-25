# AGY hostile plan review — round 8 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only, scoped sections). Scope: plan v7.4. Transcript: .scratch/r8-agy-out1.txt (verbatim below).

---

### Defensive Firewall DoS-Hardening Design Review (#6461, Plan v7.4)

#### (1) Authority Ticket Race & Origin Narrowing
- **Verdict:** **SOUND**
- **Evidence:** [`userspace-dp/src/session/entry.rs:256-262`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L256-L262) (`worker_replica_origin`) evaluates [`is_promotable_synced()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs#L252-L254). For locally-born flows (`ForwardFlow`, `SharedPromote`, `LocalMiss`), it returns `WorkerLocalImport` (siblings stay silent). For HA-wire imports (`SyncImport`, `SharedMaterialize`), `is_promotable_synced()` is `true`, returning `SyncImport`/`SharedMaterialize` (in the ticket CAS race).
- **Plan Alignment:** [`docs/research/6461-blind-rst/plan.md:615-625`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L615-L625) (§5.2 Rule 5) and [`lines 1047-1055`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1047-L1055) (§7 Close authority) specify that `WorkerLocalImport` and fabric replicas stay silent, narrowing the compare-and-delete race strictly to HA wire imports.

#### (2) Per-Side Writer Ownership for Phase-2 Anchors
- **Verdict:** **SOUND**
- **Evidence:** [`userspace-xdp/src/lib.rs:1460`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-xdp/src/lib.rs#L1460) (`select_userspace_queue`) steers packets by physical RX queue index. A worker observing direction $D$ sees $seq(D)$ and $ack(D)$, owning $seq\_hi(D)$ and $ack\_hi(D)$.
- **Total Mapping:** 
  - *Symmetric steering:* A single worker observes both $D$ and $O$, owning all 4 sides ($seq\_hi(D), ack\_hi(D), seq\_hi(O), ack\_hi(O)$).
  - *Split steering:* Worker 1 observing $D$ owns $seq\_hi(D), ack\_hi(D)$; Worker 2 observing $O$ owns $seq\_hi(O), ack\_hi(O)$. All 4 sides are strictly covered.
- **Plan Alignment:** [`docs/research/6461-blind-rst/plan.md:1432-1440`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1432-L1440) (§10.5) explicitly defines this 4-side total decomposition without gaps.

#### (3) Trust-Decay Lease & Owner Renewal Posture
- **Verdict:** **SOUND**
- **Evidence & Mechanics:** Wire-trusted sides carry `wire_anchor_lease_ns` (~240s `T_anchor`), evaluated lazily at validation. Genuinely idle flows emit 60s heartbeats ([`plan.md:1452-1456`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1452-L1456)). Leases are renewed *only* by an `AnchorUpdate` emitted by the observing owner ([`plan.md:1473-1476`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1473-L1476)).
- **No-Owner Renewal:** There is no renewal path that refreshes trust without owner observation (remote apply, import, materialization, and stale reconnect bulk explicitly never renew the lease).
- **Plan Alignment:** [`docs/research/6461-blind-rst/plan.md:1468-1487`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1468-L1487) (§10.5) enforces lazy lease evaluation and owner-only renewal.

#### Plan Contradictions
- **Contradictions Found:** **None.** The plan text across §5.2 Rule 5, §7, and §10.5 remains consistent with source structures and implementation invariants.
