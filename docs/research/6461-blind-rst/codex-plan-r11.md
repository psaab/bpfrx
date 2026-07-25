# Codex hostile plan review — round 11 — #6461 blind-RST demote gate

Reviewer: Codex (gpt-5.5 via codex-companion, resumed session 019f95f3-c124-7c60-9d1b-198b9629c197). Scope: plan v8.2 @ f6dbb3bde (v8.3 landed mid-review and is excluded from its line refs).
Run ledger: task-mrztzy3r-cn3tgd (18m56s, completed). Verbatim final output below (.scratch/r11-codex-final.txt).

---

PLAN NO

Scope: v8.2 at `f6dbb3bde`, as pinned. The later v8.3 worktree revision was excluded. No files were edited.

## Findings

1. **BLOCKER — The TTL leaves the stale-NAT rematerialization window open**

   V8.2 retains aliases until `last_touch + K×T`, with `K≥4` (`plan.md@f6dbb3bde:695-733`), but an unmarked worker entry reaps around `T` and immediately releases its SNAT/NAT64 reservation at [worker/loop_body/mod.rs:1481](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1481). The shared alias therefore outlives the reservation by roughly `3T`.

   During that interval, a shared lookup can materialize the old decision through [session_glue/mod.rs:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1092). Reactive materialization does not re-reserve the port; even the normal import reservation at [upsert_synced.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:80) has no failure result capable of vetoing installation ([source.rs:868](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:868)). If the allocator has reassigned the port, the stale flow is reinstalled with the colliding translation. At `T=86,400s`, this is about three days after worker reap.

   Moreover, every shared read refreshes `last_touch`. A tuple-matching packet can re-materialize the orphan after each local reap and keep the alias indefinitely. A refused close therefore becomes a shared-alias refresh despite §5.7’s inertness claim. Cleanup must be coupled to reservation/last-replica lifetime, not merely delayed by `K×T`.

2. **BLOCKER — Per-alias `last_touch` has no coherent family-level source of truth**

   Canonical, NAT, and forward-wire maps contain independent `SyncedSessionEntry` clones and use separate mutexes ([shared_ops.rs:482](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:482), [shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897)). A NAT lookup can refresh its clone while the canonical candidate remains stale; sweeping that candidate then deletes the recently used alias. Conversely, treating every clone as a candidate lets an unused sibling delete an active family.

   The family also includes a separately published reverse canonical entry at [ha/session_import.rs:104](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:104), which the proposed “canonical/NAT/wire” transaction does not name. V8.2’s “one coordinator lock” (`plan:715-729`) also fails to state that every packet-worker publisher, promote, lookup touch, and materialization commit participates; current publication locks the maps separately. The design needs one family liveness record and an atomic transaction covering forward canonical, reverse canonical, NAT, wire, and indexes.

3. **BLOCKER — The normative sticky close mark is not carried by the actual wire**

   V8.2 relies on wire imports preserving peer-validated `closing/reset` and re-seeding the mark after reimport (`plan:648-694`). No such field exists:

   - SessionOpen encodes no TCP close flags or validated mark ([event_stream/codec/session_sync.rs:15](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/session_sync.rs:15)).
   - `SessionSyncRequest` has no mark field ([protocol/control.rs:988](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/protocol/control.rs:988)).
   - Import construction hardcodes `tcp_flags: 0` ([server/helpers/session_sync.rs:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/helpers/session_sync.rs:168)).
   - Reimport remove/replaces the existing entry at [session/install.rs:317](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:317).

   Thus a full reimport before the two-second reap erases an accepted mark and leaves zero producers. This directly contradicts “no HA wire/shared-schema change” at `plan:1100-1113`. An incarnation-bound validated-mark field or same-incarnation mark merge is required; raw observed TCP flags are not an acceptable substitute.

   There is another acknowledged zero-producer case: reverse-synth acceptance marks only the reverse entry until a later hit (`plan:1010-1017`), while `is_reverse` excludes that entry from emission. With no later packet, the validated close never reaches an eligible forward producer.

4. **BLOCKER — `sender.rg_epoch >= current` compares unrelated local counters**

   Phase 2 requires this owner gate and claims dual-owner overlap converges (`plan:1688-1698`). The available epochs are node-local:

   - Rust increments its local `rg_epochs` on that node’s transitions ([ha/state.rs:39](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/state.rs:39)).
   - Go’s `rgStateMachine.epoch` is also local and increments during local reconciliation ([rg_state.go:250](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/rg_state.go:250)).
   - Heartbeats carry no cluster ownership term ([heartbeat.go:93](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/heartbeat.go:93)).

   A valid new owner at local epoch 5 can be rejected behind a former owner at 100; the former owner’s delayed update can likewise pass. During overlap, sender-local `bulk_epoch` and `writer_gen` provide no deterministic convergence. Phase 2 needs a cluster-agreed ownership term keyed by RG and owner process, not a numeric comparison of independent counters.

5. **BLOCKER — The Phase-2 payload cannot represent its claimed per-bundle writers**

   The payload has one outer `writer {node, worker, rg_epoch, writer_gen}` followed by two direction bundles (`plan:1502-1508`), but the normative merge assigns a distinct writer generation to each bundle (`plan:1513-1520`). Split steering explicitly places the two directions on different workers (`plan:1602-1613`). A full baseline containing both directions therefore cannot identify both writers or both generations.

   “Handed to the most recent observer” is also not a handoff protocol: no atomic claim/grant, generation increment, cancellation of old queued writes, or rule preventing one direction’s observation from renewing the other is specified. Writer identity, owner term, generation, sequence, and observation time must be per bundle.

6. **BLOCKER — Stream initialization and write-time freshness do not work over the current transport**

   Three independent failures remain:

   - V8.2 says every connection first receives `BulkStart` (`plan:1568-1575`), but the secondary fabric is added without bulk, and routine active-fabric changes resume incrementals only ([sync_conn.go:125](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:125), [sync_conn.go:208](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go:208)). When the original fabric fails, the surviving connection has no nonce/floor and its anchor updates are rejected indefinitely.
   - The wire carries only a `fresh` bit. Rust queues pre-serialized frames ([codec/mod.rs:27](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/mod.rs:27)); Go queues and indefinitely retries encoded `[]byte` ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:36), [sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268)). Neither layer retains the original observation time needed to recompute freshness at the actual peer write.
   - On a later same-connection bulk, the new epoch is published before `BulkStart` acquires `writeMu` ([sync_bulk.go:65](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:65)). An `E+1` incremental can therefore be written before `BulkStart(E+1)` and pass the existing greater-epoch rule.

   Each authenticated connection needs a stream-start marker; queued records must remain typed with per-bundle observation times; and epoch activation must be atomic with writing `BulkStart`.

7. **BLOCKER — Flow incarnation and deletion are not end-to-end**

   V8.2 asserts one `flow_incarnation_id` for every entry, replica, and alias (`plan:734-753`), but the constructor plumbing does not define that invariant:

   - Fresh installation mints internally ([session/install.rs:140](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:140)), while primary forward and reverse halves are installed separately.
   - Reverse synth installs and publishes a new entry at [shared_ops.rs:824](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:824); the planned `ForwardSessionMatch` additions at `plan:1091-1098` omit the forward incarnation.
   - Primary reverse publication currently carries zero identity ([poll_descriptor/mod.rs:2897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2897)).
   - Fabric-return and tunnel fanout have no stated inheritance/mint authority.

   Same-node deletion remains key-only: [session_glue/mod.rs:851](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:851) queues `DeleteSynced(key)`, and [delete_synced.rs:9](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:9) unconditionally deletes the current occupant. A delayed E1 cleanup can therefore kill replacement E2.

   The proposed restart lifecycle itself is coherent if fully transported: B retains A’s `(A_nonce,id)`, A reconstructs it after restart/reimport, and B’s connection identity is used only for authority. But current `SessionDelta`/Close encoding carries neither field ([session/entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [session_sync.rs:215](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/event_stream/codec/session_sync.rs:215)), and v8.2 never specifies that Close transport.

8. **HIGH — The malformed-tail residual is not strictly dominated**

   The precursor still needs an in-window hit, so it does not create an easier direct kill. But after that first hit, trusted self-slide permits contiguous follow-ons (`plan:597-607`). A packet admitted to the LocalDelivery/TUN queue can move the anchor before a later asynchronous write failure ([slow_path.rs:213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:213), [tunnel.rs:180](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/tunnel.rs:180), [slowpath.rs:534](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/slowpath.rs:534)).

   Poisoning the anchor so the endpoint’s legitimate close is soft-refused can retain a slot or NAT reservation for 300–86,400 seconds. That can be preferable to the attacker over a two-second demote, which releases resources. The plan may describe this as a same-probability resource-retention channel, but `plan:467-474` and §11 Q5 cannot call it strictly worse for every attacker objective.

9. **MEDIUM — The packet-driven mark inventory is still not exact**

   The important v8.2 folds are correct on paper: closing packets skip promotion; reverse synth validates before accepted seeding; materialize installs alive on refusal; tunnel UpsertLocal is trusted-local.

   Two unvalidated constructors remain outside the asserted three-source mark rule:

   - Fabric excludes every SYN-clear close, including FIN+ACK with payload, but `SYN|ACK|RST`/`SYN|ACK|FIN` pass both guards at [fabric.rs:404](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/fabric.rs:404) and seed raw `closing/reset` through [poll_descriptor/mod.rs:981](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:981).
   - LocalDelivery is deliberately exempt from the bare-close miss guard ([session_admission.rs:78](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:78)) and installs raw flags at [poll_descriptor/mod.rs:1950](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1950).

   Neither is a live authoritative-flow bypass: the fabric seed is `is_reverse`, while the LocalDelivery case creates a new local entry. Their consequence is junk churn and a false normative invariant, not the original cluster kill. Site 3/site 6 and their tests must nevertheless state this honestly.

10. **MEDIUM — Phase-2 capacity and whole-cost accounting remain understated**

   The claimed ~24-byte scheduling budget is already exhausted by two `u64` incarnation fields plus two `u32` sequence numbers (`plan:226-232`), leaving no room for baselines, observation timestamps, two writers/generations, heartbeat state, or dirty scheduling. The risk table still reports only 56 bytes at `plan:1279`.

   Capacity is counted per flow, while split steering requires independently emitted direction bundles. Applying the documented ~83% split to the stated ~1,167 records/s gives roughly 2.1k bundle records/s—slightly above the proposed `8×256=2,048` helper floor before headroom. The Go sidecar also lacks a live-entry-only creation rule, maximum size, and bulk-reconciliation deletion contract. Overload decays safely to refusal, but the advertised steady-state freshness is not demonstrated.

11. **MEDIUM — The normative text and mandatory tests still describe incompatible designs**

   Examples in the pinned plan:

   - `plan:1148-1164` omits `(locally_born || marked)`, calls emission single-producer, excludes `WorkerLocalImport`, and simultaneously denies and retains origin promotion.
   - `plan:1172-1188` retains the old load-bearing “peer replicas never emit Close” invariant, contradicting marked-import emission.
   - `plan:1100-1102` says no shared-map schema change despite adding `last_touch_ns` and `flow_incarnation_id`.
   - `plan:1347-1355,1373-1388` still requires exactly one producer and uses obsolete `(origin_node_id, session_id)` fencing.
   - `plan:1562-1567` omits `writer_gen` from one merge rule.
   - `plan:195-198` still summarizes the cap near `2^-13–2^-14` although §2’s own cap is approximately `2^-12.68`.

   Missing decisive tests include mark survival across reimport, NAT release versus alias purge, per-alias clock disagreement, reverse/tunnel ID inheritance, E1 key-only fanout against E2, secondary-fabric activation, queued freshness expiry, later same-connection BulkStart ordering, and dual-owner term selection. The pending-neighbor dispatch contract itself is now complete at `plan:485-502`; its incarnation-mismatch/fresh-disposition matrix still needs tests.

## Round-10 dispositions

- **R10-1 — partially resolved.** The main predicate is now exact, but its mark provenance/transport is false and stale sections restate the old predicate.
- **R10-2 — not resolved.** A clock exists, but it is attacker-refreshable, incoherent across alias clones, and outlives the NAT reservation.
- **R10-3 — partially resolved.** Expected-incarnation compare-delete is right; the family and transaction participants remain incomplete.
- **R10-4 — partially resolved.** A distinct flow ID is introduced, but paired/reverse/tunnel constructors and local conditional deletes do not carry it end to end.
- **R10-5 — partially resolved.** Writer generation and owner gating are named, but the payload cannot encode two writers, handoff is undefined, and RG epochs are incomparable.
- **R10-6 — partially resolved.** Sender nonce and write-time freshness are the right direction; secondary connections, typed observation time, and later-bulk ordering remain broken.
- **R10-7 — not resolved.** Reimport can erase the only mark, reverse synth can leave no eligible producer, and key-only fanout can delete E2.
- **R10-8 — partially resolved.** The new tuple and restart/reimport lifecycle are conceptually correct, but Close transport and atomic comparison are unspecified.
- **R10-9 — partially resolved.** Selective no-learning and capacity reporting were folded; the “strictly dominated” risk conclusion is false for resource-retention objectives.
- **R10-10 — partially resolved.** Heartbeat staggering and a flush floor were added; direction multiplicity, memory accounting, and sidecar bounds remain open.
- **R10-11 — resolved.** V8.2 now requires one deadline-preserving re-resolution and standard-dispatch of every fresh disposition or drop, never the stale decision.
- **R10-12 — partially resolved.** Several cases were corrected, but substantial predicate, fencing, capacity, and test contradictions remain.

Bottom line: the packet-level close validator is converging—promotion, reverse-synth refusal, materialize-alive, and no-baseline behavior are largely sound—but the replacement HA cleanup and Phase-2 trust protocol are not. The exact stale-SNAT hazard survives for roughly `3T`, the authoritative close mark does not exist on the wire, incarnation-sensitive cleanup remains key-only, and Phase 2 cannot establish a comparable owner term, two per-direction writers, or fresh ordered state on ordinary dual-fabric operation. Implementation should not proceed from v8.2.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
