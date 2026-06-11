# #1861 — Transactional session install (forward+reverse partial-failure interleavings)

**Status:** DRAFT v2 — round-1 verdicts: AGY PLAN-NEEDS-MINOR, Claude SMR
PLAN-NEEDS-MINOR (Codex r1 re-dispatched — first dispatch killed by a
concurrent session's Codex job; verdict folded on arrival). v2 folds:
SMR F1 (I2 severity scoped to pool-mode SNAT; interface-mode rollback is a
no-op), SMR F2 (new row I13: local-tunnel UpsertLocal pair ignores install
result), SMR F3 (at-cap allocator churn unchanged, stated), SMR F4
(stateless-limp-along → shed scenario named in §9), SMR F6 (rollback call
shape), AGY F1 = SMR Q5 (`created: true` over-count fix accepted as
in-scope ride-along — `install_reverse_session_from_forward_match` returns
`(SessionLookup, bool)`).
**Date:** 2026-06-11
**Branch:** `research/1861-install-txn` (off origin/master `6d8fa810d`)
**Issue:** #1861 (filed from the #1760 stage-2 revisit, W4 deliverable; both
faces first flagged by Codex #1760 r2 2026-06-06 and AGY r2 F2 2026-06-10)
**Mode:** /research — PLAN-READY or PLAN-KILL only. PLAN-KILL is explicitly
invited (§11 Q8). No production code in this phase.

---

## 1. Issue framing

`SessionTable::install_with_protocol_with_origin` can refuse an install
(today, only the `max_sessions` cap — `session/mod.rs:690`). The new-flow
path in `poll_descriptor/mod.rs` treats the forward install and the reverse
install as two independent best-effort operations with no transaction
boundary:

- **Face (i)** — forward install fails: the SNAT allocation is rolled back
  (`mod.rs:1340-1349`), but control falls through — the reverse resolution
  is computed, a reverse install is attempted, the trigger packet is
  **forwarded** with the just-rolled-back SNAT decision, and (worst, found
  in this walk) the rolled-back NAT decision is **inserted into the flow
  cache** (`mod.rs:2016`), making the unreserved-tuple leak persistent.
- **Face (ii)** — forward succeeds at `max_sessions-1`, reverse fails at
  cap: the forward session is fully committed (BPF entry `:1294`, shared
  maps `:1311`, dnat table `:1320`, replica fan-out `:1325`, HA Open delta
  pushed inside install) with no reverse companion and no rollback.

The fix must place a single transaction boundary around the pair, preserve
the #964 eager-cleanup invariant (`no_index_points_at`) and the #1855
corruption contract (impossible states panic in debug, tolerate+count in
release), and adopt Junos parity semantics: session-creation failure ⇒
trigger packet dropped.

## 2. Honest scope/value framing — and two corrections to the issue text

This is a correctness fix on the new-flow **cold path** at/near table
capacity (131,072 entries per worker table, `DEFAULT_MAX_SESSIONS`,
`session/mod.rs:25`; not runtime-configurable). It has zero effect on the
warm path and zero effect away from capacity. The lab never operates at
cap; production deployments under SYN flood or connection churn will.

The code walk **refutes two claims in the issue body** (both inherited from
the #1760 reviewer findings; the plan must be graded against the corrected
facts, not the filed text):

1. **Face (i) "reverse session still installed" is unreachable today.**
   The forward and reverse installs hit the *same* per-worker
   `SessionTable` (`&mut`, single-threaded) within the same descriptor
   iteration. Forward can only fail at `len() >= max_sessions`; nothing
   removes an entry between the two calls, so the reverse install fails the
   identical cap check. (Reverse is additionally gated on the same
   `track_in_userspace` flag — `mod.rs:1436` — so the
   tracking-not-required case skips both.) The half-open reverse entry is
   a *latent* hazard for any future non-cap failure mode, not a live one.
2. **Face (ii) is not a "permanent one-way blackhole."** A reply with no
   reverse entry misses BPF, reaches userspace, misses
   `lookup_session_across_scopes`, and is repaired by
   `lookup_forward_nat_across_scopes` (`shared_ops.rs:556`) — the forward
   install indexed the session under its reverse wire key
   (`index_forward_nat_key_parts`, `session/mod.rs:1376-1411`, NAT'd or
   not). `install_reverse_session_from_forward_match`
   (`shared_ops.rs:702`) then returns the rebuilt reverse decision **even
   when its own install fails at cap**, so the reply is forwarded. Face
   (ii)'s real symptoms are degradation, not blackhole: every reply rides
   the cold path until the table drops below cap, the repair install
   retries and fails per reply packet, and `session_creates` telemetry
   over-counts (the repair path returns `created: true` unconditionally —
   `session_glue/mod.rs:1086`).

**The genuinely severe, previously-undocumented leak is in face (i), and
it is pool-mode-SNAT-scoped (SMR r1 F1):** the flow-cache insert at
`mod.rs:2016` is not gated on `forward_installed`.
`FlowCacheEntry::from_forward_decision` checks protocol/disposition/family
only (`flow_cache.rs:227-233`), and the cache has **no idle TTL** — only
config/FIB-generation invalidation and 4-way-set LRU collision eviction
(`flow_cache.rs:384-404`; AGY r1 F2 confirmed). At cap, a new TCP/UDP flow
whose install was refused gets its **rolled-back SNAT tuple cached**; every
subsequent packet forwards via the cache using a translated (ip,port) the
pool allocator believes is free (`allocator.rs:517/558` — `rollback_flow`
removes the flow's `live_by_flow` entry, returning the port to the pool)
and can grant to a different flow toward the same destination. That is
wire-level tuple aliasing — the same cross-flow reply-misdelivery class as
#1760 §2.6 — and it is **not self-healing**.

**Severity scope:** this allocator desync exists only for **pool-mode
SNAT** (port-translating, `nat/source.rs:453+`). Interface-mode SNAT — the
default and the smoke config's mode — rewrites the source *address only*
with no port allocation (`nat/source.rs:442-452`: no `rewrite_src_port`),
so `release_source_nat_allocation_with_mode` short-circuits
(`nat/source.rs:357-365`) and the failure-arm "rollback" is a no-op:
nothing is allocated, nothing leaks, and a refused interface-SNAT flow's
wire tuple is identical to what a successful install would have produced
(residual collision exposure there is the pre-existing #1760 surface, not
new). Pool mode is fully supported production config, so the hole is real
— but narrower than a blanket "all SNAT" reading, and Q8's kill arithmetic
must use this scoped severity.

If reviewers conclude the at-cap behavior churn (plus mandatory failover
gating) is not justified, PLAN-KILL is an acceptable verdict — but the
flow-cache leak needs an answer even under a kill (a one-line gate, §6
Path D).

## 3. What's already shipped / composes with this

- **#1762** NAT reverse-key collision counter; **#1760 stage-2** SHELVED
  (install-time refusal of *collisions* needs HA redesign — NOT what this
  plan does; this plan only makes the existing cap refusal transactional).
- **#1789** publish-error counters (`session_publish_errors`,
  `SESSION_PUBLISH_ERRORS_SHARED`) — BPF-publish partials are already
  counted, deliberately non-rolled-back (degraded NO_SESSION path).
- **#964** value-guarded secondary-index removal + `no_index_points_at`
  debug scan (`session/mod.rs:1427-1494`).
- **#1855** corruption contract: `remove_entry`/`update_session` guard arms
  are `debug_assert!` + tolerate-in-release
  (`docs/research/1855-inplace-contract/plan.md`, pins in
  `session/tests.rs:2111+`).
- **#1357** keeps `install_with_protocol_with_origin` positional (codegen
  gate) — this plan does not change its signature.
- **#850** DNS fast-path and LocalDelivery legitimately forward without
  installing (`dns_fastpath_admit` / `track_in_userspace == false`,
  `mod.rs:1252-1262`) — the guard must not drop those.

## 4. Complete partial-failure interleaving map (deliverable)

All at origin/master `6d8fa810d`. "Self-heals?" = without operator action.

| # | Interleaving | Where | State leaked | Self-heals? | Operator symptom today |
|---|---|---|---|---|---|
| I1 | Forward install fails at cap, packet still forwarded | `mod.rs:1274/1340` | SYN/UDP leaves with rolled-back SNAT tuple; allocator free-list out of sync with wire reality while packet in flight | partially (single packet) — but see I2 | none: `create_drops` (`session/mod.rs:154`) is **write-only, never exported** |
| I2 | I1 + flow-cache insert of rolled-back NAT decision | `mod.rs:2016` | **pool-mode SNAT only** (interface mode allocates nothing — `nat/source.rs:442-452/357-365`): cache forwards the whole flow statelessly on an **unreserved** SNAT tuple; allocator can grant same tuple to a new same-destination flow → wire tuple aliasing, cross-flow reply misdelivery | **NO** — flow cache has no idle TTL (generation/LRU eviction only) | silent; at most #1762 collision counter on the *other* flow's reply path |
| I3 | Forward fails, reverse install attempted anyway | `mod.rs:1436` | none **today** (cap fails both, §2.1); latent orphan-reverse for any future failure mode | n/a | none |
| I4 | Forward succeeds at cap-1, reverse fails at cap | `mod.rs:1274/1436` | forward fully committed, no reverse entry + no BPF reverse key | YES below cap (repair `shared_ops.rs:556/702`); degraded at cap | replies ride cold path; `session_creates` over-counts (`created:true` on failed repair, `session_glue/mod.rs:1086`); `create_drops` invisible |
| I5 | Reply repair install fails at cap | `shared_ops.rs:727` | none structural — decision still returned, reply forwarded | YES | per-reply cold path + telemetry skew (I4) |
| I6 | MissingNeighborSeed install fails, packet still **buffered** and later replayed | `mod.rs:2448/2504`, buffering below not gated on `pending_installed` | replayed frame forwarded with rolled-back SNAT tuple (I1-class); session-free replay (`neighbor_dispatch.rs` forwards buffered frames without sessions) | per-frame | none |
| I7 | Fabric-return fast-path install fails, packet still forwarded | `mod.rs:479/508` | none harmful: packet was policy/NAT-validated by active peer; forwarding is stateless-degraded; no local NAT allocation | YES | none (acceptable; count only) |
| I8 | LocalMiss helper-session install fails, local delivery proceeds | `mod.rs:840` | none (optimization entry only, no NAT) | YES | none (acceptable) |
| I9 | Forward install OK, BPF publish fails | `mod.rs:1294` | shim lacks key → NO_SESSION degraded path | YES (userspace still owns session) | #1789 `session_publish_errors` — **already shipped, out of scope** |
| I10 | `publish_shared_session` partial | `shared_ops.rs:765` | only on mutex poison (a worker already panicked) — not a practical partial | n/a | process-fatal-adjacent; out of scope |
| I11 | HA sync / replica upsert at cap | `session/mod.rs:766` (`upsert_synced_with_origin`) | **no cap check at all** — sync/replica installs bypass `max_sessions`; table can exceed cap via sync while local new flows are refused | n/a (design asymmetry, pre-existing) | none; documented here, change deferred (§10) |
| I12 | HA sync partial: forward upsert rejected by `allow_replace_local` arbitration while synthesized reverse accepted (or vice versa) | `session_glue/commands/upsert_synced.rs:65`, `ha.rs:243-336` | one-sided synced state on standby | YES — next 1s sweep / traffic promotion re-asserts | none; pre-existing arbitration semantics, out of scope |
| I13 | Local-tunnel forward+reverse `UpsertLocal` pair: shared maps published unconditionally, worker-table installs silently dropped at cap | `tunnel.rs:309-331` (publish + enqueue), `session_glue/mod.rs:556-569` (install result discarded) | shared-map/local-table divergence for tunnel sessions at cap; `wait_for_local_tunnel_session_install` 1 ms wait just times out | YES-ish — per-packet shared-map lookups service traffic (degraded); installs retried on the next ≥1s/5s re-enqueue (`tunnel.rs:295-305` refresh window) | none; counter-less today (SMR r1 F2) |

The fix targets I1-I6 (+ the I5 `created: true` telemetry ride-along, AGY
r1 F1). I7/I8 get counters+comments only. I9-I13 are documented non-goals
(I13: same uncapped-sync semantics debate as I11; document + optional
counter only).

## 5. Concrete design — recommended Path A (pair preflight + drop-on-refusal)

**Key observation that collapses the design space:** both installs mutate
the *same* per-worker `SessionTable` behind `&mut` on one thread, and the
only failure mode is the cap check. Nothing can change `len()` between the
two installs in one descriptor iteration (worker commands / GC run between
poll phases, not mid-packet). Therefore "reserve-both-then-commit" needs no
slab/handle reservation API — a **pre-flight capacity check is already
atomic**. No locks, no reservation tokens, no allocation.

### 5.1 SessionTable: pair admission check

```rust
// session/mod.rs
impl SessionTable {
    /// #1861: pre-flight admission for an install group of `needed`
    /// new entries. Conservative: charges a full slot per entry even
    /// when the key already exists (matches the existing cap check,
    /// which also refuses replacements at cap).
    #[inline]
    pub fn can_admit(&self, needed: usize) -> bool {
        self.len().saturating_add(needed) <= self.max_sessions
    }

    /// #1861: counted refusal so preflight failures are visible
    /// (create_drops today is write-only; see §7 counters).
    pub fn note_admission_refused(&mut self, needed: usize) { ... }

    #[cfg(test)]
    pub(crate) fn set_max_sessions_for_test(&mut self, n: usize) { ... }
}
```

`install_with_protocol_with_origin` keeps its signature and its internal
cap check (defense in depth; #1357 positional contract untouched).

### 5.2 poll_descriptor new-flow path (`mod.rs` ~1252)

After `track_in_userspace` / `install_local_reverse` are computed and
before the forward install:

```rust
let needed = usize::from(track_in_userspace)
    + usize::from(track_in_userspace && install_local_reverse);
if needed > 0 && !sessions.can_admit(needed) {
    sessions.note_admission_refused(needed);
    if let Some(release_key) = source_nat_release_key.as_ref() {
        rollback_source_nat_allocation(
            &worker_ctx.forwarding.source_nat_rules,
            release_key, decision.nat, false, now_ns);
    }
    // Junos parity: session-creation failure => drop trigger packet.
    binding.scratch.scratch_recycle.push(desc.addr);
    continue;   // same shape as the SNAT-failure arm at mod.rs:1184
}
```

Because the drop is `continue` (the established pattern of every other
refusal arm in this function), the forwarding block AND the flow-cache
population at `:2016` are skipped — I1 and I2 die together. The
`track_in_userspace == false` case (`dns_fastpath_admit`, LocalDelivery)
has `needed == 0` and is structurally untouched — the "tracking not
required" vs "install attempted and failed" distinction the issue demands.

Two call-shape notes (SMR r1 F3/F6): (a) the rollback in the refusal arm
must mirror the existing residual-arm shape —
`source_nat_release_key.as_ref().unwrap_or(&flow.forward_key)`
(`mod.rs:1343-1345`) — not a bare `if let Some`, to avoid a semantics fork
between the two arms; (b) the preflight sits after the SNAT decision
(forced by `dns_fastpath_admit` needing `decision.nat`), so at-cap
pool-mode packets still pay an allocate→rollback round-trip per refused
packet. That churn is pre-existing, cold-path, and bounded by overload
conditions; a `len() >= max` early-out before NAT evaluation is a
follow-up optimization, not part of this fix.

After a passing preflight, both installs are infallible by construction.
Per the #1855 contract the residual is handled as:

```rust
let forward_installed = track_in_userspace
    && sessions.install_with_protocol_with_origin(/* unchanged */);
if track_in_userspace && !forward_installed {
    // Impossible-by-construction after can_admit (single-threaded
    // &mut table, cap is the only failure). debug: loud. release:
    // count + drop the packet, never half-commit.
    debug_assert!(false, "forward install failed after preflight");
    telemetry/* session_install_partial counter */;
    /* SNAT rollback + recycle + continue, as above */
}
```

The reverse install keeps its existing condition but **adds the
`forward_installed` gate** (kills latent I3) and the same
debug_assert+count residual arm (forward stays committed in release if the
impossible happens — the repair path I5 services replies; counted as
`session_install_partial_total`).

### 5.3 MissingNeighborSeed path (`mod.rs` ~2448)

Gate the pending-neighbor **buffering** on `pending_installed` (plus the
pre-existing `if let Some(hop)`): on refusal, the frame is recycled instead
of buffered (kills I6 — no replay of a frame whose SNAT was rolled back).
Sibling frames for the same unresolved hop were already dropped by the
#1771 one-representative rule, so behavior at cap converges with the
existing duplicate-drop semantics. Optionally preflight with
`can_admit(1)` before the SNAT allocation for symmetry; the seed path
installs only a forward entry.

### 5.4 Fabric-return (`:479`) and LocalMiss (`:840`)

Behavior preserved (forwarding without local session is semantically valid
there — peer-validated and local-delivery-optimization respectively). Add
refusal accounting only (they feed the same refusal counter via the
table-level `create_drops`, which §7 exports).

## 6. Alternative paths (for reviewers to weigh)

- **Path B — rollback-on-partial-failure.** Keep installs as-is; when the
  reverse install fails, unwind the forward: `sessions.delete(forward_key)`
  (`session/mod.rs:1131` — exists, exercises #964 value-guarded removal),
  BPF entry delete, `remove_shared_session`, replicate delete to siblings,
  emit Close delta (the Open delta queued in the same tick has not been
  drained yet — drain runs after `poll_binding` in the worker loop — so the
  peer sees Open+Close in one batch, net zero). Workable but strictly more
  moving parts than A for the same outcome, and it still forwards the
  trigger packet of face (i) unless combined with D. Rejected as primary:
  A's preflight makes the partial state unconstructible instead of
  cleaning it up after the fact.
- **Path C — document + count only.** Refuted by I2: the flow-cache
  unreserved-tuple leak is not self-healing, so a counter alone leaves a
  standing correctness hole. C's counters are folded into A (§7).
- **Path D — drop-packet semantics only** (gate forwarding + flow-cache on
  `forward_installed`, no pair preflight). Fixes I1/I2/I6; leaves I4
  (one-sided forward at the cap boundary) to the repair path. Defensible
  minimal fix; A subsumes D for the cost of two integer compares on the
  cold path. If reviewers judge A's cap-1 semantics change (§11 Q2) too
  risky, D is the fallback.

## 7. Counters / wire (additive)

Per the wire-additive pattern (serde default → fixture regen
`XPF_PROTOCOL_WIRE_REGEN=1` → `protocol.go` → `pkg/api` + key-absent pins
both sides):

- `session_install_admission_refused_total` — preflight refusals (Path A).
- `session_install_partial_total` — the impossible-by-construction release
  residual arms (§5.2); expected to stay 0 forever; nonzero = bug.
- Export the existing **write-only** `create_drops` as
  `session_create_drops_total` (covers I7/I8/I5 refusals without new
  plumbing at those sites).

All three flow worker→coordinator→status JSON→Go→Prometheus. No hot-path
cost (single-threaded u64 adds on refusal arms).

## 8. Public API preservation + hidden invariants

Preserved signatures: `install_with_protocol_with_origin` (positional,
#1357), `upsert_synced_with_origin`, `delete`, `find_forward_nat_match`,
`install_reverse_session_from_forward_match` (returns `SessionLookup`
unconditionally — reply forwarding at cap MUST keep working),
`poll_binding_process_descriptor`.

Invariants:
- **#964 `no_index_points_at`**: Path A never creates the orphan state, so
  the invariant is preserved trivially; the debug scan stays as-is. (Path
  B would lean on it instead.)
- **#1855 contract**: new guard arms are `debug_assert!(false)` +
  count-and-degrade in release; no new assert can fire on *reachable*
  state (cap refusal is reachable → counter, not assert). Both profiles
  get test pins.
- **Side-effect ordering**: SNAT rollback before drop (unchanged
  mechanism); no publish/replicate/delta is emitted for refused flows —
  HA peers never learn of a flow the owner refused (today's face (i)
  emits nothing either, so sync behavior is unchanged; face (ii) Open
  deltas simply stop happening for refused pairs).
- **Allocation rules**: zero new allocation; preflight is two compares; all
  changes on the new-flow cold path; warm path untouched.
- **HA sync portability**: `upsert_synced*` deliberately untouched (I11
  asymmetry documented, deferred §10).

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | at-cap semantics change from "leak + forward" to "drop" (intended, Junos parity); cap-1 paired flows now refused (§11 Q2); away from cap: zero delta. Concrete named scenario (SMR r1 F4): a refused flow whose policy permits BOTH directions (permissive intrazone) today limps along statelessly at cap — Path A sheds it until capacity frees. Intended overload shedding; for the common deny-inbound case the reply is policy-dropped today anyway, so nothing is lost. Mitigated by deterministic pins for every row I1-I8 + smoke + failover |
| Lifetime / borrow-checker | LOW | preflight reads `&self` before the `&mut` install calls in straight-line code; no overlapping borrows |
| Performance regression | LOW | cold path only; two compares + counter adds; flow-cache/warm path untouched |
| Architectural mismatch (#961-pattern) | LOW | no new abstraction; uses the existing refusal-arm idiom (`recycle + continue`) and existing counters plumbing. Does NOT touch the #1760 collision-refusal design space (HA arbitration stays unsolved, intentionally) |

Failover gating: install-path behavior change ⇒ `make test-failover`
MANDATORY before merge (project rule; stated in the issue).

## 10. Out of scope (explicit)

- I9 BPF-publish partials (#1789 shipped), I10 mutex-poison partials.
- I11: adding a (higher) cap to `upsert_synced_with_origin` — sync
  bypassing `max_sessions` is a pre-existing design asymmetry; changing it
  affects HA activation prewarm and needs its own plan.
- I12 HA arbitration partials (`allow_replace_local` semantics).
- #1760 collision install-time refusal (shelved; different problem).
- Making `max_sessions` operator-configurable.
- ~~`session_creates` over-count on failed repair installs~~ — **moved
  in-scope** as a ride-along per AGY r1 F1 + SMR Q5 answer:
  `install_reverse_session_from_forward_match` returns
  `(SessionLookup, bool)`; `resolve_flow_session_decision` propagates the
  bool into `created` (also stops `publish_bpf_conntrack_entry` firing for
  a session that does not exist locally).
- I13 local-tunnel UpsertLocal divergence at cap (document + optional
  counter only; same uncapped-sync debate as I11).

## 11. Open questions for adversarial review (PLAN-KILL invited)

1. **Preflight slot accounting:** `can_admit` charges full slots even when
   the forward key already exists (replacement would not grow the table).
   The existing cap check has the same conservatism. Should the preflight
   credit replacements (`!contains(key)` hash lookups on the cold path), or
   is matching the existing quirk correct?
2. **Cap-1 semantics:** Path A refuses a paired flow at `len == max-1`
   (needs 2 slots) where today the forward half lands. Effective paired
   capacity becomes `max-1`. Acceptable Junos-parity behavior, or does a
   reviewer see an operator-visible regression worth Path D instead?
3. **Seed-path drop:** is recycling the trigger frame on seed-install
   refusal (instead of buffering for neighbor-resolution replay) safe for
   the #1771/#1782 cold-start machinery — i.e., no harm in the
   pending-neighbor dwell accounting when a hop's representative frame is
   refused at cap?
4. **Fabric-return at cap (I7):** plan keeps forwarding without a local
   session there. Should it drop instead for strict transactional
   semantics, given the active peer already validated the packet?
5. **Ride-along:** fix the `created: true` telemetry over-count on failed
   repair installs in this PR, or file separately?
6. **Counter naming/cardinality:** three new counters (§7) vs folding
   admission refusals into the exported `create_drops` only?
7. **Is the I2 flow-cache leak claim correct?** Hostile check invited:
   `from_forward_decision` is called with the post-rollback `decision`
   (`mod.rs:1995-2016`); reviewers should verify no earlier gate prevents
   caching when `forward_installed == false` (we found none — the only
   gates are `should_cache` protocol/disposition + family + DSCP-filter).
8. **PLAN-KILL test:** if a reviewer can show (a) I2 is not reachable or
   not harmful, AND (b) at-cap drop semantics buy nothing operationally
   over today's stateless forwarding, the remaining value is hygiene
   counters — kill A and ship C/D-minimal or nothing. Make the case.
9. **Test depth:** plan pins I1-I8 at `poll_binding_process_descriptor`
   level with `set_max_sessions_for_test` (harness exists,
   `afxdp/tests.rs:3106`). Is a live at-cap cluster repro additionally
   required before merge, or are deterministic pins + smoke + failover
   sufficient evidence?

## 12. Test plan (for the /engineer phase)

- `cargo build --release`; FULL `cargo test --release` awk-aggregated over
  all "test result" lines; plain debug-profile `cargo test` for the
  session module (the #1855 debug_assert contract); `go test ./...`;
  `echo $?` after each. Known ledger flakes (wg `reconcile_peers`,
  worker_queue `concurrent_recovery`) proven standalone before
  attribution.
- New deterministic pins (debug AND release profiles):
  - SessionTable: `can_admit` boundary (cap-2/cap-1/cap), refusal counter.
  - I1/I2: at cap, NAT'd SYN via `nat_snapshot()` →
    `scratch_forwards` empty, frame recycled, **no flow-cache entry**, no
    reverse entry, SNAT allocator state empty (rollback observed),
    `session_install_admission_refused_total` == 1.
  - I3: forward-fail ⇒ reverse never attempted (gate pin).
  - I4 boundary: at cap-2 both install; at cap-1 paired flow refused
    (Path A) — pin the chosen semantics.
  - I5: reply at cap with forward-only state still forwarded
    (repair-path preservation pin).
  - I6: seed-install refusal ⇒ frame recycled, NOT buffered
    (pending-neighbor map empty).
  - I7/I8: behavior preserved at cap (forwarded / locally delivered).
  - Wire: counter key-absent pins both sides (Rust fixture + protocol.go).
- Smoke on loss userspace cluster (parent-serialized) + **mandatory
  `make test-failover`** (install path + HA-adjacent).
