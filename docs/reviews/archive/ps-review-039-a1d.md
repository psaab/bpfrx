# Review 039 — A1d: Session table (session/*.rs) — Monolithic audit

**Base:** f70146951583823a5ace87b0b11a2e58f46e8db9  
**Scope:** `userspace-dp/src/session/` (8 files, 11327 LOC inc. tests)  
**Date:** 2026-07-08

---

## File-size / shape inventory

| File | LOC | Role | Verdict |
|------|-----|------|---------|
| `mod.rs` | 2054 | `SessionTable` struct (25 fields), `SessionEntry` (16 fields), core helpers, timeout logic, scaffolding | **God-file** — carries 7 responsibilities; submodule split delegates method impls but leaves every field in one struct |
| `install.rs` | 521 | `install_with_protocol*`, `upsert_synced*`, delete/demote, capacity preflight | Code-motion from mod.rs (#2005) — accesses `self.entries`, `self.key_to_handle`, `self.nat_*_index`, `self.owner_rg_sessions`, `self.session_limit_*`, `self.deltas`, `self.wheel` directly via child-module `super::*` visibility |
| `lookup.rs` | 411 | `lookup_with_origin`, `find_forward_nat_match`, `find_forward_wire_match*`, `resolve_reverse_translated_handle`, iteration, `take_synced_local` | Same code-motion split — reads/writes `self.entries`, `self.key_to_handle`, `self.*_index`, `self.owner_rg_sessions`; mutates `entry.last_seen_ns`, `entry.expires_after_ns`, `entry.closing`, `entry.reset`, `entry.established` under direct `&mut` slab borrow |
| `expire.rs` | 625 | `push_to_wheel`, `expire_stale_entries`, `expire_stale_entries_ha`, `standby_gate_decision`, `companion_keeps_alive`, `rebucket_alive_entry` | Same — direct field access to `self.wheel`, `self.entries`, `self.key_to_handle`, all index maps, HA context closures; `companion_keeps_alive` does a second `entry_by_key` probe per idle-crossed entry |
| `key.rs` | 232 | `SessionKey`, NAT key transforms (`forward_wire_key`, `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session`) | **Clean** — pure functions, no `SessionTable` coupling |
| `entry.rs` | 284 | `SessionDecision`, `SessionMetadata`, `SessionLookup`, `ForwardSessionMatch`, `SessionOrigin`, `SessionDelta`, `ExpiredSession`, `SessionCounters` | **Clean extraction** of public data types (#1047 P2); `SessionEntry` itself stays in `mod.rs` because fields are file-private |
| `ctx.rs` | 126 | `SessionInstall`, `SessionUpdate`, `ExpireHaContext` | **Clean** — context structs replacing positional 7-arg clusters (#1357) |
| `wheel.rs` | 80 | `SessionWheel`, `WheelEntry`, `bucket_for_tick`, `target_tick_for`, constants | **Clean** — power-of-two assert, `FAR_FUTURE_OFFSET`, no table coupling |
| `tests.rs` | 6994 | Unit tests (excluded from prod LOC) | Catch-all single file — well-organized by `#[test]` fn name; not re-audited here per batch instructions |

**Production LOC:** 2054 + 521 + 411 + 625 + 232 + 284 + 126 + 80 = **4333 LOC** (6994 test-only)

---

## Finding 1: (D) — SessionTable submodule split is code-motion, not responsibility decomposition — #4421 DUP, new detail only

**Severity:** Low (modularity debt, not bug)  
**Confidence:** High  
**Refactor class:** Modularity — incomplete decomposition  
**Dedup:** #4421 already filed SessionTable god-struct (27 fields claimed, 6 responsibilities). This finding adds ONLY the new observation that the #2005 mechanical split does not constitute true responsibility separation.

### Evidence

`mod.rs` declares 7 submodules as `mod install`, `mod lookup`, `mod expire` etc. All attach `impl SessionTable { ... }` blocks. But every submodule accesses `SessionTable` private fields directly:

```rust
// install.rs — touches 7 distinct private fields of SessionTable
self.entries.insert(record);
self.key_to_handle.insert(key.clone(), handle);
self.index_forward_nat_key(&key, handle, decision, &metadata);
self.push_to_wheel(&key, now_ns);
self.session_limit_inc(key.src_ip, key.dst_ip);
self.push_delta(...);
```

```rust
// lookup.rs — mutates SessionEntry fields under &mut self.entries borrow,
// then calls self.push_to_wheel (in expire.rs) and self.propagate_tcp_state_to_companion (in mod.rs)
let record = self.entries.get_mut(handle as usize)?;
record.entry.last_seen_ns = now_ns;
record.entry.closing = true;
```

This works because in Rust a child module (`mod install;` inside `mod session`) inherits access to the parent's private fields via `super::*`. There is no trait boundary, no encapsulation, no compile-time isolation. A change to `SessionTable.nat_reverse_index`'s type (`HashMap` → `SmallVec` bucket in #4399/#4438) required touching `mod.rs` (type aliases), `install.rs` (insert path), `lookup.rs` (validate-on-lookup walk), and `expire.rs` (indirectly via `remove_entry` in mod.rs) simultaneously — four files for one field-type change, which is the same coupling as a single 2054-LOC file.

### Why this is not a new (B)/(C)

The mechanical split (#2005) was an intentional staging step — "pure code-motion, byte-for-byte identical bodies" is documented in every submodule header. The project plan calls it P2 of a multi-phase extraction. Filing it as a fresh god-struct issue would be a duplicate of #4421.

### What genuine decomposition would look like (for #4421's fix)

True extraction requires **field grouping + accessor encapsulation**:

| Proposed group | Fields | Responsibility |
|---|---|---|
| `SessionStore` | `entries: Slab<SessionRecord>`, `key_to_handle: SeededKeyMap<u32>` | canonical session storage |
| `NatIndexes` | `nat_reverse_index`, `forward_wire_index`, `reverse_translated_index`, `nat_reverse_key_collisions` | NAT secondary lookup (1:N multimap buckets — #4399/#4438 invariant holder) |
| `HaState` | `owner_rg_sessions`, `deltas`, `delta_loss_pending`, `delta_drops`, `delta_drained`, `epoch_counter` | HA sync (open/close deltas, owner-RG sets, loss-of-sync latch) |
| `IpLimitState` | `session_limit_active`, `session_limit_src_counts`, `session_limit_dst_counts` | per-IP session-limit counters (#2134/#3122/#4377) |
| `ExpiryState` | `wheel`, `last_pop_stats`, `last_gc_ns` | timer-wheel GC |
| `TimeoutConfig` | `timeouts`, `opening_overrides` | forwarding timeout policy |
| `CapacityState` | `max_sessions`, `expired`, `create_drops`, `admission_refused`, `install_partial` | capacity / admission telemetry |

Any extraction MUST preserve:
- **#4399 P5 / #4438**: `NatIndexes` 1:N bucket `SmallVec<[u32; 2]>` append-not-displace invariant — a colliding install APPENDS, removal removes only the handle — lookup validates each bucket entry. Single-value regression reintroduces session hijack.
- **Per-IP limit counting**: `session_limit_inc`/`dec` counted-class predicate (`!is_reverse && !origin.is_transient_local_seed()`, origin-agnostic since #3122), OFF->ON rebuild (#4377), decrement as sole sink in `remove_entry`.
- **`no_index_points_at` debug assert**: eager-cleanup invariant — no secondary index holds a freed handle.
- **Wheel lazy-delete discriminator**: `wheel_tick` vs `scheduled_tick`.

Hot-path preservation: `SessionStore` + `NatIndexes` stay on the same cache-line-touch path as today (one hash probe + one slab dereference per packet). Extracting to a sub-struct adds one level of field access (`self.store.entries` vs `self.entries`) — monomorphized by the compiler to identical codegen (field offset changes only). No pointer indirection (no `Box`).

---

## Finding 2: (C) — SessionEntry hot/cold fusion + SessionMetadata Arc clone per packet — thermal inefficiency, not a monolith per se

**Severity:** Medium (perf, not correctness)  
**Confidence:** High  
**Refactor class:** Performance — per-packet atomic on cloned metadata  
**Dedup:** #4421 mentions SessionEntry hot/cold fusion and "Arc metadata.clone() per packet cost" as part of the god-struct. This finding quantifies the CURRENT Arc re-introduction and proposes a hot/cold split that does NOT add pointer-chase overhead.

### Evidence

`SessionMetadata` in `entry.rs` carries:

```rust
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,        // hot (timeout override lookup)
    pub(crate) egress_zone: u16,         // cold (logging/gRPC export only)
    pub(crate) owner_rg_id: i32,         // cold (HA ownership, not per-packet)
    pub(crate) fabric_ingress: bool,     // cold (HA standby gate only)
    pub(crate) is_reverse: bool,         // HOT — checked every packet
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>, // cold
    pub(crate) log_session_init: bool,   // cold
    pub(crate) log_session_close: bool,  // cold
    pub(crate) policy_id: u32,           // cold (telemetry)
    pub(crate) inactivity_timeout_ns: Option<u64>, // warm (timeout selection on refresh)
    pub(crate) policy_counter_idx: u32,  // cold (fallback path)
    pub(crate) policy_counter: Option<Arc<PolicyRuleCounter>>, // HOT — incremented every packet on fast path
}
```

Comment at `entry.rs:16-22` documents #919: zone names were changed from `Arc<str>` to `u16` IDs to eliminate "the `LOCK XADD` atomic on every `metadata.clone()`". But `policy_counter: Option<Arc<PolicyRuleCounter>>` re-introduces exactly that:

In `lookup.rs:lookup_with_origin` (hot path — every packet that hits a session):

```rust
(
    SessionLookup {
        decision: entry.decision,
        metadata: entry.metadata.clone(), // <-- Arc::clone does LOCK XADD
    },
    entry.origin,
)
```

`SessionMetadata::clone()` clones the `Option<Arc<_>>`, which is an atomic refcount bump. Same in `find_forward_nat_match`, `find_forward_wire_match_with_origin`, `entry_with_origin`, `iter_with_origin`.

**Hot/cold field inventory of SessionEntry** (16 fields, `mod.rs:343-459`):

```
HOT (per-packet read/write):
  decision              — NAT transform for reverse lookup
  entry.metadata.*      — is_reverse, policy_counter, ingress_zone
  last_seen_ns          — re-stamped every lookup hit
  expires_after_ns      — read every touch, written on state transition
  closing, reset        — TCP close state, checked every TCP packet
  established           — half-open guard, checked every TCP-SYN/SYN-ACK
  wheel_tick            — read on every wheel push (throttle compare)
  counters              — per-packet via account_packet (fwd/rev bytes/pkts)
  observed_tos / tcp_flags — per-packet via account_packet

COLD (GC / HA / telemetry / install-only):
  origin                — HA sync classification, tested only at promotion/demote
  install_epoch         — delta ordering, not on forwarding path
  created_ns            — close-delta harvest only
  seen_rg_epoch         — HA self-heal edge detection (GC 1Hz path)
  first_held_ns         — standby hold ceiling (GC 1Hz path)
```

`SessionEntry` is 16 fields with no `#[repr(C)]` / cache-line split. Hot fields and cold fields share the same cache line(s) — a write to `seen_rg_epoch` or `first_held_ns` on the GC path (or a read of `origin`/`owner_rg_id` in the standby gate) pulls the same cache line that the next packet's lookup will need for `decision`/`metadata`/`last_seen_ns`.

`SessionRecord` = `SessionKey` + `SessionEntry`. `SessionKey` itself is `addr_family: u8 + protocol: u8 + src_ip: IpAddr (variable size — 16 bytes for V6 + discriminant) + dst_ip + src_port + dst_port` — roughly 40-56 bytes depending on IpAddr discriminant. + 16-field `SessionEntry` — total slab record likely 200+ bytes, spanning multiple cache lines.

### Proposed decomposition (preserves no-pointer-chase invariant)

Split `SessionEntry` inline (no `Box`, no added indirection — same slab allocation, same number of cache lines fetched for hot fields today, but hot fields packed contiguously at offset 0):

```rust
// Hot — fits in 2 cache lines, touched every packet
struct SessionHot {
    decision: SessionDecision,        // 32-40 bytes (NatDecision + ForwardingResolution)
    is_reverse: bool,                 // 1 byte (hoisted from SessionMetadata)
    policy_counter: Option<Arc<PolicyRuleCounter>>, // see note below
    last_seen_ns: u64,               // 8
    expires_after_ns: u64,           // 8
    closing: bool,                   // 1
    reset: bool,                     // 1
    established: bool,               // 1
    wheel_tick: u64,                 // 8
    counters: SessionCounters,       // 32 (4×u64)
    observed_tos: u8,               // 1
    observed_tcp_flags: u8,         // 1
}

// Cold — instal / GC / HA only
struct SessionCold {
    metadata_rest: SessionMetadataCold, // egress_zone, owner_rg_id, fabric_ingress, nat64_reverse, log flags, policy_id, inactivity_timeout_ns, policy_counter_idx
    ingress_zone: u16,              // needed for timeout override — borderline warm
    origin: SessionOrigin,
    install_epoch: u64,
    created_ns: u64,
    seen_rg_epoch: u32,
    first_held_ns: u64,
}

struct SessionEntry {
    hot: SessionHot,
    cold: SessionCold,
}
```

**Policy counter Arc elimination (strongest win):** The per-rule `PolicyRuleCounter` hit count is incremented via `Arc` shared ownership because `PolicyState::rules` re-hands the same `Arc` for a surviving rule_id across snapshot rebuilds. Alternative: store `*const PolicyRuleCounter` (raw pointer, stable-address via `PolicyCounterStore` pinning) + `policy_counter_idx` for validation, avoiding the atomic on every `metadata.clone()`. Or: replace the `metadata.clone()` in `lookup_with_origin` with a non-cloning return — return `(&SessionDecision, &SessionMetadata)` / `(&SessionHot, &SessionCold)` borrows and let the caller copy only the fields it needs. `SessionLookup { decision, metadata }` clones the entire `SessionMetadata` today to return an owned value; the caller (`poll_descriptor` / `account_packet`) only needs `decision.nat` + `metadata.is_reverse` + `policy_counter` for the common path. Returning a borrow would eliminate the `Arc` clone entirely on the hot path.

**Do NOT:** Replace `Arc<PolicyRuleCounter>` with `Box<PolicyRuleCounter>` (adds a pointer chase per packet — worse than current). The win is eliminating the clone, not adding indirection.

### Hot-path preservation

- `SessionEntry` today lives in a `slab::Slab<SessionRecord>` — a contiguous `Vec`-backed store indexed by `u32`. Splitting `SessionEntry` into `SessionHot`/`SessionCold` sub-structs within the same slab record is a layout reordering, not an allocation change. The compiler's struct-field-offset lowering makes `entry.hot.last_seen_ns` a single `mov` with a different immediate offset. No new pointer chase, no added cache miss on the hot path — fewer, because cold fields no longer share the first 64 bytes with hot fields.
- `Arc::clone` elimination: removing the `metadata.clone()` → replacing with borrowing or raw-pointer counter avoids `LOCK XADD` (~20-40ns on contended x86). At 23 Gbit/s / 64-byte packets = ~45M pps across 6 workers = ~7.5M pps/worker, every per-packet atomic matters.
- Benchmark gate: `cargo bench -- session` (if criterion exists) or `cargo test -- session --nocapture` timing delta. Measure `lookup_with_origin` micro-bench before/after — expect ≥ 10ns reduction from Arc elimination alone.

### Tests / gate

- `make test` (includes `userspace-dp` cargo suite — session unit tests, NAT collision tests, HA standby-gate tests, timer-wheel tests).
- `make cluster-deploy && make test-failover` — session sync during failover must preserve per-RG ownership, standby HOLD/SELF-HEAL, and per-IP limit counting (which rides the same slab).
- Criterion bench: `session::lookup_with_origin` hot loop, `session::account_packet` hot loop — compare `Arc` clone vs borrow.

---

## Finding 3: (D) — Well-decomposed leaf modules — negative finding (no action needed)

**Severity:** None — negative confirmation  
**Confidence:** High  
**Refactor class:** None — clean code confirmed

### Evidence

Three leaf modules are exemplary decompositions and should be used as the template for future SessionTable extraction:

**`key.rs` (232 LOC):** Six pure functions (`forward_wire_key`, `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session`) with no `SessionTable` coupling. NAT64 address-family / ICMP protocol mapping is centralized here — one source of truth for the forward↔reverse key duality. #4074 ICMP identifier symmetric-field handling is documented and consistent across all six functions. Re-exported at `pub(crate)` via `pub(crate) use key::*` keeps crate surface stable.

**`wheel.rs` (80 LOC):** 256-bucket × 1s-tick wheel, `WHEEL_MASK` power-of-two trick with compile-time assert, `target_tick_for` / `bucket_for_tick` pure helpers, `FAR_FUTURE_OFFSET` long-timeout re-bucket. Zero table coupling — `SessionWheel` is a data container, `SessionTable` drives it. Matches `mod.rs`-level `SESSION_GC_INTERVAL_NS` via `WHEEL_TICK_NS = SESSION_GC_INTERVAL_NS` binding (Copilot review fix — cadence cannot silently diverge).

**`ctx.rs` (126 LOC):** `SessionInstall` (owned key) + `SessionUpdate` (borrowed key) + `ExpireHaContext` (closures over HA predicates). Resolves #1357's 7-field positional cluster drift hazard. Control flags (`allow_replace_local`, `ha_activation`) correctly stay positional — not embedded in the payload struct — so callers do not populate fields the callee overwrites.

These three modules total ~438 LOC of clean, independently-testable code with zero `SessionTable` private-field coupling. They demonstrate the target pattern: data-type extraction + pure-function grouping with `pub(crate)` / `pub(super)` visibility discipline.

---

## Summary of all findings

| # | Severity | Class | Module | Summary | Action |
|---|----------|-------|--------|---------|--------|
| 1 | Low (D) | Dedup | `mod.rs` + `install.rs`/`lookup.rs`/`expire.rs` | Submodule split is pure code-motion — all 3 submodules still access all 25 private fields via child-module `super::*` visibility; true responsibility grouping (7 groups identified) not yet achieved | Feed into existing #4421 — do not open new issue |
| 2 | Medium (C) | Perf / hot-cold | `mod.rs:SessionEntry`, `entry.rs:SessionMetadata` | `SessionEntry` 16 fields hot/cold fused; `SessionMetadata.policy_counter: Option<Arc<_>>` re-introduces #919's `LOCK XADD` per-packet via `metadata.clone()` in `lookup_with_origin` hot path; propose inline hot/cold split (no Box) + Arc-clone elimination via borrow / raw-pointer counter pinning | Open new issue — "session: eliminate per-packet Arc clone + hot/cold split" — targeted, measurable, staged |
| 3 | None (D) | Negative | `key.rs`, `wheel.rs`, `ctx.rs` | Leaf modules are exemplary — pure functions, zero table coupling, compile-time guards, doc'd invariants | No action — use as template |

---

## Labels

- `modularity` (finding 1 — dedup)
- `perf` `session` `hot-path` (finding 2)
- `no-action` (finding 3)

---

## Dedup note

- **#4421 — SessionTable god-struct (27 fields, 6 responsibilities), SessionEntry hot/cold fusion — ALREADY FILED.** Finding 1 in this report does NOT re-file it — it adds the observation that the #2005 mechanical submodule split (code-motion, byte-for-byte identical bodies, child-module `super::*` private-field access) does not constitute true responsibility decomposition, and enumerates the concrete 7-group field map that a genuine fix requires. Do not open a new god-struct issue from this report.
- **#4409 — overlaps SessionTable** — checked; this report's focus is the `userspace-dp/src/session/*.rs` directory only, not the broader `SessionTable` usage outside `session/`.
- **#4399 P5 — NAT reverse-index single-value→multi-value (correctness)** — related but different (correctness bug, not refactor). This report preserves the #4399/#4438 1:N `SmallVec<[u32; 2]>` bucket invariant as a hard constraint on any proposed decomposition (see Hot-path preservation sections). No re-report.

---

## Verification performed

- [x] Read `session/mod.rs` (2054 LOC), `session/entry.rs` (284), `session/key.rs` (232), `session/ctx.rs` (126), `session/wheel.rs` (80), `session/install.rs` (521), `session/lookup.rs` (411), `session/expire.rs` (625) — 8 files, 4333 prod LOC (6994 test-only)
- [x] Read `docs/engineering-style.md` — Hot-path discipline (no per-packet alloc, atomics, compile-time guards), Modularity discipline (no monolithic files >2000 LOC prod, no god functions >100 lines / >8 params)
- [x] Counted `SessionTable` fields: **25** (issue claimed 27 — close; earlier version likely had 2 additional fields or counted type aliases)
- [x] Counted `SessionEntry` fields: **16** (`decision`, `metadata`, `origin`, `install_epoch`, `last_seen_ns`, `created_ns`, `expires_after_ns`, `closing`, `reset`, `established`, `wheel_tick`, `seen_rg_epoch`, `first_held_ns`, `counters`, `observed_tos`, `observed_tcp_flags`)
- [x] Counted `SessionMetadata` fields: **12** including `policy_counter: Option<Arc<PolicyRuleCounter>>` (re-introduces #919 Arc overhead)
- [x] Confirmed `SessionTable` 7 responsibility groups (mapped explicitly in Finding 1 table)
- [x] Verified submodule access pattern: all of `install.rs`, `lookup.rs`, `expire.rs` use `super::*` / child-module privilege to access private `SessionTable` fields directly — not encapsulated
- [x] Verified `metadata.clone()` in `lookup.rs:lookup_with_origin` hot path causes `Arc::clone` → `LOCK XADD`
- [x] Verified no `#[repr(C)]` / `#[repr(align)]` / cache-line padding on `SessionEntry` or `SessionRecord`
- [x] Verified `key.rs`, `wheel.rs`, `ctx.rs` have zero `SessionTable` coupling and carry appropriate compile-time guards
