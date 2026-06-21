# #2128 — Screen session-limit tracker phantom zero-entry leak (memory-exhaustion DoS)

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`SessionLimitTracker::check_src` / `check_dst`
(`userspace-dp/src/screen/session_limit.rs:19-36`) read the current
per-IP session count via `self.src_counts.entry(ip).or_insert(0)` /
`self.dst_counts.entry(ip).or_insert(0)`. `entry().or_insert(0)` has a
**write side effect**: it inserts a zero-valued entry for any IP that is
not already present. The check runs on the ingress hot path for every
transit packet whenever `profile.session_limit_src > 0` /
`session_limit_dst > 0` (`screen/mod.rs:342-358`,
`poll_descriptor/mod.rs:199`).

Consequence: every distinct source IP (and every distinct destination
IP) that ever reaches the screen stage permanently allocates a HashMap
entry, even when the packet never creates a session — e.g. it is later
dropped by zone policy, is a spoofed-source flood packet, or is a
stateless UDP/ICMP packet. These phantom zero entries are never
reclaimed: `session_expired` only removes an entry that was first
incremented by `session_created` and then decremented to 0. An IP whose
count was created at 0 and never incremented is never removed. The
periodic cleanup in `screen/mod.rs:361-365` sweeps only `port_scan` and
`ip_sweep`; `update_profiles` (mod.rs:118-139) never clears
`session_limits`. So the leak survives config reloads, and the map grows
without bound — one entry per unique source/destination IP.

This is the precise inversion of the protection the operator enabled:
turning on `limit-session source-ip-based <n>` makes the dataplane MORE
vulnerable to a source-IP-spray memory DoS. Each worker owns its own
`ScreenState`, so growth is per-worker and unbounded.

**Severity: HIGH (security, memory-exhaustion DoS).** Filed from the
2026-06-20 campaign-2 adversarial audit, 3/3 adversarial-skeptic votes.

## Honest scope / value framing

This is a correctness + security bug fix, not a perf refactor. The win
is bounding an unbounded attacker-controlled allocation. Absolute scale:
each `FxHashMap<IpAddr, u32>` bucket entry is ~24-32 bytes amortized
(IpAddr enum is 17 bytes + alignment, u32 value, hashbrown control
byte + load-factor slack); at, say, 10M distinct spoofed source IPs per
worker that is on the order of hundreds of MB per worker, across N
workers. The fix removes the write side effect from the read path,
which is also a tiny per-packet win (no hash insert / no rehash growth
on the hot path for never-session IPs). There is no churn beyond the two
read sites and tests.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (It should not be killed on perf
grounds — the justification is security/DoS, not throughput — but the
bar is stated for completeness.)

## What's already shipped / partially batched

- `session_created` / `session_expired` already maintain the count
  correctly via `entry().or_insert(0) += 1` and saturating decrement +
  `remove` on reaching 0. Those are the ONLY legitimate writers of the
  count map and they already prune to empty. The fix must leave them
  untouched so the prune-to-empty invariant holds.
- The orchestrator calls `check_src`/`check_dst` BEFORE session
  creation (mod.rs:342-358) so the `(limit+1)`-th attempt is dropped.
  This pre-check ordering is preserved.

## Concrete design

Make the two read methods read-only:

```rust
pub(super) fn check_src(&self, ip: IpAddr, limit: u32) -> bool {
    if limit == 0 {
        return false;
    }
    self.src_counts.get(&ip).copied().unwrap_or(0) >= limit
}

pub(super) fn check_dst(&self, ip: IpAddr, limit: u32) -> bool {
    if limit == 0 {
        return false;
    }
    self.dst_counts.get(&ip).copied().unwrap_or(0) >= limit
}
```

Two changes per method:

1. `entry(ip).or_insert(0)` → `get(&ip).copied().unwrap_or(0)` — removes
   the insert side effect. An absent IP reads as 0, which is `< limit`
   for any `limit >= 1` (and `limit == 0` already early-returns), so the
   first session attempt for a never-seen IP still passes, exactly as
   before.
2. `&mut self` → `&self` — the methods no longer mutate, so taking a
   shared borrow makes the read-only contract **compiler-enforced**.
   This is a stronger regression guard than a comment: any future edit
   that reintroduces a write side effect on this path fails to compile.

The callers in `mod.rs` invoke these from inside `&mut self` methods
(`check_packet_with_zone_id`), so a `&self` callee is fine (a `&mut`
receiver can call `&self` methods on its fields). No caller signature
changes.

### Test accessors (cfg(test) only)

Add `#[cfg(test)]` len accessors so tests can assert the map size
returns to 0 after distinct-IP churn:

```rust
#[cfg(test)]
pub(super) fn src_len(&self) -> usize { self.src_counts.len() }
#[cfg(test)]
pub(super) fn dst_len(&self) -> usize { self.dst_counts.len() }
```

Expose them through `ScreenState` (also `#[cfg(test)]`) so the existing
`screen/tests.rs` suite (which drives `ScreenState`, not the tracker
directly) can read them:

```rust
#[cfg(test)]
fn session_limit_src_len(&self) -> usize { self.session_limits.src_len() }
#[cfg(test)]
fn session_limit_dst_len(&self) -> usize { self.session_limits.dst_len() }
```

### Tests (in `screen/tests.rs`, the existing session-limit section)

1. **`session_limit_no_leak_on_distinct_ip_churn`** (the key guard):
   configure `session_limit_src = 5`, drive N (e.g. 1000) DISTINCT
   source IPs through `check_packet` WITHOUT calling `session_created`
   (the spoofed-flood / dropped-by-policy / stateless case). Assert
   `session_limit_src_len() == 0` afterwards. **This test FAILS pre-fix**
   (`entry().or_insert(0)` leaves 1000 entries) and passes post-fix —
   non-tautological.
2. **`session_limit_entry_removed_on_last_expire`**: create a session
   for one IP (`src_len() == 1`), expire it, assert `src_len() == 0` —
   the entry is removed when count returns to 0. (Confirms
   `session_expired`'s prune is the only thing populating/draining the
   map now.)
3. **`session_limit_count_tracks_up_and_down`**: open 3 sessions for one
   src IP (`src_len() == 1`, count 3), expire 2 (still present), expire
   the 3rd, assert `src_len() == 0`.
4. Reuse / keep the existing `session_limit_src_enforced`,
   `session_limit_dst_enforced`, `session_limit_decrements_on_expire`
   tests — they prove the limit is still enforced at the threshold and
   that decrement re-admits.

## Public API preservation

- `check_src(&self, IpAddr, u32) -> bool` — receiver changes `&mut` →
  `&` (private to `super`, only callers are in `screen/mod.rs`); return
  type and semantics unchanged.
- `check_dst(&self, IpAddr, u32) -> bool` — same.
- `session_created`, `session_expired` — UNCHANGED.
- `ScreenState::check_packet*`, `session_created`, `session_expired`
  public API — UNCHANGED.

## Hidden invariants the change must preserve

1. **Pre-check ordering**: check runs before `session_created`; the
   `(limit+1)`-th attempt is dropped. Preserved — only the read
   mechanism changes.
2. **First-session-for-new-IP admits**: absent IP must read as 0 and
   pass. `get().unwrap_or(0)` returns 0 for absent → `0 >= limit` is
   false for `limit >= 1`. Preserved.
3. **Count map populated only by `session_created`, drained to empty by
   `session_expired`**: after the fix this becomes strictly true (it was
   the intended contract; the bug was the read path also populating it).
4. **No new per-packet allocation**: `get` does not allocate or grow the
   table; strictly fewer writes than before. No regression.
5. **`limit == 0` early return** unchanged (session-limit disabled path).
6. **Borrow shape**: `&self` callee from `&mut self` caller compiles;
   `session_limits` field access stays a disjoint borrow.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Read semantics identical for present IPs; absent IP read-as-0 matches the old freshly-inserted-0 behavior. Limit enforcement byte-for-byte equivalent. |
| Lifetime / borrow-checker | LOW | `&mut self` → `&self` is a relaxation; callers hold `&mut self` and can call `&self` methods. No new borrows. |
| Performance regression | LOW (net win) | Removes a hash insert + potential rehash from the hot path. `get` is cheaper than `entry`. |
| Architectural mismatch | LOW | Targets the exact reported defect; matches the issue's own suggested fix. No new abstraction. |

## Test plan

- `cargo build` clean (TMPDIR=/dev/shm, CARGO_TARGET_DIR=/dev/shm).
- `cargo test --release` full userspace-dp suite — all pass.
- New `session_limit_no_leak_on_distinct_ip_churn` 5/5 flake check.
- Confirm the leak test FAILS on the pre-fix code (run once against the
  unmodified `check_src` to prove non-tautological), then fix.
- Go suite (`go test ./...`) — unaffected (Rust-only change) but run to
  confirm no breakage.
- **Cluster smoke: DEFERRED TO PARENT.** Per the driving directive this
  is a SECURITY / hot-path change; the parent runs targeted smoke if
  needed. Smoke is marked pending parent-run.

## Out of scope (explicitly)

- Capping / LRU-bounding the count map beyond evict-on-zero. With the
  read side effect removed, the map is already bounded by the number of
  IPs with live sessions, which is itself bounded by the configured
  per-IP limit times the number of distinct peers with live sessions —
  no separate cap needed. A hard cap is a possible future hardening but
  is not required to close this DoS.
- Extending periodic cleanup to sweep `session_limits` — unnecessary
  once the map only holds live-session IPs and prunes to empty.
- Any change to `port_scan` / `ip_sweep` trackers.

## Open questions for adversarial review

1. Is `get(&ip).copied().unwrap_or(0) >= limit` semantically identical
   to the old `*entry(ip).or_insert(0) >= limit` for ALL inputs,
   including the first-session-for-a-new-IP admit case? (Claim: yes —
   absent reads as 0.)
2. After the fix, is the count map provably bounded by live sessions
   only? Is there ANY remaining path that inserts a key without a
   matching `session_expired` decrement-to-zero removal?
3. Does changing `&mut self` → `&self` create any borrow conflict at the
   `mod.rs` call sites, or interact badly with any other `&mut`
   field access in `check_packet_with_zone_id`?
4. Is the leak-churn test genuinely non-tautological — does it FAIL
   against the unmodified code and PASS only after the fix? Is asserting
   `src_len() == 0` the right invariant (vs `<= some bound`)?
5. Could removing the phantom zero entry mask a real session ever being
   under-counted (e.g. a `session_created` that races a `check` and the
   entry is briefly absent)? Single-threaded per-worker `ScreenState`
   means no concurrency — confirm that assumption holds (each worker
   owns its `ScreenState`; no shared access).
6. Is evict-on-zero (already present in `session_expired`) the cleanest
   fix vs never-insert-until-positive vs an LRU cap? (Claim:
   read-only-check is strictly the simplest and closes the DoS; the
   write path already evicts-on-zero.)
