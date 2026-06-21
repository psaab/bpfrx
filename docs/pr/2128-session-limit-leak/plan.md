# #2128 — Screen session-limit tracker phantom zero-entry leak (memory-exhaustion DoS)

**Status:** v2 — Codex round-1 PLAN-KILL addressed (false "already
maintained" premise removed; enforcement gap split to a follow-up issue;
leak fix retained as the correct + complete fix for the filed DoS).
Codex round-2 PLAN-NEEDS-MINOR addressed: the out-of-scope cap note now
states the correct key-cardinality bound (distinct live-session IPs /
session-table capacity, NOT the per-IP limit). Codex round-2 confirmed
the kill is resolved, the leak fix is correct with no residual read-side
insert, and the leak test is non-tautological.

## Round-1 adversarial review outcome

**Codex round-1: PLAN-KILL** (task `task-mqn9ue7w-e3kuyd`). The verdict
was correct and is taken seriously. Codex found that the v1 plan's claim
"the count map is already maintained by `session_created` /
`session_expired`, leave it untouched" is **false**: production never
calls `ScreenState::session_created` or `ScreenState::session_expired`.
Verified independently against source —
`grep -rn '\.session_created(\|\.session_expired(' userspace-dp/src`
finds callers ONLY in `screen/tests.rs`; the production session-create
hook (`poll_descriptor/mod.rs:321`, `resolved.created`) and the expiry
loop (`worker/loop_body/mod.rs:573`) never notify `screen`. `git log -S`
confirms `screen_state.session_created` was NEVER wired in `afxdp/`.
The methods carry `#[cfg_attr(not(test), allow(dead_code))]`, which is
the smoking gun.

**Consequence (two distinct defects):**

1. **The filed leak (#2128)** — REAL. `check_src`/`check_dst` use
   `entry(ip).or_insert(0)` to read, inserting a phantom zero entry per
   distinct IP on the hot path; never reclaimed; unbounded growth ->
   memory-exhaustion DoS. **This plan's fix fully closes it.**
2. **Latent enforcement gap** — surfaced by Codex, NOT the filed issue.
   Because the lifecycle is unwired, the production count map only ever
   held phantom ZEROS, so `*count >= limit` was `0 >= limit` — always
   false. **Session-limit screen enforcement has been a no-op in the
   userspace dataplane since inception.** The read-only fix does not
   change that (the map stays empty), it just stops the leak. Wiring
   enforcement correctly requires covering ALL session deletion paths
   (stale expiry, conntrack GC, HA delete-sync, session clear) plus HA
   considerations — a separate feature-bug with its own design and test
   surface. Bolting it onto a security leak fix would be exactly the
   scope-creep / partial-delete-path leak risk Codex warned about.

**Resolution:** scope this PR to the filed leak (defect 1). Remove the
false v1 premise. File the enforcement gap (defect 2) as a dedicated
follow-up issue (#2134) and link it. The leak fix is correct and complete for
the filed bug regardless of whether enforcement is ever wired: with the
read path made read-only, the map is populated ONLY by
`session_created` (currently nothing in production, tests in the suite)
and pruned to empty by `session_expired` — bounded by definition.

---

DRAFT v1 superseded.

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

## What's already in the code (corrected after Codex round-1)

- `SessionLimitTracker::session_created` / `session_expired` are the only
  legitimate WRITERS of the count map: `session_created` does
  `entry().or_insert(0) += 1`; `session_expired` saturating-decrements
  and `remove`s on reaching 0 (evict-on-zero is already correct on the
  write path). They are pruned-to-empty by construction.
- **They are NOT called from production.** The only callers of the
  `ScreenState` wrappers are `screen/tests.rs`. The methods are
  `#[cfg_attr(not(test), allow(dead_code))]`. So in production the count
  map is, today, populated ONLY as a side effect of the buggy read path
  (`entry().or_insert(0)` in `check_src`/`check_dst`), and only ever with
  zeros. This is the v1 plan's error; see the round-1 outcome above.
- The orchestrator calls `check_src`/`check_dst` BEFORE session creation
  (`mod.rs:342-358`) so a real `(limit+1)`-th attempt WOULD be dropped —
  if the count were ever non-zero. The pre-check ordering is preserved
  by this change; making enforcement actually fire is the follow-up.

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
   `session_expired`**: after the fix this becomes strictly true — the
   read path no longer writes. (In production today nothing calls
   `session_created`, so the map stays empty; that is the separate
   enforcement gap, not a leak.)
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

- **Wiring session-limit enforcement into the production lifecycle**
  (defect 2 above) — filed as #2134. It needs a
  design that notifies `screen.session_created` on `resolved.created`
  (poll_descriptor) and `screen.session_expired` on EVERY session
  delete path (stale expiry in loop_body, conntrack GC, HA delete-sync,
  `clear security flow session`), or it will leak in the opposite
  direction (counts that never decrement eventually block legitimate
  traffic). That is a feature-correctness change with its own test
  surface and HA implications — deliberately NOT bundled with this
  security leak fix.
- Capping / LRU-bounding the count map beyond evict-on-zero. With the
  read side effect removed, the map's key cardinality is bounded by the
  number of DISTINCT IPs that currently have at least one live session —
  i.e. by global live-session cardinality / the session-table capacity,
  NOT by the configured per-IP `limit` (the per-IP limit bounds the COUNT
  stored per key, not how many distinct keys exist). The attacker can no
  longer add a key without a live session, which is what closes the DoS;
  no separate cap is needed.
- Extending periodic cleanup to sweep `session_limits` — unnecessary
  once the read path no longer inserts.
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
