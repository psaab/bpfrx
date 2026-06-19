// Timer-wheel sweeps + eviction (#2005 pure code-motion split of
// session/mod.rs). The bucketed-wheel GC (#965) machinery — wheel
// cursor initialization, the throttled per-entry wheel scheduling, and
// the per-tick bucket drain / lazy-delete expiry pass — lives here.
// Bodies are byte-for-byte identical to the prior in-`mod.rs` form;
// `push_to_wheel` was widened from a module-private `fn` to
// `pub(in crate::session)` because the in-place-refresh contract that
// stays in `mod.rs` (and the install/lookup submodules) call it across
// the submodule boundary into `expire`.
// The `SessionWheel` machinery itself remains in
// `wheel.rs`; this file holds the `SessionTable` methods that drive it.

use super::wheel::{WHEEL_TICK_NS, WheelEntry, bucket_for_tick, target_tick_for};
use super::*;

impl SessionTable {
    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Used by tests to validate K-bounds and entry classification.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last_pop_stats(&self) -> WheelPopStats {
        self.last_pop_stats
    }

    /// #965: lazily initialize the wheel cursor to the first observed
    /// `now_ns`. SessionTable::new() does not have a `now_ns`, so we
    /// must initialize on the first call to any method that takes one.
    /// Without this, `now_tick = now_ns / TICK_NS` can be billions
    /// (monotonic time) and the pop loop would walk billions of empty
    /// buckets on the first GC.
    #[inline]
    fn wheel_observe(&mut self, now_ns: u64) {
        if !self.wheel.initialized {
            self.wheel.cursor_tick = now_ns / WHEEL_TICK_NS;
            self.wheel.initialized = true;
        }
    }

    /// #965: schedule (or re-schedule) `key` for an expiration check
    /// at the tick implied by its `last_seen_ns + expires_after_ns`.
    /// Throttled: only pushes when the canonical wheel tick changes,
    /// so per-second touches within the same tick produce zero new
    /// wheel entries.
    ///
    /// MUST be called only AFTER `last_seen_ns` / `expires_after_ns`
    /// have been written and the `&mut` borrow on `self.entries` has
    /// dropped — otherwise the borrow checker will reject the
    /// `self.wheel.buckets[bucket].push_back(...)` line because it
    /// aliases `self` through both `self.entries` and `self.wheel`.
    #[inline]
    pub(in crate::session) fn push_to_wheel(&mut self, key: &SessionKey, now_ns: u64) {
        self.wheel_observe(now_ns);
        let new_tick = match self.entry_by_key_mut(key) {
            Some(entry) => {
                let nt = target_tick_for(
                    now_ns,
                    entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                );
                if nt != entry.wheel_tick {
                    entry.wheel_tick = nt;
                    Some(nt)
                } else {
                    None
                }
            }
            None => return,
        };
        if let Some(tick) = new_tick {
            let bucket = bucket_for_tick(tick);
            self.wheel.buckets[bucket].push_back(WheelEntry {
                key: key.clone(),
                scheduled_tick: tick,
            });
        }
    }

    /// #965: GC pass over the timer wheel.
    ///
    /// Replaces the prior O(N) scan over all sessions with a wheel
    /// pop. For each tick that has elapsed since the last call (up to
    /// `now_ns / WHEEL_TICK_NS`), drain the bucket at the current
    /// cursor and process its entries via the lazy-delete discriminator:
    ///
    ///   1. Entry gone (HashMap miss) → drop.
    ///   2. Stale duplicate (`wheel_tick != scheduled_tick`) → drop.
    ///   3. Expired (`now > last_seen + expires_after`) → remove,
    ///      emit delta + ExpiredSession.
    ///   4. Still alive → re-bucket at the new absolute target tick.
    ///
    /// See docs/pr/965-session-gc-timer-wheel/plan.md for the full
    /// algorithm and complexity analysis.
    pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
        // Reset per-call stats BEFORE the gc-interval gate so that a
        // gated no-op call returns zeroed stats rather than leftovers
        // from a prior call (Codex impl-review round-2 non-blocking note).
        self.last_pop_stats = WheelPopStats::default();
        if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
            return Vec::new();
        }
        self.last_gc_ns = now_ns;
        self.wheel_observe(now_ns);
        let now_tick = now_ns / WHEEL_TICK_NS;
        let mut expired_entries: Vec<ExpiredSession> = Vec::new();
        while self.wheel.cursor_tick < now_tick {
            let bucket_idx = bucket_for_tick(self.wheel.cursor_tick);
            // Drain the bucket allocation-free: snapshot the length
            // before iterating, then `pop_front` exactly that many
            // times. Re-pushes targeting THIS bucket land at the back
            // of the VecDeque and are not popped during this BUCKET
            // drain (re-pushes into LATER buckets the outer loop
            // visits will be popped within the same call — by design).
            let due_count = self.wheel.buckets[bucket_idx].len();
            for _ in 0..due_count {
                let WheelEntry {
                    key,
                    scheduled_tick,
                } = self.wheel.buckets[bucket_idx]
                    .pop_front()
                    .expect("len snapshot bounds the iteration");
                self.last_pop_stats.scanned += 1;
                // Case 1: entry already removed elsewhere — drop hint.
                let Some(entry) = self.entry_by_key(&key) else {
                    self.last_pop_stats.dropped_gone += 1;
                    continue;
                };
                // Case 2: stale duplicate — entry's canonical wheel_tick
                // has advanced past this scheduled_tick, so the new tick
                // already has its own wheel entry. Drop.
                if entry.wheel_tick != scheduled_tick {
                    self.last_pop_stats.dropped_stale += 1;
                    continue;
                }
                // Case 3 vs 4: canonical entry. Match today's strict `>`
                // expiration semantics.
                if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                    if let Some(removed) = self.remove_entry(&key) {
                        self.last_pop_stats.expired += 1;
                        let decision = removed.decision;
                        let metadata = removed.metadata;
                        if key.protocol == PROTO_TCP {
                            debug_log!(
                                "SESS_EXPIRE: proto=TCP {}:{} -> {}:{} closing={} age_ns={} timeout_ns={} rev={} origin={} nat=({:?},{:?})",
                                key.src_ip,
                                key.src_port,
                                key.dst_ip,
                                key.dst_port,
                                removed.closing,
                                now_ns.saturating_sub(removed.last_seen_ns),
                                removed.expires_after_ns,
                                metadata.is_reverse,
                                removed.origin.as_str(),
                                decision.nat.rewrite_src,
                                decision.nat.rewrite_dst,
                            );
                        }
                        if !metadata.is_reverse
                            && !removed.origin.is_peer_synced()
                            && !removed.origin.is_transient_local_seed()
                        {
                            self.push_delta(SessionDelta {
                                kind: SessionDeltaKind::Close,
                                key: key.clone(),
                                decision,
                                metadata: metadata.clone(),
                                origin: removed.origin,
                                fabric_redirect_sync: false,
                            });
                        }
                        expired_entries.push(ExpiredSession {
                            key,
                            decision,
                            metadata,
                            origin: removed.origin,
                        });
                    }
                } else {
                    // Case 4: still alive — long-timeout (>= 256s) case
                    // or a session re-scheduled to exactly this tick.
                    // Re-bucket at the new absolute target tick. The
                    // entry was just read by key immediately above with
                    // no intervening mutation, so the matching mutable
                    // lookup is a hard invariant — use
                    // `expect` instead of `if let Some` so an invariant
                    // violation surfaces loudly instead of silently
                    // pushing a stale-tick wheel entry (Copilot review).
                    let new_target_tick = target_tick_for(
                        now_ns,
                        entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                    );
                    let new_bucket = bucket_for_tick(new_target_tick);
                    let entry_mut = self
                        .entry_by_key_mut(&key)
                        .expect("entry was just read via entry_by_key; no concurrent mutation");
                    entry_mut.wheel_tick = new_target_tick;
                    self.wheel.buckets[new_bucket].push_back(WheelEntry {
                        key,
                        scheduled_tick: new_target_tick,
                    });
                    self.last_pop_stats.re_bucketed += 1;
                }
            }
            self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
        }
        let expired = expired_entries.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired_entries
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expire_stale(&mut self, now_ns: u64) -> u64 {
        self.expire_stale_entries(now_ns).len() as u64
    }
}
