// Install flow + capacity limits (#2005 pure code-motion split of
// session/mod.rs). The session-creation paths and their pre-flight
// admission live here: the #1861 capacity preflight/counter accessors
// (can_admit, note_admission_refused, admission_refused,
// note_install_partial, install_partial, create_drops,
// set_max_sessions_for_test), the new-flow installs (install_with_protocol,
// install_with_protocol_with_origin, upsert_synced,
// upsert_synced_with_origin), and the delta-emit / delete / owner-RG
// demotion helpers (emit_open_delta_with_origin,
// emit_close_delta_with_origin, delete, demote_owner_rg). Bodies are
// byte-for-byte identical; only the file boundary changed.
//
// No visibility was widened in this file: every moved method keeps its
// original `pub` / `pub(crate)` visibility (callable crate-wide off the
// pub(crate) SessionTable type). (The one widening in the overall split
// is `push_to_wheel` in expire.rs, not any method here.) The private
// helpers/structs these methods touch — remove_entry, next_epoch,
// index_forward_nat_key, push_delta, entry_by_key_mut,
// session_timeout_ns, SessionRecord/SessionEntry — live in the parent
// mod.rs and are visible to this descendant; push_to_wheel (in
// expire.rs) and owner_rg_session_keys (in lookup.rs) are reached via
// their existing pub/pub(in crate::session) visibility.
//
// The #1752/#1855 in-place-refresh contract (update_session,
// refresh_for_ha_transition, and the secondary-index re-assert helpers)
// stays in mod.rs — these installs build fresh records (remove_entry +
// insert), they are not the in-place-refresh path.

use super::*;

impl SessionTable {
    /// #1861 §5.1: pre-flight admission for an install group of `needed`
    /// new entries within ONE descriptor iteration. The table is
    /// per-worker, single-threaded, and `&mut`-exclusive during packet
    /// processing (GC and worker commands run between poll phases), so a
    /// passing preflight guarantees the subsequent `needed` installs
    /// cannot fail the `max_sessions` cap — the only install failure
    /// mode. Conservative on purpose: charges a full slot per entry even
    /// when the key already exists (a replacement would not grow the
    /// table). That matches `install_with_protocol_with_origin`'s own cap
    /// check, which also refuses replacements at cap; crediting
    /// replacements here would let the preflight pass while the install
    /// itself fails, violating the post-preflight infallibility contract.
    #[inline]
    pub fn can_admit(&self, needed: usize) -> bool {
        self.len().saturating_add(needed) <= self.max_sessions
    }

    /// #1861 §5.1: counted preflight refusal (one per refused flow).
    pub fn note_admission_refused(&mut self) {
        self.admission_refused = self.admission_refused.saturating_add(1);
    }

    /// #1861: cumulative pair-admission preflight refusals.
    pub fn admission_refused(&self) -> u64 {
        self.admission_refused
    }

    /// #1861 §5.2: counted impossible-by-construction release residual —
    /// an install failed after a passing preflight. Call sites pair this
    /// with `debug_assert!(false, ...)` per the #1855 contract.
    pub fn note_install_partial(&mut self) {
        self.install_partial = self.install_partial.saturating_add(1);
    }

    /// #1861: cumulative post-preflight partial-install residuals.
    pub fn install_partial(&self) -> u64 {
        self.install_partial
    }

    /// #1861: cumulative at-cap install refusals from
    /// `install_with_protocol_with_origin` (previously write-only —
    /// at-cap drops were operator-invisible).
    pub fn create_drops(&self) -> u64 {
        self.create_drops
    }

    /// #1861 tests: shrink the cap so at-cap interleavings can be rigged
    /// without inserting 131k entries.
    #[cfg(test)]
    pub(crate) fn set_max_sessions_for_test(&mut self, n: usize) {
        self.max_sessions = n;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            protocol,
            tcp_flags,
        )
    }

    // NOTE: this fn stays positional (NOT context-struct) per the
    // #1357 plan v3.1 rollback criterion. Empirical codegen showed
    // the struct destructuring prelude added ~30% standalone-copy
    // instructions (274 -> 357), exceeding the plan's 10% gate. The
    // 7 non-inlined production callers (forwarding, poll_descriptor,
    // session_glue, shared_ops) are on the session-install hot path
    // and cannot absorb that overhead.
    pub fn install_with_protocol_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        // remove_entry's three debug_assert!s catch invariant
        // violations in tests:
        //   - stale-handle guard (entries.get returned None for a
        //     handle in key_to_handle)
        //   - PRIMARY-KEY GUARD (record.key != lookup key)
        //   - no_index_points_at (a secondary index still points
        //     at the freed handle after cleanup)
        // The first two guards restore the prior key_to_handle
        // mapping internally before returning None. In release we
        // proceed to insert the new record — the guard already
        // restored the prior mapping; the subsequent
        // self.key_to_handle.insert(...) overwrites it cleanly.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                // #2465: stamp the creation instant once at install. Never
                // re-stamped, so the close delta reports the true session age.
                created_ns: now_ns,
                expires_after_ns: session_timeout_ns(
                    protocol,
                    tcp_flags,
                    &self.timeouts,
                    // #3227: per-application idle timeout override (None = global).
                    metadata.inactivity_timeout_ns,
                ),
                closing: matches!(protocol, PROTO_TCP) && is_closing(tcp_flags),
                reset: matches!(protocol, PROTO_TCP) && has_rst(tcp_flags),
                wheel_tick: 0,
                // #2120: a freshly-installed entry has never been HELD and
                // has not yet been self-healed. 0 is the never-self-healed
                // default; the first forwarding pass after any RG activation
                // that bumped the epoch will see current_epoch != 0 and fire
                // the self-heal (see session/expire.rs). The HOLD branch
                // does NOT write seen_rg_epoch, so it stays 0 throughout the
                // held lifetime — exactly what keeps the self-heal edge
                // intact under the old-map/new-epoch read skew.
                seen_rg_epoch: 0,
                first_held_ns: 0,
                // #2501: a fresh entry has forwarded no packets yet.
                counters: SessionCounters::default(),
            },
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        self.key_to_handle.insert(key.clone(), handle);
        self.index_forward_nat_key(&key, handle, decision, &metadata);
        // #965: schedule the new entry for expiration check.
        self.push_to_wheel(&key, now_ns);
        // #3122: SEPARATE the per-IP COUNT gate from the HA Open-delta
        // gate. The count must follow the session's PRESENCE in the table
        // regardless of origin (a forward, non-seed session consumes a
        // per-IP slot whether it was locally admitted or imported from the
        // HA peer) — otherwise a peer-synced session is invisible to the
        // limit and a client can exceed its cap after failover (#3122
        // limit bypass). The Open delta, by contrast, must NOT re-emit for
        // a peer-synced session (that would echo the peer's own session
        // back to it — a sync loop), so it keeps the `!is_peer_synced()`
        // gate. The two were one condition before #3122; they are now two.
        let counted = !metadata.is_reverse && !origin.is_transient_local_seed();
        if counted {
            // #2134/#3122: fresh-install count choke point. Capture the
            // Copy IPs before `key` is moved into the delta below. The
            // function returned `false` early at `len() >= max_sessions`
            // before any state change, so this only runs on a real
            // install.
            self.session_limit_inc(key.src_ip, key.dst_ip);
        }
        if counted && !origin.is_peer_synced() {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
                // #2465: an Open delta carries the install instant. The
                // SESSION_CREATE RT_FLOW frame does not report a duration, so
                // these are informational here, but keeping them consistent
                // with the entry avoids a 0/unknown asymmetry.
                created_ns: now_ns,
                last_seen_ns: now_ns,
                // #2501: a freshly-installed session has forwarded no
                // packets yet (the trigger packet is accounted on its own
                // forwarding pass).
                counters: SessionCounters::default(),
            });
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        self.upsert_synced_with_origin(
            SessionInstall {
                key,
                decision,
                metadata,
                origin: SessionOrigin::SyncImport,
                now_ns,
                protocol,
                tcp_flags,
            },
            allow_replace_local,
        )
    }

    #[inline]
    pub fn upsert_synced_with_origin(
        &mut self,
        req: SessionInstall,
        allow_replace_local: bool,
    ) -> bool {
        let SessionInstall {
            key,
            decision,
            metadata,
            origin,
            now_ns,
            protocol,
            tcp_flags,
        } = req;
        // Reject peer data that would clobber a locally-owned session
        // unless explicitly allowed (e.g. during HA activation).
        if matches!(self.entry_by_key(&key), Some(existing) if !existing.origin.is_peer_synced())
            && !allow_replace_local
        {
            return false;
        }
        // Same guard semantics as install_with_protocol_with_origin:
        // remove_entry has 3 debug_assert!s (stale-handle,
        // primary-key, no_index_points_at) that catch invariant
        // violations in tests. The first two restore the prior
        // key_to_handle mapping internally before returning None.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                // #2465: a re-imported synced entry stamps its creation instant
                // to the import time. The peer's original creation time is not
                // carried on the HA session-sync delta, so this best-effort
                // stamp is the local re-import time; the local close that
                // follows reports age from here.
                created_ns: now_ns,
                expires_after_ns: session_timeout_ns(
                    protocol,
                    tcp_flags,
                    &self.timeouts,
                    // #3227: per-application idle timeout override (None = global).
                    metadata.inactivity_timeout_ns,
                ),
                closing: matches!(protocol, PROTO_TCP) && is_closing(tcp_flags),
                reset: matches!(protocol, PROTO_TCP) && has_rst(tcp_flags),
                wheel_tick: 0,
                // #2120: a re-imported synced entry leaves the held world
                // with a fresh `last_seen_ns`, so it carries no carried-over
                // hold clock. `seen_rg_epoch` resets to the never-self-healed
                // default (the next SELF-HEAL pass, if this node forwards the
                // RG, records the live epoch; HOLD never writes it).
                // `upsert_synced` first `remove_entry`s any prior entry, so
                // this is the canonical re-import refresh that the §6.4
                // contract clears `first_held_ns` on.
                seen_rg_epoch: 0,
                first_held_ns: 0,
                // #2501: a fresh entry has forwarded no packets yet.
                counters: SessionCounters::default(),
            },
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        let index_key = key.clone();
        self.key_to_handle.insert(key, handle);
        self.index_forward_nat_key(&index_key, handle, decision, &metadata);
        // #965: schedule the synced entry for expiration check.
        self.push_to_wheel(&index_key, now_ns);
        // #3122: a peer-synced session counts toward the per-IP limit the
        // moment it is imported — it occupies a real slot on this node and
        // will be in the table when this node becomes active. Same
        // PRESENCE-based counted-class gate as the fresh-install path
        // (forward, non-seed), but ORIGIN-agnostic (a SyncImport is never
        // a seed; only the reverse direction is excluded so a session is
        // counted once on its forward key). The matching decrement fires
        // in `remove_entry` (now origin-agnostic too). Because failover
        // promotes a synced entry IN PLACE (`update_session`, no
        // remove+reinstall) and the promote site no longer re-increments,
        // there is no double-count across import -> promote.
        if !metadata.is_reverse && !origin.is_transient_local_seed() {
            self.session_limit_inc(index_key.src_ip, index_key.dst_ip);
        }
        true
    }

    pub fn emit_open_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        fabric_redirect_sync: bool,
    ) {
        if metadata.is_reverse {
            return;
        }
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync,
            // #2465: an explicit Open-delta emit (no entry in hand). The
            // SESSION_CREATE frame reports no duration, so 0/unknown is fine.
            created_ns: 0,
            last_seen_ns: 0,
            // #2501: an open carries no volume yet.
            counters: SessionCounters::default(),
        });
    }

    pub fn emit_close_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
    ) {
        if metadata.is_reverse {
            return;
        }
        // #2465: this explicit-close API (clear-session / NAT-remap delete
        // glue) does not carry the originating entry's creation instant — the
        // caller has typically already removed the entry. Emit 0/unknown so the
        // exporter falls back to the packet-count estimate. The dominant close
        // path (idle/age expiry in session/expire.rs) carries real timestamps.
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Close,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync: false,
            created_ns: 0,
            last_seen_ns: 0,
            // #2501: the entry was already removed by the explicit-close
            // caller, so its counters are no longer in hand — emit 0 (the
            // same fallback as the timestamps above). The dominant close
            // path (idle/age expiry) harvests the real counters.
            counters: SessionCounters::default(),
        });
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.remove_entry(key);
    }

    pub fn demote_owner_rg(&mut self, owner_rg_id: i32) -> Vec<crate::session::SessionKey> {
        if owner_rg_id <= 0 {
            return Vec::new();
        }
        let mut demoted_keys = Vec::new();
        for key in self.owner_rg_session_keys(&[owner_rg_id]) {
            let Some(entry) = self.entry_by_key_mut(&key) else {
                continue;
            };
            // #3122: an in-place demote local→synced is now (almost)
            // COUNT-NEUTRAL. Before #3122 the per-IP count tracked LOCAL
            // ownership, so a demote un-counted the session; now it tracks
            // table PRESENCE (local AND synced count alike), and a demoted
            // session is still present, so its slot must remain charged.
            // The matching decrement fires once, later, in `remove_entry`.
            //
            // The ONE exception is a transient seed (`MissingNeighborSeed`):
            // it is uncounted while a seed (presence predicate excludes
            // seeds) but the flip turns it into a `SyncImport` (a counted
            // forward session). Snapshot the pre-flip counted-class, flip,
            // then increment iff the flip ADDED the entry to the counted
            // class — otherwise the later `remove_entry` decrement would
            // underflow this IP (or wrongly debit another session's slot).
            // A normal local entry's counted-class is unchanged by the flip
            // (count-neutral); a reverse entry is uncounted before and
            // after.
            let old_origin = entry.origin;
            let is_reverse = entry.metadata.is_reverse;
            let will_flip = !old_origin.is_peer_synced();
            if will_flip {
                entry.origin = SessionOrigin::SyncImport;
            }
            // Borrow on `entry` ends here so the &mut self count helper can
            // run. `SyncImport` is never a transient seed, so the post-flip
            // counted-class is simply `!is_reverse`.
            let old_counted = !is_reverse && !old_origin.is_transient_local_seed();
            let new_counted = will_flip && !is_reverse;
            if new_counted && !old_counted {
                self.session_limit_inc(key.src_ip, key.dst_ip);
            }
            demoted_keys.push(key);
        }
        demoted_keys
    }
}
