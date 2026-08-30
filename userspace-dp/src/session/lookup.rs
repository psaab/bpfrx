// Forward/reverse tuple match logic (#2005 pure code-motion split of
// session/mod.rs). The read-path conntrack lookups that resolve a wire
// or translated tuple back to an installed session live here: the
// primary/alias `lookup` family, the NAT/wire reverse-match finders, the
// single-entry/owner-RG/iteration read accessors, and `take_synced_local`
// (the HA local-take, which is a lookup that consumes on hit). Bodies are
// byte-for-byte identical to the prior in-`mod.rs` form; this file only
// changes the module boundary. All methods retain their original `pub`
// visibility (they hang off the `pub(crate)` SessionTable type and are
// callable crate-wide). No visibility was widened here: the private
// helpers these methods call (`entry_by_key`, `remove_entry`,
// `session_timeout_ns`, the wire-key transforms) live in ancestor
// modules and are visible to this descendant.

use super::*;

/// #4109: the TCP close / handshake-promotion state a `lookup_with_origin`
/// mutation must mirror onto the matched entry's forward↔reverse companion.
/// Captured inside the `&mut self.entries` borrow (which pins the matched
/// entry) and applied via `propagate_tcp_state_to_companion` after that borrow
/// ends, since touching the companion needs a fresh `&mut self` probe.
struct TcpStatePropagation {
    /// The matched entry's own NAT decision — feeds `reverse_session_key` to
    /// recover the companion's key from the matched canonical key.
    nat: NatDecision,
    /// A FIN/RST advanced the matched entry into the close window (F17): stamp
    /// the same close/reset onto the companion and pull it onto the short
    /// window so both halves reap together.
    close: bool,
    /// The close carried RST (short 2s window), not a graceful FIN.
    reset: bool,
    /// A reverse SYN-ACK promoted the matched (reverse) entry (F16): promote the
    /// forward companion too, so ESTABLISHED requires real handshake evidence.
    established: bool,
    /// #6752: the companion's `handshake_pending` must clear with this half's,
    /// or the companion probe keeps refusing to extend a flow that IS complete.
    handshake_completed: bool,
}

impl SessionTable {
    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        self.lookup_with_origin(key, now_ns, tcp_flags)
            .map(|(lookup, _origin)| lookup)
    }

    pub fn lookup_with_origin(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<(SessionLookup, SessionOrigin)> {
        // #964 Step 1: resolve handle from key. Direct-primary path
        // looks up via key_to_handle; alias path (NAT-translated
        // reverse key) goes via reverse_translated_index.
        // #4438: reverse_translated_index is a 1:N multimap — walk the bucket
        // and pick the reverse entry whose translated tuple matches THIS key
        // (validate-on-lookup) so a translated-key collision no longer resolves
        // to a displaced/wrong session. The in-borrow alias check below
        // re-validates the same predicate as a stale-index guard.
        let (handle, via_alias) = match self.key_to_handle.get(key) {
            Some(h) => (*h, false),
            None => match self.resolve_reverse_translated_handle(key) {
                Some(h) => (h, true),
                None => return None,
            },
        };
        // Pre-compute the timeout before borrowing &mut self.entries
        // so the inner block doesn't need to access self.timeouts.
        let timeouts = self.timeouts;
        // #3527: resolve the per-zone half-open override the same way, by
        // peeking the entry's ingress zone before the &mut borrow. Only
        // consulted on the OPENING branch (a SYN retransmit on a still
        // half-open session); ignored once the session is established.
        let opening_override_ns = self
            .entries
            .get(handle as usize)
            .map(|r| r.entry.metadata.ingress_zone)
            .and_then(|zone| self.opening_override_for(zone));
        // Scope the &mut self.entries borrow so it ends BEFORE we
        // touch self.wheel via push_to_wheel. Without this scoping
        // the &mut record would conflict with the second &mut self
        // via self.wheel.
        let (result, actual_key, propagate) = {
            let record = self.entries.get_mut(handle as usize)?;
            // #964 Step 1: path-specific validation defends against
            // a stale secondary index pointing at a slab slot that
            // was reused by a different session (release-mode guard,
            // not just debug). Direct-primary checks record.key ==
            // *key; alias path verifies the NAT-translation roundtrip.
            if !via_alias {
                if record.key != *key {
                    return None;
                }
            } else {
                let must_be_reverse = record.entry.metadata.is_reverse;
                let translated = translated_session_key(&record.key, record.entry.decision.nat);
                if !must_be_reverse || translated != *key {
                    return None;
                }
            }
            let is_tcp = matches!(key.protocol, PROTO_TCP);
            let entry = &mut record.entry;
            let do_close = is_tcp && is_closing(tcp_flags);
            if do_close {
                if !entry.closing {
                    debug_log!(
                        "SESS_CLOSING: {} proto=TCP {}:{} -> {}:{} rev={} tcp_flags=0x{:02x}",
                        if has_rst(tcp_flags) {
                            "RST"
                        } else {
                            "FIN"
                        },
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.metadata.is_reverse,
                        tcp_flags,
                    );
                }
                entry.closing = true;
                // #3046: a RST close is reaped on the short timeout. The flag
                // is sticky so a later reordered non-RST segment cannot promote
                // the entry back to the 30s graceful-FIN close window.
                entry.reset |= has_rst(tcp_flags);
            }
            // #3152/#4109: promote OPENING -> ESTABLISHED only on a genuine
            // reverse SYN-ACK. Forward and reverse are two independent entries;
            // the server's handshake response is a SYN-ACK on the REVERSE half,
            // so ONLY a SYN-ACK (`is_syn_ack`, not merely any ACK) on the reverse
            // entry (`is_reverse`) promotes — and it promotes both this reverse
            // entry and its forward companion (after the borrow ends, below). A
            // client-only forward ACK never promotes a half-open session: before
            // #4109 any ACK did, so a bare SYN + a bare ACK pinned a 300s
            // established entry with no peer replying, turning the #3152 half-open
            // reap into a 2-packet bypass. Requiring the SYN bit too (not just
            // has_ack on the reverse tuple) closes the residual where a
            // server-spoofed bare reverse ACK could still promote — a legit
            // 3-way handshake's only pre-established reverse segment IS the
            // SYN-ACK, and xpf is inline so it always sees it (control segments
            // bypass the flow cache and reach this slow-path site). Sticky — an
            // already-established entry (e.g. a mid-stream pickup seeded
            // ESTABLISHED at install) is never demoted.
            let promote_from_reverse = is_tcp && is_syn_ack(tcp_flags) && entry.metadata.is_reverse;
            if promote_from_reverse {
                entry.established = true;
                // #6752: promotion is on the SYN-ACK, which is NOT handshake
                // completion. Mark the gap so the idle window below stays on the
                // OPENING class until the completing forward segment arrives.
                entry.handshake_pending = true;
            }
            // #6752: the handshake-completing forward segment. Any FORWARD-
            // direction TCP segment ends the gap — the final ACK normally, and a
            // data segment implies it too.
            //
            // This is reachable, which the fix depends on: `packet_eligible`
            // (afxdp/flow_cache.rs) admits a TCP packet to the flow cache only
            // when `is_ack_only`, and `should_cache` uses the same predicate, so
            // neither the SYN nor the SYN-ACK ever seeds an entry. The final ACK
            // is therefore a cache MISS and falls through to this slow path,
            // where it both completes the handshake and seeds the cache for the
            // data that follows.
            let handshake_completed = is_tcp && entry.handshake_pending && !entry.metadata.is_reverse;
            if handshake_completed {
                entry.handshake_pending = false;
            }
            entry.last_seen_ns = now_ns;
            entry.expires_after_ns = if is_tcp && entry.closing {
                if entry.reset {
                    TCP_RST_TIMEOUT_NS
                } else {
                    TCP_CLOSING_TIMEOUT_NS
                }
            } else {
                // #3227: re-apply the admitting application's per-app idle
                // timeout on every established refresh so the session keeps
                // aging on the app's value, not the global per-protocol one.
                // #3152: an un-established (OPENING) TCP session ages on the
                // short opening window via session_timeout_ns(established=…).
                session_timeout_ns(
                    key.protocol,
                    tcp_flags,
                    // #6752: the EFFECTIVE established class. A flow promoted by
                    // the SYN-ACK but not yet completed stays on the opening
                    // window, so a handshake the client never finishes reaps at
                    // ~20s instead of holding 300s.
                    entry.established && !entry.handshake_pending,
                    &timeouts,
                    entry.metadata.inactivity_timeout_ns,
                    // #3527: per-zone half-open override resolved above.
                    opening_override_ns,
                )
            };
            let propagate = TcpStatePropagation {
                nat: entry.decision.nat,
                close: do_close,
                reset: is_tcp && has_rst(tcp_flags),
                established: promote_from_reverse,
                handshake_completed,
            };
            (
                (
                    SessionLookup {
                        decision: entry.decision,
                        // #5445: strip the bound `policy_counter` Arc from the
                        // per-packet lookup return. `entry.metadata.clone()`
                        // bumped the SHARED `Arc<PolicyRuleCounter>` refcount
                        // (a `LOCK XADD`) on EVERY established-session lookup —
                        // the #919 hot-path atomic. The counter stays owned by
                        // this `SessionEntry`; hot-path consumers re-source it
                        // by borrow via `bound_policy_counter_for`.
                        metadata: entry.metadata.clone_without_policy_counter(),
                    },
                    entry.origin,
                ),
                record.key.clone(),
                propagate,
            )
        }; // <-- &mut self.entries borrow ends here
        // #4109: mirror the close (F17) / handshake promotion (F16) onto the
        // forward↔reverse companion now that the matched entry's &mut borrow has
        // ended (touching the companion needs a fresh &mut self probe). Resolved
        // from the matched CANONICAL key (`actual_key`, not the alias lookup
        // `key`) + its own nat, exactly as `account_packet` hops reverse→forward.
        // Skipped entirely when there is nothing to propagate.
        if propagate.close || propagate.established || propagate.handshake_completed {
            self.propagate_tcp_state_to_companion(
                &actual_key,
                propagate.nat,
                now_ns,
                propagate.close,
                propagate.reset,
                propagate.established,
                propagate.handshake_completed,
            );
        }
        // Push the canonical key (NOT the alias lookup `key`) into
        // the wheel. push_to_wheel re-reads the record to compute
        // the throttled target_tick — that matches the model in the
        // plan (~100 ns per FxHashMap lookup on the slow path).
        self.push_to_wheel(&actual_key, now_ns);
        Some(result)
    }

    pub fn find_forward_nat_match(&self, reply_key: &SessionKey) -> Option<ForwardSessionMatch> {
        // #4399: `nat_reverse_index` is a 1:N multimap — a reverse-key
        // collision (interface-mode SNAT / DNAT-to-shared-backend / NAT64 /
        // non-bijective static NAT, the #1758 latent collision) parks BOTH
        // colliding forward handles in one bucket. Walk the candidates and
        // return the first whose forward session actually reverse-maps to
        // THIS reply (validate-on-lookup): the pre-#4399 single-value map
        // returned only the last-installed handle, so a displaced session's
        // reply was mis-delivered or dropped. The common (bijective /
        // non-colliding) case is a len-1 bucket — one validate, zero heap
        // (SmallVec inline) — so the pool-mode-SNAT fast path is unchanged.
        let bucket = self.nat_reverse_index.get(reply_key)?;
        for &handle in bucket.iter() {
            let Some(record) = self.entries.get(handle as usize) else {
                continue;
            };
            let entry = &record.entry;
            if entry.metadata.is_reverse
                || !reply_matches_forward_session(&record.key, entry.decision.nat, reply_key)
            {
                continue;
            }
            return Some(ForwardSessionMatch {
                key: record.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            });
        }
        None
    }

    pub fn find_forward_wire_match(&self, wire_key: &SessionKey) -> Option<ForwardSessionMatch> {
        self.find_forward_wire_match_with_origin(wire_key)
            .map(|(matched, _origin)| matched)
    }

    pub fn find_forward_wire_match_with_origin(
        &self,
        wire_key: &SessionKey,
    ) -> Option<(ForwardSessionMatch, SessionOrigin)> {
        // #4438: `forward_wire_index` is a 1:N multimap — a forward-wire key
        // collision (interface-mode SNAT with no port translation and the other
        // non-bijective NAT classes; interface SNAT collapses both the reverse-
        // wire AND the forward-wire tuples) parks BOTH colliding forward handles
        // in one bucket. Walk the candidates and return the first whose forward
        // session actually maps to THIS wire key (validate-on-lookup): the
        // pre-#4438 single-value map returned only the last-installed handle, so
        // a displaced session's wire lookup was mis-delivered (hijacked). The
        // common (bijective / non-colliding) case is a len-1 bucket — one
        // validate, zero heap (SmallVec inline) — so the pool-mode-SNAT fast
        // path is unchanged.
        let bucket = self.forward_wire_index.get(wire_key)?;
        for &handle in bucket.iter() {
            let Some(record) = self.entries.get(handle as usize) else {
                continue;
            };
            let entry = &record.entry;
            if entry.metadata.is_reverse
                || forward_wire_key(&record.key, entry.decision.nat) != *wire_key
            {
                continue;
            }
            return Some((
                ForwardSessionMatch {
                    key: record.key.clone(),
                    decision: entry.decision,
                    metadata: entry.metadata.clone(),
                },
                entry.origin,
            ));
        }
        None
    }

    /// #4438: resolve the reverse entry whose translated (alias) tuple equals
    /// `key` from the 1:N `reverse_translated_index` bucket. A translated-key
    /// collision (non-bijective NAT: DNAT-to-shared-backend / NAT64 /
    /// interface-mode SNAT) parks multiple reverse handles under one translated
    /// key; the pre-#4438 single-value map returned only the last-installed, so
    /// a displaced reverse session's inbound alias lookup mis-resolved. Validate
    /// each candidate against the full tuple AND its `is_reverse` flag — the
    /// same check `lookup_with_origin` re-applies inside its `&mut` borrow as a
    /// stale-index guard. The common non-colliding case is a len-1 bucket (one
    /// validate, zero heap), so the fast path is unchanged. Returns the matching
    /// handle, or `None` when no live reverse entry aliases to `key`.
    pub(super) fn resolve_reverse_translated_handle(&self, key: &SessionKey) -> Option<u32> {
        let bucket = self.reverse_translated_index.get(key)?;
        for &handle in bucket.iter() {
            let Some(record) = self.entries.get(handle as usize) else {
                continue;
            };
            let entry = &record.entry;
            if entry.metadata.is_reverse
                && translated_session_key(&record.key, entry.decision.nat) == *key
            {
                return Some(handle);
            }
        }
        None
    }

    /// #5445: borrow the admitting rule's bound hit-counter handle (`#3322`)
    /// directly from this worker's session-table entry, WITHOUT cloning the
    /// `Arc`. The per-packet established-session lookup (`lookup_with_origin`)
    /// no longer carries the bound `Arc<PolicyRuleCounter>` on its returned
    /// `SessionLookup.metadata` — cloning it there bumped the shared refcount (a
    /// `LOCK XADD`) on the packet-forwarding hot path, reintroducing the #919
    /// hot-path-atomic problem. The counter itself is still owned by the
    /// `SessionEntry` (lifetime-guaranteed to outlive the packet's processing
    /// on this per-worker table), so the fast path re-sources it BY BORROW here
    /// for the per-packet policy hit-count and, once per flow, clones it into
    /// the flow-cache entry.
    ///
    /// Resolution mirrors `lookup_with_origin` — the direct primary key, then
    /// the reverse-translated (NAT alias) index — the exact two paths whose
    /// `SessionLookup` return is now counter-stripped. The `forward_wire` finder
    /// path is not mirrored: it returns a `ForwardSessionMatch` that still
    /// carries the `Arc`, so `resolve_flow_session_decision` already threads the
    /// bound handle for that (rarer, interface-mode-SNAT) case and never falls
    /// back to this accessor. Returns `None` for a miss or an entry with no
    /// bound counter (idx-0 / peer-synced entries carrying only the wire idx),
    /// which the caller resolves via the positional `policy_counter_idx`
    /// fallback exactly as `resolve_session_hit_counter(None, idx)` did before.
    pub fn bound_policy_counter_for(
        &self,
        key: &SessionKey,
    ) -> Option<&std::sync::Arc<crate::policy::PolicyRuleCounter>> {
        if let Some(entry) = self.entry_by_key(key) {
            return entry.metadata.policy_counter.as_ref();
        }
        let handle = self.resolve_reverse_translated_handle(key)?;
        let record = self.entries.get(handle as usize)?;
        record.entry.metadata.policy_counter.as_ref()
    }

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.entry_by_key(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
    }

    /// #5152: test-only read of an entry's `first_held_ns` — the standby
    /// bounded-leak HOLD clock (§6.4). Lets the session_glue activation-scan
    /// test assert the clock is PRESERVED for a session that re-resolves to
    /// `HAInactive` (skipped) and CLEARED for one that genuinely forwards
    /// (refreshed) without reaching into the private `SessionEntry` layout.
    #[cfg(test)]
    pub(crate) fn first_held_ns_for(&self, key: &SessionKey) -> Option<u64> {
        self.entry_by_key(key).map(|entry| entry.first_held_ns)
    }

    /// #2442: every owner-RG id that currently indexes at least one session in
    /// this worker's table. Used by the loss-of-sync resync path to export ALL
    /// owned forward sessions (the same RG set
    /// `export_forward_sessions_for_owner_rgs` would walk) without needing the
    /// coordinator's RG runtime view — the table's own `owner_rg_sessions`
    /// index is the ground truth for what this worker owns. Empty sets are
    /// skipped (an owner RG can transiently hold a now-empty index entry).
    pub fn all_owner_rg_ids(&self) -> Vec<i32> {
        self.owner_rg_sessions
            .iter()
            .filter(|(_, set)| !set.is_empty())
            .map(|(rg, _)| *rg)
            .collect()
    }

    pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
        // #964 Step 1: handles → keys via the slab. Each session is
        // in at most one owner-RG set, so total iteration is
        // O(owner-sessions), same complexity as today's key-based
        // index returned.
        let mut handles: FxHashSet<u32> = FxHashSet::default();
        for owner_rg_id in owner_rgs {
            if let Some(set) = self.owner_rg_sessions.get(owner_rg_id) {
                handles.extend(set.iter().copied());
            }
        }
        handles
            .into_iter()
            .filter_map(|h| self.entries.get(h as usize).map(|r| r.key.clone()))
            .collect()
    }

    pub fn take_synced_local(&mut self, key: &SessionKey) -> Option<SessionLookup> {
        let entry = self.entry_by_key(key)?;
        if !entry.origin.is_peer_synced()
            || entry.metadata.is_reverse
            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
        {
            return None;
        }
        self.remove_entry(key).map(|entry| SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata,
        })
    }

    pub fn iter_with_origin(
        &self,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin),
    ) {
        // Walk via key_to_handle (the primary index) so any orphan
        // slab record without a forward-key mapping is skipped —
        // matches the plan's "primary index is authoritative" model.
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                f(
                    key,
                    record.entry.decision,
                    &record.entry.metadata,
                    record.entry.origin,
                );
            }
        }
    }

    /// Iterate over ALL session entries in one pass with idle time (in
    /// nanoseconds) and, since #2501, the per-direction byte/packet counters.
    ///
    /// #5287: the production `refresh_bpf_conntrack_last_seen` no longer uses
    /// this unbounded full-table walk — it drives `iter_with_idle_budgeted`
    /// (below) so no single packet-loop tick scans the whole table. This method
    /// is retained as the simple full-walk primitive used by the idle-time unit
    /// tests; hence it is test-only in non-`test` builds.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn iter_with_idle(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64, SessionCounters),
    ) {
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                let entry = &record.entry;
                let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
                f(key, entry.decision, &entry.metadata, idle_ns, entry.counters);
            }
        }
    }

    /// #5287: budgeted, resumable variant of `iter_with_idle`.
    ///
    /// `iter_with_idle` walks the ENTIRE table in one uninterrupted pass. Its
    /// sole caller `refresh_bpf_conntrack_last_seen` does a BPF lookup + update
    /// per forward entry, so near the 131072-entry cap that pass is tens of
    /// thousands of synchronous kernel crossings executed between two RX/TX
    /// polls — a deterministic per-interval latency spike on a low-latency core
    /// (issue #5287).
    ///
    /// This variant bounds the work per call. It walks the `entries` slab by
    /// its STABLE integer handle (the slab index is stable across
    /// insert/remove — a removed slot goes vacant and is reused, it does not
    /// renumber live handles), starting at `cursor` and examining at most
    /// `budget` slots. `cursor` is therefore a persistent iterator position:
    /// the caller passes back the returned value on the next slice and the walk
    /// resumes exactly where it stopped, spreading a full-table pass across many
    /// packet-loop ticks.
    ///
    /// Returns the next cursor to resume from. It returns 0 once the walk
    /// reaches the end of the LIVE EXTENT, i.e. a full-table cycle just
    /// completed — the caller uses that edge to pace the next cycle. A `cursor`
    /// past the current end (the live extent shrank since the last slice)
    /// restarts the cycle from 0.
    ///
    /// #6297: the cycle end is `slot_high_watermark` (`1 + the highest slot
    /// index the slab has ever handed out`), NOT `entries.capacity()`. The slab
    /// never shrinks, so after a session-count spike drains, `capacity()` stays
    /// at the doubled peak; walking to `capacity()` would re-scan tens of
    /// thousands of now-vacant slots every cycle. The watermark tracks the true
    /// live extent (always <= `capacity()`) and is >= 1 + every occupied slot
    /// index, so a shorter walk still visits every live session.
    ///
    /// The budget counts examined slab SLOTS (occupied or vacant), not just
    /// forward entries, so both the index scan and the per-entry callback cost
    /// are hard-bounded by `budget` regardless of the occupied/vacant mix.
    /// `f` is invoked only for occupied slots (at most `budget` times). No
    /// allocation, no atomics — a bounded index walk plus one `saturating_sub`
    /// per occupied slot.
    pub fn iter_with_idle_budgeted(
        &self,
        cursor: usize,
        budget: usize,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64, SessionCounters),
    ) -> usize {
        // #6297: bound the round-robin walk to the live-extent
        // high-watermark, NOT the monotonic `entries.capacity()`. The slab
        // never shrinks, so after a session-count spike drains, `capacity()`
        // stays at the doubled peak and this walk would re-visit tens of
        // thousands of now-vacant slots every 10s cycle. `slot_high_watermark`
        // is `1 + the highest slot the slab has ever handed out` (bumped on
        // every insert via `insert_record`, never shrunk on removal) and is
        // always <= `capacity()`, so the `min` is defensive. Because the
        // watermark is >= 1 + every OCCUPIED slot index, no live session is
        // ever above `cap` — a shorter walk can never skip an entry's
        // last_seen refresh (which would look idle and expire early).
        let cap = self.slot_high_watermark.min(self.entries.capacity());
        // Empty slab (no slot ever handed out) or a degenerate zero budget: no
        // progress, restart at 0 so the caller never gets wedged at a stale
        // non-zero cursor.
        if cap == 0 || budget == 0 {
            return 0;
        }
        // A cursor past the end (the live extent shrank below a saved cursor,
        // or a stale save) restarts the cycle from the top rather than
        // skipping the whole table.
        let start = if cursor >= cap { 0 } else { cursor };
        let end = start.saturating_add(budget).min(cap);
        for idx in start..end {
            if let Some(record) = self.entries.get(idx) {
                let entry = &record.entry;
                let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
                f(&record.key, entry.decision, &entry.metadata, idle_ns, entry.counters);
            }
        }
        // Wrap to 0 on cycle completion so the caller can detect "table fully
        // walked" and pace the next cycle to the freshness window.
        if end >= cap { 0 } else { end }
    }
}
