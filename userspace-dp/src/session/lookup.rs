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
                    entry.established,
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
            };
            (
                (
                    SessionLookup {
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
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
        if propagate.close || propagate.established {
            self.propagate_tcp_state_to_companion(
                &actual_key,
                propagate.nat,
                now_ns,
                propagate.close,
                propagate.reset,
                propagate.established,
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
    fn resolve_reverse_translated_handle(&self, key: &SessionKey) -> Option<u32> {
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

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.entry_by_key(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
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

    /// Iterate over all session entries with idle time (in nanoseconds) and,
    /// since #2501, the per-direction byte/packet counters.
    ///
    /// `refresh_bpf_conntrack_last_seen` (afxdp/bpf_map) is the sole
    /// production caller: it mirrors `idle_ns` (→ `last_seen`) and the
    /// `SessionCounters` (→ fwd/rev packet+byte fields) into the BPF
    /// conntrack map on the ~1s GC cadence so `show security flow session`
    /// surfaces live idle time AND volume. Cold path: a `Copy` of the
    /// four-`u64` counter snapshot per session on top of the idle-time walk.
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
}
