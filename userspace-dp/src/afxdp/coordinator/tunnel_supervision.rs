//! #1890: GRE local-origin + WireGuard control-thread supervision,
//! split out of `coordinator/mod.rs` (pure code motion). Both aux
//! thread families are keyed by tunnel_endpoint_id and share the
//! three-pass lifecycle (#1866 for WG, #1881 for GRE): finished
//! sweep → tombstone, stale prune, spawn with backoff — see the
//! "Aux tunnel threads" section of this directory's README.md for
//! the family differences that matter. The thread BODIES live
//! elsewhere (`wg_control.rs` for WG, `afxdp/tunnel.rs` for GRE);
//! this file owns the coordinator-side lifecycle only. The entry
//! maps themselves (`tunnel_sources`, `wg_control_threads`) stay on
//! `Coordinator` in mod.rs, and `stop_inner` keeps its own inline
//! teardown of both maps.
use super::*;

/// #1866: minimum interval between WG control-thread spawn ATTEMPTS for
/// one endpoint id (durable across thread exit via the tombstone entry).
/// Bounds the retry/exception cadence under a persistently-failing bind
/// (e.g. EADDRINUSE against a host kernel wgX) without ever giving up.
pub(crate) const WG_SPAWN_BACKOFF_NS: u64 = 3_000_000_000;

impl super::Coordinator {
    /// #1881: reconcile GRE local-origin threads against the current
    /// `forwarding.tunnel_endpoints`. Called from initial worker
    /// bring-up AND every armed `refresh_runtime_snapshot` — tunnel
    /// interfaces are excluded from the binding plan
    /// (`include_userspace_binding_interface`), so tunnel-only commits
    /// take the same-plan path and never reach a full reconcile.
    /// Three passes, same shape as `spawn_wg_control_threads` (#1866):
    ///
    ///   1. Finished sweep — exited thread ⇒ TOMBSTONE (backoff stamp
    ///      + attachment retained; delivery sender cleared).
    ///   2. Stale prune — endpoint removed / mode no longer gre|ip6gre
    ///      / TUN attachment changed ⇒ UNPUBLISH the delivery map
    ///      first (Codex plan r1 MAJOR 2: workers must lose the
    ///      sender BEFORE the join so a busy producer cannot extend
    ///      it), then stop + join + remove. Endpoint CONTENT changes
    ///      are deliberately NOT stale conditions — the live thread
    ///      tracks them through the shared forwarding ArcSwap.
    ///   3. Spawn — desired gre/ip6gre endpoints with no entry (new:
    ///      immediate) or a tombstone past the backoff. Gated on live
    ///      worker handles (plan SMR-1): the deferred same-plan window
    ///      reaches this with ZERO workers, and a thread spawned there
    ///      would freeze empty live/identities/worker_commands
    ///      captures for its lifetime. WG deliberately has no such
    ///      gate — WG control threads use kernel UDP+TUN and have no
    ///      binding dependency; GRE local-origin TX does.
    ///
    /// The delivery map is republished (live handles only) whenever
    /// any pass changed the set.
    ///
    /// Visibility (#1890): `pub(super)` — called from
    /// `reconcile/bringup.rs` and the armed snapshot-refresh leg,
    /// which live in sibling files of this module after the split.
    pub(super) fn reconcile_local_tunnel_sources(&mut self) {
        let swept = self.sweep_finished_local_tunnel_sources();

        // Stale prune: removed, mode-flipped, or attachment drift.
        let mut stale: Vec<(u16, &'static str)> = Vec::new();
        for (id, entry) in self.tunnel_sources.iter() {
            let reason = match self.forwarding.tunnel_endpoints.get(id) {
                None => Some("removed"),
                Some(ep) if ep.mode != "gre" && ep.mode != "ip6gre" => Some("mode_changed"),
                Some(ep) => {
                    let attach_ok = ep.logical_ifindex == entry.spawned_ifindex
                        && self
                            .forwarding
                            .ifindex_to_name
                            .get(&ep.logical_ifindex)
                            .is_some_and(|name| *name == entry.spawned_tunnel_name);
                    if attach_ok {
                        None
                    } else {
                        Some("attachment_changed")
                    }
                }
            };
            if let Some(reason) = reason {
                stale.push((*id, reason));
            }
        }
        if swept > 0 || !stale.is_empty() {
            // Store #1 (unpublish): live-handle-only rule applied to
            // (entries − stale set) — swept tombstones drop out via
            // the live-handle rule, stale entries via the exclusion.
            let stale_ids: Vec<u16> = stale.iter().map(|(id, _)| *id).collect();
            self.publish_local_tunnel_deliveries_excluding(&stale_ids);
        }
        for (id, reason) in &stale {
            self.stop_remove_local_tunnel_entry(*id, reason);
        }

        // Spawn pass (apply-time only; the periodic liveness sweep
        // respawns tombstones but never creates entries).
        let mut spawned = false;
        if !self.workers.handles.is_empty() {
            let now = monotonic_nanos();
            let desired: Vec<u16> = self
                .forwarding
                .tunnel_endpoints
                .values()
                .filter(|ep| ep.mode == "gre" || ep.mode == "ip6gre")
                .map(|ep| ep.id)
                .collect();
            for id in desired {
                match self.tunnel_sources.get(&id) {
                    Some(entry) if entry.handle.is_some() => continue, // live
                    Some(entry)
                        if now.saturating_sub(entry.last_spawn_attempt_ns)
                            < WG_SPAWN_BACKOFF_NS =>
                    {
                        continue; // tombstone within backoff
                    }
                    _ => {}
                }
                spawned |= self.spawn_one_local_tunnel_source(id);
            }
        }
        if swept > 0 || !stale.is_empty() || spawned {
            // Store #2: final live-handle-only publication.
            self.publish_local_tunnel_deliveries_excluding(&[]);
        }
    }

    /// #1881 pass 1: join threads that already exited and tombstone
    /// their entries (keep backoff stamp + attachment; never remove).
    /// Returns the number of entries tombstoned.
    fn sweep_finished_local_tunnel_sources(&mut self) -> usize {
        let finished: Vec<u16> = self
            .tunnel_sources
            .iter()
            .filter(|(_, entry)| {
                entry
                    .handle
                    .as_ref()
                    .is_some_and(|h| h.join.as_ref().is_none_or(|j| j.is_finished()))
            })
            .map(|(id, _)| *id)
            .collect();
        let swept = finished.len();
        for id in finished {
            if let Some(entry) = self.tunnel_sources.get_mut(&id) {
                if let Some(mut handle) = entry.handle.take() {
                    handle.request_stop();
                    if let Some(join) = handle.join.take() {
                        let _ = join.join();
                    }
                }
                entry.delivery_tx = None;
                eprintln!(
                    "xpf-userspace-dp: GRE local-origin thread exited endpoint={id} tun={} — tombstoned (respawn if still configured)",
                    entry.spawned_tunnel_name
                );
            }
        }
        swept
    }

    /// #1881 pass 2 helper: stop + join + REMOVE one entry (live
    /// thread or tombstone). Callers UNPUBLISH the delivery map
    /// before invoking this (unpublish-before-join).
    fn stop_remove_local_tunnel_entry(&mut self, id: u16, reason: &str) {
        if let Some(mut entry) = self.tunnel_sources.remove(&id) {
            if let Some(mut handle) = entry.handle.take() {
                handle.request_stop();
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
            eprintln!(
                "xpf-userspace-dp: stopped GRE local-origin thread endpoint={id} tun={} reason={reason}",
                entry.spawned_tunnel_name
            );
        }
    }

    /// #1881: publish `local_tunnel_deliveries` from the entry map —
    /// live handles only (tombstones and failed spawns never publish),
    /// minus `exclude` (the pass-2 stale set, for the
    /// unpublish-before-join store #1).
    fn publish_local_tunnel_deliveries_excluding(&self, exclude: &[u16]) {
        let mut map: BTreeMap<i32, LocalTunnelDelivery> = BTreeMap::new();
        for (id, entry) in self.tunnel_sources.iter() {
            if exclude.contains(id) || entry.handle.is_none() {
                continue;
            }
            if let Some(delivery) = entry.delivery_tx.as_ref() {
                map.insert(entry.spawned_ifindex, delivery.clone());
            }
        }
        self.local_tunnel_deliveries.store(Arc::new(map));
    }

    /// #1881 pass 3 helper: one spawn ATTEMPT for endpoint `id`
    /// against the CURRENT forwarding state. Records the entry (live
    /// handle or failure tombstone) with the attempt stamped either
    /// way. TUN open happens INSIDE the spawned aux thread — never on
    /// the control-socket thread (#1866 §7 discipline). Returns true
    /// when a live thread was started.
    fn spawn_one_local_tunnel_source(&mut self, id: u16) -> bool {
        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
            return false;
        };
        if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
            return false;
        }
        let Some(tunnel_name) = self
            .forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
            .cloned()
        else {
            return false;
        };
        let logical_ifindex = endpoint.logical_ifindex;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        // #1881 D.1: the thread receives the SAME worker-visible
        // forwarding ArcSwap handle (`ha.forwarding`) instead of a
        // frozen clone — every store on the refresh/reconcile/fabric
        // paths reaches it on its next iteration.
        let shared_forwarding = self.ha.forwarding.clone();
        let ha_state = self.ha.rg_runtime.clone();
        let dynamic_neighbors = self.neighbors.dynamic.clone();
        let live = self.workers.live.clone();
        let identities = self.workers.identities.clone();
        let shared_sessions = self.sessions.synced.clone();
        let shared_nat_sessions = self.sessions.nat.clone();
        let shared_forward_wire_sessions = self.sessions.forward_wire.clone();
        let shared_owner_rg_indexes = self.sessions.owner_rg_indexes.clone();
        let worker_commands = self
            .workers
            .handles
            .values()
            .map(|handle| handle.commands.clone())
            .collect::<Vec<_>>();
        let recent_exceptions = self.recent_exceptions.clone();
        let thread_tunnel_name = tunnel_name.clone();
        let (delivery_tx, delivery_rx) = mpsc::sync_channel(LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH);
        // #2412: eventfd wake shared by the loop's poll(2), the delivery
        // producers (worker slow path), and the stop path. If the
        // eventfd cannot be created, fail the spawn like any other
        // resource failure (tombstone + respawn-backoff).
        let wake = match TunnelWake::new() {
            Ok(wake) => Arc::new(wake),
            Err(err) => {
                if let Ok(mut recent) = self.recent_exceptions.lock() {
                    push_recent_exception(
                        &mut recent,
                        ExceptionStatus {
                            timestamp: Utc::now(),
                            interface: tunnel_name.clone(),
                            reason: format!("local_tunnel_wake_eventfd_failed:{id}:{err}"),
                            ..ExceptionStatus::default()
                        },
                    );
                }
                eprintln!(
                    "xpf-userspace-dp: GRE local-origin thread spawn FAILED endpoint={id}: eventfd: {err}"
                );
                self.tunnel_sources.insert(
                    id,
                    LocalTunnelSourceEntry {
                        handle: None,
                        spawned_ifindex: logical_ifindex,
                        spawned_tunnel_name: tunnel_name,
                        delivery_tx: None,
                        last_spawn_attempt_ns: monotonic_nanos(),
                    },
                );
                return false;
            }
        };
        let thread_wake = wake.clone();
        let delivery = LocalTunnelDelivery {
            tx: delivery_tx,
            wake: wake.clone(),
        };
        eprintln!(
            "xpf-userspace-dp: spawning GRE local-origin thread endpoint={id} tun={tunnel_name}"
        );
        // #925-A: wrap aux tunnel-origin thread in catch_unwind.
        // A panic here would otherwise silently stop locally-
        // generated GRE traffic on this tunnel; transit packets
        // continue through worker_loop unaffected.
        let join = spawn_supervised_aux(
            format!("xpf-native-gre-origin-{}", tunnel_name),
            move || {
                local_tunnel_source_loop(
                    thread_tunnel_name,
                    id,
                    logical_ifindex,
                    shared_forwarding,
                    ha_state,
                    dynamic_neighbors,
                    live,
                    identities,
                    shared_sessions,
                    shared_nat_sessions,
                    shared_forward_wire_sessions,
                    shared_owner_rg_indexes,
                    worker_commands,
                    delivery_rx,
                    thread_wake,
                    recent_exceptions,
                    stop_clone,
                );
            },
        );
        let (handle, delivery_tx, started) = match join {
            Ok(join) => (
                Some(LocalTunnelSourceHandle {
                    stop,
                    wake: Some(wake),
                    join: Some(join),
                }),
                Some(delivery),
                true,
            ),
            Err(err) => {
                if let Ok(mut recent) = self.recent_exceptions.lock() {
                    push_recent_exception(
                        &mut recent,
                        ExceptionStatus {
                            timestamp: Utc::now(),
                            interface: tunnel_name.clone(),
                            reason: format!("spawn_local_tunnel_source_failed:{id}:{err}"),
                            ..ExceptionStatus::default()
                        },
                    );
                }
                eprintln!(
                    "xpf-userspace-dp: GRE local-origin thread spawn FAILED endpoint={id}: {err}"
                );
                (None, None, false)
            }
        };
        self.tunnel_sources.insert(
            id,
            LocalTunnelSourceEntry {
                handle,
                spawned_ifindex: logical_ifindex,
                spawned_tunnel_name: tunnel_name,
                delivery_tx,
                last_spawn_attempt_ns: monotonic_nanos(),
            },
        );
        started
    }

    /// #1881: stop + join + remove ALL GRE local-origin entries (live
    /// and tombstoned) and store the EMPTY delivery map (plan SMR2-2,
    /// mirroring `stop_inner`). Used by the disarmed same-plan refresh
    /// leg — a disarmed helper must not hold TUN reader fds (mirrors
    /// `stop_all_wg_control_threads`); in practice a no-op because
    /// `reconcile_status_bindings → stop()` already cleared them.
    pub(crate) fn stop_all_local_tunnel_sources(&mut self, reason: &str) {
        let ids: Vec<u16> = self.tunnel_sources.keys().copied().collect();
        if ids.is_empty() {
            return;
        }
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        for id in ids {
            self.stop_remove_local_tunnel_entry(id, reason);
        }
    }

    /// #1881 (mirrors #1866 Change 2b): stale propagation on the
    /// defer-workers apply path — the NOT-same-plan + defer_workers
    /// branch stores the snapshot WITHOUT reconciling, so a removed
    /// GRE tunnel's thread would keep its TUN reader fd (on a netdev
    /// the Go side is deleting) until the deferred bring-up. Narrow
    /// prune: stop + join + remove entries whose snapshot row is
    /// absent, no longer gre/ip6gre, OR attachment-drifted (Codex
    /// code-review r1: the defer branch never rotates forwarding, so
    /// the thread-side rotation gate cannot observe a moved
    /// attachment — the stale predicate here must match the armed
    /// pass-2 semantics, compared against the entry's SPAWNED
    /// attachment because `self.forwarding` is stale by design on
    /// this path). No spawn, no forwarding mutation;
    /// unpublish-before-join discipline applies.
    pub(crate) fn prune_local_tunnel_sources_for_snapshot(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
    ) {
        let stale: Vec<(u16, &'static str)> = self
            .tunnel_sources
            .iter()
            .filter_map(|(id, entry)| {
                let Some(row) = snapshot
                    .tunnel_endpoints
                    .iter()
                    .find(|row| row.id == *id && row.ifindex > 0)
                else {
                    return Some((*id, "removed_deferred"));
                };
                if row.mode != "gre" && row.mode != "ip6gre" {
                    return Some((*id, "mode_changed_deferred"));
                }
                // Attachment label mirrors forwarding_build/interfaces.rs.
                let row_label = if row.linux_name.is_empty() {
                    row.interface.as_str()
                } else {
                    row.linux_name.as_str()
                };
                if row.ifindex != entry.spawned_ifindex
                    || row_label != entry.spawned_tunnel_name
                {
                    return Some((*id, "attachment_changed_deferred"));
                }
                None
            })
            .collect();
        if stale.is_empty() {
            return;
        }
        let stale_ids: Vec<u16> = stale.iter().map(|(id, _)| *id).collect();
        self.publish_local_tunnel_deliveries_excluding(&stale_ids);
        for (id, reason) in stale {
            self.stop_remove_local_tunnel_entry(id, reason);
        }
    }

    /// #1881 (mirrors `reconcile_wg_control_liveness`): periodic
    /// self-heal, called from the server's `refresh_status` ONLY while
    /// `should_run_afxdp` holds. TOMBSTONE-ONLY and SNAPSHOT-COHERENT:
    /// never creates entries; a tombstone respawns only past the
    /// backoff AND only when the latest STORED snapshot's row for the
    /// id matches the forwarding endpoint's mode + attachment (the
    /// spawn-baked identity). Endpoint CONTENT is NOT gated — the
    /// thread reads it live through the ArcSwap, so a respawn bakes in
    /// nothing but the attachment (plan v3 / AGY r1 R3). The delivery
    /// map is republished when the sweep or a respawn changed the set
    /// (Codex plan r1 R3: a respawn without republication would
    /// restore the TUN reader but not inbound delivery).
    pub(crate) fn reconcile_local_tunnel_liveness(
        &mut self,
        latest_snapshot: Option<&crate::ConfigSnapshot>,
    ) {
        let swept = self.sweep_finished_local_tunnel_sources();
        let mut spawned = false;
        if let Some(snapshot) = latest_snapshot {
            if !self.workers.handles.is_empty() {
                let now = monotonic_nanos();
                let tombstones: Vec<u16> = self
                    .tunnel_sources
                    .iter()
                    .filter(|(_, entry)| entry.handle.is_none())
                    .map(|(id, _)| *id)
                    .collect();
                for id in tombstones {
                    let Some(entry) = self.tunnel_sources.get(&id) else {
                        continue;
                    };
                    if now.saturating_sub(entry.last_spawn_attempt_ns) < WG_SPAWN_BACKOFF_NS {
                        continue;
                    }
                    if !self.local_tunnel_tombstone_respawn_coherent(id, snapshot) {
                        continue;
                    }
                    spawned = self.spawn_one_local_tunnel_source(id);
                    break; // ≤1 spawn attempt per invocation
                }
            }
        }
        if swept > 0 || spawned {
            self.publish_local_tunnel_deliveries_excluding(&[]);
        }
    }

    /// #1881: whether a tombstone respawn for `id` is coherent — the
    /// latest stored snapshot must describe EXACTLY the attachment the
    /// spawn would create from the current forwarding state (mode +
    /// ifindex + linux name; the GRE analog of
    /// `wg_tombstone_respawn_coherent` minus the crypto identity).
    fn local_tunnel_tombstone_respawn_coherent(
        &self,
        id: u16,
        snapshot: &crate::ConfigSnapshot,
    ) -> bool {
        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
            return false;
        };
        if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
            return false;
        }
        let Some(name) = self
            .forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
        else {
            return false;
        };
        let Some(row) = snapshot
            .tunnel_endpoints
            .iter()
            .find(|row| row.id == id && row.ifindex > 0)
        else {
            return false;
        };
        if row.mode != endpoint.mode {
            return false;
        }
        // Attachment label mirrors forwarding_build/interfaces.rs:
        // linux_name with a fallback to the logical name when empty.
        let row_label = if row.linux_name.is_empty() {
            row.interface.as_str()
        } else {
            row.linux_name.as_str()
        };
        row.ifindex == endpoint.logical_ifindex && row_label == name
    }

    /// #1432 S2a / #1866: reconcile WG control threads against the
    /// current `forwarding.wg_engines`. Called from both initial worker
    /// bring-up AND `refresh_runtime_snapshot` (Copilot C1: a same-plan
    /// apply that adds/removes/changes a WG endpoint must not leave
    /// stale threads). Three passes, in order:
    ///
    ///   1. Finished sweep — a thread that exited (bind/TUN failure,
    ///      panic, clean stop) leaves a TOMBSTONE retaining the entry's
    ///      backoff stamp + identity (#1866 D1: a dead entry must not
    ///      permanently block respawn under an unchanged identity).
    ///   2. Stale prune — endpoint vanished, engine `Arc` address
    ///      changed, or TUN attachment changed (#1866 D5: an interface
    ///      rename with an unchanged crypto identity must restart the
    ///      thread on the new TUN) ⇒ stop + join + remove the entry.
    ///      Entries (including tombstones) are removed here and ONLY
    ///      here, so backoff state survives everything except a real
    ///      desired-set change.
    ///   3. Spawn — desired endpoints with no entry (new: immediate) or
    ///      a tombstone (respawn: gated by `WG_SPAWN_BACKOFF_NS`).
    ///
    /// An unchanged endpoint (reused engine Arc, §4.2) keeps its thread.
    ///
    /// Visibility (#1890): `pub(super)` — called from
    /// `reconcile/bringup.rs` and the armed snapshot-refresh leg,
    /// which live in sibling files of this module after the split.
    pub(super) fn spawn_wg_control_threads(&mut self) {
        self.sweep_finished_wg_control_threads();

        // Current WG engines keyed by id, with their Arc address identity.
        let mut desired: BTreeMap<u16, usize> = BTreeMap::new();
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "wireguard" {
                continue;
            }
            if let Some(engine) = self.forwarding.wg_engines.get(&endpoint.id) {
                desired.insert(endpoint.id, Arc::as_ptr(engine) as usize);
            }
        }

        // Stale prune: gone, engine Arc changed, or attachment changed.
        let mut stale: Vec<(u16, &'static str)> = Vec::new();
        for (id, entry) in self.wg_control_threads.iter() {
            let reason = match desired.get(id) {
                None => Some("removed"),
                Some(&ptr) if ptr != entry.engine_ptr => Some("engine_changed"),
                Some(_) => {
                    let attach_ok = self
                        .forwarding
                        .tunnel_endpoints
                        .get(id)
                        .is_some_and(|ep| {
                            ep.logical_ifindex == entry.spawned_ifindex
                                && self
                                    .forwarding
                                    .ifindex_to_name
                                    .get(&ep.logical_ifindex)
                                    .is_some_and(|name| *name == entry.spawned_tunnel_name)
                        });
                    if attach_ok {
                        None
                    } else {
                        Some("attachment_changed")
                    }
                }
            };
            if let Some(reason) = reason {
                stale.push((*id, reason));
            }
        }
        self.stop_remove_wg_control_entries(stale);

        // Spawn pass (apply-time only — the periodic sweep never creates
        // entries; see reconcile_wg_control_liveness).
        let now = monotonic_nanos();
        let ids: Vec<u16> = desired.keys().copied().collect();
        for id in ids {
            match self.wg_control_threads.get(&id) {
                Some(entry) if entry.handle.is_some() => continue, // live
                Some(entry)
                    if now.saturating_sub(entry.last_spawn_attempt_ns)
                        < WG_SPAWN_BACKOFF_NS =>
                {
                    continue; // tombstone within backoff
                }
                _ => {}
            }
            self.spawn_one_wg_control_thread(id);
        }
    }

    /// #1866 pass 1: join threads that already exited and tombstone
    /// their entries (keep backoff stamp + identity; never remove).
    fn sweep_finished_wg_control_threads(&mut self) {
        let finished: Vec<u16> = self
            .wg_control_threads
            .iter()
            .filter(|(_, entry)| {
                entry
                    .handle
                    .as_ref()
                    .is_some_and(|h| h.join.as_ref().is_none_or(|j| j.is_finished()))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in finished {
            if let Some(entry) = self.wg_control_threads.get_mut(&id) {
                if let Some(mut handle) = entry.handle.take() {
                    handle.request_stop();
                    if let Some(join) = handle.join.take() {
                        let _ = join.join();
                    }
                }
                eprintln!(
                    "xpf-userspace-dp: WG control thread exited endpoint={id} tun={} — tombstoned (respawn if still configured)",
                    entry.spawned_tunnel_name
                );
            }
        }
    }

    /// #1889: bulk stop + join + REMOVE. Signals ALL the listed
    /// entries' stop flags FIRST, then joins each — with the control
    /// loop blocked in poll(2) up to WG_POLL_CAP_MS, a serial
    /// stop+join per entry would cost N x ~100ms on the control-socket
    /// thread; signal-then-join bounds the whole batch at ~one cap.
    /// Used by every multi-entry stop path (stale-prune, stop-all,
    /// deferred snapshot prune).
    fn stop_remove_wg_control_entries(&mut self, batch: Vec<(u16, &str)>) {
        let mut removed: Vec<(u16, &str, super::LocalTunnelSourceHandle, String)> = Vec::new();
        for (id, reason) in batch {
            if let Some(mut entry) = self.wg_control_threads.remove(&id) {
                let name = entry.spawned_tunnel_name.clone();
                if let Some(handle) = entry.handle.take() {
                    handle.request_stop();
                    removed.push((id, reason, handle, name));
                } else {
                    eprintln!(
                        "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={name} reason={reason}"
                    );
                }
            }
        }
        for (id, reason, mut handle, name) in removed {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
            eprintln!(
                "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={name} reason={reason}"
            );
        }
    }

    /// #1866 pass 2 helper: stop + join + REMOVE one entry (live thread
    /// or tombstone). The only place entries leave the map besides
    /// `stop_inner` and the defer-branch snapshot prune. Single-entry
    /// callers only; multi-entry paths use the bulk signal-then-join
    /// helper above.
    fn stop_remove_wg_control_entry(&mut self, id: u16, reason: &str) {
        if let Some(mut entry) = self.wg_control_threads.remove(&id) {
            if let Some(mut handle) = entry.handle.take() {
                handle.request_stop();
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
            eprintln!(
                "xpf-userspace-dp: stopped WG control thread endpoint={id} tun={} reason={reason}",
                entry.spawned_tunnel_name
            );
        }
    }

    /// #1866 pass 3 helper: one spawn ATTEMPT for endpoint `id` against
    /// the CURRENT forwarding state. Records the entry (live handle or
    /// failure tombstone) with the attempt stamped either way, so a
    /// failing spawn is retried no faster than `WG_SPAWN_BACKOFF_NS`.
    /// Socket bind + TUN open happen INSIDE the spawned aux thread —
    /// never on the control-socket thread (#1866 plan §7).
    /// #2300: resolve the real OUTER (underlay) MTU the encapped WG UDP
    /// datagram egresses on, so the control-thread MTU guard uses the
    /// same source as the transit-egress guard (frame/wg.rs) instead of
    /// the old `WG_OUTER_MTU = 1500` hardcode. Route-look-up the peer
    /// endpoint IP in the endpoint's transport table and read that
    /// egress interface's MTU; fall back to `WG_DEFAULT_OUTER_MTU` when
    /// the endpoint is unconfigured (initiator-less / learn-only) or no
    /// route resolves yet.
    fn resolve_wg_outer_mtu(&self, id: u16) -> usize {
        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
            return crate::afxdp::coordinator::wg_control::WG_DEFAULT_OUTER_MTU;
        };
        // #1434: all endpoint-bearing peers on a WG interface share the
        // outer transport family (commit-gated), so the first peer that
        // declares an endpoint gives the underlay-MTU egress route. A
        // tunnel with no configured endpoint (responder-only /
        // learn-only) uses the default; the transit-egress guard applies
        // the real egress MTU for routed WG.
        let Some(peer) = endpoint.wg_peers.iter().find_map(|p| p.endpoint) else {
            return crate::afxdp::coordinator::wg_control::WG_DEFAULT_OUTER_MTU;
        };
        let table = if endpoint.transport_table.is_empty() {
            None
        } else {
            Some(endpoint.transport_table.as_str())
        };
        let resolution = lookup_forwarding_resolution_in_table_with_dynamic(
            &self.forwarding,
            self.dynamic_neighbors_ref(),
            peer.ip(),
            table,
        );
        self.forwarding
            .egress
            .get(&resolution.egress_ifindex)
            .map(|e| e.mtu)
            .filter(|m| *m > 0)
            .unwrap_or(crate::afxdp::coordinator::wg_control::WG_DEFAULT_OUTER_MTU)
    }

    fn spawn_one_wg_control_thread(&mut self, id: u16) {
        let outer_mtu = self.resolve_wg_outer_mtu(id);
        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
            return;
        };
        if endpoint.mode != "wireguard" {
            return;
        }
        let Some(engine) = self.forwarding.wg_engines.get(&id).cloned() else {
            return;
        };
        let engine_ptr = Arc::as_ptr(&engine) as usize;
        let Some(tunnel_name) = self
            .forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
            .cloned()
        else {
            return;
        };
        let spawned_ifindex = endpoint.logical_ifindex;
        let listen_port = endpoint.wg_listen_port;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let recent_exceptions = self.recent_exceptions.clone();
        let thread_tunnel_name = tunnel_name.clone();
        eprintln!(
            "xpf-userspace-dp: spawning WG control thread endpoint={id} tun={tunnel_name} port={listen_port}"
        );
        let join = spawn_supervised_aux(
            format!("xpf-wg-control-{tunnel_name}"),
            move || {
                wg_control::wg_control_loop(
                    thread_tunnel_name,
                    id,
                    engine,
                    listen_port,
                    outer_mtu,
                    recent_exceptions,
                    stop_clone,
                );
            },
        );
        let handle = match join {
            Ok(join) => Some(LocalTunnelSourceHandle {
                stop,
                // #2412: the WG control thread polls its UDP socket with
                // its own timeout cap and has no delivery eventfd.
                wake: None,
                join: Some(join),
            }),
            Err(err) => {
                if let Ok(mut recent) = self.recent_exceptions.lock() {
                    push_recent_exception(
                        &mut recent,
                        ExceptionStatus {
                            timestamp: Utc::now(),
                            interface: tunnel_name.clone(),
                            reason: format!("spawn_wg_control_failed:{id}:{err}"),
                            ..ExceptionStatus::default()
                        },
                    );
                }
                eprintln!(
                    "xpf-userspace-dp: WG control thread spawn FAILED endpoint={id}: {err}"
                );
                None
            }
        };
        self.wg_control_threads.insert(
            id,
            WgControlEntry {
                handle,
                engine_ptr,
                spawned_ifindex,
                spawned_tunnel_name: tunnel_name,
                last_spawn_attempt_ns: monotonic_nanos(),
            },
        );
    }

    /// #1866 Change 2: periodic self-heal, called from the server's
    /// `refresh_status` ONLY while `should_run_afxdp` holds. TOMBSTONE-
    /// ONLY and SNAPSHOT-COHERENT:
    ///
    ///   - never creates entries for ids absent from the map (entry
    ///     creation belongs to the apply path, where `self.forwarding`
    ///     and the snapshot are coherent by construction — the desired
    ///     set here can be STALE during a defer_workers window);
    ///   - a tombstone respawns only past `WG_SPAWN_BACKOFF_NS` AND only
    ///     when the latest STORED snapshot's row for the id is
    ///     identity-identical and attachment-identical to the forwarding
    ///     endpoint the spawn would use (a sweep must never start a
    ///     thread the latest accepted snapshot does not describe);
    ///   - at most one spawn attempt per invocation.
    pub(crate) fn reconcile_wg_control_liveness(
        &mut self,
        latest_snapshot: Option<&crate::ConfigSnapshot>,
    ) {
        self.sweep_finished_wg_control_threads();
        let Some(snapshot) = latest_snapshot else {
            return;
        };
        let now = monotonic_nanos();
        let tombstones: Vec<u16> = self
            .wg_control_threads
            .iter()
            .filter(|(_, entry)| entry.handle.is_none())
            .map(|(id, _)| *id)
            .collect();
        for id in tombstones {
            let Some(entry) = self.wg_control_threads.get(&id) else {
                continue;
            };
            if now.saturating_sub(entry.last_spawn_attempt_ns) < WG_SPAWN_BACKOFF_NS {
                continue;
            }
            if !self.wg_tombstone_respawn_coherent(id, snapshot) {
                continue;
            }
            self.spawn_one_wg_control_thread(id);
            break; // ≤1 spawn attempt per invocation
        }
    }

    /// #1866: whether a tombstone respawn for `id` is coherent — the
    /// latest stored snapshot must describe EXACTLY the thread the
    /// spawn would create from the current forwarding state (crypto
    /// identity via the shared `hydrate_wg_identity` gates, Codex r3;
    /// TUN attachment via ifindex + linux name, Codex r4).
    fn wg_tombstone_respawn_coherent(
        &self,
        id: u16,
        snapshot: &crate::ConfigSnapshot,
    ) -> bool {
        let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
            return false;
        };
        if endpoint.mode != "wireguard" || !self.forwarding.wg_engines.contains_key(&id) {
            return false;
        }
        let Some(name) = self
            .forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
        else {
            return false;
        };
        let Some(row) = snapshot
            .tunnel_endpoints
            .iter()
            .find(|row| row.id == id && row.ifindex > 0)
        else {
            return false;
        };
        let Some(identity) = hydrate_wg_identity(row) else {
            return false;
        };
        // Attachment label mirrors forwarding_build/interfaces.rs:
        // linux_name with a fallback to the logical name when empty.
        let row_label = if row.linux_name.is_empty() {
            row.interface.as_str()
        } else {
            row.linux_name.as_str()
        };
        identity.matches_endpoint(endpoint)
            && row.ifindex == endpoint.logical_ifindex
            && row_label == name
    }

    /// #1866 (PR-review Codex r1 F1): stop + join + remove ALL WG
    /// control-thread entries (live and tombstoned). Used by the
    /// same-plan apply leg when the helper is disarmed
    /// (`should_run_afxdp` false): `refresh_runtime_snapshot`
    /// reconciles WG threads for the running case, but a disarmed
    /// helper must not hold WG listen ports — mirror the
    /// `reconcile_status_bindings → stop()` semantics.
    pub(crate) fn stop_all_wg_control_threads(&mut self, reason: &str) {
        let batch: Vec<(u16, &str)> = self
            .wg_control_threads
            .keys()
            .map(|id| (*id, reason))
            .collect();
        self.stop_remove_wg_control_entries(batch);
    }

    /// #1866 Change 2b (defect D4): removal propagation on the
    /// defer-workers apply path. The NOT-same-plan + defer_workers
    /// branch stores the snapshot WITHOUT reconciling, so
    /// `self.forwarding` (and therefore the ordinary desired set) goes
    /// stale — a removed WG endpoint's thread would keep its UDP port
    /// until the deferred bring-up. This narrow prune stops + joins +
    /// removes entries whose endpoint id is absent from (or no longer a
    /// hydratable WG endpoint in) the new snapshot, mirroring the
    /// populate gates via `hydrate_wg_identity`. It does NOT spawn,
    /// does NOT touch `self.forwarding`, and does NOT mutate any
    /// worker-visible state.
    pub(crate) fn prune_wg_control_threads_for_snapshot(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
    ) {
        let desired: std::collections::BTreeSet<u16> = snapshot
            .tunnel_endpoints
            .iter()
            .filter(|row| row.id != 0 && row.ifindex > 0 && hydrate_wg_identity(row).is_some())
            .map(|row| row.id)
            .collect();
        let stale: Vec<(u16, &str)> = self
            .wg_control_threads
            .keys()
            .filter(|id| !desired.contains(id))
            .map(|id| (*id, "removed_deferred"))
            .collect();
        self.stop_remove_wg_control_entries(stale);
    }
}
