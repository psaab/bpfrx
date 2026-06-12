//! #1890: runtime-snapshot refresh, split out of `coordinator/mod.rs`
//! (pure code motion). Owns the armed/disarmed snapshot-apply legs
//! (`refresh_runtime_snapshot{,_disarmed,_inner}`) — preflight policy
//! validation, manager-neighbor key rotation, the #1873 tunnel-remap
//! purge, the forwarding-state swap + worker-visible stores, the WG/GRE
//! aux-thread reconcile or disarmed stop, and the post-apply CoS
//! owner-map + neighbor-warm passes — plus `refresh_fabric_links`
//! (the SyncFabricState path). The shared purge/log free helpers it
//! calls (`tunnel_remap_purge_ids`, `log_wg_endpoint_set_transition`)
//! stay in mod.rs: `reconcile/snapshot.rs` and tests outside this
//! module reference them at coordinator scope.
use super::*;

impl super::Coordinator {
    /// Refresh fabric link info from updated snapshots. Called when the
    /// Go daemon's refreshFabricFwd resolves a peer MAC that wasn't
    /// available at initial snapshot build time.
    ///
    /// This updates both the coordinator's local forwarding state and the
    /// shared Arc-backed state used by workers, so refreshed fabric links
    /// become visible to workers as soon as the new values are published.
    pub fn refresh_fabric_links(&mut self, snapshots: &[crate::FabricSnapshot]) {
        let new_fabrics = resolve_fabric_links_from_snapshots(
            snapshots,
            &self.forwarding.egress,
            &self.neighbors.dynamic,
        );
        if !new_fabrics.is_empty() {
            self.forwarding.fabrics = new_fabrics.clone();
            self.ha.fabrics.store(Arc::new(new_fabrics));
            // Also update shared_forwarding so workers see the new fabric
            // links for fabric redirect resolution. Without this, workers
            // use the snapshot's forwarding state which may have empty fabrics
            // if the peer MAC wasn't resolved at snapshot time.
            self.ha.forwarding.store(Arc::new(self.forwarding.clone()));
        }
    }

    pub fn refresh_runtime_snapshot(&mut self, snapshot: &crate::ConfigSnapshot) {
        self.refresh_runtime_snapshot_inner(snapshot, true);
    }

    /// #1866 (PR-review Codex r2): runtime-snapshot refresh for a
    /// DISARMED helper (`should_run_afxdp` false). Identical to
    /// `refresh_runtime_snapshot` EXCEPT it never spawns WG control
    /// threads — a disarmed helper must not transiently bind WG listen
    /// ports or emit handshake initiations; instead any existing
    /// entries are stopped (mirrors `reconcile_status_bindings →
    /// stop()`). Forwarding/validation state still refreshes so a
    /// later arming starts from current state.
    pub fn refresh_runtime_snapshot_disarmed(&mut self, snapshot: &crate::ConfigSnapshot) {
        self.refresh_runtime_snapshot_inner(snapshot, false);
    }

    fn refresh_runtime_snapshot_inner(
        &mut self,
        snapshot: &crate::ConfigSnapshot,
        spawn_wg: bool,
    ) {
        // #1606: preflight policy validation BEFORE any
        // side-effecting mutation (neighbor manager keys,
        // validation, policy_counters). If integrity errors fire,
        // keep ALL existing state.
        //
        // CRITICAL (Codex code-review F2): use a SCRATCH counter
        // store for the preflight so we don't leak counter
        // registry entries on rejected snapshots.
        let preflight_counters = crate::policy::PolicyCounterStore::default();
        if let Err(err) = crate::policy::parse_policy_state_with_counters(
            &snapshot.default_policy,
            &snapshot.policies,
            &self.forwarding.zone_name_to_id,
            &snapshot.address_books,
            &preflight_counters,
        ) {
            eprintln!(
                "xpf-userspace-dp: snapshot integrity error during refresh_runtime_snapshot preflight: {} — keeping previous state",
                err
            );
            return;
        }

        let next_manager_keys = snapshot
            .neighbors
            .iter()
            .filter_map(|neigh| {
                if neigh.ifindex <= 0
                    || !neighbor_state_usable_str(&neigh.state)
                    || neigh.mac.is_empty()
                    || parse_mac_str(&neigh.mac).is_none()
                {
                    return None;
                }
                neigh
                    .ip
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (neigh.ifindex, ip))
            })
            .collect::<FastSet<_>>();
        let old_manager_keys = if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            let old = manager_keys.iter().copied().collect::<Vec<_>>();
            *manager_keys = next_manager_keys;
            old
        } else {
            Vec::new()
        };
        // #949: bulk-remove stale manager keys atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for key in &old_manager_keys {
                bulk.remove(key);
            }
        });
        // #1873 R-D (Codex code r3): captured BEFORE the overwrite —
        // gates the new-appearance purge arm below. False only when no
        // coordinator apply has ever installed a snapshot (disarmed
        // helper pre-first-arm), where boot-time synced sessions must
        // not be purged as "new appearances" against a default state.
        let prior_snapshot_installed = self.validation.snapshot_installed;
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        // Preserve existing fabric links — they are resolved separately
        // via refresh_fabric_links (SyncFabricState) and the snapshot
        // may not include them if the peer MAC wasn't resolved at
        // snapshot build time. Always keep the better-resolved set.
        let preserved_fabrics = self.forwarding.fabrics.clone();
        // #1606: preflight policy build. If integrity errors fire,
        // keep the existing forwarding state.
        let new_forwarding = match build_forwarding_state_with_policy_counters_and_previous(
            snapshot,
            &self.policy_counters,
            Some(&self.forwarding),
        ) {
            Ok(fwd) => fwd,
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: snapshot integrity error during runtime-snapshot refresh: {} — keeping previous forwarding state",
                    err
                );
                return;
            }
        };
        self.policy_counters.reconcile_rules(&snapshot.policies);
        // #1866 D3: WG endpoint-set transition log at the Rust apply
        // boundary. Rare (only when the set actually changes); pairs
        // with the Go publish-boundary log to pin which layer dropped
        // or retained an endpoint in one journal capture.
        log_wg_endpoint_set_transition("snapshot-refresh", &self.forwarding, &new_forwarding);
        // #1873 R-D: compute the remap purge set BEFORE the swap, and
        // PURGE before any store (Codex code-review r1). The worker
        // loop reads the forwarding Arc, drains commands, THEN runs the
        // RX sweep — so a worker that observes the new state in
        // iteration N drains these DeleteSynced commands in the same
        // iteration before processing a single packet with it. The
        // purge is CLEANUP (shared maps, worker tables, HA delete
        // propagation), not the correctness boundary: a stale session
        // that escapes any purge window can never mis-encapsulate,
        // because re-resolution and the encap builders refuse an id
        // whose owning netdev ifindex differs from the one stored in
        // the session's resolution (Codex code-review r2 — the r1
        // rotation-barrier approach was unsound: workers can hold
        // private fabric-overlay Arc clones, and a barrier timeout was
        // fail-open).
        // New-appearance purging is gated on a previously-installed
        // snapshot (Codex code r3): a DISARMED helper stores synced
        // sessions before its first coordinator apply (reconcile never
        // ran — `self.forwarding` is still default), so a same-plan
        // disarmed refresh would otherwise see every configured id as
        // "new" and wipe those boot-time entries.
        let tunnel_purge_ids = tunnel_remap_purge_ids(
            &self.forwarding,
            &new_forwarding,
            prior_snapshot_installed,
        );
        self.purge_remapped_tunnel_sessions(&tunnel_purge_ids);
        self.forwarding = new_forwarding;
        if self.forwarding.fabrics.is_empty() && !preserved_fabrics.is_empty() {
            self.forwarding.fabrics = preserved_fabrics;
        } else if !preserved_fabrics.is_empty() {
            // Merge: for each preserved fabric, if the new snapshot
            // doesn't have a matching parent_ifindex, keep the old one.
            for old in &preserved_fabrics {
                if !self
                    .forwarding
                    .fabrics
                    .iter()
                    .any(|f| f.parent_ifindex == old.parent_ifindex)
                {
                    self.forwarding.fabrics.push(*old);
                }
            }
        }
        self.shared_validation.store(Arc::new(self.validation));
        self.ha.forwarding.store(Arc::new(self.forwarding.clone()));
        // #1432 S2a (Copilot C1): reconcile WG control threads on every
        // runtime-snapshot refresh, not just initial bring-up, so a
        // same-plan apply that adds/removes/changes a WG endpoint starts,
        // stops, or restarts the matching UDP/TUN control thread.
        // #1866 (Codex code-r2): NEVER on a disarmed helper — not even
        // transiently (the control loop binds + may emit an initiation
        // before its first stop check); stop anything present instead.
        if spawn_wg {
            self.spawn_wg_control_threads();
            // #1881: reconcile GRE local-origin threads on every armed
            // runtime-snapshot refresh — tunnel interfaces are excluded
            // from the binding plan, so tunnel add/remove/reattach
            // commits reach ONLY this path. Runs AFTER the forwarding
            // swap + ha.forwarding.store above (same position as the WG
            // reconcile): pass decisions and a fresh thread's first
            // load_full() see the new state, and the store-to-join
            // window is covered by the thread-side rotation gate
            // (tunnel.rs endpoint_attachment_valid, plan D.1b).
            self.reconcile_local_tunnel_sources();
        } else {
            self.stop_all_wg_control_threads("disarmed");
            // #1881: a disarmed helper must not hold GRE TUN reader
            // fds either (mirrors the WG rule; in practice a no-op —
            // reconcile_status_bindings → stop() already cleared them).
            self.stop_all_local_tunnel_sources("disarmed");
        }
        self.refresh_cos_owner_worker_map_from_identities();
        self.ha
            .fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
        // #1636 option C: proactively warm configured next-hops so the
        // neighbor cache is hot before the first user flow. Non-forced:
        // the 1s snapshot-level rate-limit coalesces config storms.
        self.queue_warm_pass(false);
    }
}
