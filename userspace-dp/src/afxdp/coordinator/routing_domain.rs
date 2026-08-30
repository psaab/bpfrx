//! #7160 (#2387) — routing-domain readers on the coordinator.
//!
//! Split out of `coordinator/mod.rs` to keep that file under the modularity
//! floor. Both answer a question a peer-synced session cannot answer for
//! itself: which routing domain to key it under on THIS node, and which
//! domains a bare-5-tuple delete has to sweep. Bodies are byte-identical to
//! their prior location in `mod.rs`.

use super::*;

impl Coordinator {
    /// #7160 (#2387): every non-zero routing DOMAIN this config defines, for
    /// the delete path.
    ///
    /// A Go "delete" request built from a bare 5-tuple (the `clear security
    /// flow session` / batch-revoke path, `deleteHelperSessionsV4`) carries no
    /// ingress identity, so `synced_routing_domain` resolves 0 for it and an
    /// exact-key delete would MISS a session that lives in a routing instance
    /// — leaving a stale entry the operator was told had been cleared. The
    /// handler therefore retries the delete once per configured domain.
    ///
    /// The set is the number of routing instances with member interfaces, i.e.
    /// a handful, and the delete path is a slow path. `has_routing_domains`
    /// false (every single-instance deployment) makes this an empty vec and the
    /// retry loop disappears.
    /// Test seam: how many entries the shared synced-session map holds. The
    /// map is `pub(in crate::afxdp)`, so a `server::tests` cell that drives the
    /// real control-socket delete cannot read the outcome directly.
    #[cfg(test)]
    pub(crate) fn synced_session_entry_count_for_test(&self) -> usize {
        // #6653: a shared-session surface is locked through the recover helper,
        // never bare, so a worker that panicked under this mutex cannot make
        // the read silently report "empty" instead of recovering. The audit in
        // `ha_tests.rs` enforces that on every non-test file under `afxdp/`,
        // and this file is not one — the seam is `#[cfg(test)]`, the FILE is
        // production.
        crate::afxdp::shared_ops::lock_shared_recover(&self.sessions.synced).len()
    }

    /// Test seam: declare an interface a routing-instance member without
    /// building a whole `ConfigSnapshot`. The two fields are
    /// `pub(in crate::afxdp)`, so a `server::tests` cell that needs a
    /// domain-carrying coordinator cannot set them directly.
    #[cfg(test)]
    pub(crate) fn seed_routing_domain_for_test(&mut self, ifindex: i32, domain: u32) {
        self.forwarding.has_routing_domains = true;
        self.forwarding
            .ifindex_to_routing_domain
            .insert(ifindex, domain);
    }

    pub fn routing_domains(&self) -> Vec<u32> {
        if !self.forwarding.has_routing_domains {
            return Vec::new();
        }
        let mut out: Vec<u32> = self
            .forwarding
            .ifindex_to_routing_domain
            .values()
            .copied()
            .filter(|d| *d != 0)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// #7160 (#2387): the routing DOMAIN a peer-synced session should be keyed
    /// under on THIS node, resolved from the LOCAL ingress identity #7095
    /// already carries across the cluster wire.
    ///
    /// The domain is NOT sent as its own wire field, and that is deliberate.
    /// It is a pure function of the flow's ingress interface and the config,
    /// both HA nodes run identical config, and #7095 already resolves the
    /// peer's cluster-stable ingress name into THIS node's own ifindex/vlan
    /// before the request reaches here. Sending the number as well would be a
    /// second spelling of one fact, and the two could disagree — which is the
    /// failure mode a derived value cannot have.
    ///
    /// A session whose ingress identity the peer could not name (fabric-
    /// redirected, #7096; no cluster-stable name) arrives with ifindex 0 and
    /// resolves to domain 0. That is the pre-#7160 identity, so such a session
    /// imports exactly as it did before; the cost is that its flow
    /// re-adjudicates through policy after a failover instead of being taken
    /// over, which is a correctness-preserving degradation, not a bypass.
    pub fn synced_routing_domain(&self, ingress_ifindex: i32, ingress_vlan_id: u16) -> Option<u32> {
        // No routing instances configured: 0 is not a fallback here, it is the
        // ONLY domain that exists, and it is the right answer for every
        // session. Returned as `Some` so a single-instance node never refuses
        // an import — its behaviour must stay bit-identical to pre-#7160.
        if !self.forwarding.has_routing_domains {
            return Some(0);
        }
        // Routing instances DO exist and the request named no ingress identity
        // to resolve one from. This is the third state, and collapsing it into
        // `Some(0)` is the bug: 0 means THE DEFAULT ROUTING INSTANCE, so a
        // tenant's session would be filed in another tenant's identity space
        // and reachable from it. The caller must refuse, not default.
        if ingress_ifindex <= 0 {
            return None;
        }
        Some(crate::afxdp::forwarding::ingress_routing_domain(
            &self.forwarding,
            ingress_ifindex,
            ingress_vlan_id,
            None,
        ))
    }

    /// #7160 (#2387): count one import refused for an unresolvable routing
    /// domain. Separate from the refusal itself because the refusal is decided
    /// in the control-socket handler, where the request's ingress identity is,
    /// while the counter lives with its siblings on the session manager.
    pub fn note_unknown_routing_domain_import(&self) {
        self.sessions
            .import_unknown_routing_domain
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
