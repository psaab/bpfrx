//! RFC 2637 PPTP call associations (#7699, stage 1).
//!
//! # Why this table exists
//!
//! A PPTP GRE data packet carries the Call ID **of the peer it is being sent
//! to** (RFC 2637 §4.1), and each side allocates its own during the
//! control-connection exchange. So the two directions of ONE call carry
//! DIFFERENT values, and no transform of a single packet can pair them —
//! `reverse_wire_key` and friends apply a symmetric swap, which is right for a
//! TCP port pair and for an RFC 2890 Key (one value, both directions) and wrong
//! here.
//!
//! That is why [`TunnelDiscriminator::Pptp`] carries a locally-derived **call
//! handle** rather than the value off the packet: both directions of one call
//! resolve through this table to the same handle, which makes the class
//! direction-symmetric like every other and lets a reply match the stored
//! reverse companion. The alternative — a discriminator built from the packet's
//! own call ID — makes the reply match NO session at all, which is strictly
//! worse than the aliasing it would replace (#8382, closed for this reason).
//!
//! # Why the handle is derived, not allocated
//!
//! HA session sync is session-oriented: a flat per-session record with no
//! auxiliary-table mechanism. A standby that receives a PPTP session but not
//! the association holds a session it can never match a packet against, because
//! it cannot compute the handle. So the association must reach the standby
//! under ANY handle scheme.
//!
//! Given that, a handle **derived** from the association is strictly better
//! than a node-local one: both nodes compute the same value from the same
//! association, so there is no import-time translation table to drift. The
//! derivation is written out explicitly rather than delegated to a std hasher,
//! because it must be stable across processes, builds and nodes — a property
//! std's hashers do not promise.

use std::net::IpAddr;

use rustc_hash::FxHashMap;

/// A learned PPTP call: the two peers and the call ID each ALLOCATED.
///
/// Stored canonically (lower IP first) so the two directions of one call
/// produce one association and one handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PptpCall {
    lo: IpAddr,
    hi: IpAddr,
    /// Call ID allocated BY the peer at `lo` — so it appears in packets sent TO
    /// `lo`, i.e. those whose destination is `lo`.
    lo_call_id: u16,
    /// Call ID allocated BY the peer at `hi`.
    hi_call_id: u16,
}

impl PptpCall {
    /// Build the canonical association from the two `(peer, call-id-it
    /// allocated)` halves, in either argument order.
    pub(crate) fn new(a: IpAddr, a_call_id: u16, b: IpAddr, b_call_id: u16) -> Self {
        if (a, a_call_id) <= (b, b_call_id) {
            Self { lo: a, hi: b, lo_call_id: a_call_id, hi_call_id: b_call_id }
        } else {
            Self { lo: b, hi: a, lo_call_id: b_call_id, hi_call_id: a_call_id }
        }
    }

    /// The deterministic call handle.
    ///
    /// FNV-1a over the canonical association, written out so it is auditable
    /// and provably identical on both nodes. Never returns 0: a zero handle
    /// would encode as the bare PPTP wire tag, and reserving it keeps "handle
    /// zero" from colliding with any future use of a bare tag.
    pub(crate) fn handle(&self) -> u32 {
        const OFFSET: u32 = 0x811c_9dc5;
        const PRIME: u32 = 0x0100_0193;
        let mut h = OFFSET;
        let mut eat = |bytes: &[u8]| {
            for b in bytes {
                h ^= u32::from(*b);
                h = h.wrapping_mul(PRIME);
            }
        };
        match self.lo {
            IpAddr::V4(v4) => { eat(&[4]); eat(&v4.octets()); }
            IpAddr::V6(v6) => { eat(&[6]); eat(&v6.octets()); }
        }
        match self.hi {
            IpAddr::V4(v4) => { eat(&[4]); eat(&v4.octets()); }
            IpAddr::V6(v6) => { eat(&[6]); eat(&v6.octets()); }
        }
        eat(&self.lo_call_id.to_be_bytes());
        eat(&self.hi_call_id.to_be_bytes());
        if h == 0 { 1 } else { h }
    }
}

/// Why an association was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PptpInstallError {
    /// A DIFFERENT association already derived this handle.
    ///
    /// Fail closed, matching the posture of every other derived-name collision
    /// in this tree (#5277 composed route-maps, #5116 redistribute aliases,
    /// #7625 the reserved deny name): refuse rather than let two calls share an
    /// identity, which is the exact collapse this class exists to prevent.
    HandleCollision { existing: PptpCall, handle: u32 },
}

/// The learned associations, indexed for packet resolution.
#[derive(Default)]
pub(crate) struct PptpAssociations {
    /// `(allocator, call-id it allocated) -> handle`.
    ///
    /// A packet is keyed on its DESTINATION, because the Call ID it carries
    /// belongs to the peer it is being sent to. Two entries per call — one per
    /// peer — which is what makes both directions resolve to one handle.
    by_allocator: FxHashMap<(IpAddr, u16), u32>,
    /// `handle -> association`, for teardown and for collision detection.
    by_handle: FxHashMap<u32, PptpCall>,
    /// Version-1 packets that resolved to no association.
    ///
    /// **Expected non-zero during startup and after a restart**, and after any
    /// event that loses control-channel state: the association is learned from
    /// the control channel, so data packets legitimately arrive before it. This
    /// counter is a "PPTP is running unattributed" signal, NOT an error rate,
    /// and reading it as one is how a routinely non-zero counter gets ignored.
    unassociated: u64,
}

impl PptpAssociations {
    /// Learn a call. Idempotent for an identical association.
    pub(crate) fn install(&mut self, call: PptpCall) -> Result<u32, PptpInstallError> {
        let handle = call.handle();
        match self.by_handle.get(&handle) {
            Some(existing) if *existing == call => return Ok(handle),
            Some(existing) => {
                return Err(PptpInstallError::HandleCollision { existing: *existing, handle });
            }
            None => {}
        }
        self.by_handle.insert(handle, call);
        self.by_allocator.insert((call.lo, call.lo_call_id), handle);
        self.by_allocator.insert((call.hi, call.hi_call_id), handle);
        Ok(handle)
    }

    /// Resolve a data packet to its call handle.
    ///
    /// `dst` is the packet's destination and `call_id` the value in its GRE
    /// header — which the sender set to the value the DESTINATION allocated.
    /// `None` means unassociated; the caller forwards and counts rather than
    /// dropping (see [`Self::note_unassociated`]).
    pub(crate) fn resolve(&self, dst: IpAddr, call_id: u16) -> Option<u32> {
        self.by_allocator.get(&(dst, call_id)).copied()
    }

    /// Forget a call, by handle. Returns whether anything was removed.
    pub(crate) fn remove(&mut self, handle: u32) -> bool {
        let Some(call) = self.by_handle.remove(&handle) else {
            return false;
        };
        self.by_allocator.remove(&(call.lo, call.lo_call_id));
        self.by_allocator.remove(&(call.hi, call.hi_call_id));
        true
    }

    /// Count a version-1 packet that resolved to nothing.
    pub(crate) fn note_unassociated(&mut self) {
        self.unassociated = self.unassociated.saturating_add(1);
    }

    pub(crate) fn unassociated_count(&self) -> u64 {
        self.unassociated
    }

    pub(crate) fn len(&self) -> usize {
        self.by_handle.len()
    }

    /// Force an association in at a CHOSEN handle, so the collision arm is
    /// reachable from a test.
    ///
    /// FNV-1a collisions are not constructible by hand, so without this seam
    /// `PptpInstallError::HandleCollision` would be an untested fail-closed
    /// path — the shape that quietly rots into a fail-open one. Test-only.
    #[cfg(test)]
    pub(crate) fn force_handle_for_test(&mut self, call: PptpCall, handle: u32) {
        self.by_handle.insert(handle, call);
        self.by_allocator.insert((call.lo, call.lo_call_id), handle);
        self.by_allocator.insert((call.hi, call.hi_call_id), handle);
    }
}

#[cfg(test)]
mod tests_7699 {
    use super::*;
    use crate::session::TunnelDiscriminator;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// THE PROPERTY THE WHOLE DESIGN EXISTS FOR: both directions of one call
    /// resolve to the SAME handle.
    ///
    /// A→B carries the call ID B allocated; B→A carries the one A allocated.
    /// They are different values, and a discriminator built from either would
    /// differ per direction — which is why #8382 was closed. Resolving through
    /// the association makes the class direction-symmetric.
    #[test]
    fn both_directions_of_one_call_resolve_to_one_handle_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let (a_id, b_id) = (0x1111u16, 0x2222u16);
        let mut t = PptpAssociations::default();
        let handle = t.install(PptpCall::new(a, a_id, b, b_id)).expect("install");

        // A→B carries B's call id, so it is keyed on the destination B.
        assert_eq!(
            t.resolve(b, b_id),
            Some(handle),
            "the A->B direction must resolve to the call handle"
        );
        // B→A carries A's call id, keyed on destination A.
        assert_eq!(
            t.resolve(a, a_id),
            Some(handle),
            "the B->A direction must resolve to the SAME handle; if these two \
             differ, the reply is looked up under a key the forward session's \
             reverse companion does not equal and it matches NO session"
        );
    }

    /// Criterion 2: two simultaneous calls between the SAME endpoints must not
    /// alias. This is the case that motivated the whole issue.
    #[test]
    fn two_calls_between_one_endpoint_pair_get_distinct_handles_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let mut t = PptpAssociations::default();
        let h1 = t.install(PptpCall::new(a, 0x1001, b, 0x2001)).expect("call 1");
        let h2 = t.install(PptpCall::new(a, 0x1002, b, 0x2002)).expect("call 2");
        assert_ne!(
            h1, h2,
            "two calls between one endpoint pair shared a handle, so they share \
             a session: one policy decision, one NAT state, one counter set"
        );
        assert_eq!(t.resolve(b, 0x2001), Some(h1));
        assert_eq!(t.resolve(b, 0x2002), Some(h2));
    }

    /// The handle must depend on EVERY component, varied ONE AT A TIME.
    ///
    /// This cell exists because the two-calls cell below could not see it. That
    /// fixture varies both call IDs together, so a handle that ignored one of
    /// them still separated the two calls and the cell stayed green — an
    /// escaped mutation found by dropping `hi_call_id` from the derivation.
    ///
    /// A handle blind to one component collides for every pair of calls that
    /// differ only in it, which is two calls sharing one session: the exact
    /// collapse this class exists to prevent. Varying one axis at a time is the
    /// only shape that catches it.
    #[test]
    fn the_handle_depends_on_every_component_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let base = PptpCall::new(a, 0x1111, b, 0x2222);
        let h = base.handle();

        for (what, other) in [
            ("the call id allocated by A", PptpCall::new(a, 0x9999, b, 0x2222)),
            ("the call id allocated by B", PptpCall::new(a, 0x1111, b, 0x9999)),
            ("peer A's address", PptpCall::new(ip("198.51.100.8"), 0x1111, b, 0x2222)),
            ("peer B's address", PptpCall::new(a, 0x1111, ip("203.0.113.10"), 0x2222)),
        ] {
            assert_ne!(
                h,
                other.handle(),
                "the handle ignores {what}: two calls differing only in it would \
                 share one handle, and therefore one session"
            );
        }
    }

    /// The handle must be a pure function of the association — same value from
    /// either argument order, and from a freshly built table.
    ///
    /// This is what lets both HA nodes compute it without a translation table,
    /// which is the reason it is derived rather than allocated.
    #[test]
    fn the_handle_is_deterministic_and_order_independent_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let forward = PptpCall::new(a, 0x1111, b, 0x2222);
        let reversed = PptpCall::new(b, 0x2222, a, 0x1111);
        assert_eq!(
            forward, reversed,
            "the association must canonicalize, or the two peers store two rows \
             for one call"
        );
        assert_eq!(
            forward.handle(),
            reversed.handle(),
            "the handle must not depend on which peer's half was seen first — \
             the standby derives it from the synced association, not from the \
             order the active happened to learn it in"
        );
    }

    /// FAIL CLOSED on a handle collision, matching #5277 / #5116 / #7625.
    ///
    /// Reached through a test seam because FNV-1a collisions are not
    /// constructible by hand. Without the seam this arm would be untested, and
    /// an untested fail-closed path is the one that quietly becomes fail-open.
    #[test]
    fn a_handle_collision_is_refused_not_merged_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let squatter = PptpCall::new(a, 0x1001, b, 0x2001);
        let victim = PptpCall::new(a, 0x3003, b, 0x4004);
        let handle = victim.handle();

        let mut t = PptpAssociations::default();
        t.force_handle_for_test(squatter, handle);

        match t.install(victim) {
            Err(PptpInstallError::HandleCollision { existing, handle: h }) => {
                assert_eq!(existing, squatter);
                assert_eq!(h, handle);
            }
            other => panic!(
                "a colliding association must be REFUSED, not merged; two calls \
                 sharing one handle share one session, which is the collapse \
                 this class exists to prevent. Got {other:?}"
            ),
        }
        // NEGATIVE CONTROL, on a CLEAN table: re-installing the identical
        // association is idempotent, not a collision — otherwise a re-learn on
        // a retransmitted control message would refuse a call that is already
        // correct, and the guard would be indistinguishable from one that
        // refuses everything.
        //
        // It must not reuse the forced table above: `squatter` was planted at
        // VICTIM's handle there, so installing it would go to its own handle
        // and the assertion would be about the seam rather than about
        // idempotence.
        let mut clean = PptpAssociations::default();
        let first = clean.install(squatter).expect("first install");
        assert_eq!(
            clean.install(squatter),
            Ok(first),
            "re-learning an identical association must be idempotent"
        );
        assert_eq!(clean.len(), 1, "idempotent re-install must not add a row");
    }

    /// The unassociated path: resolve to nothing, count, and do NOT drop.
    ///
    /// The counter is expected non-zero at startup and after a restart — data
    /// packets legitimately precede the control channel — so it is a "running
    /// unattributed" signal, not an error rate.
    #[test]
    fn an_unassociated_packet_resolves_to_none_and_is_counted_7699() {
        let mut t = PptpAssociations::default();
        assert_eq!(t.resolve(ip("203.0.113.9"), 0x2222), None);
        assert_eq!(t.unassociated_count(), 0, "resolve must not itself count");
        t.note_unassociated();
        t.note_unassociated();
        assert_eq!(t.unassociated_count(), 2);
    }

    /// Teardown must remove BOTH allocator entries.
    ///
    /// Leaving one behind is the mis-attribution hazard: PPTP call IDs are
    /// 16-bit and REUSED, so a stale half-entry pairs a future call onto a dead
    /// handle. Asserted per direction, because removing only the direction the
    /// teardown arrived on would pass a single-direction check.
    #[test]
    fn removing_a_call_clears_both_directions_7699() {
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let mut t = PptpAssociations::default();
        let handle = t.install(PptpCall::new(a, 0x1111, b, 0x2222)).expect("install");
        assert!(t.remove(handle));
        assert_eq!(t.resolve(a, 0x1111), None, "A-side entry survived teardown");
        assert_eq!(t.resolve(b, 0x2222), None, "B-side entry survived teardown");
        assert_eq!(t.len(), 0);
        assert!(!t.remove(handle), "a second remove must report nothing removed");
    }

    /// The end-to-end property: a session keyed on a PPTP handle has a reverse
    /// companion keyed on the SAME handle, so a reply matches it.
    ///
    /// This is the assertion #8382 could not make, and the reason that slice
    /// was closed rather than landed.
    #[test]
    fn a_pptp_session_reverse_companion_keeps_the_handle_7699() {
        let call = PptpCall::new(ip("198.51.100.7"), 0x1111, ip("203.0.113.9"), 0x2222);
        let handle = call.handle();
        let disc = TunnelDiscriminator::Pptp(handle);
        assert_eq!(
            crate::session::key::reverse_direction_discriminator_for_test(disc),
            disc,
            "the reverse companion must carry the same handle; if this ever \
             transforms, a reply is looked up under a key the stored companion \
             does not equal and matches no session at all"
        );
    }
}
