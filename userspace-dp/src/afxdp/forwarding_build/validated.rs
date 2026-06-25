//! #2410: validated narrowing newtypes for the forwarding-build trust
//! boundary.
//!
//! The Go control plane is the primary validator, but the Rust
//! forwarding-build conversion is the SECOND trust boundary: it must not
//! silently build a DIFFERENT config from a bad / mixed-version snapshot.
//! These newtypes decode a control-plane integer ONCE, with a checked
//! `try_*` conversion that returns a typed
//! [`crate::policy::SnapshotIntegrityError`] on an out-of-range value —
//! instead of the pre-fix unchecked `as` cast that silently WRAPPED
//! (`vlan 65537 → 1`, `ttl 256 → 0`) or the `filter_map` range check that
//! silently DROPPED an out-of-range CoS queue id.
//!
//! The valid path is byte-identical to the old cast: an in-range value
//! produces the same `u16`/`u8`. Only the out-of-range case changes — it
//! now fails the snapshot closed (the apply preflight keeps the previous
//! live forwarding state) rather than installing a wrapped/partial config.

use crate::policy::SnapshotIntegrityError;

/// A validated 802.1Q VLAN id (0..=65535). 0 is the legitimate
/// "untagged" sentinel the egress/ingress paths already use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct VlanId(u16);

impl VlanId {
    /// Decode an interface snapshot `vlan_id` (an `i32`). A NEGATIVE
    /// value is the legitimate "no VLAN" sentinel the pre-fix `.max(0)`
    /// collapsed to 0, so it maps to `VlanId(0)` (untagged) — preserving
    /// the old valid-path behavior. A value > `u16::MAX` is REJECTED
    /// (the pre-fix cast wrapped it to a different VLAN).
    pub(in crate::afxdp) fn try_from_snapshot(
        vlan_id: i32,
        interface: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        if vlan_id < 0 {
            return Ok(Self(0));
        }
        u16::try_from(vlan_id).map(Self).map_err(|_| {
            SnapshotIntegrityError::InterfaceVlanOutOfRange {
                interface: interface.to_string(),
                vlan_id,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u16 {
        self.0
    }
}

/// A validated outer-IP tunnel TTL / hop-limit (0..=255).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct TunnelTtl(u8);

impl TunnelTtl {
    /// Decode a tunnel-endpoint snapshot `ttl` (an `i32`). A NEGATIVE
    /// value maps to `TunnelTtl(0)` (the pre-fix `.max(0)` behavior); a
    /// value > `u8::MAX` is REJECTED (the pre-fix cast wrapped it,
    /// 256→0).
    pub(in crate::afxdp) fn try_from_snapshot(
        ttl: i32,
        tunnel_id: u16,
    ) -> Result<Self, SnapshotIntegrityError> {
        if ttl < 0 {
            return Ok(Self(0));
        }
        u8::try_from(ttl)
            .map(Self)
            .map_err(|_| SnapshotIntegrityError::TunnelTtlOutOfRange { tunnel_id, ttl })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u8 {
        self.0
    }
}

/// A validated CoS queue id (0..=255).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct QueueId(u8);

impl QueueId {
    /// Decode a CoS forwarding-class snapshot `queue` (an `i32`). Unlike
    /// VLAN/TTL there is NO negative sentinel — a negative or > `u8::MAX`
    /// queue id is REJECTED (the pre-fix `filter_map` silently DROPPED
    /// the whole class, unmapping every classifier/scheduler entry that
    /// referenced it).
    pub(in crate::afxdp) fn try_from_snapshot(
        queue: i32,
        forwarding_class: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        u8::try_from(queue).map(Self).map_err(|_| {
            SnapshotIntegrityError::CosQueueIdOutOfRange {
                forwarding_class: forwarding_class.to_string(),
                queue,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u8 {
        self.0
    }
}

/// A validated egress interface MTU.
///
/// #2706: the pre-fix code narrowed the snapshot `mtu` with
/// `iface.mtu.max(0) as usize`, so a NEGATIVE (malformed / version-drifted)
/// value silently collapsed to `0`. The egress MTU guard
/// (`forwarded_egress_mtu_decision`) treats `mtu == 0` as "unknown; forward"
/// (fail-open: never invent an MTU smaller than the link), so a negative MTU
/// silently DISABLED PTB / drop enforcement instead of failing the snapshot.
///
/// `0` is the LEGITIMATE "unknown MTU" sentinel the Go control plane emits
/// (an interface whose link could not be resolved — `buildLinkSnapshot`
/// returns mtu 0, dropped on the wire by `json:"mtu,omitempty"` and decoded
/// back to 0). That permissive case is preserved unchanged: `0` maps to
/// `InterfaceMtu(0)`. Only a NEGATIVE value (which a healthy Go path never
/// produces — netlink MTUs are non-negative) is REJECTED, consistent with the
/// #2410/#2696 fail-closed boundary: rejecting the whole snapshot keeps the
/// previous live forwarding state rather than installing an interface with MTU
/// enforcement silently switched off.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct InterfaceMtu(usize);

impl InterfaceMtu {
    /// Decode an interface snapshot `mtu` (an `i32`). `0` (and only 0) is the
    /// legitimate "unknown, forward permissively" sentinel and maps to
    /// `InterfaceMtu(0)`. A NEGATIVE value is REJECTED (the pre-fix `.max(0)`
    /// silently turned it into the permissive 0, disabling egress MTU
    /// enforcement). A positive value passes through unchanged.
    pub(in crate::afxdp) fn try_from_snapshot(
        mtu: i32,
        interface: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        usize::try_from(mtu).map(Self).map_err(|_| {
            SnapshotIntegrityError::InterfaceMtuInvalid {
                interface: interface.to_string(),
                mtu,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> usize {
        self.0
    }
}
