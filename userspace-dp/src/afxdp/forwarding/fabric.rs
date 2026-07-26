//! #5650: fabric cross-chassis forwarding — link resolution/skip classification,
//! fabric redirect selection (plain + zone-encoded), the HA cluster-peer-return
//! fast path, and the shared kernel-neighbor-state classifier used by the FIB
//! and tunnel neighbor paths. Pure code-motion split out of `forwarding/mod.rs`
//! (behavior-identical). See `docs/fabric-cross-chassis-fwd.md`.

use super::*;

/// #3771 (M12): count of neighbors skipped because their kernel state string
/// classified as UNKNOWN (empty / `none` / a future or corrupt token) rather
/// than a recognized usable state (`reachable`/`stale`/`delay`/`probe`/
/// `permanent`/`noarp`) or a known-unusable state (`failed`/`incomplete`). The
/// pre-#3771 denylist (`!(contains("failed") || contains("incomplete"))`)
/// treated EVERY unrecognized state as usable, so a `none` / empty / future
/// state with a parseable IP+MAC was installed into the FIB. This diagnostic
/// counter bumps once per skipped unknown-state neighbor per snapshot build; a
/// steadily climbing value signals a version-drifted or corrupt control-plane
/// producer.
pub(in crate::afxdp) static NEIGHBOR_UNKNOWN_STATE_SKIPPED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #3773 (M13): count of fabric links skipped during a forwarding
/// build/refresh because a value was MALFORMED — `parent_ifindex <= 0`, an
/// unparseable `peer_address`, or a NON-EMPTY local/peer MAC string that failed
/// to parse. Before #3773 each was a bare `continue` with no signal, so an HA
/// cross-chassis fabric link that silently failed to install (and therefore
/// silently did not forward) was invisible. A non-zero — especially a steadily
/// climbing — value is a config/environment fault the operator must fix; the
/// paired `log_fabric_skip_transition` journal line names which fabric and why.
/// Bumps once per malformed fabric per build/refresh pass, in both
/// `populate_fabrics` (snapshot build) and `resolve_fabric_links_from_snapshots`
/// (runtime refresh). Surfaced in status/Prometheus
/// (`xpf_userspace_fabric_link_skipped_malformed_total`).
pub(in crate::afxdp) static FABRIC_LINK_SKIPPED_MALFORMED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #3773 (M13): count of fabric links skipped during a forwarding
/// build/refresh because the peer or local MAC could not be resolved YET — an
/// EMPTY MAC field with no neighbor (peer) or interface (local) MAC available.
/// This is the EXPECTED transient of the late-resolution `SyncFabricState` path
/// (`FabricSnapshot.peer_mac` is empty until ARP/NDP resolves the peer). A
/// briefly non-zero value at startup is normal; a PERSISTENTLY non-zero value
/// means a fabric peer is not resolving (peer down, wrong sync IP, L2 broken) —
/// a distinct, non-malformed state per the issue's intent (an unresolved-peer
/// state is fine; a SILENT skip is not). Surfaced in status/Prometheus
/// (`xpf_userspace_fabric_link_unresolved_peer_total`).
pub(in crate::afxdp) static FABRIC_LINK_UNRESOLVED_PEER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #3773 (M13): bump the appropriate cumulative counter for a skipped fabric
/// link and return the named `FabricLinkSkip` record (for the ForwardingState
/// skip list + the transition log). Malformed reasons bump
/// `FABRIC_LINK_SKIPPED_MALFORMED`; unresolved-MAC reasons bump
/// `FABRIC_LINK_UNRESOLVED_PEER`.
fn record_fabric_skip(fabric: &crate::FabricSnapshot, reason: FabricSkipReason) -> FabricLinkSkip {
    if reason.is_malformed() {
        FABRIC_LINK_SKIPPED_MALFORMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        FABRIC_LINK_UNRESOLVED_PEER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    FabricLinkSkip {
        name: fabric.name.clone(),
        parent_ifindex: fabric.parent_ifindex,
        reason,
    }
}

/// #3773 (M13): SHARED fabric-link classifier for both build paths
/// (`populate_fabrics` and `resolve_fabric_links_from_snapshots`). Each caller
/// resolves the peer address + local/peer MACs through its own iface/neighbor
/// context, then hands the resolved `Option`s here; this centralizes the
/// skip-vs-install decision AND the counter/record so the two paths cannot
/// drift. Returns the installable `FabricLink` or a counted `FabricLinkSkip`.
/// Checks proceed in the pre-#3773 order (parent → peer address → local MAC →
/// peer MAC) so the FIRST failing reason is reported. An EMPTY MAC field is an
/// UNRESOLVED skip (transient); a NON-EMPTY MAC field that still resolved to
/// `None` is a MALFORMED skip (the string failed to parse).
pub(in crate::afxdp) fn build_fabric_link_or_skip(
    fabric: &crate::FabricSnapshot,
    peer_addr: Option<std::net::IpAddr>,
    local_mac: Option<[u8; 6]>,
    peer_mac: Option<[u8; 6]>,
) -> Result<FabricLink, FabricLinkSkip> {
    if fabric.parent_ifindex <= 0 {
        return Err(record_fabric_skip(
            fabric,
            FabricSkipReason::InvalidParentIfindex,
        ));
    }
    let Some(peer_addr) = peer_addr else {
        return Err(record_fabric_skip(
            fabric,
            FabricSkipReason::UnparseablePeerAddress,
        ));
    };
    let Some(local_mac) = local_mac else {
        let reason = if fabric.local_mac.trim().is_empty() {
            FabricSkipReason::UnresolvedLocalMac
        } else {
            FabricSkipReason::MalformedLocalMac
        };
        return Err(record_fabric_skip(fabric, reason));
    };
    let Some(peer_mac) = peer_mac else {
        let reason = if fabric.peer_mac.trim().is_empty() {
            FabricSkipReason::UnresolvedPeerMac
        } else {
            FabricSkipReason::MalformedPeerMac
        };
        return Err(record_fabric_skip(fabric, reason));
    };
    Ok(FabricLink {
        parent_ifindex: fabric.parent_ifindex,
        overlay_ifindex: fabric.overlay_ifindex,
        peer_addr,
        peer_mac,
        local_mac,
        // #4082: carry the parent carrier/oper state through so the redirect can
        // prefer an UP fabric. An old daemon that omits the wire field defaults
        // to true (fail-open) via `FabricSnapshot::default_true`.
        up: fabric.up,
    })
}

/// #3771 (M12): three-way classification of a kernel neighbor state string for
/// FIB installation.
///
/// - `Usable` — a recognized forwarding-usable NUD state; install the entry.
/// - `KnownUnusable` — `failed` / `incomplete`; an EXPECTED transient/failed
///   state, skipped silently (the pre-fix denylist already rejected these).
/// - `Unknown` — empty / `none` / a future or corrupt token; skipped AND
///   counted (`NEIGHBOR_UNKNOWN_STATE_SKIPPED`).
///
/// The Go producer (`neighborStateString`, pkg/dataplane/userspace/neighbors.go)
/// joins multiple NUD bits with `|`, so a pipe-joined state is `Usable` only
/// when EVERY token is in the allowlist; any unrecognized token makes the whole
/// state `Unknown`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) enum NeighborStateClass {
    Usable,
    KnownUnusable,
    Unknown,
}

pub(in crate::afxdp) fn classify_neighbor_state(state: &str) -> NeighborStateClass {
    let trimmed = state.trim();
    if trimmed.is_empty() {
        return NeighborStateClass::Unknown;
    }
    let mut saw_known_unusable = false;
    for token in trimmed.split('|') {
        match token.trim().to_ascii_lowercase().as_str() {
            "reachable" | "stale" | "delay" | "probe" | "permanent" | "noarp" => {}
            "failed" | "incomplete" => saw_known_unusable = true,
            // #3771 (M12): an empty / `none` / future / corrupt token is NOT in
            // the allowlist — reject the whole state as Unknown (was silently
            // treated as usable by the pre-fix denylist).
            _ => return NeighborStateClass::Unknown,
        }
    }
    if saw_known_unusable {
        NeighborStateClass::KnownUnusable
    } else {
        NeighborStateClass::Usable
    }
}

/// #3771 (M12): allowlist gate over [`classify_neighbor_state`] — true iff the
/// state is a recognized usable NUD state. Shared by the FIB build
/// (`populate_neighbors`), the runtime snapshot-refresh manager-key computation
/// (`snapshot_refresh.rs`), the `update_neighbors` control handler
/// (`server/handlers/neighbors.rs`), and `parse_neighbor_entries` — all of which
/// must agree on which neighbors are installable so a neighbor the FIB installs
/// is never pruned as a stale manager key (and vice versa).
pub(in crate::afxdp) fn neighbor_state_usable(state: &str) -> bool {
    matches!(classify_neighbor_state(state), NeighborStateClass::Usable)
}

pub(in crate::afxdp) fn ingress_is_fabric(forwarding: &ForwardingState, ingress_ifindex: i32) -> bool {
    forwarding.fabrics.iter().any(|fabric| {
        fabric.parent_ifindex == ingress_ifindex || fabric.overlay_ifindex == ingress_ifindex
    })
}

/// #6458: the fabric link whose parent OR overlay ifindex is
/// `ingress_ifindex`, or `None` when the ingress is not a fabric. Single
/// source of truth for the parent-or-overlay match so the identity check
/// below and [`ingress_is_fabric`] cannot drift.
pub(in crate::afxdp) fn fabric_for_ingress(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
) -> Option<&FabricLink> {
    forwarding.fabrics.iter().find(|fabric| {
        fabric.parent_ifindex == ingress_ifindex || fabric.overlay_ifindex == ingress_ifindex
    })
}

/// #6458: validate a zone-encoded fabric-ingress stamp against the fabric
/// link identity and live RG ownership. A stamped frame claims "this
/// packet ingressed the PEER in zone `zone_id`, and the peer punted it
/// here" — an L2-adjacent host on the fabric segment can forge the magic
/// bytes and compute any configured zone's `StableZoneID` offline, so the
/// stamp is honored only when the frame ALSO looks like something the
/// peer actually sent:
///
/// - **V1a — unicast to our fabric link.** The frame's destination MAC
///   must equal the matched fabric link's `local_mac`. The legitimate
///   sender always redirects to the peer's fabric MAC
///   (`resolve_fabric_redirect_from_list` sets
///   `neighbor_mac = fabric.peer_mac`; on the IPVLAN fabric the peer's
///   neighbor MAC is the same MAC the receiver reports as `local_mac`).
///   This rejects broadcast/multicast sprays and frames addressed to a
///   third party.
/// - **V1b — RG binding.** The claimed zone must have at least one
///   RG-bound member interface (`zone_to_rgs`), and NOT ALL of its bound
///   RGs may be forwarding-active LOCALLY — at least one must be
///   peer-active for the stamp to hold. When every RG the zone spans is
///   primary on the RECEIVER, traffic in that zone ingresses locally —
///   the peer has no business stamping it (on a single-primary cluster
///   this rejects every stamp on the primary; the policy teeth are V2's
///   owner-RG gate regardless). A zone spanning MULTIPLE RGs on a
///   split-RG node (one locally active, one peer-active) still accepts:
///   the peer legitimately punts the flows it owns (review-fold — the
///   NONE-active form over-rejected that legitimate active/active
///   stamp). A zone with no RG-bound members (`mgmt`/fxp0,
///   `control`/em0+fab, empty zones) can never be legitimately stamped,
///   which kills the host-inbound variant's `mgmt` claim.
///
/// What this deliberately does NOT try to stop: on a SHARED fabric
/// segment with a live RG split, an attacker can clone the exact stamp
/// shape of a currently-legitimate punt (remote-RG zone, unicast dst) —
/// indistinguishable from the real thing at L2. That residual is closed
/// only by a direct-attached or MACsec fabric; see
/// `docs/fabric-cross-chassis-fwd.md` (#6458 section).
///
/// Hot-path: runs only for frames that already matched the fabric-ingress
/// + magic + zone-exists gates in
/// `parse_zone_encoded_fabric_ingress_from_frame`. One 6-byte compare, one
/// `zone_to_rgs` hash lookup, and one `ha_state` lookup per bound RG
/// (typically one). No allocation, no atomics.
pub(in crate::afxdp) fn zone_encoded_fabric_stamp_valid(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    frame_dst_mac: &[u8],
    ingress_ifindex: i32,
    zone_id: u16,
) -> bool {
    let Some(fabric) = fabric_for_ingress(forwarding, ingress_ifindex) else {
        return false;
    };
    // V1a: the redirect is always unicast to our fabric link's MAC.
    if frame_dst_mac != fabric.local_mac.as_slice() {
        return false;
    }
    // V1b: the claimed zone must be RG-bound, and NOT ALL of its RGs may
    // be forwarding-active locally — at least one must be peer-active
    // (reject only when EVERY bound RG is locally active: the single-
    // primary kill with no multi-RG-zone over-rejection). An absent/empty
    // entry means the zone has no RG-bound members and can never be
    // legitimately stamped.
    match forwarding.zone_to_rgs.get(&zone_id) {
        Some(rgs) => {
            !rgs.is_empty()
                && !rgs.iter().all(|rg| {
                    ha_state
                        .get(rg)
                        .is_some_and(|group| group.is_forwarding_active(now_secs))
                })
        }
        None => false,
    }
}

/// #6458: V2 owner binding for the session-MISS zone-pair computation. A
/// (V1-validated) zone-encoded stamp drives NEW-flow policy / NAT scope /
/// host-inbound evaluation only when the packet's resolved owner RG is
/// forwarding-active LOCALLY — the peer punts a new flow to us only
/// because WE own its egress RG (split-RG active/active or an asymmetric
/// failover window). On a single-primary backup nothing is locally
/// active, so every stamp degrades to the fabric interface's own zone
/// (default-deny) there. The resolution's owner RG is identical before
/// and after `finalize_new_flow_ha_resolution` for a fabric-ingress
/// packet, so gating here at the zone-pair site covers the final
/// resolution.
#[inline]
pub(in crate::afxdp) fn gate_fabric_zone_override_on_owner_rg(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_zone_override: Option<u16>,
    resolution: ForwardingResolution,
) -> Option<u16> {
    let zone = ingress_zone_override?;
    let owner_rg = owner_rg_for_resolution(forwarding, resolution);
    if owner_rg > 0
        && ha_state
            .get(&owner_rg)
            .is_some_and(|group| group.is_forwarding_active(now_secs))
    {
        Some(zone)
    } else {
        None
    }
}

/// #6458 (review fold): owner RG of a LOCAL (firewall-owned) address —
/// the redundancy group of the egress interface whose primary address
/// matches, 0 when no RG-bound interface owns it. Used by the IKE
/// host-inbound variant of the V2 owner binding: a stamped zone may drive
/// host-inbound admission for an address only when THAT address's RG is
/// forwarding-active locally (on a single-primary backup no local address
/// is locally active, so every stamped host-inbound admission degrades to
/// the fabric interface's own zone — default-deny).
pub(in crate::afxdp) fn owner_rg_for_local_address(
    forwarding: &ForwardingState,
    ip: IpAddr,
) -> i32 {
    forwarding
        .egress
        .values()
        .find(|iface| match ip {
            IpAddr::V4(v4) => iface.primary_v4 == Some(v4),
            IpAddr::V6(v6) => iface.primary_v6 == Some(v6),
        })
        .map(|iface| iface.redundancy_group.max(0))
        .unwrap_or_default()
}

/// #6458 (review fold): V2 owner binding for HOST-DESTINED packets (the
/// Stage-11 IKE host-inbound gate). Mirrors
/// [`gate_fabric_zone_override_on_owner_rg`] but resolves the owner RG
/// from the packet's local destination address instead of a forwarding
/// resolution — a stamped zone drives host-inbound admission only when
/// the destination address's owner RG is forwarding-active LOCALLY. A
/// forged stamp to a backup's reth address (owner RG primary on the peer)
/// is stripped, so the fabric interface's own zone governs (default-deny)
/// and a forged NEW IKE initiation is denied instead of seeding the
/// #6471 live-exchange table.
#[inline]
pub(in crate::afxdp) fn gate_fabric_zone_override_on_local_owner_rg(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_zone_override: Option<u16>,
    dst_ip: IpAddr,
) -> Option<u16> {
    let zone = ingress_zone_override?;
    let owner_rg = owner_rg_for_local_address(forwarding, dst_ip);
    if owner_rg > 0
        && ha_state
            .get(&owner_rg)
            .is_some_and(|group| group.is_forwarding_active(now_secs))
    {
        Some(zone)
    } else {
        None
    }
}

pub(in crate::afxdp) fn ingress_is_fabric_overlay(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
) -> bool {
    forwarding
        .fabrics
        .iter()
        .any(|fabric| fabric.overlay_ifindex == ingress_ifindex)
}

pub(in crate::afxdp) fn resolve_fabric_links_from_snapshots(
    snapshots: &[crate::FabricSnapshot],
    egress: &FastMap<i32, EgressInterface>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> (Vec<FabricLink>, Vec<FabricLinkSkip>) {
    let mut out = Vec::with_capacity(snapshots.len());
    let mut skips = Vec::new();
    for fabric in snapshots {
        // Resolve the same inputs the pre-#3773 code did, then classify /
        // count the skip-vs-install decision through the shared helper so this
        // runtime-refresh path and `populate_fabrics` cannot diverge (#3773
        // M13). The peer-MAC neighbor lookup keys on the parsed peer address,
        // so it is gated on a successful parse; an unparseable address is
        // reported as `UnparseablePeerAddress` regardless of the MAC fields.
        let peer_addr = fabric.peer_address.parse::<IpAddr>().ok();
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| egress.get(&fabric.parent_ifindex).map(|e| e.src_mac));
        let peer_mac = peer_addr.and_then(|addr| {
            parse_mac(&fabric.peer_mac).or_else(|| {
                dynamic_neighbors
                    .get(&(fabric.overlay_ifindex, addr))
                    .or_else(|| dynamic_neighbors.get(&(fabric.parent_ifindex, addr)))
                    .map(|e| e.mac)
            })
        });
        match build_fabric_link_or_skip(fabric, peer_addr, local_mac, peer_mac) {
            Ok(link) => out.push(link),
            Err(skip) => skips.push(skip),
        }
    }
    (out, skips)
}

/// #5686: an already-resolved `FabricLink` is SUPERSEDED when the incoming
/// fabric snapshots still configure its parent interface but now name a
/// DIFFERENT peer address — a same-parent peer REPLACEMENT. Such a stale link
/// must never be preserved across a snapshot/refresh merge: until the
/// replacement peer resolves (its neighbor MAC is learned), redirecting fabric
/// traffic to the OLD peer would send it to a peer that is no longer current
/// (the M01 stale-fabric-peer window). Dropping the old link makes
/// `resolve_fabric_redirect` return `None` for that parent during the
/// resolution window, so a synced-session packet takes its normal non-fabric
/// disposition (safe) instead of a wrong-peer redirect.
///
/// Only a same-parent, different-and-parseable peer address supersedes:
/// - A snapshot that still names the SAME peer (the steady-state periodic
///   `SyncFabricState` refresh) is NOT a supersession — the working link is
///   preserved unchanged.
/// - A snapshot that OMITS the parent entirely (fabric removed, not replaced)
///   is NOT a supersession — link teardown is a separate concern, and the
///   existing preserve-across-unresolved-refresh behavior is kept.
/// - An UNPARSEABLE replacement address is ignored: the malformed new link
///   cannot resolve anyway, so it is not yet a valid replacement to gate on.
pub(in crate::afxdp) fn fabric_link_superseded_by_snapshots(
    old: &FabricLink,
    snapshots: &[crate::FabricSnapshot],
) -> bool {
    snapshots.iter().any(|snap| {
        snap.parent_ifindex == old.parent_ifindex
            && snap
                .peer_address
                .parse::<IpAddr>()
                .map(|addr| addr != old.peer_addr)
                .unwrap_or(false)
    })
}

pub(in crate::afxdp) fn resolve_fabric_redirect(
    forwarding: &ForwardingState,
) -> Option<ForwardingResolution> {
    resolve_fabric_redirect_from_list(&forwarding.fabrics)
}

pub(in crate::afxdp) fn resolve_fabric_redirect_from_list(
    fabrics: &[FabricLink],
) -> Option<ForwardingResolution> {
    // #4082: prefer the FIRST fabric whose local parent carrier is UP so a
    // dual-fabric cluster fails the cross-chassis redirect over to fab1 when
    // fab0's parent link goes down. The fabric list arrives in a stable
    // Go-sorted-by-name order (pkg/dataplane/userspace/fabric.go), so both
    // nodes deterministically prefer fab0 while it is up — no hash/round-robin,
    // matching the control-plane `activeConnLocked` fab0-preferred failover.
    // If NO fabric reports up (a stale peer that omits the `up` field defaults
    // every fabric to up=true, so this only triggers on a genuine all-down
    // state), fall back to the first resolvable fabric — fail-open, never worse
    // than the pre-#4082 pin-to-first behavior (a blackhole is no worse than
    // dropping).
    let fabric = fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex > 0 && fabric.up)
        .or_else(|| fabrics.iter().find(|fabric| fabric.parent_ifindex > 0))
        .copied()?;
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: fabric.parent_ifindex,
        tx_ifindex: fabric.parent_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: Some(fabric.peer_addr),
        neighbor_mac: Some(fabric.peer_mac),
        src_mac: Some(fabric.local_mac),
        tx_vlan_id: 0,
    })
}

pub(in crate::afxdp) fn resolve_zone_encoded_fabric_redirect(
    forwarding: &ForwardingState,
    ingress_zone: &str,
) -> Option<ForwardingResolution> {
    let zone_id = forwarding.zone_name_to_id.get(ingress_zone).copied()?;
    resolve_zone_encoded_fabric_redirect_by_id(forwarding, zone_id)
}

/// #919/#922: ID-keyed variant of `resolve_zone_encoded_fabric_redirect`.
/// Avoids the name-string round-trip when the caller already has a u16
/// zone ID (e.g. from `SessionMetadata.ingress_zone`).
pub(in crate::afxdp) fn resolve_zone_encoded_fabric_redirect_by_id(
    forwarding: &ForwardingState,
    zone_id: u16,
) -> Option<ForwardingResolution> {
    let mut resolution = resolve_fabric_redirect(forwarding)?;
    // #3075: the zone id is now a stable name-hash u16, so the synthetic fabric
    // src MAC carries it in TWO bytes — high byte at [4], low byte at [5]
    // (big-endian), where the old u8 scheme hardcoded [4]=0x00. The decode in
    // frame/inspect.rs::parse_zone_encoded_fabric_ingress_from_frame and the
    // skip-learn check in neighbor_dispatch.rs read the full u16 in lock-step.
    // A reserved-range id is never produced by StableZoneID, so any id != 0 is
    // a real configured zone.
    if zone_id == 0 {
        return None;
    }
    let [hi, lo] = zone_id.to_be_bytes();
    resolution.src_mac = Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    Some(resolution)
}

pub(in crate::afxdp) fn redirect_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        return resolution;
    }
    resolve_fabric_redirect(forwarding).unwrap_or(resolution)
}

pub(in crate::afxdp) fn prefer_local_forward_candidate_for_fabric_ingress(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    fabric_ingress: bool,
    target_ip: IpAddr,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !fabric_ingress || matches!(resolution.disposition, ForwardingDisposition::LocalDelivery) {
        return resolution;
    }

    let current_owner_rg = owner_rg_for_resolution(forwarding, resolution);
    let current_egress_is_fabric =
        resolution.egress_ifindex > 0 && ingress_is_fabric(forwarding, resolution.egress_ifindex);
    if !current_egress_is_fabric
        && current_owner_rg > 0
        && resolution.disposition != ForwardingDisposition::FabricRedirect
    {
        return resolution;
    }

    let local_resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_state,
        now_secs,
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip),
    );
    let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
    let local_egress_is_fabric = local_resolution.egress_ifindex > 0
        && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
    if matches!(
        local_resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && local_owner_rg > 0
        && !local_egress_is_fabric
    {
        return local_resolution;
    }

    resolution
}

pub(in crate::afxdp) fn cluster_peer_return_fast_path(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    resolution_target: IpAddr,
) -> Option<(SessionDecision, SessionMetadata)> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let ingress_zone = ingress_zone_override?;
    if is_icmp_echo_request(packet_frame, meta) {
        return None;
    }
    // #2151: `is_initial_syn` == the prior
    // `(tcp_flags & SYN) != 0 && (tcp_flags & ACK) == 0` — a bare
    // connection-opening SYN has no peer-owned session to return for.
    if meta.protocol == PROTO_TCP && crate::tcp_flags::is_initial_syn(meta.tcp_flags) {
        return None;
    }
    // #4453: a bare TCP RST/FIN (closing flags, SYN clear) is the same
    // session-less phantom-closing packet the LOCAL session-miss path drops
    // via the #4400 strict-syn-check (`strict_syn_check_drops_new_flow` ==
    // PROTO_TCP && is_closing && !has_syn). It carries no return value: a real
    // established flow's RST/FIN is served by the synced session in
    // `resolve_flow_session_decision` before this point. Without this arm, a
    // transit bare RST/FIN to a locally-HAInactive RG is converted to a
    // FabricRedirect (safety net) and forwarded to the peer, where it arrives
    // as fabric ingress and gets fast-pathed into a NAT-less
    // `SessionOrigin::ReverseFlow` seed — installing on the peer, via the
    // trusted fabric path, exactly the immediately-closing session the peer's
    // own #4400 guard prevents locally. Exclude it here (SAME predicate as
    // #4400) so it falls through to the peer's normal forward decision, whose
    // session-miss guard drops it — no reverse seed. This completes the
    // fast-path invariant: fire ONLY for provably-return traffic (exclude the
    // TCP initial SYN, the ICMP echo request, all UDP, AND the bare RST/FIN).
    if meta.protocol == PROTO_TCP
        && crate::tcp_flags::is_closing(meta.tcp_flags)
        && !crate::tcp_flags::has_syn(meta.tcp_flags)
    {
        return None;
    }
    // #4439/#4414: this fast path may fire ONLY for packets that are provably
    // RETURN traffic — the reverse direction of a flow the active owner
    // already policy/NAT-validated. That requires a protocol with a
    // packet-level flow-initiator marker so the initiating (forward) form can
    // be told apart from the return form, and the initiator is excluded above:
    // TCP excludes the initial SYN (and the bare RST/FIN, #4453); ICMP/ICMPv6
    // exclude the echo REQUEST. Every OTHER protocol — UDP (#4439), and
    // likewise ESP/AH/GRE/SCTP/OSPF/… (the #4414 residual) — has NO such
    // marker: any datagram can open a new flow, and there is no
    // "non-initiating" form to key on. A session-less packet of one of these
    // protocols reaching here (a real established reply is served by the
    // synced session in `resolve_flow_session_decision` before this point) is
    // therefore a NEW forward flow, NOT return traffic. Fast-pathing it built
    // a NAT-less, reverse-keyed session for a forward flow — the source-NAT a
    // new outbound flow requires was skipped (NAT bypass) and the owner
    // recorded the flow in the wrong direction (session-state corruption).
    // Refuse every protocol that is not TCP or ICMP/ICMPv6 so it falls through
    // to the RG owner's normal forward decision: source-NAT applied and a
    // FORWARD session installed. (Subsumes the #4439 UDP-only guard.)
    if !matches!(meta.protocol, PROTO_TCP | PROTO_ICMP | PROTO_ICMPV6) {
        return None;
    }

    let fabric_return_resolution =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, resolution_target);
    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    // #921: direct ifindex → u16 lookup (was a two-hop name round-trip).
    let egress_zone = forwarding
        .ifindex_to_zone_id
        .get(&fabric_return_resolution.egress_ifindex)
        .copied()?;
    let metadata = SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id: owner_rg_for_resolution(forwarding, fabric_return_resolution),
        fabric_ingress: true,
        is_reverse: true,
        nat64_reverse: None,
        // #2508: fabric-return reverse seed carries no local per-policy
        // `then log` selection (the admitting node logs).
        log_session_init: false,
        log_session_close: false,
        // #3056: the fabric-return reverse seed is created on the peer-forwarding
        // node, which never ran the admitting policy — leave the policy ID unset.
        policy_id: 0,
        inactivity_timeout_ns: None,
        // #3073: peer-forwarded fabric-return seed; no local admitting rule, so
        // no per-rule hit counter.
        policy_counter_idx: 0,
        policy_counter: None,
    };
    Some((
        SessionDecision {
            resolution: fabric_return_resolution,
            nat: NatDecision::default(),
        },
        metadata,
    ))
}
