//! Zone-table population for `build_forwarding_state`.
//!
//! Populates `state.zone_name_to_id` and `state.zone_id_to_name`
//! from `snapshot.zones`. Rejects reserved-range zone IDs
//! (>= ZONE_ID_RESERVED_MIN). #3075 widened the event-stream zone
//! field to u16, so ids up to ZONE_ID_RESERVED_MIN-1 are addressable
//! (the former >u8::MAX skip is retired).

use super::super::*;

/// Populate `state.zone_name_to_id` / `state.zone_id_to_name`.
/// Must run before any other pass that resolves zone names
/// (interfaces addresses pass, interfaces egress pass,
/// `parse_policy_state_with_counters`).
pub(super) fn populate_zones(snapshot: &ConfigSnapshot, state: &mut ForwardingState) {
    // #3402: build the name→id map from the shared SSOT so the apply-time
    // integrity preflight (which has no live forwarding state yet) resolves
    // policy zones against the IDENTICAL validated map this build path uses.
    // The loop below only fills the id-keyed maps (zone_id_to_name /
    // host-inbound / tcp-rst) and emits the #919/#922 skip diagnostics.
    state.zone_name_to_id = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        // #919/#922: reserve the top of the u16 space for the
        // `JUNOS_GLOBAL_ZONE_ID` sentinel. Reject any snapshot that
        // would collide.
        if zone.id >= crate::policy::ZONE_ID_RESERVED_MIN {
            eprintln!(
                "xpf-userspace-dp: zone {:?} has reserved id {}; skipping (max usable id is {})",
                zone.name,
                zone.id,
                crate::policy::ZONE_ID_RESERVED_MIN - 1
            );
            continue;
        }
        // #3075: the event-stream codec now writes zone IDs as u16, so the
        // former >u8::MAX skip is retired — a stable name-hash zone id in
        // [1, ZONE_ID_RESERVED_MIN-1] = [1, 65533] is fully addressable. The
        // reserved-range reject above (>= ZONE_ID_RESERVED_MIN) remains the only
        // out-of-range guard.
        // zone_name_to_id is populated above by the shared SSOT helper.
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
        // #3070/#3405/#3705: build the host-inbound admission set keyed by the
        // SAME validated id for EVERY KNOWN zone (a zone present in the snapshot
        // with a valid, addressable id). Post-#3405 the Go control plane sends
        // HostInboundConfigured=true for every configured zone (security.go:70,
        // zones.go), so a configured zone with NO `host-inbound-traffic` stanza is
        // NOT left absent — it ships an EMPTY token set that inserts a default
        // `ZoneHostInbound` here (`admits()` -> false for every service/protocol
        // => default-DENY, Junos parity).
        //
        // #3705: the insert is NO LONGER gated on `host_inbound_configured`. A
        // KNOWN zone whose snapshot carries `host_inbound_configured == false` —
        // the tolerant / HA nil-zone shape (Security.Zones[name] == nil ships a
        // valid name+id but configured=false; #3493), or an old pre-#3405 Go
        // control plane that omits the field — would otherwise be left ABSENT from
        // this table and hit the `None => true` admit-all arm in
        // `host_inbound_admits`, making that known configured zone admit ALL
        // host-bound traffic (reopening the #3405 default-deny on the nil shape).
        // A configured=false zone carries empty token vecs, so it inserts an empty
        // `ZoneHostInbound` -> default-DENY, identical to a no-stanza zone. The
        // Go builder now also ships configured=true for a nil zone; this insert is
        // the fail-closed backstop for a mismatched-version control plane. The
        // `None => true` arm consequently fires ONLY for a genuinely unknown /
        // global ingress zone (id 0, never in this table — skipped above).
        // Lifeline interfaces (fxp0/em0/fab*) are exempt because they never reach
        // the AF_XDP local-delivery classifier (#3682). SSOT:
        // docs/host-inbound-service-matrix.md.
        state
            .zone_host_inbound
            .insert(zone.id, zone_host_inbound_from_snapshot(zone));
        // #3071: record the per-zone Junos `tcp-rst` knob keyed by zone id so
        // the policy-deny hot path can answer a denied TCP flow whose ingress
        // (from) zone has tcp-rst with a RST instead of a silent drop. Only
        // tcp-rst-enabled zones are inserted; the absence of a key is "off".
        if zone.tcp_rst {
            state.zone_tcp_rst.insert(zone.id, true);
        }
    }
}
