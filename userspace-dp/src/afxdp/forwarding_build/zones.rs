//! Zone-table population for `build_forwarding_state`.
//!
//! Populates `state.zone_name_to_id` and `state.zone_id_to_name`
//! from `snapshot.zones`. Rejects reserved-range and >u8::MAX
//! zone IDs per #919/#922 wire-format constraints.

use super::super::*;

/// Populate `state.zone_name_to_id` / `state.zone_id_to_name`.
/// Must run before any other pass that resolves zone names
/// (interfaces addresses pass, interfaces egress pass,
/// `parse_policy_state_with_counters`).
pub(super) fn populate_zones(snapshot: &ConfigSnapshot, state: &mut ForwardingState) {
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
        // #919/#922: defense-in-depth. The event-stream codec writes
        // zone IDs as u8 (release builds elide the debug_assert). A
        // hostile or future malformed snapshot with id > 255 would
        // silently corrupt wire-level zone IDs without this gate.
        if zone.id > u8::MAX as u16 {
            eprintln!(
                "xpf-userspace-dp: zone {:?} has id {} > wire u8 max {}; skipping",
                zone.name,
                zone.id,
                u8::MAX
            );
            continue;
        }
        state.zone_name_to_id.insert(zone.name.clone(), zone.id);
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
    }
}
