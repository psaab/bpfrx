// Three-color policer *application* helpers extracted from engine.rs by
// #1546. Distinct from `filter/policer.rs`, which holds the standalone
// `ThreeColorPolicerState`/`ThreeColorPolicerRuntime` types. These helpers
// invoke `runtime.meter()` once per matching term and merge the returned
// `ThreeColorDecision` into the caller-visible `ThreeColorPolicerAction`.
//
// Concurrency contract preserved across the split:
//   - `ThreeColorPolicerState::meter` is `&mut self` and not used directly
//     here; we go through `ThreeColorPolicerRuntime::meter(&self, ...)`
//     which serializes via the wrapper's `Mutex<ThreeColorPolicerState>`
//     and then records counters via relaxed atomic adds.
//   - The `meter()` call -> counter-record order is preserved: each call
//     site invokes `runtime.meter()` and propagates its `dscp_rewrite`/
//     `drop` decision without intervening allocations.

use super::super::*;

#[inline]
pub(super) fn apply_term_three_color_policer(
    term: &FilterTerm,
    now_ns: Option<u64>,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let Some(runtime) = term.three_color_policer.as_ref() else {
        return ThreeColorPolicerAction::default();
    };
    let Some(now_ns) = now_ns else {
        return ThreeColorPolicerAction::default();
    };
    let decision = runtime.meter(now_ns, packet_bytes, PacketColor::Green);
    ThreeColorPolicerAction {
        dscp_rewrite: decision.dscp_rewrite,
        drop: decision.drop,
    }
}

pub(crate) fn apply_cached_three_color_policers(
    policers: &CachedThreeColorPolicers,
    now_ns: u64,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let mut action = ThreeColorPolicerAction::default();
    policers.for_each(|policer| {
        let decision = policer.meter(now_ns, packet_bytes, PacketColor::Green);
        action.dscp_rewrite = action.dscp_rewrite.or(decision.dscp_rewrite);
        action.drop |= decision.drop;
    });
    action
}

pub(crate) fn filter_state_has_input_three_color_policer(
    state: &FilterState,
    is_v6: bool,
) -> bool {
    if is_v6 {
        state.has_input_three_color_policer_v6
    } else {
        state.has_input_three_color_policer_v4
    }
}
