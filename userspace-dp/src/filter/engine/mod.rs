// Per-packet filter evaluation engine. Split into responsibility-scoped
// submodules by #1546 (pure code motion — function bodies byte-identical
// with the pre-split engine.rs). Visibility tightened from pub(crate)
// engine-wide flat to pub(super) for engine-local helpers; the surface
// re-exported below matches the prior engine.rs `pub(crate) fn` set.

mod cache_sensitive;
mod eval;
mod matching;
mod policer;
mod tx_selection;

pub(crate) use cache_sensitive::{
    evaluate_filter_ref_tx_selection_cached, input_dscp_filter_families_changed,
    interface_input_filter_has_dscp_match, interface_output_filter_has_dscp_match,
};
pub(crate) use eval::{
    evaluate_filter, evaluate_filter_counted, evaluate_interface_filter,
    evaluate_interface_filter_counted, evaluate_interface_filter_log_match,
    evaluate_interface_filter_non_routing_counted,
    evaluate_interface_filter_routing_instance_counted,
    evaluate_interface_filter_routing_instance_event_counted, evaluate_interface_output_filter,
    evaluate_interface_output_filter_counted, evaluate_lo0_filter, evaluate_lo0_filter_counted,
    evaluate_lo0_filter_log_match, interface_filter_affects_route_lookup,
};
pub(crate) use policer::{
    apply_cached_three_color_policers, filter_state_has_input_three_color_policer,
};
pub(crate) use tx_selection::{
    evaluate_filter_ref_tx_selection_counted, evaluate_filter_ref_tx_selection_runtime_counted,
    evaluate_interface_filter_tx_selection_counted,
    evaluate_interface_output_filter_tx_selection_counted, filter_state_has_input_tx_selection,
    filter_state_has_output_tx_selection, interface_filter_affects_tx_selection,
    interface_output_filter_needs_tx_eval,
};
