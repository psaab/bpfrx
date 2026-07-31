//! Dataplane-event queue-budget release for frames leaving the channel.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. Queue-budget
//! ADMISSION happens on producer threads (`producer.rs`); this is the I/O-thread
//! RETIREMENT side — every telemetry frame that leaves the channel (drained,
//! replayed, evicted, popped on ACK, or dropped on shutdown) releases exactly
//! the per-kind budget slot it acquired at emit.

use super::*;

pub(super) fn release_dataplane_event_queue_budget(
    shared: &Arc<EventStreamShared>,
    frame: &EventFrame,
) {
    if let Some(kind) = frame.dataplane_event_kind() {
        shared.dataplane_event_queue.release(kind);
    }
}
