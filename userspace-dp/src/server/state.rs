// Server state types extracted from main.rs (#1048 P2 step 2).
// `PollMode` was already pub at the crate root; `Args` and
// `ServerState` were file-private — widened to pub(crate) here
// (and likewise their fields) so server/handlers.rs and main.rs's
// run() loop can both construct and destructure them.

use crate::state_writer::StateWriter;
use crate::{afxdp, ConfigSnapshot, ProcessStatus};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMode {
    BusyPoll,
    Interrupt,
}

impl PollMode {
    pub(crate) fn from_str(s: &str) -> Self {
        match s {
            "interrupt" => PollMode::Interrupt,
            _ => PollMode::BusyPoll,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) control_socket: String,
    pub(crate) state_file: String,
    pub(crate) workers: usize,
    pub(crate) ring_entries: usize,
    pub(crate) poll_mode: PollMode,
}

pub(crate) struct ServerState {
    pub(crate) status: ProcessStatus,
    pub(crate) snapshot: Option<ConfigSnapshot>,
    pub(crate) afxdp: afxdp::Coordinator,
    pub(crate) state_writer: Arc<StateWriter>,
}
