// #1345: per-verb handler for drain_session_deltas. Body byte-identical
// to handlers.rs lines 343-353.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::{ControlResponse, SessionDeltaDrainRequest};

pub(super) fn drain(
    guard: &mut ServerState,
    session_deltas: Option<&SessionDeltaDrainRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let max = session_deltas.map(|req| req.max).unwrap_or(256).max(1) as usize;
    response.session_deltas = guard.afxdp.drain_session_deltas(max);
    refresh_status(guard);
    *persist_state = true;
}
