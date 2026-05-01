// #1048 P2 step 2: server/ became a directory module so the
// public-API state types and the handler dispatch can live in
// separate sibling files (server/state.rs and server/handlers.rs).
//
// This file is a thin index — declarations + re-exports only.

// Submodules are private — external callers reach their items only
// through the explicit `pub(crate) use` re-exports below.
mod handlers;
mod state;

pub(crate) use handlers::handle_stream;
pub(crate) use state::{Args, PollMode, ServerState};
