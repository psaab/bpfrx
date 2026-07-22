// Re-export the `afxdp` namespace into `ha` so the `#[path]`-included
// `ha_tests` child module (which uses `use super::*`) resolves the shared HA
// types exactly as it did before this module was split into submodules. The
// per-owner submodules import `crate::afxdp::*` directly and do not rely on
// this. rustc's unused-import lint does not see the child-module re-import,
// hence the allow.
#[allow(unused_imports)]
use super::*;

mod state;
mod export;
mod session_import;
mod tunnel_purge;

pub(crate) use self::export::{AllSessionsExport, OwnerRgExportWait};
#[cfg(test)]
pub(crate) use self::export::drain_session_deltas_from_live;

#[cfg(test)]
#[path = "../ha_tests.rs"]
mod tests;
