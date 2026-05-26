//! Control request/response and snapshot schema types shared between the
//! control socket server (`main.rs`) and the AF_XDP coordinator
//! (`afxdp/` module tree).
//!
//! All types are `pub(crate)` so they are visible across the crate without
//! being part of the public API, with one historical exception:
//! `WorkerRuntimeStatus` carries `pub` visibility (preserved from before
//! the split for #869 instrumentation that surfaced it for external
//! tooling). All other types stay `pub(crate)`.
//!
//! Split (#1325) into domain submodules:
//!   - `snapshot`: config DTOs (ConfigSnapshot tree, interface/route/zone/
//!     fabric/tunnel/neighbor/mirror snapshots, MapPins, capabilities)
//!   - `cos`: CoS config (ClassOfServiceSnapshot tree) and CoS status
//!     (CoSInterfaceStatus, CoSQueueStatus, CoSActiveFlowCountStatus)
//!   - `nat`: NAT rule snapshots (SNAT/DNAT/Static/NAT64/Nptv6) and
//!     SourceNatPoolStatus
//!   - `security`: screen/firewall-filter/policer/policy snapshots and
//!     counter statuses
//!   - `control`: control socket request/response, ProcessStatus,
//!     session-sync wire shapes, protocol-version consts
//!   - `binding`: BindingStatus + BindingCountersSnapshot, HAGroupStatus,
//!     QueueStatus, WorkerRuntimeStatus, ExceptionStatus,
//!     SessionDeltaInfo, plus the `u64_is_zero` skip-serializing helper
//!   - `resolution`: per-packet trace types (PacketResolution,
//!     FlowTupleStatus, FlowWorkerStatus)
//!
//! Every type is re-exported here so existing `crate::protocol::X`
//! callers and `use protocol::*;` in `main.rs` keep working unchanged.

mod binding;
mod control;
mod cos;
mod nat;
mod resolution;
mod security;
mod snapshot;

#[cfg(test)]
mod tests;

pub(crate) use binding::*;
pub(crate) use control::*;
pub(crate) use cos::*;
pub(crate) use nat::*;
pub(crate) use resolution::*;
pub(crate) use security::*;
pub(crate) use snapshot::*;
