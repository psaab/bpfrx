// TX-request types extracted from afxdp/types/mod.rs (Issue 68.3).
// 8 items / ~80 LOC of transmit-side request descriptors used by
// tx/dispatch.rs and the per-binding pending-forward queues.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// tx::*;` so external call sites resolve unchanged.

use super::*;

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct TxRequest {
    pub(in crate::afxdp) bytes: Vec<u8>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_protocol: u8,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) egress_ifindex: i32,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

pub(in crate::afxdp) enum PendingForwardFrame {
    Live,
    Owned(Vec<u8>),
    Prebuilt(Vec<u8>),
}

impl Default for PendingForwardFrame {
    fn default() -> Self {
        Self::Live
    }
}

pub(in crate::afxdp) struct PendingForwardRequest {
    pub(in crate::afxdp) target_ifindex: i32,
    pub(in crate::afxdp) target_binding_index: Option<usize>,
    pub(in crate::afxdp) ingress_queue_id: u32,
    pub(in crate::afxdp) desc: XdpDesc,
    pub(in crate::afxdp) frame: PendingForwardFrame,
    pub(in crate::afxdp) meta: ForwardPacketMeta,
    pub(in crate::afxdp) decision: SessionDecision,
    pub(in crate::afxdp) apply_nat_on_fabric: bool,
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) nat64_reverse: Option<Nat64ReverseInfo>,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

pub(in crate::afxdp) struct PreparedTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
    pub(in crate::afxdp) recycle: PreparedTxRecycle,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_protocol: u8,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) egress_ifindex: i32,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct ExactLocalScratchTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct ExactPreparedScratchTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
}

#[derive(Debug)]
pub(in crate::afxdp) struct LocalTunnelTxPlan {
    pub(in crate::afxdp) tx_ifindex: i32,
    pub(in crate::afxdp) tx_request: TxRequest,
    pub(in crate::afxdp) session_entry: SyncedSessionEntry,
    pub(in crate::afxdp) reverse_session_entry: Option<SyncedSessionEntry>,
}
