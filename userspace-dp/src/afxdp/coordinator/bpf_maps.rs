// BPF map file descriptors owned by the Coordinator. Bundled
// together because they share lifecycle (loaded on `cluster up`,
// dropped on `cluster down`) and have no other state.

use crate::afxdp::bpf_map::OwnedFd;

#[derive(Default)]
pub(crate) struct BpfMaps {
    pub(crate) map_fd: Option<OwnedFd>,
    pub(crate) heartbeat_map_fd: Option<OwnedFd>,
    pub(crate) session_map_fd: Option<OwnedFd>,
    pub(crate) conntrack_v4_fd: Option<OwnedFd>,
    pub(crate) conntrack_v6_fd: Option<OwnedFd>,
    pub(crate) dnat_table_fd: Option<OwnedFd>,
    pub(crate) dnat_table_v6_fd: Option<OwnedFd>,
}
