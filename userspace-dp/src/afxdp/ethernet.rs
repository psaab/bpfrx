//! Shared Ethernet / VLAN / EtherType constants.
//!
//! Single source of truth for L2 magic numbers used across the
//! AF_XDP fast path. Previously these were defined privately in
//! `tx.rs` (`ETH_HDR_LEN`, `VLAN_TAG_LEN`) and `parser.rs`
//! (`ETHERTYPE_*`). Extracted per Gemini review of #947 to avoid
//! drift between modules.
//!
//! These are `pub(super)` so any sibling submodule of `afxdp` can
//! import via `use super::ethernet::*;` (or by-name).

/// Size of a bare Ethernet header (6 dst MAC + 6 src MAC + 2 ethertype).
pub(super) const ETH_HDR_LEN: usize = 14;

/// Size of a single 802.1Q / 802.1ad VLAN tag (TPID + TCI).
pub(super) const VLAN_TAG_LEN: usize = 4;

/// EtherType constants.
pub(super) const ETHERTYPE_ARP: u16 = 0x0806;
pub(super) const ETHERTYPE_IPV6: u16 = 0x86DD;
pub(super) const ETHERTYPE_VLAN: u16 = 0x8100;
