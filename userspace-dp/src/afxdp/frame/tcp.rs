//! TCP-specific inspection + mutation kernels (#989).
//!
//! Per the design doc (docs/pr/989-l4-specializations/design.md
//! rev-3), this module owns:
//!
//!  - TCP-flag/window/RST inspection helpers (read-only, no side
//!    effects), previously scattered in `frame/inspect.rs`.
//!  - TCP MSS-clamping byte-mutation kernels, previously in
//!    `forwarding/mod.rs`. These walk TCP options, rewrite the MSS
//!    field for SYN/SYN+ACK only, and incrementally update the TCP
//!    checksum.
//!
//! Pure relocation: bodies are byte-for-byte identical to the
//! pre-move sources. Visibility is preserved
//! (`pub(in crate::afxdp)` for the inspection helpers that were
//! previously crate-internal; `pub(super)` for the clamp helpers
//! that were previously `forwarding/mod.rs`-internal).
//!
//! `#[inline]` is applied to every fn so the move does not regress
//! cross-codegen-unit inlining at the hot call sites in
//! `frame/mod.rs`. With the default `codegen-units > 1`, an
//! un-annotated cross-module call cannot be guaranteed to inline
//! without LTO; `#[inline]` emits the body into every CGU that
//! references it.

use super::*;

/// Check if a frame contains a TCP RST flag.
#[inline(always)]
pub(in crate::afxdp) fn frame_has_tcp_rst(frame: &[u8]) -> bool {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return false,
    };
    let ip = match frame.get(l3..) {
        Some(ip) if ip.len() >= 20 => ip,
        _ => return false,
    };
    let (protocol, l4_offset) = match ip[0] >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 if ip.len() >= 40 => (ip[6], 40usize),
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13: RST = 0x04
    (tcp[13] & 0x04) != 0
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
#[inline]
pub(in crate::afxdp) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some((flags, window))
}

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
#[inline]
#[allow(dead_code)]
pub(in crate::afxdp) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        libc::AF_INET6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    // TCP window is at offset 14-15 (big-endian)
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

#[inline]
pub(in crate::afxdp) fn tcp_flags_str(flags: u8) -> String {
    let mut s = String::with_capacity(12);
    if flags & 0x02 != 0 {
        s.push_str("SYN ");
    }
    if flags & 0x10 != 0 {
        s.push_str("ACK ");
    }
    if flags & 0x01 != 0 {
        s.push_str("FIN ");
    }
    if flags & 0x04 != 0 {
        s.push_str("RST ");
    }
    if flags & 0x08 != 0 {
        s.push_str("PSH ");
    }
    if flags & 0x20 != 0 {
        s.push_str("URG ");
    }
    if s.ends_with(' ') {
        s.truncate(s.len() - 1);
    }
    if s.is_empty() {
        s.push_str("none");
    }
    s
}

/// Clamp the TCP MSS option of a SYN / SYN+ACK packet to `max_mss`.
/// `packet` is the L3+L4 view (no Ethernet header); `max_mss` is
/// the maximum allowed MSS value. Returns `true` iff the MSS was
/// rewritten (and the TCP checksum incrementally updated).
///
/// No-ops on:
///   - non-TCP packets
///   - packets shorter than the IPv4/IPv6 header
///   - non-SYN packets (ACK-only, FIN-only, etc.)
///   - frames where the MSS option is absent or already <= max_mss
///   - malformed TCP options (length=0, length=1, or option past
///     data_offset boundary)
#[inline]
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if max_mss == 0 {
        return false;
    }
    // Determine L3 header length and protocol.
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    let (l4_offset, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            (40, packet[6])
        }
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match packet.get_mut(l4_offset..) {
        Some(s) if s.len() >= 20 => s,
        _ => return false,
    };
    let flags = tcp[13];
    // Only clamp on SYN or SYN+ACK
    if (flags & 0x02) == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return false;
    }
    // Walk TCP options looking for MSS (kind=2, len=4)
    let mut pos = 20;
    while pos + 4 <= data_offset {
        let kind = tcp[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        let opt_len = tcp[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let current_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
            if current_mss > max_mss {
                // Clamp MSS and adjust TCP checksum
                let old_bytes = [tcp[pos + 2], tcp[pos + 3]];
                tcp[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental TCP checksum update per RFC 1624:
                //   HC' = HC + m + ~m'  (ones-complement, end-around carry)
                // The result is stored directly; no further negation.
                let old_val = u16::from_be_bytes(old_bytes) as u32;
                let new_val = max_mss as u32;
                let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]) as u32;
                let mut sum = old_csum + old_val + (!new_val & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                tcp[16..18].copy_from_slice(&(sum as u16).to_be_bytes());
                return true;
            }
            return false;
        }
        pos += opt_len;
    }
    false
}

/// Clamp TCP MSS in a full Ethernet frame starting at `l3_offset`.
#[inline(always)]
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
