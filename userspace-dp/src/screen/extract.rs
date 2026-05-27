//! Allocation-free extraction of screen-relevant fields from raw
//! packet bytes plus the upstream parser's metadata. Parses just
//! enough of IPv4/IPv6 + TCP options to populate `ScreenPacketInfo`.

use std::net::IpAddr;

use super::packet::{PROTO_TCP, ScreenPacketInfo};

/// Extract screen-relevant fields from raw packet bytes and metadata.
/// This avoids full packet parsing — just reads the fields needed for checks.
pub(crate) fn extract_screen_info(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    pkt_len: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    l3_offset: usize,
) -> ScreenPacketInfo {
    let mut info = ScreenPacketInfo {
        addr_family,
        protocol,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
    };

    let mut tcp_offset: Option<usize> = None;

    if addr_family == libc::AF_INET as u8 && l3_offset + 20 <= frame.len() {
        // IPv4: extract IHL, total_len, frag_off from the fixed 20-byte
        // base header. frag_off is bytes 6-7, big-endian.
        let ip_hdr = &frame[l3_offset..];
        info.ip_ihl = ip_hdr[0] & 0x0F;
        info.ip_total_len = u16::from_be_bytes([ip_hdr[2], ip_hdr[3]]);
        info.ip_frag_off = u16::from_be_bytes([ip_hdr[6], ip_hdr[7]]);
        // Fragment if MF bit (0x2000) set OR fragment offset (0x1FFF) > 0.
        // First fragment: MF=1 AND offset==0 (#1137, mirrors BPF #866).
        info.is_fragment = (info.ip_frag_off & 0x3FFF) != 0;
        info.is_first_fragment =
            (info.ip_frag_off & 0x2000) != 0 && (info.ip_frag_off & 0x1FFF) == 0;
        tcp_offset = Some(l3_offset + (info.ip_ihl as usize) * 4);
    } else if addr_family == libc::AF_INET6 as u8 && l3_offset + 40 <= frame.len() {
        // IPv6: walk the extension header chain looking for
        // NEXTHDR_FRAGMENT (44). Fixed IPv6 base header is 40 bytes.
        // We bound the walk to MAX_EXT_HDRS=8 like the BPF parser.
        //
        // Parity note (#1137 / Codex round-1): if the chain is
        // truncated (out-of-bounds before we find a FRAGMENT
        // header), we silently `break` and leave is_first_fragment
        // at its default `false`. The BPF `parse_ipv6hdr` returns
        // -1 on the same condition, causing the packet to be
        // dropped earlier in the pipeline. On the userspace-dp
        // path the upstream metadata parser (try_parse_metadata)
        // should already have rejected malformed IPv6 packets
        // before they reach extract_screen_info, so the parity
        // gap is theoretical. If a SYN-bearing IPv6 frame with a
        // truncated FRAGMENT header somehow reaches the screen
        // layer, it would pass syn_frag — operators relying on
        // that defense should keep the BPF screen path enabled
        // upstream of userspace-dp.
        const NEXTHDR_HOP: u8 = 0;
        const NEXTHDR_ROUTING: u8 = 43;
        const NEXTHDR_FRAGMENT: u8 = 44;
        const NEXTHDR_DEST: u8 = 60;
        const NEXTHDR_AUTH: u8 = 51;
        let mut nexthdr = frame[l3_offset + 6];
        let mut offset = l3_offset + 40;
        for _ in 0..8 {
            match nexthdr {
                NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => {
                    if offset + 2 > frame.len() {
                        break;
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 1) * 8;
                }
                NEXTHDR_AUTH => {
                    if offset + 2 > frame.len() {
                        break;
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 2) * 4;
                }
                NEXTHDR_FRAGMENT => {
                    if offset + 8 > frame.len() {
                        break;
                    }
                    // IPv6 frag_off layout (big-endian u16 at offset+2):
                    //   offset (13 bits, top) | reserved (2 bits) | M (1 bit, lowest)
                    // Mirrors BPF #866: MF=0x1, offset=0xFFF8.
                    let frag_off = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    info.ip_frag_off = frag_off;
                    info.is_fragment = (frag_off & 0x1) != 0 || (frag_off & 0xFFF8) != 0;
                    info.is_first_fragment = (frag_off & 0x1) != 0 && (frag_off & 0xFFF8) == 0;
                    if frame[offset] == PROTO_TCP {
                        tcp_offset = Some(offset + 8);
                    }
                    break;
                }
                PROTO_TCP => {
                    tcp_offset = Some(offset);
                    break;
                }
                _ => break,
            }
        }
    }

    if protocol == PROTO_TCP
        && (!info.is_fragment || info.is_first_fragment)
        && let Some(tcp_start) = tcp_offset
        && tcp_start + 20 <= frame.len()
    {
        let tcp = &frame[tcp_start..];
        info.tcp_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        info.tcp_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        if data_offset >= 20 && tcp.len() >= data_offset {
            let mut pos = 20;
            while pos < data_offset {
                let kind = tcp[pos];
                if kind == 0 {
                    break;
                }
                if kind == 1 {
                    pos += 1;
                    continue;
                }
                if pos + 2 > data_offset {
                    break;
                }
                let opt_len = tcp[pos + 1] as usize;
                if opt_len < 2 || pos + opt_len > data_offset {
                    break;
                }
                if kind == 2 && opt_len == 4 {
                    info.tcp_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
                    break;
                }
                pos += opt_len;
            }
        }
    }

    info
}
