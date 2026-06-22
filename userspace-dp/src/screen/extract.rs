//! Allocation-free extraction of screen-relevant fields from raw
//! packet bytes plus the upstream parser's metadata. Parses just
//! enough of IPv4/IPv6 + TCP options to populate `ScreenPacketInfo`.

use std::net::IpAddr;

use super::packet::{PROTO_TCP, ScreenPacketInfo, ScreenParseError};

/// Extract screen-relevant fields from raw packet bytes and metadata.
/// This avoids full packet parsing — just reads the fields needed for checks.
///
/// Returns `Err(ScreenParseError)` when the L3 header cannot be parsed
/// far enough to evaluate the fragment/TCP screens (#2146). The caller
/// MUST treat an `Err` as FAIL-CLOSED (drop). A truncated IPv6
/// extension-header chain used to `break` out of the walk silently and
/// leave `is_first_fragment=false`, which let a SYN-bearing frame with
/// a truncated FRAGMENT header bypass the `syn-frag` screen — the exact
/// IDS-evasion the screen claims to defend against now that the BPF
/// screen path (#1373/#1476) that masked it is gone.
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
) -> Result<ScreenPacketInfo, ScreenParseError> {
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
        ip_payload_len: 0,
        frag_data_off: 0,
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
    } else if addr_family == libc::AF_INET6 as u8 {
        // IPv6: walk the extension header chain looking for
        // NEXTHDR_FRAGMENT (44). Fixed IPv6 base header is 40 bytes.
        // We bound the walk to MAX_EXT_HDRS=8 like the BPF parser.
        //
        // FAIL-CLOSED (#2146): every place the walk runs out of bytes
        // (the base header is short, or an extension header's declared
        // length runs past the captured frame) returns
        // `Err(TruncatedIpv6ExtChain)`. Returning defaults here would
        // leave `is_first_fragment=false` and let a SYN-bearing frame
        // with a truncated FRAGMENT header bypass the `syn-frag`
        // screen. The legacy BPF `parse_ipv6hdr` returned -1 (drop)
        // on the same condition; with the BPF screen path retired
        // (#1373/#1476) the extractor is the only enforcement point.
        if l3_offset + 40 > frame.len() {
            return Err(ScreenParseError::TruncatedIpv6ExtChain);
        }
        // #2293: IPv6 payload-length field (bytes 4-5 of the 40-byte base
        // header) — the length of everything after the base header
        // (extension headers + L4 + data). The ping-of-death check uses
        // it with `frag_data_off` to size a fragment's contribution to
        // the reassembled datagram.
        info.ip_payload_len = u16::from_be_bytes([frame[l3_offset + 4], frame[l3_offset + 5]]);
        const NEXTHDR_HOP: u8 = 0;
        const NEXTHDR_ROUTING: u8 = 43;
        const NEXTHDR_FRAGMENT: u8 = 44;
        const NEXTHDR_DEST: u8 = 60;
        const NEXTHDR_AUTH: u8 = 51;
        let mut nexthdr = frame[l3_offset + 6];
        let mut offset = l3_offset + 40;
        for _ in 0..8 {
            // FAIL-CLOSED (#2146/#2189): an intermediate extension header
            // can advance `offset` past the captured frame using its own
            // DECLARED length (HOP/ROUTING/DEST `hdr_ext_len`, AUTH
            // `payload_len`). The terminal arms below (`NEXTHDR_FRAGMENT`,
            // `PROTO_TCP`, `_`) read or trust `offset`, so re-validate it
            // at the TOP of every iteration before any arm runs. Without
            // this, a base NextHdr=HOP-BY-HOP with HdrExtLen=200 jumps
            // `offset` far past `frame.len()`, then an inner NextHdr=TCP
            // hits `PROTO_TCP`, sets `tcp_offset=Some(offset)` and breaks
            // with `Ok{is_first_fragment:false}` — a SYN bypasses the
            // `syn-frag` screen (the IDS evasion #2146 set out to close).
            if offset > frame.len() {
                return Err(ScreenParseError::TruncatedIpv6ExtChain);
            }
            match nexthdr {
                NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => {
                    if offset + 2 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 1) * 8;
                }
                NEXTHDR_AUTH => {
                    if offset + 2 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 2) * 4;
                }
                NEXTHDR_FRAGMENT => {
                    if offset + 8 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    // IPv6 frag_off layout (big-endian u16 at offset+2):
                    //   offset (13 bits, top) | reserved (2 bits) | M (1 bit, lowest)
                    // Mirrors BPF #866: MF=0x1, offset=0xFFF8.
                    let frag_off = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    info.ip_frag_off = frag_off;
                    info.is_fragment = (frag_off & 0x1) != 0 || (frag_off & 0xFFF8) != 0;
                    info.is_first_fragment = (frag_off & 0x1) != 0 && (frag_off & 0xFFF8) == 0;
                    // #2293: payload-region bytes that precede THIS
                    // fragment's data — every extension header up to and
                    // including this 8-byte fragment header. `offset + 8`
                    // is the frame position of the fragment payload;
                    // subtract the base-header end (`l3_offset + 40`) to
                    // get the payload-region offset of the fragment data.
                    // `ip_payload_len - frag_data_off` is then the L4/data
                    // bytes this fragment carries. Saturating: a hostile
                    // chain whose declared payload_len is smaller than the
                    // headers we walked yields 0 contribution, never an
                    // underflow.
                    info.frag_data_off =
                        ((offset + 8).saturating_sub(l3_offset + 40)) as u16;
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

    Ok(info)
}
