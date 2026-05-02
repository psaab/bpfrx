// #989: targeted unit tests for the relocated TCP helpers. Per
// design doc rev-3 §2.3, these directly exercise the parser-edge
// cases for clamp_tcp_mss that integration tests don't cover:
// MSS-not-at-start, malformed option lengths, EOL before MSS,
// multiple MSS options, IPv6 pseudo-header recompute, non-SYN
// no-op, and the no-op-when-already-smaller path.
//
// `clamp_tcp_mss` checksum sanity: every "mutated checksum is still
// valid" claim is verified by independent recomputation (sum the
// pseudo-header + TCP segment, verify the folded value is 0xFFFF).
// The incremental update path inside clamp_tcp_mss is not trusted
// blindly — these tests provide an oracle via from-scratch sum.

use super::*;

// ---------- Frame builders (Ethernet + IPv4/IPv6 + TCP) ----------

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// Build an Ethernet header with given EtherType (0x0800 v4, 0x86dd v6).
fn eth_header(ethertype: u16) -> [u8; ETH_HDR_LEN] {
    let mut eth = [0u8; ETH_HDR_LEN];
    // dst+src MAC zero, ethertype at offset 12.
    eth[12..14].copy_from_slice(&ethertype.to_be_bytes());
    eth
}

/// Build IPv4 header (no options, fixed 20-byte). Caller supplies
/// `total_len` (full IPv4 datagram length including this header)
/// and `protocol` (e.g. 6 for TCP).
fn ipv4_header(total_len: u16, protocol: u8) -> [u8; IPV4_HDR_LEN] {
    let mut ip = [0u8; IPV4_HDR_LEN];
    ip[0] = 0x45; // version=4, IHL=5
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    // header checksum computed by caller if needed
    ip
}

/// Build IPv6 header. `payload_len` is the L4+payload size.
fn ipv6_header(payload_len: u16, next_header: u8) -> [u8; IPV6_HDR_LEN] {
    let mut ip6 = [0u8; IPV6_HDR_LEN];
    ip6[0] = 0x60; // version=6
    ip6[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip6[6] = next_header;
    ip6[7] = 64; // hop limit
    // src = fe00::1, dst = fe00::2 — high byte 0xfe is just to
    // make the address recognizably non-zero in failure dumps.
    ip6[8] = 0xfe;
    ip6[8 + 15] = 0x01;
    ip6[24] = 0xfe;
    ip6[24 + 15] = 0x02;
    ip6
}

/// Build a 20-byte TCP header skeleton with the given flags.
/// `data_offset_dwords` is the data-offset field value (TCP header
/// length in 4-byte units, e.g. 5 for no options, 7 for 8 bytes
/// of options, etc.).
fn tcp_header_skeleton(flags: u8, data_offset_dwords: u8) -> [u8; 20] {
    let mut tcp = [0u8; 20];
    // src port 12345, dst port 80
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    // seq=1, ack=0
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    // data offset (high nibble of byte 12)
    tcp[12] = data_offset_dwords << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    // checksum at 16..18 set later
    tcp
}

/// Independent ones-complement TCP checksum: sums pseudo-header
/// (v4 or v6) + TCP segment bytes, returns the folded 16-bit value.
/// On a properly-checksummed segment this returns 0xFFFF.
fn checksum_tcp_v4(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    let tcp_len = tcp.len() as u16;
    let mut sum: u32 = 0;
    // Pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + tcp_len(2)
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    sum += u32::from(6u16); // protocol
    sum += u32::from(tcp_len);
    // TCP segment
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], tcp[i + 1]]));
        i += 2;
    }
    if i < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// IPv6 pseudo-header variant.
fn checksum_tcp_v6(src: [u8; 16], dst: [u8; 16], tcp: &[u8]) -> u16 {
    let tcp_len = tcp.len() as u32;
    let mut sum: u32 = 0;
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    sum += tcp_len; // 32-bit length
    sum += 6u32; // next header
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], tcp[i + 1]]));
        i += 2;
    }
    if i < tcp.len() {
        sum += u32::from(u16::from_be_bytes([tcp[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Set a v4 TCP segment's checksum so that
/// `checksum_tcp_v4(src, dst, tcp) == 0xFFFF`.
fn set_v4_tcp_checksum(tcp: &mut [u8], src: [u8; 4], dst: [u8; 4]) {
    tcp[16..18].copy_from_slice(&[0, 0]);
    let raw = checksum_tcp_v4(src, dst, tcp);
    let csum = !raw;
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
}

fn set_v6_tcp_checksum(tcp: &mut [u8], src: [u8; 16], dst: [u8; 16]) {
    tcp[16..18].copy_from_slice(&[0, 0]);
    let raw = checksum_tcp_v6(src, dst, tcp);
    let csum = !raw;
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
}

// ---------- frame_has_tcp_rst ----------

#[test]
fn frame_has_tcp_rst_true_when_rst_set() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(0x04, 5); // RST
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    assert!(frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_when_rst_clear() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(TCP_FLAG_SYN, 5);
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    assert!(!frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_for_non_tcp() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(28, 17); // UDP
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&[0u8; 8]); // UDP header
    assert!(!frame_has_tcp_rst(&frame));
}

#[test]
fn frame_has_tcp_rst_false_for_truncated() {
    // Only Ethernet + 5 bytes — too short for an IP header.
    let mut frame = Vec::with_capacity(20);
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&[0u8; 5]);
    assert!(!frame_has_tcp_rst(&frame));
}

// ---------- extract_tcp_flags_and_window ----------

#[test]
fn extract_tcp_flags_and_window_returns_syn_ack_window() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let mut tcp = tcp_header_skeleton(TCP_FLAG_SYN | TCP_FLAG_ACK, 5);
    tcp[14..16].copy_from_slice(&8192u16.to_be_bytes());
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    let (flags, window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(window, 8192);
}

#[test]
fn extract_tcp_flags_and_window_handles_fin_ack() {
    let eth = eth_header(0x0800);
    let ip = ipv4_header(40, 6);
    let tcp = tcp_header_skeleton(0x01 | TCP_FLAG_ACK, 5); // FIN+ACK
    let mut frame = Vec::with_capacity(54);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    let (flags, _window) = extract_tcp_flags_and_window(&frame).expect("Some");
    assert_eq!(flags, 0x01 | TCP_FLAG_ACK);
}

#[test]
fn extract_tcp_flags_and_window_returns_none_for_truncated() {
    let mut frame = Vec::with_capacity(28);
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&ipv4_header(20, 6)); // claims TCP but no TCP bytes follow
    assert!(extract_tcp_flags_and_window(&frame).is_none());
}

// ---------- extract_tcp_window ----------

#[test]
fn extract_tcp_window_v4_v6() {
    // v4
    let mut frame4 = Vec::new();
    frame4.extend_from_slice(&eth_header(0x0800));
    frame4.extend_from_slice(&ipv4_header(40, 6));
    let mut tcp4 = tcp_header_skeleton(0, 5);
    tcp4[14..16].copy_from_slice(&4096u16.to_be_bytes());
    frame4.extend_from_slice(&tcp4);
    assert_eq!(
        extract_tcp_window(&frame4, libc::AF_INET as u8),
        Some(4096)
    );
    // v6
    let mut frame6 = Vec::new();
    frame6.extend_from_slice(&eth_header(0x86dd));
    frame6.extend_from_slice(&ipv6_header(20, 6));
    let mut tcp6 = tcp_header_skeleton(0, 5);
    tcp6[14..16].copy_from_slice(&2048u16.to_be_bytes());
    frame6.extend_from_slice(&tcp6);
    assert_eq!(
        extract_tcp_window(&frame6, libc::AF_INET6 as u8),
        Some(2048)
    );
}

#[test]
fn extract_tcp_window_returns_none_for_truncated() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&ipv4_header(20, 6)); // no TCP bytes
    assert_eq!(extract_tcp_window(&frame, libc::AF_INET as u8), None);
}

// ---------- tcp_flags_str ----------

#[test]
fn tcp_flags_str_renders_zero_as_none() {
    assert_eq!(tcp_flags_str(0), "none");
}

#[test]
fn tcp_flags_str_renders_single_flag() {
    assert_eq!(tcp_flags_str(TCP_FLAG_SYN), "SYN");
    assert_eq!(tcp_flags_str(TCP_FLAG_ACK), "ACK");
    assert_eq!(tcp_flags_str(0x04), "RST");
}

#[test]
fn tcp_flags_str_renders_combinations() {
    assert_eq!(tcp_flags_str(TCP_FLAG_SYN | TCP_FLAG_ACK), "SYN ACK");
    assert_eq!(
        tcp_flags_str(TCP_FLAG_ACK | 0x08),
        "ACK PSH",
        "ACK+PSH ordering matches the in-source flag-iteration order"
    );
}

#[test]
fn tcp_flags_str_renders_all_flags() {
    let all = TCP_FLAG_SYN | TCP_FLAG_ACK | 0x01 | 0x04 | 0x08 | 0x20;
    assert_eq!(tcp_flags_str(all), "SYN ACK FIN RST PSH URG");
}

// ---------- clamp_tcp_mss: parser-edge cases ----------

/// Helper: build a v4 IP+TCP packet (no Ethernet header) with a
/// configurable TCP options trailer. `flags` controls the TCP
/// flags; `options` is appended after the 20-byte TCP header.
/// Returns the L3+L4 buffer plus the source/dst v4 addrs for
/// independent checksum verification.
fn build_v4_ip_tcp_with_options(flags: u8, options: &[u8]) -> (Vec<u8>, [u8; 4], [u8; 4]) {
    // TCP header is 20 bytes + options. data_offset = (20 + opts) / 4.
    let pad = (4 - (options.len() % 4)) % 4;
    let mut opts = options.to_vec();
    opts.resize(opts.len() + pad, 0); // pad with NOP-like zero bytes (EOL is fine)
    let tcp_total = 20 + opts.len();
    assert!(tcp_total % 4 == 0, "TCP header must be 4-byte aligned");
    let data_offset = (tcp_total / 4) as u8;

    let total_ip = (IPV4_HDR_LEN + tcp_total) as u16;
    let ip = ipv4_header(total_ip, 6);
    let mut tcp = vec![0u8; tcp_total];
    tcp[..20].copy_from_slice(&tcp_header_skeleton(flags, data_offset));
    tcp[20..].copy_from_slice(&opts);

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    set_v4_tcp_checksum(&mut tcp, src, dst);

    let mut packet = Vec::with_capacity(IPV4_HDR_LEN + tcp_total);
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(&tcp);
    (packet, src, dst)
}

fn build_v6_ip_tcp_with_options(flags: u8, options: &[u8]) -> (Vec<u8>, [u8; 16], [u8; 16]) {
    let pad = (4 - (options.len() % 4)) % 4;
    let mut opts = options.to_vec();
    opts.resize(opts.len() + pad, 0);
    let tcp_total = 20 + opts.len();
    let data_offset = (tcp_total / 4) as u8;
    let ip6 = ipv6_header(tcp_total as u16, 6);
    let mut tcp = vec![0u8; tcp_total];
    tcp[..20].copy_from_slice(&tcp_header_skeleton(flags, data_offset));
    tcp[20..].copy_from_slice(&opts);

    let mut src = [0u8; 16];
    src[0] = 0xfe;
    src[15] = 0x01;
    let mut dst = [0u8; 16];
    dst[0] = 0xfe;
    dst[15] = 0x02;
    set_v6_tcp_checksum(&mut tcp, src, dst);

    let mut packet = Vec::with_capacity(IPV6_HDR_LEN + tcp_total);
    packet.extend_from_slice(&ip6);
    packet.extend_from_slice(&tcp);
    (packet, src, dst)
}

/// Strip the L3 header from a packet so the MSS-option assertions
/// can index into the TCP segment directly.
fn tcp_segment_v4(packet: &[u8]) -> &[u8] {
    &packet[IPV4_HDR_LEN..]
}

#[test]
fn clamp_tcp_mss_clamps_when_mss_at_start_of_options() {
    // MSS option (kind=2, len=4, value=1460) at TCP offset 20.
    let opts = [2, 4, 0x05, 0xb4]; // 1460 BE
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(clamped, "MSS 1460 > 1200 → must clamp");

    // MSS bytes at TCP offset 22..24 are now 1200.
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);

    // Independent checksum recompute.
    let folded = checksum_tcp_v4(src, dst, tcp);
    assert_eq!(
        folded, 0xFFFF,
        "post-clamp TCP checksum must independently fold to 0xFFFF"
    );
}

#[test]
fn clamp_tcp_mss_walks_past_nop_and_timestamp_to_find_mss() {
    // NOP NOP TIMESTAMP(8) MSS(4) — MSS NOT at start.
    let opts = [
        1, 1, // 2x NOP
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // TS option (kind=8, len=10)
        2, 4, 0x05, 0xb4, // MSS=1460
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    assert!(clamp_tcp_mss(&mut packet, 1300));
    let tcp = tcp_segment_v4(&packet);
    // MSS option is at TCP offset 20 + 2 + 10 = 32; value at 34..36.
    assert_eq!(u16::from_be_bytes([tcp[34], tcp[35]]), 1300);
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_eol_before_mss_is_no_op() {
    // EOL (kind=0) terminates options before MSS — clamp must skip.
    let opts = [
        0, 0, 0, 0, // EOL + padding
        2, 4, 0x05, 0xb4, // MSS option (unreachable due to EOL)
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "EOL before MSS → clamp must be a no-op");
    assert_eq!(packet, pre, "no bytes mutated when MSS unreachable");
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp),
        0xFFFF,
        "checksum unchanged"
    );
}

#[test]
fn clamp_tcp_mss_first_mss_only_when_multiple_present() {
    // Two MSS options. clamp_tcp_mss returns after rewriting the
    // first match; second one stays untouched. (This documents
    // current behavior — the parser is not RFC-strict on multiples.)
    let opts = [
        2, 4, 0x05, 0xb4, // MSS=1460 (first)
        2, 4, 0x05, 0xb4, // MSS=1460 (second)
    ];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    assert!(clamp_tcp_mss(&mut packet, 1200));
    let tcp = tcp_segment_v4(&packet);
    assert_eq!(
        u16::from_be_bytes([tcp[22], tcp[23]]),
        1200,
        "first MSS clamped"
    );
    assert_eq!(
        u16::from_be_bytes([tcp[26], tcp[27]]),
        1460,
        "second MSS untouched (parser stops at first)"
    );
    // Checksum was incrementally adjusted only for the first
    // rewrite — but the second MSS field's bytes are unchanged, so
    // the segment as a whole still folds correctly when summed
    // against the new value.
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_malformed_option_length_bails_safely() {
    // kind=42 (unknown) with len=0 → would loop infinitely if not
    // guarded; len=1 is also invalid (must be >= 2). Both must
    // cause the parser to break out without clamping or panicking.
    let opts_len0 = [42, 0, 0, 0];
    let (mut packet, _, _) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts_len0);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped);
    assert_eq!(packet, pre);

    let opts_len1 = [42, 1, 2, 4];
    let (mut packet, _, _) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts_len1);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped);
    assert_eq!(packet, pre);
}

#[test]
fn clamp_tcp_mss_opt_len_past_data_offset_bails() {
    // Gemini round-2 gap: a TCP option whose length field walks
    // PAST the end of the TCP-options region (pos + opt_len >
    // data_offset) must cause the parser to break out, not OOB.
    //
    // Construct: a single option at TCP offset 20 with kind=42 and
    // len=20. data_offset for a 24-byte TCP header = 6 dwords, so
    // the options region is exactly 4 bytes (20..24). An opt_len of
    // 20 takes pos=20+20=40, which is well past data_offset=24.
    // The parser must hit the `pos + opt_len > data_offset` branch
    // at the bounds check inside clamp_tcp_mss and break out
    // without rewriting anything or panicking.
    let opts = [42, 20, 0xaa, 0xbb]; // kind=42, malformed len=20
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 100);
    assert!(!clamped, "opt_len past data_offset → no rewrite");
    assert_eq!(
        packet, pre,
        "no bytes mutated when option length walks past options end"
    );
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)),
        0xFFFF,
        "checksum unchanged on parser bail-out"
    );
}

#[test]
fn clamp_tcp_mss_non_syn_is_no_op() {
    // ACK-only (no SYN bit) → clamp_tcp_mss must not touch.
    let opts = [2, 4, 0x05, 0xb4];
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_ACK, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "non-SYN must be no-op");
    assert_eq!(packet, pre);
    assert_eq!(checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_no_op_when_mss_already_smaller() {
    // current_mss = 1000, max_mss = 1200 → no rewrite.
    let opts = [2, 4, 0x03, 0xe8]; // MSS=1000
    let (mut packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let pre = packet.clone();
    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(!clamped, "MSS 1000 <= 1200 → no rewrite");
    assert_eq!(packet, pre, "bytes unchanged on no-op");
    assert_eq!(
        checksum_tcp_v4(src, dst, tcp_segment_v4(&packet)),
        0xFFFF,
        "checksum unchanged on no-op"
    );
}

#[test]
fn clamp_tcp_mss_v6_recomputes_with_pseudoheader() {
    let opts = [2, 4, 0x05, 0xb4];
    let (mut packet, src, dst) = build_v6_ip_tcp_with_options(TCP_FLAG_SYN, &opts);

    let clamped = clamp_tcp_mss(&mut packet, 1200);
    assert!(clamped, "IPv6 SYN with MSS=1460 → must clamp to 1200");

    let tcp = &packet[IPV6_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    // IPv6 pseudo-header recompute: must still fold to 0xFFFF.
    assert_eq!(
        checksum_tcp_v6(src, dst, tcp),
        0xFFFF,
        "post-clamp v6 TCP checksum must fold to 0xFFFF with IPv6 pseudo-header"
    );
}

// ---------- clamp_tcp_mss_frame ----------

#[test]
fn clamp_tcp_mss_frame_clamps_full_ethernet_frame_v4() {
    let opts = [2, 4, 0x05, 0xb4];
    let (l3_packet, src, dst) = build_v4_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let mut frame = Vec::with_capacity(ETH_HDR_LEN + l3_packet.len());
    frame.extend_from_slice(&eth_header(0x0800));
    frame.extend_from_slice(&l3_packet);

    let clamped = clamp_tcp_mss_frame(&mut frame, ETH_HDR_LEN, 1200);
    assert!(clamped);
    let tcp = &frame[ETH_HDR_LEN + IPV4_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    assert_eq!(checksum_tcp_v4(src, dst, tcp), 0xFFFF);
}

#[test]
fn clamp_tcp_mss_frame_clamps_full_ethernet_frame_v6() {
    let opts = [2, 4, 0x05, 0xb4];
    let (l3_packet, src, dst) = build_v6_ip_tcp_with_options(TCP_FLAG_SYN, &opts);
    let mut frame = Vec::with_capacity(ETH_HDR_LEN + l3_packet.len());
    frame.extend_from_slice(&eth_header(0x86dd));
    frame.extend_from_slice(&l3_packet);

    let clamped = clamp_tcp_mss_frame(&mut frame, ETH_HDR_LEN, 1200);
    assert!(clamped);
    let tcp = &frame[ETH_HDR_LEN + IPV6_HDR_LEN..];
    assert_eq!(u16::from_be_bytes([tcp[22], tcp[23]]), 1200);
    assert_eq!(checksum_tcp_v6(src, dst, tcp), 0xFFFF);
}
