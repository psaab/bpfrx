// #963 PR-B: pin the byte-write helpers' offset semantics. These
// helpers do nothing but copy bytes, so the tests check exact
// byte positions and the surrounding unmodified bytes (so a
// future refactor that drifts offsets surfaces here).

use super::*;

const ZERO_FRAME_LEN: usize = 64;

fn zero_frame() -> Vec<u8> {
    vec![0u8; ZERO_FRAME_LEN]
}

#[test]
fn write_ipv4_src_writes_at_ip_plus_12() {
    let mut packet = zero_frame();
    let ip = 14; // typical Ethernet header offset
    write_ipv4_src(&mut packet, ip, Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(&packet[ip + 12..ip + 16], &[10, 0, 1, 2]);
    // Surrounding bytes untouched
    assert_eq!(&packet[..ip + 12], &[0u8; 26]);
    assert_eq!(&packet[ip + 16..], &[0u8; 34]);
}

#[test]
fn write_ipv4_dst_writes_at_ip_plus_16() {
    let mut packet = zero_frame();
    let ip = 14;
    write_ipv4_dst(&mut packet, ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(&packet[ip + 16..ip + 20], &[192, 168, 1, 1]);
    assert_eq!(&packet[..ip + 16], &[0u8; 30]);
    assert_eq!(&packet[ip + 20..], &[0u8; 30]);
}

#[test]
fn write_ipv6_src_writes_at_ip_plus_8() {
    let mut packet = vec![0u8; 128];
    let ip = 14;
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    write_ipv6_src(&mut packet, ip, addr);
    assert_eq!(&packet[ip + 8..ip + 24], &addr.octets());
    assert_eq!(&packet[..ip + 8], &[0u8; 22]);
    // 128-byte frame, ip+24 = 38 → 128-38 = 90 trailing bytes.
    assert_eq!(&packet[ip + 24..], &[0u8; 90]);
}

#[test]
fn write_ipv6_dst_writes_at_ip_plus_24() {
    let mut packet = vec![0u8; 128];
    let ip = 14;
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    write_ipv6_dst(&mut packet, ip, addr);
    assert_eq!(&packet[ip + 24..ip + 40], &addr.octets());
    assert_eq!(&packet[..ip + 24], &[0u8; 38]);
    // 128-byte frame, ip+40 = 54 → 128-54 = 74 trailing bytes.
    assert_eq!(&packet[ip + 40..], &[0u8; 74]);
}

#[test]
fn write_l4_src_port_writes_be_at_l4() {
    let mut packet = zero_frame();
    let l4 = 34; // typical TCP-after-IPv4 offset
    write_l4_src_port(&mut packet, l4, 0x1234);
    assert_eq!(&packet[l4..l4 + 2], &[0x12, 0x34]);
    // Surrounding bytes untouched (matches the IPv4/IPv6 test discipline).
    assert_eq!(&packet[..l4], &[0u8; 34]);
    assert_eq!(&packet[l4 + 2..], &[0u8; 28]);
}

#[test]
fn write_l4_dst_port_writes_be_at_l4_plus_2() {
    let mut packet = zero_frame();
    let l4 = 34;
    write_l4_dst_port(&mut packet, l4, 0xabcd);
    assert_eq!(&packet[l4 + 2..l4 + 4], &[0xab, 0xcd]);
    // Bytes before l4+2 (including src-port slot) and after l4+4 untouched.
    assert_eq!(&packet[..l4 + 2], &[0u8; 36]);
    assert_eq!(&packet[l4 + 4..], &[0u8; 26]);
}

#[test]
fn write_l4_src_port_skips_truncated_frame() {
    // packet is exactly l4+1 long → write would need l4+2; skip.
    let l4 = 10;
    let mut packet = vec![0u8; l4 + 1];
    write_l4_src_port(&mut packet, l4, 0xffff);
    assert_eq!(packet[l4], 0, "truncated frame: write must be skipped");
}

#[test]
fn write_l4_dst_port_skips_truncated_frame() {
    // packet is exactly l4+3 long → write would need l4+4; skip.
    let l4 = 10;
    let mut packet = vec![0u8; l4 + 3];
    write_l4_dst_port(&mut packet, l4, 0xffff);
    assert_eq!(&packet[l4..l4 + 3], &[0u8; 3]);
}
