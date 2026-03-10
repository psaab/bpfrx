#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, xdp_md},
    helpers::r#gen::{bpf_ktime_get_ns, bpf_xdp_adjust_meta},
    macros::{map, xdp},
    maps::{Array, HashMap, ProgramArray, XskMap},
    programs::XdpContext,
};
use core::mem;

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 3;
const USERSPACE_BINDING_READY: u32 = 1;
const USERSPACE_FALLBACK_MAIN: u32 = 0;
const USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS: u32 = 5000;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const MAX_EXT_HDRS: usize = 6;
const NEXTHDR_HOP: u8 = 0;
const NEXTHDR_ROUTING: u8 = 43;
const NEXTHDR_FRAGMENT: u8 = 44;
const NEXTHDR_AUTH: u8 = 51;
const NEXTHDR_DEST: u8 = 60;
const NEXTHDR_NONE: u8 = 59;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceCtrl {
    enabled: u32,
    metadata_version: u32,
    workers: u32,
    flags: u32,
    config_generation: u64,
    fib_generation: u32,
    heartbeat_timeout_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceDpMeta {
    magic: u32,
    version: u16,
    length: u16,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    ingress_vlan_id: u16,
    ingress_zone: u16,
    routing_table: u32,
    l3_offset: u16,
    l4_offset: u16,
    payload_offset: u16,
    pkt_len: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    meta_flags: u8,
    dscp: u8,
    dscp_rewrite: u8,
    reserved: u16,
    flow_src_port: u16,
    flow_dst_port: u16,
    flow_src_addr: [u8; 16],
    flow_dst_addr: [u8; 16],
    config_generation: u64,
    fib_generation: u32,
    reserved2: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceBindingKey {
    ifindex: u32,
    queue_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceBindingValue {
    slot: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceLocalV6Key {
    addr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VlanHdr {
    tci: u16,
    encapsulated_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6OptHdr {
    nexthdr: u8,
    hdrlen: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FragHdr {
    nexthdr: u8,
    reserved: u8,
    frag_off: u16,
    identification: u32,
}

#[map(name = "userspace_ctrl")]
static USERSPACE_CTRL: Array<UserspaceCtrl> = Array::with_max_entries(1, 0);

#[map(name = "userspace_bindings")]
static USERSPACE_BINDINGS: HashMap<UserspaceBindingKey, UserspaceBindingValue> =
    HashMap::with_max_entries(4096, 0);

#[map(name = "userspace_heartbeat")]
static USERSPACE_HEARTBEAT: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map(name = "userspace_xsk_map")]
static USERSPACE_XSK_MAP: XskMap = XskMap::with_max_entries(4096, 0);

#[map(name = "userspace_local_v4")]
static USERSPACE_LOCAL_V4: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_local_v6")]
static USERSPACE_LOCAL_V6: HashMap<UserspaceLocalV6Key, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_fallback_progs")]
static USERSPACE_FALLBACK_PROGS: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[xdp]
pub fn xdp_userspace_prog(ctx: XdpContext) -> u32 {
    match try_xdp_userspace(&ctx) {
        Ok(ret) => ret,
        Err(_) => pass_to_kernel_or_abort(),
    }
}

fn try_xdp_userspace(ctx: &XdpContext) -> Result<u32, i64> {
    let ctrl = USERSPACE_CTRL.get(0).ok_or(0i64)?;
    if ctrl.enabled == 0 || ctrl.metadata_version != USERSPACE_META_VERSION as u32 {
        return fallback_to_main(ctx);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some((eth_proto, vlan_id, l3_offset)) = parse_l2(data, data_end) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let parsed = match eth_proto {
        ETH_P_IP => parse_ipv4(data, data_end, vlan_id, l3_offset),
        ETH_P_IPV6 => parse_ipv6(data, data_end, vlan_id, l3_offset),
        _ => return Ok(xdp_action::XDP_PASS),
    };
    let Some(parsed) = parsed else {
        return fallback_to_main(ctx);
    };

    let ingress_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let rx_queue_index = unsafe { (*ctx.ctx).rx_queue_index };
    let binding_key = UserspaceBindingKey {
        ifindex: ingress_ifindex,
        queue_id: rx_queue_index,
    };
    let binding = unsafe { USERSPACE_BINDINGS.get(&binding_key) };
    let Some(binding) = binding else {
        return fallback_to_main(&ctx);
    };
    if (binding.flags & USERSPACE_BINDING_READY) == 0 {
        return fallback_to_main(&ctx);
    }
    let last_heartbeat = unsafe { USERSPACE_HEARTBEAT.get(&binding.slot) };
    let Some(last_heartbeat) = last_heartbeat else {
        return fallback_to_main(ctx);
    };
    let timeout_ms = if ctrl.heartbeat_timeout_ms == 0 {
        USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS
    } else {
        ctrl.heartbeat_timeout_ms
    };
    let timeout_ns = (timeout_ms as u64) * 1_000_000;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if now_ns < *last_heartbeat || now_ns.saturating_sub(*last_heartbeat) > timeout_ns {
        return fallback_to_main(ctx);
    }

    let packet_len = data_end.saturating_sub(data);
    if should_fallback_early(&parsed) {
        return fallback_to_main(ctx);
    }
    if is_local_destination(&parsed) {
        return fallback_to_main(ctx);
    }
    let meta_len = mem::size_of::<UserspaceDpMeta>() as i32;
    let adjust_rc = unsafe { bpf_xdp_adjust_meta(ctx.ctx as *mut xdp_md, -meta_len) };
    if adjust_rc != 0 {
        return fallback_to_main(ctx);
    }

    let meta_ptr = ctx.metadata() as *mut UserspaceDpMeta;
    if (meta_ptr as usize).saturating_add(mem::size_of::<UserspaceDpMeta>()) > ctx.metadata_end() {
        return fallback_to_main(ctx);
    }

    unsafe {
        *meta_ptr = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex,
            rx_queue_index,
            ingress_vlan_id: parsed.vlan_id,
            ingress_zone: 0,
            routing_table: 0,
            l3_offset: parsed.l3_offset,
            l4_offset: parsed.l4_offset,
            payload_offset: parsed.payload_offset,
            pkt_len: packet_len.min(u16::MAX as usize) as u16,
            addr_family: parsed.addr_family,
            protocol: parsed.protocol,
            tcp_flags: parsed.tcp_flags,
            meta_flags: 0,
            dscp: parsed.dscp,
            dscp_rewrite: 0xff,
            reserved: 0,
            flow_src_port: parsed.flow_src_port,
            flow_dst_port: parsed.flow_dst_port,
            flow_src_addr: parsed.src_addr,
            flow_dst_addr: parsed.dst_addr,
            config_generation: ctrl.config_generation,
            fib_generation: ctrl.fib_generation,
            reserved2: 0,
        };
    }

    match USERSPACE_XSK_MAP.redirect(binding.slot, 0) {
        Ok(action) => Ok(action),
        Err(_) => fallback_to_main(ctx),
    }
}

fn fallback_to_main(ctx: &XdpContext) -> Result<u32, i64> {
    unsafe {
        let _ = USERSPACE_FALLBACK_PROGS.tail_call(ctx, USERSPACE_FALLBACK_MAIN);
    }
    Ok(xdp_action::XDP_DROP)
}

fn pass_to_kernel_or_abort() -> u32 {
    xdp_action::XDP_PASS
}

#[derive(Clone, Copy)]
struct ParsedPacket {
    vlan_id: u16,
    l3_offset: u16,
    l4_offset: u16,
    payload_offset: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    flow_src_port: u16,
    flow_dst_port: u16,
    dscp: u8,
    src_addr: [u8; 16],
    dst_v4: u32,
    dst_v6: [u8; 16],
    dst_addr: [u8; 16],
}

fn parse_l2(data: usize, data_end: usize) -> Option<(u16, u16, u16)> {
    let eth = read_bytes(data, data_end, 0, 14)?;
    let mut eth_proto = u16::from_be_bytes([eth[12], eth[13]]);
    let mut l3_offset = mem::size_of::<EthHdr>() as u16;
    let mut vlan_id = 0u16;

    if eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD {
        let vlan = read_bytes(data, data_end, l3_offset as usize, 4)?;
        vlan_id = u16::from_be_bytes([vlan[0], vlan[1]]) & 0x0fff;
        eth_proto = u16::from_be_bytes([vlan[2], vlan[3]]);
        l3_offset += mem::size_of::<VlanHdr>() as u16;
    }

    Some((eth_proto, vlan_id, l3_offset))
}

fn parse_ipv4(data: usize, data_end: usize, vlan_id: u16, l3_offset: u16) -> Option<ParsedPacket> {
    let iph = read_bytes(data, data_end, l3_offset as usize, 20)?;
    let version_ihl = iph[0];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    read_bytes(data, data_end, l3_offset as usize, ihl)?;
    let protocol = iph[9];
    let tos = iph[1];
    let l4_offset = l3_offset.checked_add(ihl as u16)?;
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port) =
        parse_l4(data, data_end, l4_offset, protocol)?;
    let src_bytes = read_bytes(data, data_end, l3_offset as usize + 12, 4)?;
    let dst_bytes = read_bytes(data, data_end, l3_offset as usize + 16, 4)?;
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(src_bytes);
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(dst_bytes);
    Some(ParsedPacket {
        vlan_id,
        l3_offset,
        l4_offset,
        payload_offset,
        addr_family: AF_INET,
        protocol,
        tcp_flags,
        flow_src_port,
        flow_dst_port,
        dscp: tos >> 2,
        src_addr,
        dst_v4: u32::from_be_bytes([dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]]),
        dst_v6: [0; 16],
        dst_addr,
    })
}

fn parse_ipv6(data: usize, data_end: usize, vlan_id: u16, l3_offset: u16) -> Option<ParsedPacket> {
    let ip6 = read_bytes(data, data_end, l3_offset as usize, 40)?;
    let version_priority = ip6[0];
    if (version_priority >> 4) != 6 {
        return None;
    }
    let mut protocol = ip6[6];
    let mut offset = l3_offset.checked_add(mem::size_of::<Ipv6Hdr>() as u16)?;

    for _ in 0..MAX_EXT_HDRS {
        match protocol {
            NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => {
                let opt = read_bytes(data, data_end, offset as usize, 2)?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;
                read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                )?;
            }
            NEXTHDR_AUTH => {
                let opt = read_bytes(data, data_end, offset as usize, 2)?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 2) * 4)?;
                read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                )?;
            }
            NEXTHDR_FRAGMENT => {
                let frag = read_bytes(data, data_end, offset as usize, 8)?;
                protocol = frag[0];
                offset = offset.checked_add(mem::size_of::<FragHdr>() as u16)?;
            }
            NEXTHDR_NONE => break,
            _ => break,
        }
    }

    let flow_lbl0 = ip6[1];
    let dscp = ((version_priority & 0x0f) << 2) | (flow_lbl0 >> 6);
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port) =
        parse_l4(data, data_end, offset, protocol)?;
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(read_bytes(data, data_end, l3_offset as usize + 8, 16)?);
    let mut dst_v6 = [0u8; 16];
    dst_v6.copy_from_slice(read_bytes(data, data_end, l3_offset as usize + 24, 16)?);
    Some(ParsedPacket {
        vlan_id,
        l3_offset,
        l4_offset: offset,
        payload_offset,
        addr_family: AF_INET6,
        protocol,
        tcp_flags,
        flow_src_port,
        flow_dst_port,
        dscp,
        src_addr,
        dst_v4: 0,
        dst_v6,
        dst_addr: dst_v6,
    })
}

fn should_fallback_early(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => {
            if pkt.dst_v4 == 0xffff_ffff
                || is_ipv4_multicast(pkt.dst_v4)
                || is_ipv4_link_local(pkt.dst_v4)
            {
                return true;
            }
            false
        }
        AF_INET6 => {
            if pkt.dst_v6[0] == 0xff || is_ipv6_link_local(pkt.dst_v6) {
                return true;
            }
            false
        }
        _ => true,
    }
}

fn is_local_destination(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => unsafe { USERSPACE_LOCAL_V4.get(&pkt.dst_v4) }.is_some(),
        AF_INET6 => {
            unsafe { USERSPACE_LOCAL_V6.get(&UserspaceLocalV6Key { addr: pkt.dst_v6 }) }.is_some()
        }
        _ => true,
    }
}

fn is_ipv4_multicast(ip: u32) -> bool {
    (ip & 0xf000_0000) == 0xe000_0000
}

fn is_ipv4_link_local(ip: u32) -> bool {
    (ip & 0xffff_0000) == 0xa9fe_0000
}

fn is_ipv6_link_local(ip: [u8; 16]) -> bool {
    ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80
}

fn parse_l4(
    data: usize,
    data_end: usize,
    l4_offset: u16,
    protocol: u8,
) -> Option<(u16, u8, u16, u16)> {
    match protocol {
        PROTO_TCP => {
            let bytes = read_bytes(data, data_end, l4_offset as usize, 14)?;
            let data_offset = ((bytes[12] >> 4) as u16) * 4;
            if data_offset < 20 {
                return None;
            }
            read_bytes(data, data_end, l4_offset as usize, data_offset as usize)?;
            Some((
                l4_offset.checked_add(data_offset)?,
                bytes[13],
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_UDP => {
            let bytes = read_bytes(data, data_end, l4_offset as usize, 8)?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let bytes = read_bytes(data, data_end, l4_offset as usize, 8)?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[4], bytes[5]]),
                0,
            ))
        }
        _ => Some((l4_offset, 0, 0, 0)),
    }
}

fn read_bytes<'a>(data: usize, data_end: usize, offset: usize, len: usize) -> Option<&'a [u8]> {
    if data.checked_add(offset)?.checked_add(len)? > data_end {
        return None;
    }
    let ptr = (data + offset) as *const u8;
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
