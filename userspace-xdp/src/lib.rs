#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, xdp_md},
    helpers::r#gen::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_xdp_adjust_meta},
    macros::{map, xdp},
    maps::{Array, CpuMap, HashMap, ProgramArray, XskMap},
    programs::XdpContext,
};
use core::mem;

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
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
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;
const PROTO_ICMPV6: u8 = 58;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const MAX_EXT_HDRS: usize = 6;
const NEXTHDR_HOP: u8 = 0;
const NEXTHDR_ROUTING: u8 = 43;
const NEXTHDR_FRAGMENT: u8 = 44;
const NEXTHDR_AUTH: u8 = 51;
const NEXTHDR_DEST: u8 = 60;
const NEXTHDR_NONE: u8 = 59;
const USERSPACE_FALLBACK_REASON_CTRL_DISABLED: u32 = 0;
const USERSPACE_FALLBACK_REASON_PARSE_FAIL: u32 = 1;
const USERSPACE_FALLBACK_REASON_BINDING_MISSING: u32 = 2;
const USERSPACE_FALLBACK_REASON_BINDING_NOT_READY: u32 = 3;
const USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING: u32 = 4;
const USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE: u32 = 5;
const USERSPACE_FALLBACK_REASON_ICMP: u32 = 6;
const USERSPACE_FALLBACK_REASON_EARLY_FILTER: u32 = 7;
const USERSPACE_FALLBACK_REASON_ADJUST_META: u32 = 8;
const USERSPACE_FALLBACK_REASON_META_BOUNDS: u32 = 9;
const USERSPACE_FALLBACK_REASON_REDIRECT_ERR: u32 = 10;
const USERSPACE_FALLBACK_REASON_INTERFACE_NAT_NO_SESSION: u32 = 11;
const USERSPACE_FALLBACK_REASON_NO_SESSION: u32 = 12;
const USERSPACE_FALLBACK_REASON_MAX: u32 = 16;
const USERSPACE_CTRL_FLAG_CPUMAP: u32 = 1;
const USERSPACE_CTRL_FLAG_TRACE: u32 = 2;
const BINDING_QUEUES_PER_IFACE: u32 = 16;
const BINDING_ARRAY_MAX_ENTRIES: u32 = 1024 * BINDING_QUEUES_PER_IFACE; // 16384
const USERSPACE_TRACE_STAGE_RECEIVED: u32 = 1;
const USERSPACE_TRACE_STAGE_BINDING_MISSING: u32 = 2;
const USERSPACE_TRACE_STAGE_BINDING_NOT_READY: u32 = 3;
const USERSPACE_TRACE_STAGE_HEARTBEAT_MISSING: u32 = 4;
const USERSPACE_TRACE_STAGE_HEARTBEAT_STALE: u32 = 5;
const USERSPACE_TRACE_STAGE_ICMP_FALLBACK: u32 = 6;
const USERSPACE_TRACE_STAGE_EARLY_FILTER: u32 = 7;
const USERSPACE_TRACE_STAGE_INTERFACE_NAT_LOCAL: u32 = 8;
const USERSPACE_TRACE_STAGE_LOCAL_DESTINATION: u32 = 9;
const USERSPACE_TRACE_STAGE_REDIRECT: u32 = 10;
const USERSPACE_TRACE_STAGE_REDIRECT_ERR: u32 = 11;
const USERSPACE_TRACE_STAGE_NO_SESSION: u32 = 12;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceCtrl {
    enabled: u32,
    metadata_version: u32,
    workers: u32,
    queue_count: u32,
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

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceSessionKey {
    addr_family: u8,
    protocol: u8,
    pad: u16,
    src_port: u16,
    dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceTraceValue {
    seq: u64,
    stage: u32,
    reason: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    selected_queue: u32,
    slot: u32,
    vlan_id: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    flow_src_port: u16,
    flow_dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
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

// Array indexed by (ifindex * BINDING_QUEUES_PER_IFACE + queue_id).
// Go manager populates entries; unoccupied entries have flags=0.
#[map(name = "userspace_bindings")]
static USERSPACE_BINDINGS: Array<UserspaceBindingValue> =
    Array::with_max_entries(BINDING_ARRAY_MAX_ENTRIES, 0);

#[map(name = "userspace_ingress_ifaces")]
static USERSPACE_INGRESS_IFACES: Array<u8> = Array::with_max_entries(1024, 0);

#[map(name = "userspace_heartbeat")]
static USERSPACE_HEARTBEAT: Array<u64> = Array::with_max_entries(4096, 0);

#[map(name = "userspace_xsk_map")]
static USERSPACE_XSK_MAP: XskMap = XskMap::with_max_entries(4096, 0);

#[map(name = "userspace_local_v4")]
static USERSPACE_LOCAL_V4: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_local_v6")]
static USERSPACE_LOCAL_V6: HashMap<UserspaceLocalV6Key, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_interface_nat_v4")]
static USERSPACE_INTERFACE_NAT_V4: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_interface_nat_v6")]
static USERSPACE_INTERFACE_NAT_V6: HashMap<UserspaceLocalV6Key, u8> =
    HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_sessions")]
static USERSPACE_SESSIONS: HashMap<UserspaceSessionKey, u8> =
    HashMap::with_max_entries(262144, 0);

#[map(name = "userspace_fallback_progs")]
static USERSPACE_FALLBACK_PROGS: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[map(name = "userspace_fallback_stats")]
static USERSPACE_FALLBACK_STATS: Array<u64> = Array::with_max_entries(USERSPACE_FALLBACK_REASON_MAX, 0);

#[map(name = "userspace_trace")]
static USERSPACE_TRACE: HashMap<u32, UserspaceTraceValue> = HashMap::with_max_entries(1024, 0);

#[map(name = "userspace_cpumap")]
static USERSPACE_CPUMAP: CpuMap = CpuMap::with_max_entries(256, 0);

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
        return fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_CTRL_DISABLED);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some((eth_proto, vlan_id, l3_offset)) = parse_l2(data, data_end) else {
        return Ok(cpumap_or_pass(ctrl));
    };
    let parsed = match eth_proto {
        ETH_P_IP => parse_ipv4(data, data_end, vlan_id, l3_offset),
        ETH_P_IPV6 => parse_ipv6(data, data_end, vlan_id, l3_offset),
        _ => return Ok(cpumap_or_pass(ctrl)),
    };
    let Some(parsed) = parsed else {
        return fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_PARSE_FAIL);
    };

    let ingress_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    if USERSPACE_INGRESS_IFACES.get(ingress_ifindex).map_or(true, |v| *v == 0) {
        return Ok(cpumap_or_pass(ctrl));
    }
    let rx_queue_index = unsafe { (*ctx.ctx).rx_queue_index };
    let selected_queue = select_userspace_queue(ctrl, rx_queue_index, &parsed);
    record_trace(
        ctrl.flags,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        u32::MAX,
        USERSPACE_TRACE_STAGE_RECEIVED,
        0,
        &parsed,
    );
    let binding_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + selected_queue;
    let mut binding = USERSPACE_BINDINGS.get(binding_idx);
    // Treat zero-flags (unpopulated Array entry) as missing.
    if binding.map_or(true, |b| b.flags == 0) && selected_queue != rx_queue_index {
        let fallback_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + rx_queue_index;
        binding = USERSPACE_BINDINGS.get(fallback_idx);
    }
    let binding = match binding {
        Some(b) if b.flags != 0 => b,
        _ => {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                u32::MAX,
                USERSPACE_TRACE_STAGE_BINDING_MISSING,
                USERSPACE_FALLBACK_REASON_BINDING_MISSING,
                &parsed,
            );
            // Drop all TCP on DP-managed interfaces: legacy BPF has no session
            // for DP-managed flows, so falling back generates RSTs that kill the
            // real connection. TCP retransmit recovers from a single drop.
            incr_fallback_stat(USERSPACE_FALLBACK_REASON_BINDING_MISSING);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    if (binding.flags & USERSPACE_BINDING_READY) == 0 {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_BINDING_NOT_READY,
            USERSPACE_FALLBACK_REASON_BINDING_NOT_READY,
            &parsed,
        );
        incr_fallback_stat(USERSPACE_FALLBACK_REASON_BINDING_NOT_READY);
        return Ok(xdp_action::XDP_DROP);
    }
    let last_heartbeat = USERSPACE_HEARTBEAT.get(binding.slot);
    let Some(last_heartbeat) = last_heartbeat else {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_HEARTBEAT_MISSING,
            USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING,
            &parsed,
        );
        incr_fallback_stat(USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING);
        return Ok(xdp_action::XDP_DROP);
    };
    let timeout_ms = if ctrl.heartbeat_timeout_ms == 0 {
        USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS
    } else {
        ctrl.heartbeat_timeout_ms
    };
    let timeout_ns = (timeout_ms as u64) * 1_000_000;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if now_ns < *last_heartbeat || now_ns.saturating_sub(*last_heartbeat) > timeout_ns {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_HEARTBEAT_STALE,
            USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE,
            &parsed,
        );
        incr_fallback_stat(USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE);
        return Ok(xdp_action::XDP_DROP);
    }

    let packet_len = data_end.saturating_sub(data);
    // ICMP/ICMPv6 is now handled by the userspace dataplane — no fallback needed.
    if should_fallback_early(&parsed) {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_EARLY_FILTER,
            USERSPACE_FALLBACK_REASON_EARLY_FILTER,
            &parsed,
        );
        return fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_EARLY_FILTER);
    }
    // Fast path: for established TCP/UDP sessions, skip LOCAL and
    // INTERFACE_NAT hash map lookups — if the session exists, the
    // destination cannot be local (userspace DP only creates sessions
    // for transit traffic). This eliminates 2-3 hash map lookups per
    // packet on the hot path.
    if has_live_userspace_session(&parsed) {
        // Session exists — go directly to metadata stamping + XSK redirect.
    } else {
        // Session miss — run full checks for new connections.
        if is_icmp_to_interface_nat_local(&parsed) {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                binding.slot,
                USERSPACE_TRACE_STAGE_INTERFACE_NAT_LOCAL,
                0,
                &parsed,
            );
            return Ok(cpumap_or_pass(ctrl));
        }
        if is_local_destination(&parsed) {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                binding.slot,
                USERSPACE_TRACE_STAGE_LOCAL_DESTINATION,
                0,
                &parsed,
            );
            return Ok(cpumap_or_pass(ctrl));
        }
        // Let all session misses through to the userspace dataplane.
        // The userspace DP will evaluate policy and either create a
        // session (new flow) or drop (stale non-SYN TCP / policy deny).
    }
    let meta_len = mem::size_of::<UserspaceDpMeta>() as i32;
    let adjust_rc = unsafe { bpf_xdp_adjust_meta(ctx.ctx as *mut xdp_md, -meta_len) };
    if adjust_rc != 0 {
        return fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_ADJUST_META);
    }

    let meta_ptr = ctx.metadata() as *mut UserspaceDpMeta;
    if (meta_ptr as usize).saturating_add(mem::size_of::<UserspaceDpMeta>()) > ctx.metadata_end() {
        return fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_META_BOUNDS);
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

    record_trace(
        ctrl.flags,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        binding.slot,
        USERSPACE_TRACE_STAGE_REDIRECT,
        0,
        &parsed,
    );
    match USERSPACE_XSK_MAP.redirect(binding.slot, 0) {
        Ok(action) => Ok(action),
        Err(_) => {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                binding.slot,
                USERSPACE_TRACE_STAGE_REDIRECT_ERR,
                USERSPACE_FALLBACK_REASON_REDIRECT_ERR,
                &parsed,
            );
            if is_interface_nat_destination(&parsed) {
                incr_fallback_stat(USERSPACE_FALLBACK_REASON_REDIRECT_ERR);
                return Ok(xdp_action::XDP_DROP);
            }
            fallback_to_main(ctx, ctrl, USERSPACE_FALLBACK_REASON_REDIRECT_ERR)
        }
    }
}

fn fallback_to_main(ctx: &XdpContext, _ctrl: &UserspaceCtrl, reason: u32) -> Result<u32, i64> {
    incr_fallback_stat(reason);
    // Always tail-call to the main eBPF pipeline for firewall processing.
    // The main pipeline handles zone lookup, policy, NAT, and forwarding.
    // Do NOT use cpumap here — it bypasses the firewall entirely.
    // XDP_PASS from the main pipeline is safe in zero-copy mode: mlx5
    // copies data and frees the XSK buffer automatically.
    unsafe {
        let _ = USERSPACE_FALLBACK_PROGS.tail_call(ctx, USERSPACE_FALLBACK_MAIN);
    }
    Ok(xdp_action::XDP_DROP)
}

fn incr_fallback_stat(reason: u32) {
    if reason >= USERSPACE_FALLBACK_REASON_MAX {
        return;
    }
    if let Some(ptr) = USERSPACE_FALLBACK_STATS.get_ptr_mut(reason) {
        unsafe {
            *ptr = (*ptr).saturating_add(1);
        }
    }
}

fn record_trace(
    ctrl_flags: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    selected_queue: u32,
    slot: u32,
    stage: u32,
    reason: u32,
    parsed: &ParsedPacket,
) {
    if (ctrl_flags & USERSPACE_CTRL_FLAG_TRACE) == 0 {
        return;
    }
    if matches!(parsed.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return;
    }
    let value = UserspaceTraceValue {
        seq: unsafe { bpf_ktime_get_ns() },
        stage,
        reason,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        slot,
        vlan_id: parsed.vlan_id,
        addr_family: parsed.addr_family,
        protocol: parsed.protocol,
        tcp_flags: parsed.tcp_flags,
        flow_src_port: parsed.flow_src_port,
        flow_dst_port: parsed.flow_dst_port,
        src_addr: parsed.src_addr,
        dst_addr: parsed.dst_addr,
    };
    let _ = unsafe { USERSPACE_TRACE.insert(&ingress_ifindex, &value, 0) };
}

fn pass_to_kernel_or_abort() -> u32 {
    xdp_action::XDP_PASS
}

/// Deliver packet to kernel via cpumap redirect (avoids UMEM frame leak in
/// zero-copy AF_XDP mode). Falls back to XDP_PASS when cpumap is not enabled.
fn cpumap_or_pass(ctrl: &UserspaceCtrl) -> u32 {
    if (ctrl.flags & USERSPACE_CTRL_FLAG_CPUMAP) != 0 {
        let cpu = unsafe { bpf_get_smp_processor_id() };
        if let Ok(action) = USERSPACE_CPUMAP.redirect(cpu, 0) {
            return action;
        }
    }
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
    icmp_type: u8,
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
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port, icmp_type) =
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
        icmp_type,
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
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port, icmp_type) =
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
        icmp_type,
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
    // GRE (47) and ESP (50) are tunnel encapsulation protocols that must
    // be delivered to the kernel for decapsulation (GRE→gr-0-0-0, ESP→XFRM).
    // The userspace DP cannot decapsulate these — always fall back to eBPF.
    if matches!(pkt.protocol, PROTO_GRE | PROTO_ESP) {
        return true;
    }
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
        AF_INET => {
            if unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some() {
                return false;
            }
            unsafe { USERSPACE_LOCAL_V4.get(&pkt.dst_v4) }.is_some()
        }
        AF_INET6 => {
            let key = UserspaceLocalV6Key { addr: pkt.dst_v6 };
            if unsafe { USERSPACE_INTERFACE_NAT_V6.get(&key) }.is_some() {
                return false;
            }
            unsafe { USERSPACE_LOCAL_V6.get(&key) }.is_some()
        }
        _ => true,
    }
}

fn is_icmp_to_interface_nat_local(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => {
            if pkt.protocol != PROTO_ICMP || pkt.icmp_type != 8 {
                return false;
            }
            unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some()
        }
        AF_INET6 => {
            if pkt.protocol != PROTO_ICMPV6 || pkt.icmp_type != 128 {
                return false;
            }
            unsafe { USERSPACE_INTERFACE_NAT_V6.get(&UserspaceLocalV6Key { addr: pkt.dst_v6 }) }
                .is_some()
        }
        _ => false,
    }
}

fn is_interface_nat_destination(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some(),
        AF_INET6 => unsafe {
            USERSPACE_INTERFACE_NAT_V6.get(&UserspaceLocalV6Key { addr: pkt.dst_v6 })
        }
        .is_some(),
        _ => false,
    }
}

fn has_live_userspace_session(pkt: &ParsedPacket) -> bool {
    let key = UserspaceSessionKey {
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        pad: 0,
        src_port: pkt.flow_src_port,
        dst_port: pkt.flow_dst_port,
        src_addr: pkt.src_addr,
        dst_addr: pkt.dst_addr,
    };
    unsafe { USERSPACE_SESSIONS.get(&key) }.is_some()
}

fn is_connection_initiating(pkt: &ParsedPacket) -> bool {
    match pkt.protocol {
        PROTO_TCP => (pkt.tcp_flags & TCP_FLAG_SYN) != 0 && (pkt.tcp_flags & TCP_FLAG_ACK) == 0,
        PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6 => true,
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

fn select_userspace_queue(ctrl: &UserspaceCtrl, rx_queue_index: u32, _parsed: &ParsedPacket) -> u32 {
    let queue_count = if ctrl.queue_count == 0 {
        ctrl.workers
    } else {
        ctrl.queue_count
    };
    if queue_count <= 1 {
        return 0;
    }
    /*
     * AF_XDP delivery is queue-bound. XDP may only redirect to a socket bound
     * to the packet's actual RX queue. Hashing to a different userspace queue
     * here silently strands packets between redirect intent and ring delivery.
     *
     * Keep the XDP handoff on the ingress queue and let userspace do any
     * higher-level work redistribution after the packet is received.
     */
    rx_queue_index % queue_count
}

fn parse_l4(
    data: usize,
    data_end: usize,
    l4_offset: u16,
    protocol: u8,
) -> Option<(u16, u8, u16, u16, u8)> {
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
                0,
            ))
        }
        PROTO_UDP => {
            let bytes = read_bytes(data, data_end, l4_offset as usize, 8)?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                0,
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let bytes = read_bytes(data, data_end, l4_offset as usize, 8)?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[4], bytes[5]]),
                0,
                bytes[0],
            ))
        }
        _ => Some((l4_offset, 0, 0, 0, 0)),
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
