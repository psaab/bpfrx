use super::*;
use core::num::NonZeroU32;
use std::path::Path;
use xdpilone::{IfInfo, Socket, SocketConfig};

const AUTO_BIND_FLAGS: [u16; 1] = [0];
const EXPLICIT_MODE_BIND_FLAGS: [u16; 2] = [XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBindStrategy {
    UmemOwnerSocket,
    #[allow(dead_code)]
    SeparateOwnerSocket,
}

impl AfXdpBindStrategy {
    fn uses_umem_owner_socket(self) -> bool {
        matches!(self, Self::UmemOwnerSocket)
    }

    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::UmemOwnerSocket => "umem-owner-socket",
            Self::SeparateOwnerSocket => "separate-owner-socket",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBinder {
    Umem,
    #[allow(dead_code)]
    DeviceQueue,
}

pub(super) fn binding_frame_count(ring_entries: u32) -> u32 {
    reserved_tx_frames(ring_entries)
        .saturating_add(ring_entries.saturating_mul(2).max(1))
}

pub(super) fn ifinfo_from_binding(
    binding: &BindingStatus,
) -> Result<IfInfo, Box<dyn std::error::Error + Send + Sync>> {
    let mut info = IfInfo::invalid();
    info.from_ifindex(binding.ifindex as u32)
        .map_err(|e| format!("lookup ifindex {}: {e}", binding.ifindex))?;
    info.set_queue(binding.queue_id);
    Ok(info)
}

pub(super) fn preferred_bind_strategy(binding: &BindingStatus) -> AfXdpBindStrategy {
    bind_strategy_for_driver(interface_driver_name(&binding.interface).as_deref())
}

pub(super) fn open_binding_worker_rings(
    worker_umem: &WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    driver_name: Option<&str>,
    poll_mode: crate::PollMode,
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        AfXdpBindStrategy,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let bind_flag_candidates = bind_flag_candidates_for_driver(driver_name);
    let mut strategies = vec![bind_strategy];
    if let Some(fallback_strategy) = alternate_bind_strategy(driver_name, bind_strategy) {
        strategies.push(fallback_strategy);
    }
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for (strategy_idx, strategy) in strategies.iter().copied().enumerate() {
        for (flags_idx, flags) in bind_flag_candidates.iter().copied().enumerate() {
            match try_open_bind(worker_umem, info, ring_entries, strategy, flags, poll_mode) {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_err = Some(err);
                    let more_flag_attempts = flags_idx + 1 < bind_flag_candidates.len();
                    let more_strategy_attempts = strategy_idx + 1 < strategies.len();
                    if more_flag_attempts {
                        eprintln!(
                            "bpfrx-userspace-dp: {} bind failed using {}: {} — trying {}",
                            describe_bind_flags(flags),
                            strategy.describe(),
                            last_err.as_ref().unwrap(),
                            describe_bind_flags(bind_flag_candidates[flags_idx + 1]),
                        );
                    } else if more_strategy_attempts {
                        eprintln!(
                            "bpfrx-userspace-dp: {} bind failed using {} on driver {:?}: {} — retrying {}",
                            describe_bind_flags(flags),
                            strategy.describe(),
                            driver_name,
                            last_err.as_ref().unwrap(),
                            strategies[strategy_idx + 1].describe(),
                        );
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "AF_XDP bind: no attempts executed".into()))
}

pub(super) fn bind_flag_candidates_for_driver(driver: Option<&str>) -> &'static [u16] {
    match driver {
        Some("virtio_net") => &AUTO_BIND_FLAGS,
        _ => &EXPLICIT_MODE_BIND_FLAGS,
    }
}

fn describe_bind_flags(flags: u16) -> &'static str {
    if flags == 0 {
        "auto-mode"
    } else if (flags & SocketConfig::XDP_BIND_ZEROCOPY) != 0 {
        "zero-copy"
    } else {
        "copy-mode"
    }
}

pub(super) fn prime_fill_ring_offsets(
    device: &mut xdpilone::DeviceQueue,
    offsets: &[u64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let inserted = {
        let mut fill = device.fill(offsets.len() as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        inserted
    };
    if inserted != offsets.len() as u32 {
        return Err(format!("prefill fill ring inserted {inserted}/{}", offsets.len()).into());
    }
    // Trigger NAPI to consume fill ring entries and post RX WQEs.
    // mlx5 zero-copy processes the fill ring during RX NAPI poll.
    // We trigger it by calling recvmsg() which enters the busy-poll
    // path (if SO_BUSY_POLL is set) and drives NAPI processing.
    // Also use poll(POLLIN) and sendto() as belt-and-suspenders.
    let fd = device.as_raw_fd();
    for _ in 0..20 {
        // recvmsg with MSG_DONTWAIT triggers xsk_recvmsg → busy-poll
        let mut iov = libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        };
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        // Also poll and sendto
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, 1) };
        unsafe {
            libc::sendto(fd, core::ptr::null_mut(), 0, libc::MSG_DONTWAIT,
                core::ptr::null_mut(), 0);
        }
        std::thread::yield_now();
    }
    Ok(())
}

pub(super) fn bind_strategy_for_driver(driver: Option<&str>) -> AfXdpBindStrategy {
    match driver {
        _ => AfXdpBindStrategy::UmemOwnerSocket,
    }
}

pub(super) fn binder_for_strategy(strategy: AfXdpBindStrategy) -> AfXdpBinder {
    if strategy.uses_umem_owner_socket() {
        AfXdpBinder::Umem
    } else {
        AfXdpBinder::DeviceQueue
    }
}

pub(super) fn alternate_bind_strategy(
    driver: Option<&str>,
    current: AfXdpBindStrategy,
) -> Option<AfXdpBindStrategy> {
    match (driver, current) {
        _ => None,
    }
}

pub(super) fn reserved_tx_frames(ring_entries: u32) -> u32 {
    ring_entries
        .saturating_div(2)
        .clamp(MIN_RESERVED_TX_FRAMES, MAX_RESERVED_TX_FRAMES)
        .min(ring_entries.saturating_sub(1))
        .max(1)
}

pub(super) fn umem_ring_size(entries: u32) -> u32 {
    entries
        .max(64)
        .checked_next_power_of_two()
        .unwrap_or(entries.max(64))
}

pub(super) fn interface_driver_name(ifname: &str) -> Option<String> {
    if ifname.is_empty() {
        return None;
    }
    let driver_link = Path::new("/sys/class/net")
        .join(ifname)
        .join("device")
        .join("driver");
    let target = std::fs::read_link(driver_link).ok()?;
    target.file_name()?.to_str().map(str::to_string)
}

#[cfg(test)]
pub(super) fn shared_umem_group_key_for_device(
    driver: Option<&str>,
    device_path: Option<&str>,
) -> Option<String> {
    match (driver, device_path) {
        // Narrow prototype only: same-device mlx5 bindings can share UMEM safely.
        (Some("mlx5_core"), Some(path)) if !path.is_empty() => Some(format!("mlx5:{path}")),
        _ => None,
    }
}

fn try_open_bind(
    worker_umem: &WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    flags: u16,
    poll_mode: crate::PollMode,
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        AfXdpBindStrategy,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (device, user, rx, tx, bind_mode) = if bind_strategy.uses_umem_owner_socket() {
        let sock = Socket::with_shared(info, worker_umem.umem())
            .map_err(|e| format!("create shared socket: {e}"))?;
        let mut device = worker_umem
            .umem()
            .fq_cq(&sock)
            .map_err(|e| format!("create fq/cq: {e}"))?;
        let (user, rx, tx, _requested_mode) =
            open_user_rings(worker_umem.umem(), &sock, ring_entries, flags)?;
        let bind_mode = bind_user_rings(
            worker_umem.umem(),
            &device,
            &user,
            bind_strategy,
            poll_mode,
        )?;
        (device, user, rx, tx, bind_mode)
    } else {
        let owner_sock = Socket::new(info).map_err(|e| format!("create owner socket: {e}"))?;
        let device = worker_umem
            .umem()
            .fq_cq(&owner_sock)
            .map_err(|e| format!("create fq/cq: {e}"))?;
        let user_sock = Socket::new(info).map_err(|e| format!("create user socket: {e}"))?;
        let (user, rx, tx, _requested_mode) =
            open_user_rings(worker_umem.umem(), &user_sock, ring_entries, flags)?;
        let bind_mode = bind_user_rings(
            worker_umem.umem(),
            &device,
            &user,
            bind_strategy,
            poll_mode,
        )?;
        (device, user, rx, tx, bind_mode)
    };
    Ok((user, rx, tx, bind_mode, bind_strategy, device))
}

fn open_user_rings(
    umem: &Umem,
    sock: &Socket,
    ring_entries: u32,
    bind_flags: u16,
) -> Result<
    (User, xdpilone::RingRx, xdpilone::RingTx, XskBindMode),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let user = umem
        .rx_tx(
            sock,
            &SocketConfig {
                rx_size: NonZeroU32::new(ring_entries),
                tx_size: NonZeroU32::new(ring_entries),
                bind_flags,
            },
        )
        .map_err(|e| format!("configure rx/tx rings: {e}"))?;
    let rx = user.map_rx().map_err(|e| format!("map rx ring: {e}"))?;
    let tx = user.map_tx().map_err(|e| format!("map tx ring: {e}"))?;
    let bind_mode = if (bind_flags & SocketConfig::XDP_BIND_ZEROCOPY) != 0 {
        XskBindMode::ZeroCopy
    } else {
        XskBindMode::Copy
    };
    Ok((user, rx, tx, bind_mode))
}

fn query_bound_xsk_mode(fd: c_int) -> Option<XskBindMode> {
    let mut opt = XdpOptions { flags: 0 };
    let mut optlen = core::mem::size_of::<XdpOptions>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_OPTIONS,
            (&mut opt as *mut XdpOptions).cast::<c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 || optlen as usize != core::mem::size_of::<XdpOptions>() {
        return None;
    }
    Some(if (opt.flags & XDP_OPTIONS_ZEROCOPY) != 0 {
        XskBindMode::ZeroCopy
    } else {
        XskBindMode::Copy
    })
}

#[allow(dead_code)]
fn bind_user_with_retry(
    umem: &Umem,
    user: &User,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        match umem.bind(user) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                return Err(format!("bind AF_XDP socket: {msg}").into());
            }
        }
    }
    Err("bind AF_XDP socket: exhausted retries".into())
}

fn bind_user_rings(
    umem: &Umem,
    device: &xdpilone::DeviceQueue,
    user: &User,
    bind_strategy: AfXdpBindStrategy,
    poll_mode: crate::PollMode,
) -> Result<XskBindMode, Box<dyn std::error::Error + Send + Sync>> {
    let user_fd = user.as_raw_fd();
    let binder = binder_for_strategy(bind_strategy);
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        let bind_result = match binder {
            AfXdpBinder::Umem => umem.bind(user),
            AfXdpBinder::DeviceQueue => device.bind(user),
        };
        match bind_result {
            Ok(()) => {
                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                set_busy_poll_opts(user_fd, poll_mode);
                eprintln!(
                    "bpfrx-userspace-dp: umem.bind(fd={}) OK on attempt {} mode={:?} strategy={}",
                    user_fd,
                    attempt,
                    bind_mode,
                    bind_strategy.describe(),
                );
                return Ok(bind_mode);
            }
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                let binder_name = match binder {
                    AfXdpBinder::Umem => "umem.bind(umem-owner)",
                    AfXdpBinder::DeviceQueue => "device.bind(separate-owner)",
                };
                return Err(format!("bind AF_XDP socket via {binder_name}: {msg}").into());
            }
        }
    }
    let binder_name = match binder {
        AfXdpBinder::Umem => "umem.bind(umem-owner)",
        AfXdpBinder::DeviceQueue => "device.bind(separate-owner)",
    };
    Err(format!("bind AF_XDP socket via {binder_name}: exhausted retries").into())
}

fn set_busy_poll_opts(fd: c_int, poll_mode: crate::PollMode) {
    if poll_mode == crate::PollMode::Interrupt {
        // Interrupt mode: don't set busy-poll sockopts.
        // The kernel will use normal interrupt-driven NAPI delivery,
        // which uses less CPU but has higher per-packet latency.
        return;
    }
    const SO_BUSY_POLL: c_int = 46;
    const SO_PREFER_BUSY_POLL: c_int = 69;
    const SO_BUSY_POLL_BUDGET: c_int = 70;
    let busy_poll_us: c_int = 50;
    let prefer: c_int = 1;
    let budget: c_int = RX_BATCH_SIZE as c_int;

    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            (&busy_poll_us as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PREFER_BUSY_POLL,
            (&prefer as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL_BUDGET,
            (&budget as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
    }
}
