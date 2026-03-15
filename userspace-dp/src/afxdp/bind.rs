use super::*;
use core::num::NonZeroU32;
use std::path::Path;
use xdpilone::{IfInfo, Socket, SocketConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBindStrategy {
    UmemOwnerSocket,
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
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    match try_open_bind(worker_umem, info, ring_entries, bind_strategy, XSK_BIND_FLAGS_ZEROCOPY) {
        Ok(result) => return Ok(result),
        Err(e) => {
            eprintln!(
                "bpfrx-userspace-dp: zero-copy bind failed using {}: {e} — falling back to copy mode",
                bind_strategy.describe(),
            );
        }
    }
    match try_open_bind(worker_umem, info, ring_entries, bind_strategy, XSK_BIND_FLAGS_COPY) {
        Ok(result) => Ok(result),
        Err(err) => {
            let Some(fallback_strategy) = alternate_bind_strategy(driver_name, bind_strategy) else {
                return Err(err);
            };
            eprintln!(
                "bpfrx-userspace-dp: copy-mode bind failed using {} on driver {:?}: {} — retrying {}",
                bind_strategy.describe(),
                driver_name,
                err,
                fallback_strategy.describe(),
            );
            match try_open_bind(
                worker_umem,
                info,
                ring_entries,
                fallback_strategy,
                XSK_BIND_FLAGS_ZEROCOPY,
            ) {
                Ok(result) => Ok(result),
                Err(e) => {
                    eprintln!(
                        "bpfrx-userspace-dp: zero-copy bind failed using {}: {e} — falling back to copy mode",
                        fallback_strategy.describe(),
                    );
                    try_open_bind(
                        worker_umem,
                        info,
                        ring_entries,
                        fallback_strategy,
                        XSK_BIND_FLAGS_COPY,
                    )
                }
            }
        }
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
    if device.needs_wakeup() {
        device.wake();
    }
    Ok(())
}

pub(super) fn bind_strategy_for_driver(driver: Option<&str>) -> AfXdpBindStrategy {
    match driver {
        Some("virtio_net") => AfXdpBindStrategy::SeparateOwnerSocket,
        _ => AfXdpBindStrategy::UmemOwnerSocket,
    }
}

pub(super) fn alternate_bind_strategy(
    driver: Option<&str>,
    current: AfXdpBindStrategy,
) -> Option<AfXdpBindStrategy> {
    match (driver, current) {
        (Some("virtio_net"), AfXdpBindStrategy::SeparateOwnerSocket) => {
            Some(AfXdpBindStrategy::UmemOwnerSocket)
        }
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

fn try_open_bind(
    worker_umem: &WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    flags: u16,
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let sock = if bind_strategy.uses_umem_owner_socket() {
        Socket::with_shared(info, &worker_umem.umem)
            .map_err(|e| format!("create shared socket: {e}"))?
    } else {
        Socket::new(info).map_err(|e| format!("create socket: {e}"))?
    };
    let device = worker_umem
        .umem
        .fq_cq(&sock)
        .map_err(|e| format!("create fq/cq: {e}"))?;
    let (user, rx, tx, _bind_mode) =
        open_user_rings(&worker_umem.umem, &sock, ring_entries, flags)?;
    let bind_mode = bind_user_rings(&worker_umem.umem, &device, &user, bind_strategy)?;
    Ok((user, rx, tx, bind_mode, device))
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
    _device: &xdpilone::DeviceQueue,
    user: &User,
    bind_strategy: AfXdpBindStrategy,
) -> Result<XskBindMode, Box<dyn std::error::Error + Send + Sync>> {
    let user_fd = user.as_raw_fd();
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        let bind_result = umem.bind(user);
        match bind_result {
            Ok(()) => {
                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                set_busy_poll_opts(user_fd);
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
                let binder = if bind_strategy.uses_umem_owner_socket() {
                    "umem.bind(umem-owner)"
                } else {
                    "umem.bind(separate-owner)"
                };
                return Err(format!("bind AF_XDP socket via {binder}: {msg}").into());
            }
        }
    }
    let binder = if bind_strategy.uses_umem_owner_socket() {
        "umem.bind(umem-owner)"
    } else {
        "umem.bind(separate-owner)"
    };
    Err(format!("bind AF_XDP socket via {binder}: exhausted retries").into())
}

fn set_busy_poll_opts(fd: c_int) {
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
