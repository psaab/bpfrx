use super::*;
use crate::xsk_ffi::{self, DeviceQueue, IfInfo, RingRx, RingTx, SocketConfig};
use std::path::Path;

const AUTO_BIND_FLAGS: [u16; 1] = [0];
const COPY_ONLY_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_COPY];
const EXPLICIT_MODE_BIND_FLAGS: [u16; 2] = [XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY];
const SHARED_OWNER_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_ZEROCOPY];
const SHARED_SECONDARY_BIND_FLAGS: [u16; 1] = [SocketConfig::XDP_BIND_SHARED_UMEM];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBindStrategy {
    UmemOwnerSocket,
    #[allow(dead_code)]
    SeparateOwnerSocket,
}

impl AfXdpBindStrategy {
    #[allow(dead_code)]
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

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBinder {
    Umem,
    DeviceQueue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XskSocketRole {
    Private,
    SharedOwner,
    SharedSecondary,
}

impl XskSocketRole {
    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::SharedOwner => "shared-owner",
            Self::SharedSecondary => "shared-secondary",
        }
    }

    fn create_mode(self) -> xsk_ffi::XskCreateMode {
        match self {
            Self::Private => xsk_ffi::XskCreateMode::PrivateUmem,
            Self::SharedOwner | Self::SharedSecondary => xsk_ffi::XskCreateMode::SharedUmem,
        }
    }

    fn requires_zerocopy(self) -> bool {
        !matches!(self, Self::Private)
    }
}

/// Total UMEM frames per binding: reserved TX + 2×ring_entries for RX fill.
/// For virtio_net (fabric parent), reserved TX = ring_entries, so total is
/// 3×ring_entries frames. At UMEM_FRAME_SIZE=4096 and ring_entries=8192,
/// that's ~96 MB per binding (×queues per interface).
pub(super) fn binding_frame_count_for_driver(driver: Option<&str>, ring_entries: u32) -> u32 {
    reserved_tx_frames_for_driver(driver, ring_entries)
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

/// Open the AF_XDP socket/ring handles for one binding.
///
/// # Safety
/// The returned XSK handles must be stored/dropped before `worker_umem`, so
/// `xsk_socket__delete` runs while the UMEM state is still live and before
/// `xsk_umem__delete`. Private UMEM sockets borrow `worker_umem`'s
/// fill/completion ring structs directly. Shared UMEM sockets own
/// socket-local fill/completion rings but still depend on the live shared UMEM
/// pointer passed through `worker_umem`.
pub(super) unsafe fn open_binding_worker_rings(
    worker_umem: &mut WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    socket_role: XskSocketRole,
    driver_name: Option<&str>,
    poll_mode: crate::PollMode,
    pre_bind_fill_offsets: Option<&[u64]>,
) -> Result<
    (
        User,
        RingRx,
        RingTx,
        XskBindMode,
        u16,
        AfXdpBindStrategy,
        DeviceQueue,
        // #2374: fill-ring suffix the bringup prime could not place — the
        // caller stashes this in `pending_fill_frames` so it is retried by
        // the steady-state drain rather than leaked.
        Vec<u64>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let bind_flag_candidates = bind_flag_candidates_for_socket_role(info, driver_name, socket_role);
    let mut strategies = vec![bind_strategy];
    if let Some(fallback_strategy) = alternate_bind_strategy(driver_name, bind_strategy) {
        strategies.push(fallback_strategy);
    }
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for (strategy_idx, strategy) in strategies.iter().copied().enumerate() {
        for (flags_idx, flags) in bind_flag_candidates.iter().copied().enumerate() {
            match try_open_bind(
                worker_umem,
                info,
                ring_entries,
                flags,
                socket_role,
                poll_mode,
                pre_bind_fill_offsets,
            ) {
                Ok((user, rx, tx, bind_mode, actual_flags, device, uninserted_fill)) => {
                    return Ok((
                        user,
                        rx,
                        tx,
                        bind_mode,
                        actual_flags,
                        strategy,
                        device,
                        uninserted_fill,
                    ));
                }
                Err(err) => {
                    last_err = Some(err);
                    let more_flag_attempts = flags_idx + 1 < bind_flag_candidates.len();
                    let more_strategy_attempts = strategy_idx + 1 < strategies.len();
                    if more_flag_attempts {
                        eprintln!(
                            "xpf-userspace-dp: {} bind failed using {}: {} — trying {}",
                            describe_bind_flags(flags),
                            strategy.describe(),
                            last_err.as_ref().unwrap(),
                            describe_bind_flags(bind_flag_candidates[flags_idx + 1]),
                        );
                    } else if more_strategy_attempts {
                        eprintln!(
                            "xpf-userspace-dp: {} bind failed using {} on driver {:?}: {} — retrying {}",
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

pub(super) fn bind_flag_candidates_for_interface(
    info: &IfInfo,
    driver: Option<&str>,
) -> &'static [u16] {
    if interface_uses_generic_xdp(info.ifindex()) {
        return match driver {
            Some("virtio_net") => &AUTO_BIND_FLAGS,
            _ => &COPY_ONLY_BIND_FLAGS,
        };
    }
    bind_flag_candidates_for_driver(driver)
}

pub(super) fn bind_flag_candidates_for_socket_role(
    info: &IfInfo,
    driver: Option<&str>,
    socket_role: XskSocketRole,
) -> &'static [u16] {
    match socket_role {
        XskSocketRole::Private => bind_flag_candidates_for_interface(info, driver),
        XskSocketRole::SharedOwner => &SHARED_OWNER_BIND_FLAGS,
        XskSocketRole::SharedSecondary => &SHARED_SECONDARY_BIND_FLAGS,
    }
}

pub(super) fn bind_flag_candidates_for_driver(driver: Option<&str>) -> &'static [u16] {
    match driver {
        Some("virtio_net") => &AUTO_BIND_FLAGS,
        _ => &EXPLICIT_MODE_BIND_FLAGS,
    }
}

fn interface_uses_generic_xdp(ifindex: u32) -> bool {
    let mut opts = libbpf_sys::bpf_xdp_query_opts {
        sz: core::mem::size_of::<libbpf_sys::bpf_xdp_query_opts>() as _,
        ..Default::default()
    };
    let rc = unsafe { libbpf_sys::bpf_xdp_query(ifindex as c_int, 0, &mut opts) };
    if rc != 0 {
        eprintln!(
            "xpf-userspace-dp: bpf_xdp_query(ifindex={}) failed rc={} — assuming generic XDP",
            ifindex, rc
        );
        return true;
    }
    opts.attach_mode == libbpf_sys::XDP_ATTACHED_SKB as u8
}

pub(super) fn describe_bind_flags(flags: u16) -> &'static str {
    if flags == 0 {
        "auto-mode"
    } else if (flags & SocketConfig::XDP_BIND_SHARED_UMEM) != 0 {
        "shared-umem"
    } else if (flags & SocketConfig::XDP_BIND_ZEROCOPY) != 0 {
        "zero-copy"
    } else {
        "copy-mode"
    }
}

/// Bringup fill-ring total-failure predicate (#2374).
///
/// A *total* failure (the very first reserve placed zero frames into a
/// non-empty fill request) is fatal: the socket would run with no RX
/// descriptors at all, so the bind must fail closed. An empty request
/// (`total == 0`) is not a failure. Extracted as a pure helper so the
/// fail-closed decision is unit-testable without a bound `DeviceQueue`.
pub(super) fn fill_prime_is_total_failure(total: usize, inserted_first: usize) -> bool {
    total > 0 && inserted_first == 0
}

/// Bringup fill-ring partial-insert suffix recovery (#2374).
///
/// Given the offsets handed to the bringup prime and the total number the fill
/// ring eventually accepted (after retries), return the un-inserted suffix the
/// caller MUST defer into the worker's `pending_fill_frames` queue. Returning
/// the suffix (rather than dropping it) is what prevents the UMEM frame leak:
/// the steady-state `tx::rings::drain_pending_fill` loop then retries exactly
/// these offsets. A full insert returns an empty `Vec`. Pure helper so the
/// recovery is unit-testable without a bound `DeviceQueue`.
pub(super) fn defer_uninserted_fill_suffix(offsets: &[u64], inserted_total: usize) -> Vec<u64> {
    let inserted_total = inserted_total.min(offsets.len());
    offsets[inserted_total..].to_vec()
}

/// Prime the RX fill ring with `offsets` at socket bringup.
///
/// Returns the suffix of `offsets` that could NOT be inserted into the fill
/// ring (empty `Vec` when all `offsets.len()` frames were placed). The caller
/// MUST hand that suffix to the worker's `pending_fill_frames` queue so the
/// steady-state `drain_pending_fill` loop retries it — otherwise those UMEM
/// frame addresses are leaked from every local pool, permanently shrinking RX
/// capacity (#2374).
///
/// A *total* failure (`inserted == 0` on the very first reserve) is fatal and
/// returns `Err` so the bind fails closed rather than running with no RX
/// descriptors. A *partial* insert is recovered: this matches the steady-state
/// suffix recovery in `tx::rings::drain_pending_fill` (push the un-inserted
/// suffix back for retry) rather than silently dropping it.
pub(super) fn prime_fill_ring_offsets(
    device: &mut DeviceQueue,
    offsets: &[u64],
) -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
    // An empty prime request is a no-op (not a total failure — see
    // `fill_prime_is_total_failure`). Return the empty deferred suffix without
    // entering the fixed 20-iteration NAPI-trigger loop below, which would
    // otherwise burn 20 recvmsg/poll/sendto syscalls at bringup for no frames.
    if offsets.is_empty() {
        return Ok(Vec::new());
    }
    // `remaining` is the slice index of the first not-yet-inserted offset.
    // We retry the insert across the NAPI-trigger loop below: each NAPI kick
    // lets the kernel consume fill-ring entries and post RX WQEs, which frees
    // ring slots so a transiently-full ring can accept the suffix on a later
    // iteration without leaking frames.
    let total = offsets.len();
    let mut remaining: usize = {
        let mut fill = device.fill(total as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        inserted as usize
    };
    eprintln!(
        "prime_fill_ring: inserted={}/{} fill_pending={}",
        remaining,
        total,
        device.pending()
    );
    // A total failure on the first reserve means the ring rejected everything;
    // fail closed (no RX descriptors at all). Do NOT regress this behavior.
    if fill_prime_is_total_failure(total, remaining) {
        return Err(format!("prefill fill ring inserted 0/{}", total).into());
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
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            );
        }
        // After NAPI has had a chance to drain the ring, retry inserting the
        // un-inserted suffix. This recovers a transiently-full fill ring at
        // bringup the same way the steady-state drain does.
        if remaining < total {
            let suffix = &offsets[remaining..];
            let inserted = {
                let mut fill = device.fill(suffix.len() as u32);
                let inserted = fill.insert(suffix.iter().copied());
                fill.commit();
                inserted as usize
            };
            remaining += inserted;
        }
        std::thread::yield_now();
    }
    if remaining < total {
        eprintln!(
            "prime_fill_ring: partial prime — {} of {} frames not placed, deferring suffix to pending_fill_frames",
            total - remaining,
            total
        );
    }
    // Return the un-inserted suffix (frames the ring still has not accepted).
    // The worker constructor stashes these in `pending_fill_frames` so the
    // running loop's `drain_pending_fill` retries them — never leaked.
    Ok(defer_uninserted_fill_suffix(offsets, remaining))
}

pub(super) fn bind_strategy_for_driver(driver: Option<&str>) -> AfXdpBindStrategy {
    match driver {
        _ => AfXdpBindStrategy::UmemOwnerSocket,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
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

pub(super) fn reserved_tx_frames_for_driver(driver: Option<&str>, ring_entries: u32) -> u32 {
    let preferred = match driver {
        Some("virtio_net") => ring_entries,
        _ => ring_entries.saturating_div(2),
    };
    preferred
        .clamp(MIN_RESERVED_TX_FRAMES, MAX_RESERVED_TX_FRAMES)
        .min(ring_entries.saturating_mul(2).saturating_sub(1))
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

/// Create and bind an XSK socket using libxdp's `xsk_socket__create_shared`.
///
/// This replaces the multi-step xdpilone flow (Socket::with_shared →
/// umem.fq_cq → umem.rx_tx → user.map_rx/map_tx → umem.bind) with a
/// single libxdp call that does UMEM registration, ring setup, and bind
/// atomically — matching the proven libbpf xsk code path.
fn try_open_bind(
    worker_umem: &mut WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
    socket_role: XskSocketRole,
    poll_mode: crate::PollMode,
    pre_bind_fill_offsets: Option<&[u64]>,
) -> Result<
    (User, RingRx, RingTx, XskBindMode, u16, DeviceQueue, Vec<u64>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        let create_result = match socket_role.create_mode() {
            xsk_ffi::XskCreateMode::PrivateUmem => unsafe {
                xsk_ffi::create_xsk_binding_private(
                    worker_umem.umem_mut(),
                    info,
                    ring_entries,
                    bind_flags,
                )
            },
            xsk_ffi::XskCreateMode::SharedUmem => unsafe {
                xsk_ffi::create_xsk_binding_shared(
                    worker_umem.as_raw_umem_ptr(),
                    info,
                    ring_entries,
                    bind_flags,
                )
            },
        };
        match create_result {
            Ok((user, rx, tx, mut device)) => {
                let user_fd = user.as_raw_fd();

                // Prime the fill ring AFTER bind — libxdp already binds
                // the socket during create_shared. Post-bind fill ring
                // priming triggers NAPI to consume entries and post WQEs.
                // Any suffix the ring could not accept is returned so the
                // worker stashes it in `pending_fill_frames` (#2374) instead
                // of leaking the UMEM frames.
                let uninserted_fill = match pre_bind_fill_offsets {
                    Some(offsets) => prime_fill_ring_offsets(&mut device, offsets)?,
                    None => Vec::new(),
                };

                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                if socket_role.requires_zerocopy() && !bind_mode.is_zerocopy() {
                    return Err(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind",
                        socket_role.describe(),
                        user_fd
                    )
                    .into());
                }
                set_busy_poll_opts(user_fd, poll_mode);
                eprintln!(
                    "xpf-userspace-dp: libxdp bind(fd={}) OK on attempt {} role={} mode={:?} flags=0x{:04x}",
                    user_fd,
                    attempt,
                    socket_role.describe(),
                    bind_mode,
                    bind_flags,
                );

                return Ok((user, rx, tx, bind_mode, bind_flags, device, uninserted_fill));
            }
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                return Err(format!(
                    "libxdp {} bind(flags=0x{:04x}): {msg}",
                    socket_role.describe(),
                    bind_flags,
                )
                .into());
            }
        }
    }
    Err(format!(
        "libxdp bind: exhausted {} retries with flags=0x{:04x}",
        BIND_RETRY_ATTEMPTS, bind_flags,
    )
    .into())
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

fn set_busy_poll_opts(fd: c_int, poll_mode: crate::PollMode) {
    const SO_BUSY_POLL: c_int = 46;
    const SO_PREFER_BUSY_POLL: c_int = 69;
    const SO_BUSY_POLL_BUDGET: c_int = 70;
    // Use 1us timeout: just enough to trigger one napi_busy_loop() cycle
    // per poll() call, which posts fill ring WQEs. The 50us value caused
    // 15% CPU overhead from spin-waiting. 1us triggers NAPI and returns
    // immediately, bootstrapping the fill ring with negligible overhead.
    let busy_poll_us: c_int = if poll_mode == crate::PollMode::Interrupt {
        1
    } else {
        50
    };
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

#[cfg(test)]
mod fill_prime_tests {
    use super::{defer_uninserted_fill_suffix, fill_prime_is_total_failure};

    // #2374: a partial bringup prime (inserted < N) MUST recover the
    // un-inserted suffix so the worker can stash it in pending_fill_frames.
    // If the recovery is removed (e.g. revert to dropping the suffix), the
    // returned Vec would be empty and the (N - inserted) frames would leak —
    // this test asserts the suffix is the EXACT tail and FAILS on that revert.
    #[test]
    fn partial_prime_recovers_uninserted_suffix_not_leaked() {
        let offsets: Vec<u64> = vec![0, 4096, 8192, 12288, 16384];
        // Ring accepted only the first 3; the remaining 2 must be deferred.
        let inserted = 3;
        let suffix = defer_uninserted_fill_suffix(&offsets, inserted);
        assert_eq!(
            suffix,
            vec![12288, 16384],
            "partial bringup prime must defer the exact un-inserted suffix \
             (else the (N - inserted) UMEM frames leak — #2374)"
        );
        // No frame is lost: inserted-count + deferred-count == total.
        assert_eq!(
            inserted + suffix.len(),
            offsets.len(),
            "every bringup fill frame must be either inserted or deferred — none dropped"
        );
        // A partial insert is NOT a total failure (must not fail closed).
        assert!(
            !fill_prime_is_total_failure(offsets.len(), inserted),
            "a partial insert must be recovered, not treated as a fatal bind failure"
        );
    }

    // No regression: a full insert defers nothing and is not a failure.
    #[test]
    fn full_prime_defers_nothing() {
        let offsets: Vec<u64> = vec![0, 4096, 8192, 12288];
        let inserted = offsets.len();
        let suffix = defer_uninserted_fill_suffix(&offsets, inserted);
        assert!(
            suffix.is_empty(),
            "a full insert must defer nothing (no spurious pending_fill_frames)"
        );
        assert!(!fill_prime_is_total_failure(offsets.len(), inserted));
        // Defensive: an over-count (inserted reported > total) still defers
        // nothing and never panics (min() clamp).
        assert!(defer_uninserted_fill_suffix(&offsets, inserted + 10).is_empty());
    }

    // No regression: a total failure (inserted == 0 on a non-empty request)
    // must still be classified as fatal so the bind fails closed.
    #[test]
    fn zero_insert_is_total_failure() {
        let offsets: Vec<u64> = vec![0, 4096, 8192];
        assert!(
            fill_prime_is_total_failure(offsets.len(), 0),
            "inserted == 0 on a non-empty prime must remain a fatal bind failure (fail closed)"
        );
        // An empty prime request is a no-op, not a failure. The empty-offsets
        // early return in `prime_fill_ring_offsets` yields exactly this: no
        // total failure AND an empty deferred suffix (and skips the NAPI loop).
        assert!(
            !fill_prime_is_total_failure(0, 0),
            "an empty fill request must not be treated as a failure"
        );
        let empty: Vec<u64> = Vec::new();
        assert!(
            defer_uninserted_fill_suffix(&empty, 0).is_empty(),
            "an empty prime defers nothing"
        );
        // Even when total-failure errors out upstream, the suffix helper for a
        // zero insert would be the whole set (nothing accepted) — proving the
        // recovery path would otherwise carry all frames.
        assert_eq!(defer_uninserted_fill_suffix(&offsets, 0), offsets);
    }
}
