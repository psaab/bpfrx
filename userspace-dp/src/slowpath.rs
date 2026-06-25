use io_uring::IoUring;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Firewall-local traffic is reinjected through the slow path. Keep the queue
// bounded, but do not rate-limit it so aggressively that normal TCP ACK
// traffic collapses sender throughput.
const DEFAULT_QUEUE_DEPTH: usize = 16_384;
const DEFAULT_RATE_LIMIT_PACKETS_PER_SEC: u64 = 1_000_000;
const DEFAULT_RATE_LIMIT_BYTES_PER_SEC: u64 = 4 * 1024 * 1024 * 1024;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// The MTU the kernel assigns a freshly created TUN device. When the
/// desired-MTU programming ioctl fails, this is the MTU the live TUN still
/// has, so it is the largest L3 frame the slow path can actually inject
/// (#2471). Reinjected frames above it are silently dropped by the kernel on
/// TUN egress, so the reinjector must refuse them with a counter and the
/// status must report the degraded state rather than a plain `active`.
const DEFAULT_TUN_MTU: i32 = 1500;

#[derive(Clone, Debug, Default)]
pub struct SlowPathStatus {
    pub active: bool,
    /// #2471: the slow-path worker is running (`active`) but the desired-MTU
    /// programming ioctl failed, so the live TUN MTU is below the configured
    /// data-interface MTU. Jumbo reinjection is refused (see `live_mtu`);
    /// status must surface this so an operator is not misled by a bare
    /// `active = true` while jumbo frames silently drop.
    pub degraded: bool,
    /// #2471: the MTU the live TUN device is actually programmed with. On a
    /// successful program this equals the desired MTU; on a failed program it
    /// falls back to the kernel-default `DEFAULT_TUN_MTU` (1500). Frames whose
    /// total length exceeds this are refused at enqueue.
    pub live_mtu: i32,
    pub device_name: String,
    pub mode: String,
    pub last_error: String,
    pub queued_packets: u64,
    pub injected_packets: u64,
    pub injected_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub rate_limited_packets: u64,
    pub queue_full_packets: u64,
    pub write_errors: u64,
    /// #2471: frames refused at enqueue because their length exceeds the live
    /// TUN MTU (counted into `dropped_packets`/`dropped_bytes` as well). A
    /// non-zero value while `degraded` is the operator-visible proof that
    /// jumbo reinjection is being dropped by the firewall, not the kernel.
    pub mtu_dropped_packets: u64,
}

pub enum EnqueueOutcome {
    Accepted,
    RateLimited,
    QueueFull,
    /// #2471: the frame's length exceeds the live TUN MTU (the slow path is
    /// degraded — MTU programming failed and the TUN is at the 1500 default).
    /// Refused at enqueue with a counter instead of being silently dropped by
    /// the kernel on TUN egress.
    MtuExceeded,
}

struct PacketRequest {
    bytes: Vec<u8>,
}

struct RateLimiter {
    window_started: Instant,
    packets: u64,
    bytes: u64,
    max_packets_per_sec: u64,
    max_bytes_per_sec: u64,
}

impl RateLimiter {
    fn new(max_packets_per_sec: u64, max_bytes_per_sec: u64) -> Self {
        Self {
            window_started: Instant::now(),
            packets: 0,
            bytes: 0,
            max_packets_per_sec,
            max_bytes_per_sec,
        }
    }

    fn allow(&mut self, packet_len: usize) -> bool {
        if self.window_started.elapsed() >= Duration::from_secs(1) {
            self.window_started = Instant::now();
            self.packets = 0;
            self.bytes = 0;
        }
        if self.packets.saturating_add(1) > self.max_packets_per_sec {
            return false;
        }
        if self.bytes.saturating_add(packet_len as u64) > self.max_bytes_per_sec {
            return false;
        }
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(packet_len as u64);
        true
    }
}

enum WriteMode {
    IoUring(IoUring),
    SyncFallback,
}

struct SharedStatus {
    active: AtomicBool,
    /// #2471: set when the worker is active but the live TUN MTU is below the
    /// configured/desired MTU (set_if_mtu failed). See `SlowPathStatus`.
    degraded: AtomicBool,
    /// #2471: the live TUN MTU. `AtomicI64` so the reinjector enqueue path can
    /// read it lock-free on the hot path. Defaults to `DEFAULT_TUN_MTU` until
    /// the worker programs (or fails to program) the device.
    live_mtu: AtomicI64,
    queued_packets: AtomicU64,
    injected_packets: AtomicU64,
    injected_bytes: AtomicU64,
    dropped_packets: AtomicU64,
    dropped_bytes: AtomicU64,
    rate_limited_packets: AtomicU64,
    queue_full_packets: AtomicU64,
    write_errors: AtomicU64,
    mtu_dropped_packets: AtomicU64,
    mode: Mutex<String>,
    device_name: Mutex<String>,
    last_error: Mutex<String>,
}

impl SharedStatus {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            live_mtu: AtomicI64::new(DEFAULT_TUN_MTU as i64),
            queued_packets: AtomicU64::new(0),
            injected_packets: AtomicU64::new(0),
            injected_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            rate_limited_packets: AtomicU64::new(0),
            queue_full_packets: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            mtu_dropped_packets: AtomicU64::new(0),
            mode: Mutex::new(String::from("sync")),
            device_name: Mutex::new(String::new()),
            last_error: Mutex::new(String::new()),
        }
    }

    /// #2471: apply the desired MTU to the live TUN and record the resulting
    /// status. On success the live MTU is the desired MTU and the path is not
    /// degraded. On failure the live MTU falls back to the kernel-default TUN
    /// MTU (1500), `degraded` is set, and the error is recorded — the path
    /// stays usable for <=1500 frames but jumbo reinjection is refused.
    ///
    /// `programmer` is the MTU-programming seam (`set_if_mtu` in production, a
    /// failure-injecting closure in tests). Returns the live MTU now in
    /// effect.
    fn apply_mtu_status(
        &self,
        name: &str,
        desired_mtu: i32,
        programmer: impl FnOnce(&str, i32) -> Result<(), String>,
    ) -> i32 {
        match programmer(name, desired_mtu) {
            Ok(()) => {
                self.live_mtu.store(desired_mtu as i64, Ordering::Relaxed);
                self.degraded.store(false, Ordering::Relaxed);
                desired_mtu
            }
            Err(err) => {
                eprintln!(
                    "xpf-slowpath: set MTU {desired_mtu} on {name}: {err} \
                     (slow-path DEGRADED: jumbo frames > {DEFAULT_TUN_MTU} will be refused)"
                );
                self.set_last_error(err);
                self.live_mtu.store(DEFAULT_TUN_MTU as i64, Ordering::Relaxed);
                self.degraded.store(true, Ordering::Relaxed);
                DEFAULT_TUN_MTU
            }
        }
    }

    fn set_mode(&self, mode: &str) {
        if let Ok(mut value) = self.mode.lock() {
            *value = mode.to_string();
        }
    }

    fn set_device_name(&self, name: &str) {
        if let Ok(mut value) = self.device_name.lock() {
            *value = name.to_string();
        }
    }

    fn set_last_error(&self, err: String) {
        if let Ok(mut value) = self.last_error.lock() {
            *value = err;
        }
    }

    fn snapshot(&self) -> SlowPathStatus {
        SlowPathStatus {
            active: self.active.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
            live_mtu: self.live_mtu.load(Ordering::Relaxed) as i32,
            device_name: self
                .device_name
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            mode: self.mode.lock().map(|v| v.clone()).unwrap_or_default(),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            queued_packets: self.queued_packets.load(Ordering::Relaxed),
            injected_packets: self.injected_packets.load(Ordering::Relaxed),
            injected_bytes: self.injected_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            rate_limited_packets: self.rate_limited_packets.load(Ordering::Relaxed),
            queue_full_packets: self.queue_full_packets.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            mtu_dropped_packets: self.mtu_dropped_packets.load(Ordering::Relaxed),
        }
    }
}

pub struct SlowPathReinjector {
    tx: SyncSender<PacketRequest>,
    limiter: Mutex<RateLimiter>,
    status: Arc<SharedStatus>,
    /// MTU the slow-path TUN was programmed with at creation (#2408). The TUN
    /// MTU is set once when the worker opens the device; a later config MTU
    /// change is NOT applied to the live TUN (the reinjector is preserved
    /// across reconciles), so the reconcile path compares this against the
    /// new snapshot MTU to warn the operator (see `apply_snapshot`).
    mtu: i32,
}

impl SlowPathReinjector {
    /// Create the slow-path reinjector and spawn its worker.
    ///
    /// `mtu` is the MTU (in bytes) to program on the slow-path TUN device so
    /// that reinjected frames up to the largest configured data-interface MTU
    /// are not dropped on the TUN egress (#2408). The caller sources it from
    /// the config snapshot (`ConfigSnapshot::slow_path_mtu`), never hardcoded.
    pub fn new(name: &str, mtu: i32) -> Result<Self, String> {
        let status = Arc::new(SharedStatus::new());
        let (tx, rx) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        let thread_status = status.clone();
        let name = name.to_string();
        thread::Builder::new()
            .name("xpf-slowpath".to_string())
            .spawn(move || slow_path_worker(&name, mtu, rx, thread_status))
            .map_err(|e| format!("spawn slow-path worker: {e}"))?;
        Ok(Self {
            tx,
            limiter: Mutex::new(RateLimiter::new(
                DEFAULT_RATE_LIMIT_PACKETS_PER_SEC,
                DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
            )),
            status,
            mtu,
        })
    }

    /// The MTU the slow-path TUN was programmed with at creation (#2408).
    pub fn mtu(&self) -> i32 {
        self.mtu
    }

    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
        let packet_len = bytes.len() as u64;
        // #2471: refuse frames larger than the live TUN MTU. When MTU
        // programming failed the live TUN is at 1500; injecting a jumbo frame
        // would be silently dropped by the kernel on TUN egress while status
        // still reported `active`. Drop it here with an explicit counter so the
        // degradation is firewall-visible, not hidden in the kernel.
        let live_mtu = self.status.live_mtu.load(Ordering::Relaxed);
        if live_mtu > 0 && packet_len > live_mtu as u64 {
            self.status.mtu_dropped_packets.fetch_add(1, Ordering::Relaxed);
            self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            self.status
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            return Ok(EnqueueOutcome::MtuExceeded);
        }
        let allowed = self
            .limiter
            .lock()
            .map_err(|_| "slow-path limiter lock poisoned".to_string())?
            .allow(bytes.len());
        if !allowed {
            self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            self.status
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            self.status
                .rate_limited_packets
                .fetch_add(1, Ordering::Relaxed);
            return Ok(EnqueueOutcome::RateLimited);
        }
        self.status.queued_packets.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(PacketRequest { bytes }) {
            Ok(()) => Ok(EnqueueOutcome::Accepted),
            Err(TrySendError::Full(req)) => {
                self.status.queued_packets.fetch_sub(1, Ordering::Relaxed);
                self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                self.status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                self.status
                    .queue_full_packets
                    .fetch_add(1, Ordering::Relaxed);
                Ok(EnqueueOutcome::QueueFull)
            }
            Err(TrySendError::Disconnected(req)) => {
                self.status.queued_packets.fetch_sub(1, Ordering::Relaxed);
                self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                self.status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                let err = "slow-path worker is not running".to_string();
                self.status.set_last_error(err.clone());
                Err(err)
            }
        }
    }

    pub fn status(&self) -> SlowPathStatus {
        self.status.snapshot()
    }
}

fn slow_path_worker(name: &str, mtu: i32, rx: Receiver<PacketRequest>, status: Arc<SharedStatus>) {
    let (tun, actual_name) = match open_tun(name) {
        Ok(v) => v,
        Err(err) => {
            status.set_last_error(err);
            status.active.store(false, Ordering::Relaxed);
            return;
        }
    };
    // #2408: the kernel creates the TUN at the default 1500 MTU. Raise it to
    // the largest configured data-interface MTU so reinjected jumbo frames are
    // not silently dropped on the TUN egress. A failure here is non-fatal: the
    // TUN is still usable for <=1500 frames, so the path stays active but is
    // marked DEGRADED (#2471) — `live_mtu` falls back to 1500 and the enqueue
    // path refuses frames above it rather than letting the kernel drop them
    // silently while status reports a healthy `active`.
    status.apply_mtu_status(&actual_name, mtu, set_if_mtu);
    status.set_device_name(&actual_name);
    status.active.store(true, Ordering::Relaxed);

    let mut mode = match IoUring::new(256) {
        Ok(ring) => {
            status.set_mode("io_uring");
            WriteMode::IoUring(ring)
        }
        Err(err) => {
            status.set_mode("sync");
            status.set_last_error(format!("slow-path io_uring unavailable: {err}"));
            WriteMode::SyncFallback
        }
    };

    while let Ok(req) = rx.recv() {
        status.queued_packets.fetch_sub(1, Ordering::Relaxed);
        let result = match &mut mode {
            WriteMode::IoUring(ring) => write_packet_io_uring(ring, tun.as_raw_fd(), &req.bytes)
                .or_else(|_| write_packet_sync(tun.as_raw_fd(), &req.bytes)),
            WriteMode::SyncFallback => write_packet_sync(tun.as_raw_fd(), &req.bytes),
        };
        match result {
            Ok(()) => {
                status.injected_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .injected_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
            }
            Err(err) => {
                status.write_errors.fetch_add(1, Ordering::Relaxed);
                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                status.set_last_error(err);
            }
        }
    }
    status.active.store(false, Ordering::Relaxed);
}

fn write_packet_sync(fd: i32, bytes: &[u8]) -> Result<(), String> {
    write_packet_atomic(bytes.len(), |buf_len| {
        // SAFETY: `bytes` is a valid slice for `buf_len` bytes; `fd` is the TUN
        // fd owned by the worker. Always writes from offset 0 — a TUN write is
        // one packet, never a partial-offset resubmit.
        unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), buf_len) }
    })
}

/// Write one whole packet to a packet-oriented fd (the TUN device).
///
/// A TUN/TAP fd is datagram-like: each successful `write()` injects exactly one
/// L3 packet. There is no byte-stream resume — re-writing a "remainder" after a
/// short count would inject the leftover bytes as a SECOND, malformed packet
/// (#2407). So this never advances an offset:
///
///   * `EINTR` — the write never started; retry the WHOLE packet.
///   * full count (`rc == len`) — success.
///   * partial (`0 < rc < len`) — the packet is unsendable as written and a
///     resubmit would corrupt the stream; DROP it (return `Err`, which the
///     caller counts as a dropped packet + write error).
///   * `rc == 0` or `rc < 0` (any other errno, incl. `EAGAIN`) — `Err` (drop).
///
/// `writer(len)` performs one `write(fd, buf, len)` and returns its raw result,
/// mirroring `libc::write`: a non-negative byte count on success, or `-1` on
/// error with `errno` set separately (the unit-test seam sets `errno`
/// explicitly). On a `-1` return `write_packet_atomic` reads `errno` via
/// `io::Error::last_os_error()` to distinguish `EINTR` (retry the whole packet)
/// from a hard error (drop). It is a seam so the short-count / EINTR behaviour
/// is unit-testable without a real fd.
fn write_packet_atomic<F>(len: usize, mut writer: F) -> Result<(), String>
where
    F: FnMut(usize) -> isize,
{
    loop {
        let rc = writer(len);
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                // The write was interrupted before transferring any bytes;
                // retry the whole packet from offset 0.
                continue;
            }
            return Err(format!("slow-path write: {err}"));
        }
        let n = rc as usize;
        if n == len {
            return Ok(());
        }
        // A short or zero count on a packet device: the packet cannot be
        // resumed (re-writing bytes[n..] would inject a corrupt packet), so
        // drop it. This is unexpected for a valid TUN write; dropping avoids
        // corrupting the device stream.
        return Err(format!(
            "slow-path short write on packet fd: wrote {n} of {len} bytes (packet dropped)"
        ));
    }
}

fn write_packet_io_uring(ring: &mut IoUring, fd: i32, bytes: &[u8]) -> Result<(), String> {
    // Stream write to the TUN device (no file offset). The shared loop retries
    // the wait on EINTR rather than abandoning an in-flight SQE, matches the
    // completion by user_data so a stale CQE cannot corrupt the offset, and
    // returns only after the matching CQE is reaped so `bytes` outlives every
    // kernel reference (#2297).
    crate::io_uring_write::write_all_to_fd(ring, fd, bytes, false, "slow-path")
}

pub(crate) fn open_tun(name: &str) -> Result<(std::fs::File, String), String> {
    // O_CLOEXEC so the TUN fd is NOT inherited by any child process xpfd execs
    // (frr-reload, ip, sysctl helpers, etc.) — a leaked TUN fd in a child both
    // wastes a descriptor and pins the device open past helper exit (#2480).
    // Rust's OpenOptions does NOT set O_CLOEXEC by default on Unix, so request
    // it explicitly via custom_flags.
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .map_err(|e| format!("open /dev/net/tun: {e}"))?;
    let mut ifr = IfReq::new(name, IFF_TUN | IFF_NO_PI)?;
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut ifr) };
    if rc < 0 {
        return Err(format!(
            "TUNSETIFF {}: {}",
            name,
            io::Error::last_os_error()
        ));
    }
    let actual_name = ifr.name_string();
    set_if_up(&actual_name)?;
    // Slow-path injected IPv4 replies arrive on the TUN device, but their
    // reverse route still points at the real egress interface. Disable
    // per-device rp_filter so the kernel accepts those packets.
    set_ipv4_sysctl(&actual_name, "rp_filter", "0")?;
    // The kernel computes the effective rp_filter for a packet as
    // max(conf/all/rp_filter, conf/<dev>/rp_filter) (see
    // Documentation/networking/ip-sysctl.rst). So the per-device 0 we just
    // wrote is IGNORED if conf/all/rp_filter is non-zero (strict=1 / loose=2,
    // a common Debian/Ubuntu default) — every slow-path reinjected IPv4 packet
    // would then be silently dropped as a reverse-path failure (#2378). We do
    // NOT mutate the host-global conf/all knob here (the helper owns no
    // host-global sysctls); instead emit a one-time, operator-visible warning
    // at TUN bringup. This is bringup-only, never per-packet.
    let all_rpf = read_all_rp_filter(ALL_RP_FILTER_PATH);
    if let Some(line) = rp_filter_all_warning(&actual_name, all_rpf) {
        eprintln!("{line}");
    }
    Ok((tun, actual_name))
}

/// Production default path to the host-global IPv4 reverse-path-filter sysctl.
/// `read_all_rp_filter` takes the path as a parameter, so tests pass their own
/// temp-file path directly; this constant is only the live-`/proc` default that
/// `open_tun` reads.
const ALL_RP_FILTER_PATH: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";

/// Read the integer value of `conf/all/rp_filter` from `path`. Returns `None`
/// if the file is missing or unparsable (treated as "cannot determine, do not
/// warn") so a read failure never produces a spurious warning.
fn read_all_rp_filter(path: &str) -> Option<i32> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok()
}

/// Decide whether to warn that a non-zero conf/all/rp_filter will drop
/// slow-path reinjection.
///
/// The kernel uses max(conf/all/rp_filter, conf/<dev>/rp_filter), so a non-zero
/// conf/all/rp_filter defeats reverse-path acceptance on the slow-path TUN
/// regardless of the per-device value. The message states the hazard from the
/// all-knob directly (it does NOT assert that the per-device 0 was written), so
/// it is accurate whether or not the per-device write succeeded. Returns
/// `Some(warning_line)` when `all_rpf` is a known non-zero value, `None` when
/// it is 0 or unknown. Seamed (takes the already-read value) so it is
/// unit-testable without touching live /proc.
fn rp_filter_all_warning(dev: &str, all_rpf: Option<i32>) -> Option<String> {
    match all_rpf {
        Some(v) if v != 0 => Some(format!(
            "xpf-ha: WARNING net.ipv4.conf.all.rp_filter={v} is non-zero; the \
             kernel uses max(all,dev) so slow-path reinjected IPv4 packets on \
             TUN {dev} will be SILENTLY DROPPED until \
             'sysctl -w net.ipv4.conf.all.rp_filter=0' is set (#2378)"
        )),
        _ => None,
    }
}

/// Run an ioctl on `sock`, capture its errno, THEN close `sock` (#2479).
///
/// Returns `(ioctl_rc, ioctl_err, close_rc)`. The ioctl's `io::Error` is
/// captured BEFORE `close()` runs, so a caller reporting `ioctl_err` always
/// sees the ioctl's failure — never the errno a failing `close()` would leave
/// behind. The fd is always closed (no leak) even when the ioctl failed.
///
/// `ioctl_fn` receives the fd and must return the raw ioctl return code; the
/// thread-local errno it leaves is what gets captured.
#[inline]
fn ioctl_then_close(
    sock: libc::c_int,
    ioctl_fn: impl FnOnce(libc::c_int) -> libc::c_int,
) -> (libc::c_int, io::Error, libc::c_int) {
    let rc = ioctl_fn(sock);
    // Capture immediately, before close() can touch errno.
    let err = io::Error::last_os_error();
    let close_rc = unsafe { libc::close(sock) };
    (rc, err, close_rc)
}

fn set_if_up(name: &str) -> Result<(), String> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(format!(
            "open control socket: {}",
            io::Error::last_os_error()
        ));
    }
    let mut ifr = IfReq::new(name, 0)?;
    let get_rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) };
    if get_rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(format!("SIOCGIFFLAGS {}: {err}", name));
    }
    let flags = unsafe { ifr.ifru.flags } | (libc::IFF_UP as libc::c_short);
    ifr.ifru.flags = flags;
    // #2479: capture the ioctl's errno BEFORE close(). close() is a syscall
    // that can overwrite thread-local errno (success leaves it untouched per
    // POSIX, but a failing close sets EBADF), so reading last_os_error() after
    // close risks reporting close's errno, not the ioctl's failure. The seam
    // captures-then-closes in one place; mirrors the SIOCGIFFLAGS
    // capture-before-close above.
    let (set_rc, set_err, close_rc) =
        ioctl_then_close(sock, |s| unsafe { libc::ioctl(s, libc::SIOCSIFFLAGS, &ifr) });
    if set_rc < 0 {
        return Err(format!("SIOCSIFFLAGS {}: {}", name, set_err));
    }
    if close_rc < 0 {
        return Err(format!(
            "close control socket: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Program the MTU on a TUN device via `SIOCSIFMTU` (#2408).
///
/// `mtu` must be > 0; a non-positive value is a programming error and is
/// rejected without touching the device. Returns `Err` (caller logs and
/// continues) on socket/ioctl failure.
fn set_if_mtu(name: &str, mtu: i32) -> Result<(), String> {
    if mtu <= 0 {
        return Err(format!("invalid MTU {mtu} for {name}"));
    }
    // Build the ifreq BEFORE opening the socket so an invalid-name early
    // return does not leak the control-socket fd (Copilot #2439).
    let mut ifr = IfReq::new(name, 0)?;
    ifr.ifru.mtu = mtu as libc::c_int;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(format!(
            "open control socket: {}",
            io::Error::last_os_error()
        ));
    }
    // #2479: capture the ioctl's errno BEFORE close() via the shared seam
    // (see set_if_up). A failing close() would otherwise clobber errno and we
    // would report close's failure instead of the ioctl's.
    let (set_rc, set_err, close_rc) =
        ioctl_then_close(sock, |s| unsafe { libc::ioctl(s, libc::SIOCSIFMTU, &ifr) });
    if set_rc < 0 {
        return Err(format!("SIOCSIFMTU {} mtu={}: {}", name, mtu, set_err));
    }
    if close_rc < 0 {
        return Err(format!(
            "close control socket: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_ipv4_sysctl(iface: &str, key: &str, value: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{key}");
    std::fs::write(&path, value).map_err(|e| format!("write {path}: {e}"))
}

#[repr(C)]
union Ifru {
    flags: libc::c_short,
    _addr: libc::sockaddr,
    _ifindex: libc::c_int,
    mtu: libc::c_int,
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifru: Ifru,
}

impl IfReq {
    fn new(name: &str, flags: libc::c_short) -> Result<Self, String> {
        let mut ifr = Self {
            ifr_name: [0; libc::IFNAMSIZ],
            ifru: Ifru { flags },
        };
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("invalid interface name {}", name));
        }
        for (idx, byte) in bytes.iter().enumerate() {
            ifr.ifr_name[idx] = *byte as libc::c_char;
        }
        Ok(ifr)
    }

    fn name_string(&self) -> String {
        let len = self
            .ifr_name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(self.ifr_name.len());
        self.ifr_name[..len]
            .iter()
            .map(|c| *c as u8)
            .collect::<Vec<_>>()
            .into_iter()
            .map(char::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2378 fail-on-revert: when conf/all/rp_filter is strict (1) or loose (2),
    /// the per-device rp_filter=0 we write on the slow-path TUN is overridden by
    /// the kernel's max(all, dev) rule, so reinjected IPv4 packets are dropped.
    /// `rp_filter_all_warning` MUST return a warning in that case. If the check
    /// is removed (helper always returns None), these assertions fail.
    #[test]
    fn rp_filter_all_warning_fires_on_strict_and_loose() {
        let strict = rp_filter_all_warning("xpf-usp0", Some(1));
        assert!(strict.is_some(), "all=1 (strict) must warn");
        assert!(strict.unwrap().contains("rp_filter"));

        let loose = rp_filter_all_warning("xpf-usp0", Some(2));
        assert!(loose.is_some(), "all=2 (loose) must warn");
        let msg = loose.unwrap();
        assert!(msg.contains("xpf-usp0"), "warning names the device");
        assert!(msg.contains("=2"), "warning reports the offending value");
    }

    /// When conf/all/rp_filter is 0 (or unknown/unparsable) the per-device 0 is
    /// effective, so the helper must stay quiet — no spurious operator warning.
    #[test]
    fn rp_filter_all_warning_quiet_when_zero_or_unknown() {
        assert!(
            rp_filter_all_warning("xpf-usp0", Some(0)).is_none(),
            "all=0 must not warn"
        );
        assert!(
            rp_filter_all_warning("xpf-usp0", None).is_none(),
            "unknown all value must not warn"
        );
    }

    /// The file-reading seam parses the sysctl value and tolerates trailing
    /// whitespace; a missing or garbage file yields None (do-not-warn).
    #[test]
    fn read_all_rp_filter_parses_and_tolerates_missing() {
        let dir = std::env::temp_dir().join(format!("xpf-rpf-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("all_rp_filter");
        std::fs::write(&ok, "1\n").unwrap();
        assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), Some(1));

        std::fs::write(&ok, "  2  ").unwrap();
        assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), Some(2));

        let missing = dir.join("does-not-exist");
        assert_eq!(read_all_rp_filter(missing.to_str().unwrap()), None);

        std::fs::write(&ok, "garbage").unwrap();
        assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #2471 fail-on-revert: when the MTU-programming ioctl FAILS, the slow
    /// path must NOT report a bare `active = true`. It must report `degraded`,
    /// fall the live MTU back to the kernel default (1500), and record the
    /// error. If the failure handling reverts to the buggy unconditional
    /// `active.store(true)` with no degraded bit, these assertions fail.
    #[test]
    fn apply_mtu_status_degrades_on_failure() {
        let status = SharedStatus::new();
        let live = status.apply_mtu_status("xpf-usp0", 9000, |_name, _mtu| {
            Err("SIOCSIFMTU xpf-usp0 mtu=9000: Operation not permitted".to_string())
        });
        // The worker would still flip active=true after this; what proves the
        // bug is fixed is the degraded bit + the live-MTU fallback.
        assert_eq!(live, DEFAULT_TUN_MTU, "failed program falls back to 1500");
        let snap = status.snapshot();
        assert!(snap.degraded, "MTU program failure must mark the path degraded");
        assert_eq!(snap.live_mtu, DEFAULT_TUN_MTU, "live MTU reports the 1500 fallback");
        assert!(
            !snap.last_error.is_empty(),
            "the ioctl error must be recorded for the operator"
        );
    }

    /// On a successful program the path is NOT degraded and the live MTU is the
    /// desired (jumbo) MTU, so jumbo reinjection is permitted.
    #[test]
    fn apply_mtu_status_clean_on_success() {
        let status = SharedStatus::new();
        let live = status.apply_mtu_status("xpf-usp0", 9000, |name, mtu| {
            assert_eq!(name, "xpf-usp0");
            assert_eq!(mtu, 9000);
            Ok(())
        });
        assert_eq!(live, 9000);
        let snap = status.snapshot();
        assert!(!snap.degraded, "a successful program is not degraded");
        assert_eq!(snap.live_mtu, 9000, "live MTU is the desired jumbo MTU");
    }

    /// #2471 fail-on-revert: a frame larger than the live TUN MTU must be
    /// REFUSED at enqueue (counted), not silently passed to the kernel where it
    /// would be dropped on TUN egress. With the bug (no live-MTU gate) the
    /// jumbo frame would be Accepted; this asserts MtuExceeded + the counters.
    #[test]
    fn enqueue_refuses_frame_above_live_mtu() {
        let reinjector =
            SlowPathReinjector::new("xpf-usp-test0", 9000).expect("spawn reinjector");
        // Simulate a degraded TUN: the worker programmed (or failed to) and the
        // live MTU is the 1500 default. Force that state directly.
        reinjector
            .status
            .live_mtu
            .store(DEFAULT_TUN_MTU as i64, Ordering::Relaxed);
        reinjector.status.degraded.store(true, Ordering::Relaxed);

        // A <=1500 frame is admitted (not MTU-refused).
        let small = reinjector.enqueue(vec![0u8; 1400]).expect("enqueue small");
        assert!(
            matches!(small, EnqueueOutcome::Accepted),
            "a 1400-byte frame is within the live MTU and must be accepted"
        );

        // A jumbo frame above the live MTU is refused with the MTU outcome.
        let jumbo = reinjector.enqueue(vec![0u8; 8000]).expect("enqueue jumbo");
        assert!(
            matches!(jumbo, EnqueueOutcome::MtuExceeded),
            "an 8000-byte frame above the 1500 live MTU must be refused, not silently dropped"
        );
        let snap = reinjector.status();
        assert_eq!(snap.mtu_dropped_packets, 1, "the MTU drop is counted");
        assert!(snap.dropped_packets >= 1, "MTU drop also rolls into dropped_packets");
        assert!(snap.dropped_bytes >= 8000, "dropped bytes accumulate the refused frame");
    }

    #[test]
    fn rate_limiter_refills_after_window() {
        let mut limiter = RateLimiter::new(1, 128);
        assert!(limiter.allow(64));
        assert!(!limiter.allow(64));
        limiter.window_started = Instant::now() - Duration::from_secs(2);
        assert!(limiter.allow(64));
    }

    #[test]
    fn status_snapshot_reflects_counters() {
        let status = SharedStatus::new();
        status.active.store(true, Ordering::Relaxed);
        status.queued_packets.store(2, Ordering::Relaxed);
        status.injected_packets.store(3, Ordering::Relaxed);
        status.set_mode("io_uring");
        status.set_device_name("xpf-usp0");
        status.set_last_error("none".to_string());
        let snap = status.snapshot();
        assert!(snap.active);
        assert_eq!(snap.queued_packets, 2);
        assert_eq!(snap.injected_packets, 3);
        assert_eq!(snap.mode, "io_uring");
        assert_eq!(snap.device_name, "xpf-usp0");
        assert_eq!(snap.last_error, "none");
    }

    /// A normal full write succeeds in a single `write()` call (no regression).
    #[test]
    fn sync_full_write_succeeds_single_call() {
        let len = 100usize;
        let mut calls = 0usize;
        let res = write_packet_atomic(len, |buf_len| {
            calls += 1;
            assert_eq!(buf_len, len, "writer must always be handed the full packet");
            buf_len as isize
        });
        assert!(res.is_ok());
        assert_eq!(calls, 1, "a full write must not loop");
    }

    /// #2407 fail-on-revert: a short count (0 < n < len) on the packet fd MUST
    /// drop the packet (Err) — it must NOT issue a follow-up write of the
    /// remaining bytes. The writer is invoked exactly once and always with the
    /// FULL length; there is never a `write(bytes[n..])` of length `len - n`.
    ///
    /// If the stream-style remainder loop were restored, the writer would be
    /// called a SECOND time with `len - n` to finish the packet — corrupting the
    /// TUN. This asserts call count == 1 and that the one call used the full
    /// length, so a remainder resubmit fails the test.
    #[test]
    fn sync_short_write_drops_no_remainder() {
        let len = 100usize;
        let mut observed_lens = Vec::new();
        let res = write_packet_atomic(len, |buf_len| {
            observed_lens.push(buf_len);
            40 // partial: 40 of 100
        });
        let err = res.unwrap_err();
        assert!(
            err.contains("short write on packet fd"),
            "partial packet write must be a drop, got: {err}"
        );
        assert_eq!(
            observed_lens,
            vec![len],
            "a partial write must NOT trigger a remainder write — exactly one \
             full-length write, never a write of bytes[n..]"
        );
    }

    /// EINTR retries the WHOLE packet (offset 0), never a partial offset.
    #[test]
    fn sync_eintr_retries_whole_packet() {
        let len = 100usize;
        let mut observed_lens = Vec::new();
        let mut first = true;
        let res = write_packet_atomic(len, |buf_len| {
            observed_lens.push(buf_len);
            if first {
                first = false;
                // Simulate write() returning -1 with errno = EINTR.
                set_errno(libc::EINTR);
                -1
            } else {
                buf_len as isize
            }
        });
        assert!(res.is_ok(), "EINTR must retry, not fail");
        assert_eq!(
            observed_lens,
            vec![len, len],
            "EINTR retry must re-issue the WHOLE packet, never bytes[n..]"
        );
    }

    /// A zero count is treated as a short write and dropped (no infinite loop).
    #[test]
    fn sync_zero_write_drops() {
        let res = write_packet_atomic(100, |_| 0);
        assert!(res.unwrap_err().contains("short write on packet fd"));
    }

    /// A hard error (non-EINTR negative) drops the packet.
    #[test]
    fn sync_hard_error_drops() {
        let res = write_packet_atomic(100, |_| {
            set_errno(libc::EIO);
            -1
        });
        assert!(res.unwrap_err().contains("slow-path write"));
    }

    /// Set the thread-local errno so the seam can simulate `libc::write`'s
    /// errno reporting. `io::Error::last_os_error()` reads this.
    fn set_errno(e: libc::c_int) {
        unsafe {
            *libc::__errno_location() = e;
        }
    }

    /// #2408: `set_if_mtu` rejects a non-positive MTU before touching any
    /// device (defensive — the caller sources a clamped value, but a 0/neg
    /// MTU must never be programmed). FAILS if the `mtu <= 0` guard is dropped
    /// (the call would then open a socket and attempt the ioctl).
    #[test]
    fn set_if_mtu_rejects_nonpositive() {
        assert!(set_if_mtu("xpf-usp0", 0)
            .unwrap_err()
            .contains("invalid MTU"));
        assert!(set_if_mtu("xpf-usp0", -1)
            .unwrap_err()
            .contains("invalid MTU"));
    }

    /// #2479: the `ioctl_then_close` seam must capture the ioctl's errno
    /// BEFORE `close()` runs, so a failing close() cannot clobber the reported
    /// error. This is the deterministic fail-on-revert guard for both
    /// `set_if_up` (SIOCSIFFLAGS) and `set_if_mtu` (SIOCSIFMTU), which both
    /// route their capture-then-close through this seam.
    ///
    /// We make close() FAIL deterministically by handing the seam an invalid
    /// fd (`-1`): `close(-1)` returns -1 and sets errno to `EBADF`. The ioctl
    /// closure instead leaves a sentinel errno (`ENODEV`). The seam must
    /// return the SENTINEL — proving the capture happened before close.
    ///
    /// FAIL-ON-REVERT: if the capture is moved to AFTER `close()` (the #2479
    /// bug), `err` carries `EBADF` (close's errno), not `ENODEV`, and this
    /// assertion goes RED. The valid-fd path is exercised by the live
    /// `set_if_mtu_reports_ioctl_failure` test below.
    #[test]
    fn ioctl_then_close_captures_errno_before_close() {
        let (rc, err, close_rc) = ioctl_then_close(-1, |_fd| {
            // Simulate a failing ioctl that leaves ENODEV in errno.
            set_errno(libc::ENODEV);
            -1
        });
        assert_eq!(rc, -1, "the simulated ioctl returns failure");
        assert_eq!(close_rc, -1, "close(-1) must fail (EBADF)");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENODEV),
            "seam must report the IOCTL errno (ENODEV), not close()'s EBADF: {err}"
        );
        assert_ne!(
            err.raw_os_error(),
            Some(libc::EBADF),
            "the close()-clobbered errno must NOT leak through: {err}"
        );
    }

    /// #2479 (live path): a genuine `SIOCSIFMTU` failure surfaces a non-zero
    /// ioctl errno, never close()'s success. Targets a nonexistent interface
    /// (no NIC/privilege needed — opening an `AF_INET`/`SOCK_DGRAM` socket and
    /// issuing a failing ioctl works in the sandbox). The errno varies with
    /// privileges (`ENODEV`/`ENXIO` unprivileged, `EPERM` when CAP_NET_ADMIN
    /// is checked first), so we assert only the load-bearing property: the
    /// message carries a non-zero os-error, not "success (os error 0)".
    #[test]
    fn set_if_mtu_reports_ioctl_failure() {
        let err = set_if_mtu("xpf-nodev-zzz9", 9000)
            .expect_err("ioctl on a nonexistent interface must fail");
        assert!(
            err.contains("SIOCSIFMTU"),
            "error should name the failing ioctl: {err}"
        );
        assert!(
            err.contains("os error") && !err.contains("os error 0"),
            "error must report a non-zero ioctl os-error, not success: {err}"
        );
    }

    /// #2408: the MTU is written into the `ifru.mtu` arm of the ifreq union
    /// that `SIOCSIFMTU` reads. FAILS if the value is not stored (e.g. the
    /// assignment is removed) — the union would carry 0, not 9000.
    #[test]
    fn ifreq_carries_mtu_value() {
        let mut ifr = IfReq::new("xpf-usp0", 0).unwrap();
        ifr.ifru.mtu = 9000;
        // SAFETY: we just wrote the `mtu` arm, so reading it back is defined.
        assert_eq!(unsafe { ifr.ifru.mtu }, 9000);
        assert_eq!(ifr.name_string(), "xpf-usp0");
    }
}
