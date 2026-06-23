use io_uring::IoUring;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

#[derive(Clone, Debug, Default)]
pub struct SlowPathStatus {
    pub active: bool,
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
}

pub enum EnqueueOutcome {
    Accepted,
    RateLimited,
    QueueFull,
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
    queued_packets: AtomicU64,
    injected_packets: AtomicU64,
    injected_bytes: AtomicU64,
    dropped_packets: AtomicU64,
    dropped_bytes: AtomicU64,
    rate_limited_packets: AtomicU64,
    queue_full_packets: AtomicU64,
    write_errors: AtomicU64,
    mode: Mutex<String>,
    device_name: Mutex<String>,
    last_error: Mutex<String>,
}

impl SharedStatus {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            queued_packets: AtomicU64::new(0),
            injected_packets: AtomicU64::new(0),
            injected_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            rate_limited_packets: AtomicU64::new(0),
            queue_full_packets: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            mode: Mutex::new(String::from("sync")),
            device_name: Mutex::new(String::new()),
            last_error: Mutex::new(String::new()),
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
        }
    }
}

pub struct SlowPathReinjector {
    tx: SyncSender<PacketRequest>,
    limiter: Mutex<RateLimiter>,
    status: Arc<SharedStatus>,
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
        })
    }

    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
        let packet_len = bytes.len() as u64;
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
    // TUN is still usable for <=1500 frames, so log and continue rather than
    // tearing down the whole slow path.
    if let Err(err) = set_if_mtu(&actual_name, mtu) {
        eprintln!(
            "xpf-slowpath: set MTU {mtu} on {actual_name}: {err} (slow-path jumbo frames may drop)"
        );
        status.set_last_error(err);
    }
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
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
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
    Ok((tun, actual_name))
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
    let set_rc = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) };
    let close_rc = unsafe { libc::close(sock) };
    if set_rc < 0 {
        return Err(format!(
            "SIOCSIFFLAGS {}: {}",
            name,
            io::Error::last_os_error()
        ));
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
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(format!(
            "open control socket: {}",
            io::Error::last_os_error()
        ));
    }
    let mut ifr = IfReq::new(name, 0)?;
    ifr.ifru.mtu = mtu as libc::c_int;
    let set_rc = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU, &ifr) };
    let close_rc = unsafe { libc::close(sock) };
    if set_rc < 0 {
        return Err(format!(
            "SIOCSIFMTU {} mtu={}: {}",
            name,
            mtu,
            io::Error::last_os_error()
        ));
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
