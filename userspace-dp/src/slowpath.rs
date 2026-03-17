use io_uring::{IoUring, opcode, types};
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
    tx: Option<SyncSender<PacketRequest>>,
    join: Option<thread::JoinHandle<()>>,
    limiter: Mutex<RateLimiter>,
    status: Arc<SharedStatus>,
}

impl SlowPathReinjector {
    pub fn new(name: &str) -> Result<Self, String> {
        let status = Arc::new(SharedStatus::new());
        let (tx, rx) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        let thread_status = status.clone();
        let name = name.to_string();
        let join = thread::Builder::new()
            .name("bpfrx-slowpath".to_string())
            .spawn(move || slow_path_worker(&name, rx, thread_status))
            .map_err(|e| format!("spawn slow-path worker: {e}"))?;
        Ok(Self {
            tx: Some(tx),
            join: Some(join),
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
        let Some(tx) = self.tx.as_ref() else {
            self.status.queued_packets.fetch_sub(1, Ordering::Relaxed);
            self.status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            self.status
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            let err = "slow-path worker is not running".to_string();
            self.status.set_last_error(err.clone());
            return Err(err);
        };
        match tx.try_send(PacketRequest { bytes }) {
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

impl Drop for SlowPathReinjector {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn slow_path_worker(name: &str, rx: Receiver<PacketRequest>, status: Arc<SharedStatus>) {
    let (tun, actual_name) = match open_tun(name) {
        Ok(v) => v,
        Err(err) => {
            status.set_last_error(err);
            status.active.store(false, Ordering::Relaxed);
            return;
        }
    };
    status.set_device_name(&actual_name);
    status.active.store(true, Ordering::Relaxed);
    let mut last_ipv4_sysctl_refresh = Instant::now() - Duration::from_secs(1);

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
        if last_ipv4_sysctl_refresh.elapsed() >= Duration::from_secs(1) {
            if let Err(err) = ensure_ipv4_sysctl_value(&actual_name, "rp_filter", "0") {
                status.set_last_error(err);
            }
            last_ipv4_sysctl_refresh = Instant::now();
        }
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
    let mut written = 0usize;
    while written < bytes.len() {
        let rc = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(written).cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if rc < 0 {
            return Err(format!("slow-path write: {}", io::Error::last_os_error()));
        }
        if rc == 0 {
            return Err("slow-path write returned 0".to_string());
        }
        written += rc as usize;
    }
    Ok(())
}

fn write_packet_io_uring(ring: &mut IoUring, fd: i32, bytes: &[u8]) -> Result<(), String> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let entry = opcode::Write::new(
            types::Fd(fd),
            unsafe { bytes.as_ptr().add(offset) },
            (bytes.len() - offset) as _,
        )
        .build()
        .user_data(1);
        unsafe {
            ring.submission()
                .push(&entry)
                .map_err(|_| "slow-path submit queue full".to_string())?;
        }
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit slow-path write: {e}"))?;
        let mut completion = ring.completion();
        let cqe = completion
            .next()
            .ok_or_else(|| "missing slow-path completion".to_string())?;
        let res = cqe.result();
        if res < 0 {
            return Err(format!(
                "slow-path io_uring write failed: {}",
                io::Error::from_raw_os_error(-res)
            ));
        }
        if res == 0 {
            return Err("slow-path io_uring short write: 0".to_string());
        }
        offset += res as usize;
    }
    Ok(())
}

fn open_tun(name: &str) -> Result<(std::fs::File, String), String> {
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
    // reverse route still points at the real egress interface. New links may
    // get a wildcard rp_filter reapplied shortly after creation, so keep
    // forcing the per-device value until the interface settles.
    ensure_ipv4_sysctl_value(&actual_name, "rp_filter", "0")?;
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

fn set_ipv4_sysctl(iface: &str, key: &str, value: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{key}");
    std::fs::write(&path, value).map_err(|e| format!("write {path}: {e}"))
}

fn read_ipv4_sysctl(iface: &str, key: &str) -> Result<String, String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{key}");
    std::fs::read_to_string(&path)
        .map(|value| value.trim().to_string())
        .map_err(|e| format!("read {path}: {e}"))
}

fn ensure_ipv4_sysctl_value(iface: &str, key: &str, value: &str) -> Result<(), String> {
    let mut last_error = String::new();
    for _ in 0..20 {
        set_ipv4_sysctl(iface, key, value)?;
        match read_ipv4_sysctl(iface, key) {
            Ok(current) if current == value => return Ok(()),
            Ok(current) => {
                last_error = format!(
                    "verify /proc/sys/net/ipv4/conf/{iface}/{key}: got {current}, want {value}"
                );
            }
            Err(err) => {
                last_error = err;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last_error)
}

#[repr(C)]
union Ifru {
    flags: libc::c_short,
    _addr: libc::sockaddr,
    _ifindex: libc::c_int,
    _mtu: libc::c_int,
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
        status.set_device_name("bpfrx-usp0");
        status.set_last_error("none".to_string());
        let snap = status.snapshot();
        assert!(snap.active);
        assert_eq!(snap.queued_packets, 2);
        assert_eq!(snap.injected_packets, 3);
        assert_eq!(snap.mode, "io_uring");
        assert_eq!(snap.device_name, "bpfrx-usp0");
        assert_eq!(snap.last_error, "none");
    }
}
