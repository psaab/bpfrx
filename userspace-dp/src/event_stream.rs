//! Event stream producer for session sync.
//!
//! Replaces the polled `drain_session_deltas` RPC with a push-based binary
//! event stream over a dedicated Unix socket. The Go daemon creates a listener
//! at the event socket path; the helper connects and pushes binary-framed
//! session events (open/close/update) with monotonic sequence numbers.
//!
//! Wire format (per docs/session-sync-design.md):
//!   Frame header: [length:u32 LE][type:u8][reserved:3][seq:u64 LE]
//!   Payload: type-specific binary (see encode functions)

use crate::afxdp::ForwardingDisposition;
use crate::session::{SessionDelta, SessionDeltaKind, SessionDecision, SessionKey, SessionMetadata};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

const FRAME_HEADER_SIZE: usize = 16;

const MSG_SESSION_OPEN: u8 = 1;
const MSG_SESSION_CLOSE: u8 = 2;
#[allow(dead_code)]
const MSG_SESSION_UPDATE: u8 = 3;
const MSG_ACK: u8 = 4;
const MSG_PAUSE: u8 = 5;
const MSG_RESUME: u8 = 6;
const MSG_DRAIN_REQUEST: u8 = 7;
const MSG_DRAIN_COMPLETE: u8 = 8;
const MSG_FULL_RESYNC: u8 = 9;
const MSG_KEEPALIVE: u8 = 10;

/// Interval between keepalive frames to prevent idle disconnect.
const KEEPALIVE_INTERVAL_NS: u64 = 10_000_000_000; // 10 seconds

/// Maximum event frames buffered in the mpsc channel (shared across workers).
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum frames retained for replay after disconnect.
const REPLAY_BUFFER_CAPACITY: usize = 4096;

/// Disposition encoding for the wire format.
const DISP_FORWARD_CANDIDATE: u8 = 0;
const DISP_LOCAL_DELIVERY: u8 = 1;
const DISP_FABRIC_REDIRECT: u8 = 2;
const DISP_POLICY_DENIED: u8 = 3;
const DISP_NO_ROUTE: u8 = 4;
const DISP_MISSING_NEIGHBOR: u8 = 5;
const DISP_HA_INACTIVE: u8 = 6;
const DISP_DISCARD_ROUTE: u8 = 7;
const DISP_NEXT_TABLE_UNSUPPORTED: u8 = 8;

// Flag bits for SessionOpen/Close
const FLAG_FABRIC_REDIRECT: u8 = 1 << 0;
const FLAG_FABRIC_INGRESS: u8 = 1 << 1;
const FLAG_IS_REVERSE: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// EventFrame — zero-allocation stack-buffered wire frame
// ---------------------------------------------------------------------------

/// Pre-serialized event frame ready for socket write.
#[derive(Clone)]
pub(crate) struct EventFrame {
    data: [u8; 256],
    len: u16,
    seq: u64,
}

impl EventFrame {
    /// Encode a SessionOpen (type 1) or SessionUpdate (type 3) frame.
    pub(crate) fn encode_session_open(
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE; // skip header, fill later

        // [0] AddrFamily
        let is_v6 = key.addr_family == libc::AF_INET6 as u8;
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort LE
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort LE
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // [6:8] NATSrcPort LE
        let nat = &decision.nat;
        buf[pos..pos + 2]
            .copy_from_slice(&nat.rewrite_src_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [8:10] NATDstPort LE
        buf[pos..pos + 2]
            .copy_from_slice(&nat.rewrite_dst_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [10:12] OwnerRGID i16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&(metadata.owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // [12:14] EgressIfindex i16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&(decision.resolution.egress_ifindex as i16).to_le_bytes());
        pos += 2;

        // [14:16] TXIfindex i16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&(decision.resolution.tx_ifindex as i16).to_le_bytes());
        pos += 2;

        // [16:18] TunnelEndpointID u16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&decision.resolution.tunnel_endpoint_id.to_le_bytes());
        pos += 2;

        // [18:20] TXVLANID u16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&decision.resolution.tx_vlan_id.to_le_bytes());
        pos += 2;

        // [20] Flags
        let mut flags: u8 = 0;
        if fabric_redirect_sync
            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        {
            flags |= FLAG_FABRIC_REDIRECT;
        }
        if metadata.fabric_ingress {
            flags |= FLAG_FABRIC_INGRESS;
        }
        if metadata.is_reverse {
            flags |= FLAG_IS_REVERSE;
        }
        buf[pos] = flags;
        pos += 1;

        // [21] IngressZoneID u8
        let ingress_id = zone_name_to_id
            .get(metadata.ingress_zone.as_ref())
            .copied()
            .unwrap_or(0) as u8;
        buf[pos] = ingress_id;
        pos += 1;

        // [22] EgressZoneID u8
        let egress_id = zone_name_to_id
            .get(metadata.egress_zone.as_ref())
            .copied()
            .unwrap_or(0) as u8;
        buf[pos] = egress_id;
        pos += 1;

        // [23] Disposition u8
        buf[pos] = encode_disposition(decision.resolution.disposition);
        pos += 1;

        // Addresses: 4 bytes each for v4, 16 bytes each for v6
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_src, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_dst, is_v6);

        // NeighborMAC [6 bytes]
        if let Some(mac) = decision.resolution.neighbor_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // SrcMAC [6 bytes]
        if let Some(mac) = decision.resolution.src_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // NextHop (4 or 16 bytes)
        pos = write_ip_opt(&mut buf, pos, decision.resolution.next_hop, is_v6);

        // Write header
        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_OPEN, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a SessionClose (type 2) frame — minimal payload.
    pub(crate) fn encode_session_close(
        seq: u64,
        key: &SessionKey,
        owner_rg_id: i32,
        close_flags: u8,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE;

        let is_v6 = key.addr_family == libc::AF_INET6 as u8;

        // [0] AddrFamily
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // SrcIP, DstIP
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);

        // OwnerRGID i16 LE
        buf[pos..pos + 2].copy_from_slice(&(owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // Flags
        buf[pos] = close_flags;
        pos += 1;

        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_CLOSE, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a DrainComplete (type 8) frame — header only, no payload.
    fn encode_drain_complete(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_DRAIN_COMPLETE, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }

    /// Encode a FullResync (type 9) frame — header only, no payload.
    fn encode_full_resync(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_FULL_RESYNC, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }

    /// The raw bytes of this frame (header + payload).
    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

// ---------------------------------------------------------------------------
// Header / address helpers
// ---------------------------------------------------------------------------

fn write_header(buf: &mut [u8; 256], payload_len: u32, msg_type: u8, seq: u64) {
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    // buf[5..8] reserved (already zeroed)
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
}

fn write_ip(buf: &mut [u8; 256], pos: usize, ip: IpAddr, is_v6: bool) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            buf[pos..pos + 4].copy_from_slice(&v4.octets());
            if is_v6 {
                // pad to 16 bytes if frame is v6 but this particular IP is v4
                // (shouldn't normally happen, but be safe)
                pos + 16
            } else {
                pos + 4
            }
        }
        IpAddr::V6(v6) => {
            buf[pos..pos + 16].copy_from_slice(&v6.octets());
            pos + 16
        }
    }
}

fn write_ip_opt(buf: &mut [u8; 256], pos: usize, ip: Option<IpAddr>, is_v6: bool) -> usize {
    match ip {
        Some(addr) => write_ip(buf, pos, addr, is_v6),
        None => {
            let size = if is_v6 { 16 } else { 4 };
            // already zeroed
            pos + size
        }
    }
}

fn encode_disposition(d: ForwardingDisposition) -> u8 {
    match d {
        ForwardingDisposition::ForwardCandidate => DISP_FORWARD_CANDIDATE,
        ForwardingDisposition::LocalDelivery => DISP_LOCAL_DELIVERY,
        ForwardingDisposition::FabricRedirect => DISP_FABRIC_REDIRECT,
        ForwardingDisposition::PolicyDenied => DISP_POLICY_DENIED,
        ForwardingDisposition::NoRoute => DISP_NO_ROUTE,
        ForwardingDisposition::MissingNeighbor => DISP_MISSING_NEIGHBOR,
        ForwardingDisposition::HAInactive => DISP_HA_INACTIVE,
        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
    }
}

/// Compute the close flags byte from a SessionDelta.
pub(crate) fn close_flags(delta: &SessionDelta) -> u8 {
    let mut flags: u8 = 0;
    if delta.fabric_redirect_sync
        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
    {
        flags |= FLAG_FABRIC_REDIRECT;
    }
    if delta.metadata.fabric_ingress {
        flags |= FLAG_FABRIC_INGRESS;
    }
    flags
}

// ---------------------------------------------------------------------------
// Shared state between I/O thread and workers
// ---------------------------------------------------------------------------

/// Statistics exposed to coordinator / status reporting.
pub(crate) struct EventStreamStats {
    pub(crate) connected: bool,
    pub(crate) seq: u64,
    pub(crate) acked_seq: u64,
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
    pub(crate) replayed: u64,
}

struct EventStreamShared {
    /// Workers fetch_add to get globally monotonic sequence numbers.
    next_seq: AtomicU64,
    /// Updated by I/O thread from Ack frames.
    acked_seq: AtomicU64,
    /// Set by Pause, cleared by Resume.
    paused: AtomicBool,
    /// True when the event socket is connected.
    connected: AtomicBool,
    /// Counters.
    frames_sent: AtomicU64,
    frames_dropped: AtomicU64,
    frames_replayed: AtomicU64,
}

impl EventStreamShared {
    fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(0),
            acked_seq: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            frames_sent: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            frames_replayed: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// EventStreamSender — coordinator-level handle
// ---------------------------------------------------------------------------

/// Coordinator-level event stream handle. Owns the I/O thread.
pub(crate) struct EventStreamSender {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
    io_thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl EventStreamSender {
    /// Create a new event stream sender and spawn the I/O thread.
    /// The helper connects to the daemon listener at `socket_path`.
    pub(crate) fn new(socket_path: &str) -> Self {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let shared = Arc::new(EventStreamShared::new());
        let stop = Arc::new(AtomicBool::new(false));

        let shared_clone = shared.clone();
        let stop_clone = stop.clone();
        let path = socket_path.to_string();

        let io_thread = thread::Builder::new()
            .name("bpfrx-event-stream".to_string())
            .spawn(move || {
                io_thread_main(rx, shared_clone, stop_clone, path);
            })
            .expect("spawn event stream I/O thread");

        Self {
            tx,
            shared,
            io_thread: Some(io_thread),
            stop,
        }
    }

    /// Get a lightweight handle to pass to worker threads.
    pub(crate) fn worker_handle(&self) -> EventStreamWorkerHandle {
        EventStreamWorkerHandle {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
        }
    }

    /// Current event stream statistics.
    pub(crate) fn stats(&self) -> EventStreamStats {
        EventStreamStats {
            connected: self.shared.connected.load(Ordering::Relaxed),
            seq: self.shared.next_seq.load(Ordering::Relaxed),
            acked_seq: self.shared.acked_seq.load(Ordering::Relaxed),
            sent: self.shared.frames_sent.load(Ordering::Relaxed),
            dropped: self.shared.frames_dropped.load(Ordering::Relaxed),
            replayed: self.shared.frames_replayed.load(Ordering::Relaxed),
        }
    }

    /// Signal the I/O thread to stop and wait for it to exit.
    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.io_thread.take() {
            let _ = join.join();
        }
    }
}

impl Drop for EventStreamSender {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// EventStreamWorkerHandle — lightweight clone for worker threads
// ---------------------------------------------------------------------------

/// Worker-thread handle. Cheap to clone (Arc + SyncSender clone).
#[derive(Clone)]
pub(crate) struct EventStreamWorkerHandle {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
}

impl EventStreamWorkerHandle {
    /// Allocate the next globally-monotonic sequence number.
    pub(crate) fn next_seq(&self) -> u64 {
        self.shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Non-blocking send. Returns false if the channel is full (event dropped).
    pub(crate) fn try_send(&self, frame: EventFrame) -> bool {
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Encode and send a session delta as an event frame.
    pub(crate) fn push_delta(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) {
        let seq = self.next_seq();
        let frame = match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
            ),
            SessionDeltaKind::Close => EventFrame::encode_session_close(
                seq,
                &delta.key,
                delta.metadata.owner_rg_id,
                close_flags(delta),
            ),
        };
        self.try_send(frame);
    }
}

// ---------------------------------------------------------------------------
// I/O thread — manages connection, writes events, reads control frames
// ---------------------------------------------------------------------------

fn io_thread_main(
    rx: mpsc::Receiver<EventFrame>,
    shared: Arc<EventStreamShared>,
    stop: Arc<AtomicBool>,
    socket_path: String,
) {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    let mut ctrl_read_buf: Vec<u8> = Vec::with_capacity(128);

    while !stop.load(Ordering::Acquire) {
        // ---- Connect phase ----
        let stream = match try_connect(&socket_path, &stop) {
            Some(s) => s,
            None => break, // stop requested during connect
        };
        stream.set_nonblocking(true).ok();
        shared.connected.store(true, Ordering::Release);
        eprintln!(
            "bpfrx-event-stream: connected to {}",
            socket_path
        );

        // Replay buffered events from last acked seq
        let acked = shared.acked_seq.load(Ordering::Acquire);
        let replay_result = replay_buffered(&stream, &mut replay_buf, acked, &shared);
        if replay_result.is_err() {
            shared.connected.store(false, Ordering::Release);
            eprintln!("bpfrx-event-stream: replay failed, reconnecting");
            continue;
        }

        // ---- Steady-state loop ----
        ctrl_read_buf.clear(); // discard stale data from previous connection
        let disconnect = run_connected_loop(
            &rx,
            &stream,
            &shared,
            &stop,
            &mut replay_buf,
            &mut ctrl_read_buf,
        );

        shared.connected.store(false, Ordering::Release);
        if disconnect {
            eprintln!("bpfrx-event-stream: disconnected, will reconnect");
        }
    }

    // Drain remaining events on shutdown
    drain_remaining(&rx);
    shared.connected.store(false, Ordering::Release);
    eprintln!("bpfrx-event-stream: I/O thread exiting");
}

/// Try to connect to the daemon event socket, retrying every 100ms.
/// Returns None if stop is requested.
fn try_connect(path: &str, stop: &Arc<AtomicBool>) -> Option<UnixStream> {
    loop {
        if stop.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(path) {
            Ok(stream) => return Some(stream),
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Replay buffered events that are newer than the last acked sequence.
/// If the replay buffer doesn't cover acked+1, send FullResync.
fn replay_buffered(
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
    acked_seq: u64,
    shared: &Arc<EventStreamShared>,
) -> io::Result<()> {
    // Check if replay buffer covers what we need.
    // Only send FullResync if the daemon previously acked real events
    // (acked_seq > 0) AND our replay buffer has a gap (can't replay
    // from acked+1). On fresh start with no events, just start clean.
    let oldest_buffered = replay_buf.front().map(|f| f.seq).unwrap_or(0);
    let has_gap = replay_buf.is_empty() || oldest_buffered > acked_seq + 1;
    if acked_seq > 0 && has_gap {
        let seq = shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let frame = EventFrame::encode_full_resync(seq);
        write_frame_blocking(stream, &frame)?;
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        eprintln!("bpfrx-event-stream: sent FullResync (buffer gap: acked={}, oldest_buffered={})",
            acked_seq, oldest_buffered);
        replay_buf.clear();
        return Ok(());
    }

    // Replay frames newer than acked_seq
    let mut replayed = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > acked_seq {
            write_frame_blocking(stream, frame)?;
            replayed += 1;
        }
    }
    if replayed > 0 {
        shared.frames_replayed.fetch_add(replayed, Ordering::Relaxed);
        shared.frames_sent.fetch_add(replayed, Ordering::Relaxed);
        eprintln!("bpfrx-event-stream: replayed {replayed} events");
    }
    Ok(())
}

/// Write a full frame to the stream (blocking).
fn write_frame_blocking(stream: &UnixStream, frame: &EventFrame) -> io::Result<()> {
    use std::io::Write;
    // Temporarily set blocking for reliable writes during replay/drain
    stream.set_nonblocking(false).ok();
    let result = (&*stream).write_all(frame.as_bytes());
    stream.set_nonblocking(true).ok();
    result
}

/// Main connected loop. Returns true if we should reconnect, false if stopping.
fn run_connected_loop(
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    stop: &Arc<AtomicBool>,
    replay_buf: &mut VecDeque<EventFrame>,
    ctrl_read_buf: &mut Vec<u8>,
) -> bool {
    use std::io::{Read, Write};

    let mut write_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp_read = [0u8; 64];
    let mut idle_cycles = 0u32;
    let mut last_write = Instant::now();

    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }

        let paused = shared.paused.load(Ordering::Acquire);
        let mut drained_any = false;

        // Drain channel into replay buffer + write buffer
        loop {
            match rx.try_recv() {
                Ok(frame) => {
                    drained_any = true;
                    // Add to replay buffer (drop oldest if over capacity)
                    if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
                        replay_buf.pop_front();
                    }
                    replay_buf.push_back(frame.clone());

                    if !paused {
                        write_buf.extend_from_slice(frame.as_bytes());
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return false,
            }
        }

        // Write buffered frames to socket
        if !write_buf.is_empty() {
            match (&*stream).write(&write_buf) {
                Ok(n) => {
                    if n < write_buf.len() {
                        // Partial write — keep remainder
                        write_buf.drain(..n);
                    } else {
                        write_buf.clear();
                    }
                    // Count frames sent (approximate — count by frames drained)
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Socket buffer full, keep write_buf for next cycle
                }
                Err(_) => {
                    // Socket error — disconnect
                    return true;
                }
            }
        }

        // Read control frames from daemon (non-blocking), accumulating
        // partial reads so that incomplete frames are not lost.
        match (&*stream).read(&mut tmp_read) {
            Ok(0) => {
                // EOF — peer closed
                return true;
            }
            Ok(n) => {
                ctrl_read_buf.extend_from_slice(&tmp_read[..n]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available — normal
            }
            Err(_) => {
                return true;
            }
        }

        // Process complete control frames from accumulated buffer
        if !ctrl_read_buf.is_empty() {
            let (action, consumed) =
                process_control_frames(ctrl_read_buf, shared, rx, stream, replay_buf);
            if consumed > 0 {
                ctrl_read_buf.drain(..consumed);
            }
            if let Some(reconnect) = action {
                return reconnect;
            }
        }

        // Idle backoff + keepalive
        if drained_any {
            idle_cycles = 0;
            last_write = Instant::now();
        } else {
            idle_cycles = idle_cycles.saturating_add(1);
            if idle_cycles > 10 {
                // Send keepalive to prevent idle disconnect on Go side
                if last_write.elapsed().as_secs() >= 10 {
                    let mut ka = [0u8; FRAME_HEADER_SIZE];
                    ka[4] = MSG_KEEPALIVE;
                    if let Err(_) = (&*stream).write_all(&ka) {
                        return true; // disconnect
                    }
                    last_write = Instant::now();
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Process control frames received from the daemon.
/// Returns (action, bytes_consumed) where action is Some(true) to reconnect,
/// Some(false) to stop, or None to continue. Only complete frames are consumed;
/// any trailing partial frame is left for the next read cycle.
fn process_control_frames(
    data: &[u8],
    shared: &Arc<EventStreamShared>,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
) -> (Option<bool>, usize) {
    let mut offset = 0;
    while offset + FRAME_HEADER_SIZE <= data.len() {
        let payload_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let frame_len = FRAME_HEADER_SIZE + payload_len as usize;
        if offset + frame_len > data.len() {
            break; // incomplete frame — wait for more data
        }
        let msg_type = data[offset + 4];
        let seq = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        offset += frame_len;

        match msg_type {
            MSG_ACK => {
                shared.acked_seq.store(seq, Ordering::Release);
                // Trim replay buffer: remove frames with seq <= acked
                while let Some(front) = replay_buf.front() {
                    if front.seq <= seq {
                        replay_buf.pop_front();
                    } else {
                        break;
                    }
                }
            }
            MSG_PAUSE => {
                shared.paused.store(true, Ordering::Release);
                eprintln!("bpfrx-event-stream: paused by daemon");
            }
            MSG_RESUME => {
                shared.paused.store(false, Ordering::Release);
                eprintln!("bpfrx-event-stream: resumed by daemon");
                // Flush any buffered-during-pause frames on next write cycle
            }
            MSG_DRAIN_REQUEST => {
                // Drain channel until we have all events up to target seq,
                // then send DrainComplete.
                let target_seq = seq;
                handle_drain_request(target_seq, rx, stream, shared, replay_buf);
            }
            _ => {
                eprintln!(
                    "bpfrx-event-stream: unknown control frame type {}",
                    msg_type
                );
            }
        }
    }
    (None, offset)
}

/// Handle DrainRequest: drain channel, write all buffered events up to target
/// seq, then send DrainComplete.
fn handle_drain_request(
    target_seq: u64,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    use std::io::Write;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_millis(200);
    let was_paused = shared.paused.load(Ordering::Acquire);

    // Drain channel until we've seen target_seq or timeout
    loop {
        match rx.try_recv() {
            Ok(frame) => {
                let frame_seq = frame.seq;
                if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
                    replay_buf.pop_front();
                }
                replay_buf.push_back(frame);
                if frame_seq >= target_seq {
                    break;
                }
            }
            Err(TryRecvError::Empty) => {
                // Check if we already have the target in replay buf
                if replay_buf.back().map(|f| f.seq >= target_seq).unwrap_or(false) {
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "bpfrx-event-stream: drain timeout, highest_seq={}",
                        replay_buf.back().map(|f| f.seq).unwrap_or(0)
                    );
                    break;
                }
                thread::sleep(Duration::from_micros(100));
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }

    // Write all replay-buffered frames to socket (blocking)
    stream.set_nonblocking(false).ok();
    for frame in replay_buf.iter() {
        if let Err(e) = (&*stream).write_all(frame.as_bytes()) {
            eprintln!("bpfrx-event-stream: drain write error: {e}");
            break;
        }
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
    }

    // Send DrainComplete
    let drain_seq = replay_buf.back().map(|f| f.seq).unwrap_or(target_seq);
    let complete_frame = EventFrame::encode_drain_complete(drain_seq);
    if let Err(e) = (&*stream).write_all(complete_frame.as_bytes()) {
        eprintln!("bpfrx-event-stream: drain complete write error: {e}");
    }
    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
    stream.set_nonblocking(true).ok();

    // Restore pause state
    if was_paused {
        shared.paused.store(true, Ordering::Release);
    }

    eprintln!(
        "bpfrx-event-stream: drain complete up to seq {}",
        drain_seq
    );
}

/// Drain remaining events from the channel on shutdown.
fn drain_remaining(rx: &mpsc::Receiver<EventFrame>) {
    loop {
        match rx.try_recv() {
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::ForwardingResolution;
    use crate::nat::NatDecision;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn test_zone_map() -> FxHashMap<String, u16> {
        let mut m = FxHashMap::default();
        m.insert("trust".to_string(), 1);
        m.insert("untrust".to_string(), 2);
        m.insert("dmz".to_string(), 3);
        m
    }

    fn test_key_v4() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 200)),
            src_port: 12345,
            dst_port: 80,
        }
    }

    fn test_key_v6() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: 6,
            src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf01, 0, 0, 0, 0x102)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf02, 0, 0, 0, 0x200)),
            src_port: 54321,
            dst_port: 443,
        }
    }

    fn test_decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
                neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                src_mac: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 10))),
                rewrite_dst: None,
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        }
    }

    fn test_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: Arc::from("trust"),
            egress_zone: Arc::from("untrust"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            synced: false,
            nat64_reverse: None,
        }
    }

    #[test]
    fn test_encode_session_open_v4() {
        let zones = test_zone_map();
        let frame = EventFrame::encode_session_open(
            42,
            &test_key_v4(),
            &test_decision(),
            &test_metadata(),
            &zones,
            false,
        );

        // Check header
        let payload_len =
            u32::from_le_bytes([frame.data[0], frame.data[1], frame.data[2], frame.data[3]]);
        assert_eq!(frame.data[4], MSG_SESSION_OPEN);
        let seq = u64::from_le_bytes(frame.data[8..16].try_into().unwrap());
        assert_eq!(seq, 42);
        assert_eq!(frame.seq, 42);
        assert!(frame.len as usize > FRAME_HEADER_SIZE);
        assert_eq!(frame.len as usize, FRAME_HEADER_SIZE + payload_len as usize);

        // Check payload fields
        let p = &frame.data[FRAME_HEADER_SIZE..];
        assert_eq!(p[0], 4); // AddrFamily
        assert_eq!(p[1], 6); // Protocol TCP
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 12345); // SrcPort
        assert_eq!(u16::from_le_bytes([p[4], p[5]]), 80); // DstPort
        assert_eq!(u16::from_le_bytes([p[6], p[7]]), 40000); // NATSrcPort
        assert_eq!(u16::from_le_bytes([p[8], p[9]]), 0); // NATDstPort
        assert_eq!(i16::from_le_bytes([p[10], p[11]]), 0); // OwnerRGID
        assert_eq!(i16::from_le_bytes([p[12], p[13]]), 3); // EgressIfindex
        assert_eq!(i16::from_le_bytes([p[14], p[15]]), 3); // TXIfindex
        assert_eq!(p[20], 0); // Flags (no fabric redirect, no fabric ingress)
        assert_eq!(p[21], 1); // IngressZoneID (trust=1)
        assert_eq!(p[22], 2); // EgressZoneID (untrust=2)
        assert_eq!(p[23], DISP_FORWARD_CANDIDATE); // Disposition
    }

    #[test]
    fn test_encode_session_open_v6() {
        let zones = test_zone_map();
        let frame = EventFrame::encode_session_open(
            100,
            &test_key_v6(),
            &test_decision(),
            &test_metadata(),
            &zones,
            false,
        );

        let p = &frame.data[FRAME_HEADER_SIZE..];
        assert_eq!(p[0], 6); // AddrFamily v6
        assert_eq!(p[1], 6); // Protocol TCP
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 54321); // SrcPort
        assert_eq!(u16::from_le_bytes([p[4], p[5]]), 443); // DstPort

        // v6 frame should be larger than v4 (16-byte addresses instead of 4)
        assert!(frame.len > 100);
    }

    #[test]
    fn test_encode_session_close_v4() {
        let frame = EventFrame::encode_session_close(7, &test_key_v4(), 1, FLAG_FABRIC_REDIRECT);

        assert_eq!(frame.data[4], MSG_SESSION_CLOSE);
        assert_eq!(frame.seq, 7);

        let p = &frame.data[FRAME_HEADER_SIZE..];
        assert_eq!(p[0], 4); // AddrFamily
        assert_eq!(p[1], 6); // Protocol
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 12345); // SrcPort
        assert_eq!(u16::from_le_bytes([p[4], p[5]]), 80); // DstPort
        // After addresses (4+4 = 8 bytes starting at p[6]):
        // p[6..10] SrcIP, p[10..14] DstIP
        // p[14..16] OwnerRGID
        assert_eq!(i16::from_le_bytes([p[14], p[15]]), 1);
        // p[16] Flags
        assert_eq!(p[16], FLAG_FABRIC_REDIRECT);
    }

    #[test]
    fn test_encode_drain_complete() {
        let frame = EventFrame::encode_drain_complete(999);
        assert_eq!(frame.data[4], MSG_DRAIN_COMPLETE);
        assert_eq!(frame.seq, 999);
        assert_eq!(frame.len, FRAME_HEADER_SIZE as u16);
    }

    #[test]
    fn test_encode_full_resync() {
        let frame = EventFrame::encode_full_resync(500);
        assert_eq!(frame.data[4], MSG_FULL_RESYNC);
        assert_eq!(frame.seq, 500);
        assert_eq!(frame.len, FRAME_HEADER_SIZE as u16);
    }

    #[test]
    fn test_sequence_monotonicity() {
        let shared = Arc::new(EventStreamShared::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let s = shared.clone();
                std::thread::spawn(move || {
                    let mut seqs = Vec::with_capacity(100);
                    for _ in 0..100 {
                        let seq = s.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                        seqs.push(seq);
                    }
                    seqs
                })
            })
            .collect();

        let mut all_seqs: Vec<u64> = Vec::new();
        for h in handles {
            all_seqs.extend(h.join().unwrap());
        }
        all_seqs.sort();
        all_seqs.dedup();
        // All 400 sequences should be unique
        assert_eq!(all_seqs.len(), 400);
        // Should be 1..=400
        assert_eq!(*all_seqs.first().unwrap(), 1);
        assert_eq!(*all_seqs.last().unwrap(), 400);
    }

    #[test]
    fn test_replay_buffer_trim() {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

        // Add 10 frames with seq 1..=10
        for seq in 1..=10u64 {
            replay_buf.push_back(EventFrame::encode_drain_complete(seq));
        }
        assert_eq!(replay_buf.len(), 10);

        // Simulate Ack seq=5: trim frames <= 5
        let acked_seq = 5u64;
        while let Some(front) = replay_buf.front() {
            if front.seq <= acked_seq {
                replay_buf.pop_front();
            } else {
                break;
            }
        }
        assert_eq!(replay_buf.len(), 5);
        assert_eq!(replay_buf.front().unwrap().seq, 6);
    }

    #[test]
    fn test_close_flags() {
        let delta = SessionDelta {
            kind: SessionDeltaKind::Close,
            key: test_key_v4(),
            decision: test_decision(),
            metadata: SessionMetadata {
                ingress_zone: Arc::from("trust"),
                egress_zone: Arc::from("untrust"),
                owner_rg_id: 0,
                fabric_ingress: true,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
            origin: crate::session::SessionOrigin::ForwardFlow,
            fabric_redirect_sync: true,
        };
        let flags = close_flags(&delta);
        assert_eq!(flags & FLAG_FABRIC_REDIRECT, FLAG_FABRIC_REDIRECT);
        assert_eq!(flags & FLAG_FABRIC_INGRESS, FLAG_FABRIC_INGRESS);
    }

    #[test]
    fn test_channel_backpressure() {
        let (tx, _rx) = mpsc::sync_channel::<EventFrame>(2);
        let shared = Arc::new(EventStreamShared::new());
        let handle = EventStreamWorkerHandle {
            tx,
            shared: shared.clone(),
        };

        // Fill the channel (capacity 2)
        let frame = EventFrame::encode_drain_complete(1);
        assert!(handle.try_send(frame.clone()));
        assert!(handle.try_send(frame.clone()));

        // Third send should fail (channel full)
        assert!(!handle.try_send(frame));
        assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_disposition_encoding() {
        assert_eq!(encode_disposition(ForwardingDisposition::ForwardCandidate), 0);
        assert_eq!(encode_disposition(ForwardingDisposition::LocalDelivery), 1);
        assert_eq!(encode_disposition(ForwardingDisposition::FabricRedirect), 2);
        assert_eq!(encode_disposition(ForwardingDisposition::PolicyDenied), 3);
        assert_eq!(encode_disposition(ForwardingDisposition::NoRoute), 4);
        assert_eq!(encode_disposition(ForwardingDisposition::MissingNeighbor), 5);
        assert_eq!(encode_disposition(ForwardingDisposition::HAInactive), 6);
        assert_eq!(encode_disposition(ForwardingDisposition::DiscardRoute), 7);
        assert_eq!(encode_disposition(ForwardingDisposition::NextTableUnsupported), 8);
    }

    /// Build a raw 16-byte ACK control frame with the given sequence number.
    fn build_raw_ack_frame(seq: u64) -> [u8; FRAME_HEADER_SIZE] {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        // payload_len = 0 (header-only)
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4] = MSG_ACK;
        // reserved bytes 5..8 stay zero
        buf[8..16].copy_from_slice(&seq.to_le_bytes());
        buf
    }

    #[test]
    fn test_partial_read_accumulation() {
        // Simulate a partial Unix stream read: first 8 bytes, then the
        // remaining 8 bytes of a 16-byte ACK frame.
        let shared = Arc::new(EventStreamShared::new());
        let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
        // Seed replay buffer so we can observe the trim from the ACK.
        for seq in 1..=5u64 {
            replay_buf.push_back(EventFrame::encode_drain_complete(seq));
        }

        let raw = build_raw_ack_frame(3);
        let mut ctrl_buf: Vec<u8> = Vec::new();

        // We don't have a real stream for this unit test, so call
        // process_control_frames directly with partial data.

        // First "read": only the first 8 bytes arrive.
        ctrl_buf.extend_from_slice(&raw[..8]);
        let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (action, consumed) =
            process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
        assert!(action.is_none());
        assert_eq!(consumed, 0, "partial frame must not be consumed");
        // Replay buffer untouched — no ACK processed yet
        assert_eq!(replay_buf.len(), 5);

        // Second "read": remaining 8 bytes arrive.
        ctrl_buf.extend_from_slice(&raw[8..]);
        let (action, consumed) =
            process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
        assert!(action.is_none());
        assert_eq!(consumed, FRAME_HEADER_SIZE);
        // ACK seq=3 should have trimmed frames 1,2,3
        assert_eq!(replay_buf.len(), 2);
        assert_eq!(replay_buf.front().unwrap().seq, 4);
        assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);

        // Drain consumed bytes as the real loop would.
        ctrl_buf.drain(..consumed);
        assert!(ctrl_buf.is_empty());
    }

    #[test]
    fn test_two_frames_in_one_read() {
        // Two complete ACK frames arrive in a single read.
        let shared = Arc::new(EventStreamShared::new());
        let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
        for seq in 1..=10u64 {
            replay_buf.push_back(EventFrame::encode_drain_complete(seq));
        }

        let ack5 = build_raw_ack_frame(5);
        let ack8 = build_raw_ack_frame(8);
        let mut ctrl_buf: Vec<u8> = Vec::new();
        ctrl_buf.extend_from_slice(&ack5);
        ctrl_buf.extend_from_slice(&ack8);

        let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (action, consumed) =
            process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
        assert!(action.is_none());
        assert_eq!(consumed, 2 * FRAME_HEADER_SIZE);
        // ACK 5, then ACK 8 — replay should have frames 9,10
        assert_eq!(replay_buf.len(), 2);
        assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn test_one_and_half_frames() {
        // 1.5 frames: one complete ACK + first 4 bytes of next frame.
        let shared = Arc::new(EventStreamShared::new());
        let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
        for seq in 1..=5u64 {
            replay_buf.push_back(EventFrame::encode_drain_complete(seq));
        }

        let ack2 = build_raw_ack_frame(2);
        let ack4 = build_raw_ack_frame(4);
        let mut ctrl_buf: Vec<u8> = Vec::new();
        ctrl_buf.extend_from_slice(&ack2);
        ctrl_buf.extend_from_slice(&ack4[..4]); // partial second frame

        let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (action, consumed) =
            process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
        assert!(action.is_none());
        assert_eq!(consumed, FRAME_HEADER_SIZE); // only first frame consumed
        assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
        assert_eq!(replay_buf.len(), 3); // frames 3,4,5 remain

        // Drain consumed, then "read" remaining bytes of second frame.
        ctrl_buf.drain(..consumed);
        assert_eq!(ctrl_buf.len(), 4);
        ctrl_buf.extend_from_slice(&ack4[4..]);

        let (action, consumed) =
            process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
        assert!(action.is_none());
        assert_eq!(consumed, FRAME_HEADER_SIZE);
        assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 4);
        assert_eq!(replay_buf.len(), 1); // only frame 5 remains
    }
}
