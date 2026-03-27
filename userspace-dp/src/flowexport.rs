//! NetFlow v9 flow export for the userspace dataplane.
//!
//! Samples every Nth session creation, buffers flow records, and periodically
//! flushes them as NetFlow v9 UDP packets to the configured collector.
//!
//! Template fields:
//!   1  IN_BYTES
//!   2  IN_PKTS
//!   4  PROTOCOL
//!   7  L4_SRC_PORT
//!   8  IPV4_SRC_ADDR
//!  11  L4_DST_PORT
//!  12  IPV4_DST_ADDR
//!  21  LAST_SWITCHED
//!  22  FIRST_SWITCHED

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Instant;

/// NetFlow v9 field type IDs.
#[allow(dead_code)]
const NF9_IN_BYTES: u16 = 1;
#[allow(dead_code)]
const NF9_IN_PKTS: u16 = 2;
#[allow(dead_code)]
const NF9_PROTOCOL: u16 = 4;
#[allow(dead_code)]
const NF9_L4_SRC_PORT: u16 = 7;
#[allow(dead_code)]
const NF9_IPV4_SRC_ADDR: u16 = 8;
#[allow(dead_code)]
const NF9_L4_DST_PORT: u16 = 11;
#[allow(dead_code)]
const NF9_IPV4_DST_ADDR: u16 = 12;
#[allow(dead_code)]
const NF9_LAST_SWITCHED: u16 = 21;
#[allow(dead_code)]
const NF9_FIRST_SWITCHED: u16 = 22;

/// NetFlow v9 header version.
const NETFLOW_V9_VERSION: u16 = 9;

/// Template ID (must be > 255 per RFC 3954).
const TEMPLATE_ID: u16 = 256;

/// Number of fields in the template.
#[allow(dead_code)]
const TEMPLATE_FIELD_COUNT: u16 = 9;

/// Default flush interval in seconds.
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;

/// Default active timeout in seconds (when the Go side sends 0).
const DEFAULT_ACTIVE_TIMEOUT_SECS: u64 = 60;

/// Default inactive timeout in seconds (when the Go side sends 0).
const DEFAULT_INACTIVE_TIMEOUT_SECS: u64 = 15;

/// Maximum buffered records before force-flush.
const MAX_BUFFERED_RECORDS: usize = 30;

/// A single flow record to export.
#[derive(Clone, Debug)]
pub(crate) struct FlowRecord {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u64,
    pub packets: u64,
    pub first_seen_ms: u32, // milliseconds since exporter boot
    pub last_seen_ms: u32,  // milliseconds since exporter boot
}

/// Configuration for the flow exporter.
#[derive(Clone, Debug)]
pub(crate) struct FlowExportConfig {
    pub collector: SocketAddr,
    pub sampling_rate: u32,
    pub active_timeout_secs: u64,
    #[allow(dead_code)]
    pub inactive_timeout_secs: u64,
}

/// NetFlow v9 flow exporter. Buffers records and periodically flushes via UDP.
pub(crate) struct FlowExporter {
    config: FlowExportConfig,
    socket: Option<UdpSocket>,
    records: Vec<FlowRecord>,
    sequence: u32,
    session_counter: u64,
    boot_instant: Instant,
    last_flush_ns: u64,
    #[allow(dead_code)]
    last_template_ns: u64,
    source_id: u32,
    #[allow(dead_code)]
    flush_interval_ns: u64,
    #[allow(dead_code)]
    template_interval_ns: u64,
}

impl FlowExporter {
    pub fn new(config: FlowExportConfig) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
            s.set_nonblocking(true).ok()?;
            s.connect(config.collector).ok()?;
            Some(s)
        });
        let template_interval_ns = config.active_timeout_secs.max(60) * 1_000_000_000;
        Self {
            config,
            socket,
            records: Vec::with_capacity(MAX_BUFFERED_RECORDS),
            sequence: 0,
            session_counter: 0,
            boot_instant: Instant::now(),
            last_flush_ns: 0,
            last_template_ns: 0,
            source_id: std::process::id(),
            flush_interval_ns: DEFAULT_FLUSH_INTERVAL_SECS * 1_000_000_000,
            template_interval_ns,
        }
    }

    /// Returns the number of milliseconds since the exporter started.
    pub fn uptime_ms(&self) -> u32 {
        self.boot_instant.elapsed().as_millis() as u32
    }

    /// Called on every new session creation. Returns true if this session
    /// was sampled (and a flow record should be tracked).
    pub fn should_sample(&mut self) -> bool {
        self.session_counter += 1;
        if self.config.sampling_rate == 0 {
            return false;
        }
        self.session_counter % (self.config.sampling_rate as u64) == 0
    }

    /// Record a flow for export. Call on session creation for sampled flows.
    pub fn record_flow(&mut self, record: FlowRecord) {
        self.records.push(record);
    }

    /// Update an existing flow record's counters (bytes, packets, last_seen).
    /// Called on session expiry or periodically to finalize the record.
    pub fn finalize_flow(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        bytes: u64,
        packets: u64,
        last_seen_ms: u32,
    ) {
        for rec in self.records.iter_mut().rev() {
            if rec.src_ip == src_ip
                && rec.dst_ip == dst_ip
                && rec.src_port == src_port
                && rec.dst_port == dst_port
                && rec.protocol == protocol
            {
                rec.bytes = rec.bytes.saturating_add(bytes);
                rec.packets = rec.packets.saturating_add(packets);
                rec.last_seen_ms = last_seen_ms;
                return;
            }
        }
    }

    /// Periodic tick: flush records if the interval has elapsed or buffer is full.
    #[allow(dead_code)]
    pub fn tick(&mut self, now_ns: u64) {
        if self.socket.is_none() {
            return;
        }
        // Send template periodically
        if now_ns.saturating_sub(self.last_template_ns) >= self.template_interval_ns {
            self.send_template(now_ns);
            self.last_template_ns = now_ns;
        }
        // Flush data records
        let should_flush = self.records.len() >= MAX_BUFFERED_RECORDS
            || (now_ns.saturating_sub(self.last_flush_ns) >= self.flush_interval_ns
                && !self.records.is_empty());
        if should_flush {
            self.flush(now_ns);
        }
    }

    /// Flush all buffered records as NetFlow v9 data packets.
    fn flush(&mut self, now_ns: u64) {
        if self.records.is_empty() {
            return;
        }
        let socket = match &self.socket {
            Some(s) => s,
            None => return,
        };
        let uptime = self.uptime_ms();
        let unix_secs = (now_ns / 1_000_000_000) as u32;

        // Build packet: header + data flowset
        let records = std::mem::take(&mut self.records);
        // Each IPv4 record is 32 bytes (4+4+4+2+2+1+4+4+3pad = ~25, actually
        // we use fixed field sizes). Let's compute exactly:
        // IN_BYTES(4) + IN_PKTS(4) + PROTOCOL(1) + L4_SRC_PORT(2) + IPV4_SRC_ADDR(4)
        // + L4_DST_PORT(2) + IPV4_DST_ADDR(4) + LAST_SWITCHED(4) + FIRST_SWITCHED(4) = 29
        // Pad to 4-byte boundary: 32 bytes per record (3 bytes padding)
        const RECORD_SIZE: usize = 32; // 29 bytes data + 3 padding
        let data_flowset_header = 4usize; // flowset_id(2) + length(2)
        let data_flowset_len = data_flowset_header + records.len() * RECORD_SIZE;
        let packet_size = 20 + data_flowset_len; // 20 byte NF9 header

        let mut buf = vec![0u8; packet_size];
        let count = records.len() as u16 + 0; // number of flowsets (just the data flowset)

        self.sequence += 1;

        // NetFlow v9 header (20 bytes)
        buf[0..2].copy_from_slice(&NETFLOW_V9_VERSION.to_be_bytes());
        buf[2..4].copy_from_slice(&1u16.to_be_bytes()); // count: 1 flowset
        buf[4..8].copy_from_slice(&uptime.to_be_bytes());
        buf[8..12].copy_from_slice(&unix_secs.to_be_bytes());
        buf[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        buf[16..20].copy_from_slice(&self.source_id.to_be_bytes());

        // Data FlowSet header
        let off = 20;
        buf[off..off + 2].copy_from_slice(&TEMPLATE_ID.to_be_bytes());
        buf[off + 2..off + 4].copy_from_slice(&(data_flowset_len as u16).to_be_bytes());

        // Data records
        let mut pos = off + 4;
        for rec in &records {
            let src_v4 = match rec.src_ip {
                IpAddr::V4(v4) => v4.octets(),
                _ => [0u8; 4],
            };
            let dst_v4 = match rec.dst_ip {
                IpAddr::V4(v4) => v4.octets(),
                _ => [0u8; 4],
            };
            // IN_BYTES (4)
            buf[pos..pos + 4].copy_from_slice(&(rec.bytes as u32).to_be_bytes());
            pos += 4;
            // IN_PKTS (4)
            buf[pos..pos + 4].copy_from_slice(&(rec.packets as u32).to_be_bytes());
            pos += 4;
            // PROTOCOL (1)
            buf[pos] = rec.protocol;
            pos += 1;
            // L4_SRC_PORT (2)
            buf[pos..pos + 2].copy_from_slice(&rec.src_port.to_be_bytes());
            pos += 2;
            // IPV4_SRC_ADDR (4)
            buf[pos..pos + 4].copy_from_slice(&src_v4);
            pos += 4;
            // L4_DST_PORT (2)
            buf[pos..pos + 2].copy_from_slice(&rec.dst_port.to_be_bytes());
            pos += 2;
            // IPV4_DST_ADDR (4)
            buf[pos..pos + 4].copy_from_slice(&dst_v4);
            pos += 4;
            // LAST_SWITCHED (4)
            buf[pos..pos + 4].copy_from_slice(&rec.last_seen_ms.to_be_bytes());
            pos += 4;
            // FIRST_SWITCHED (4)
            buf[pos..pos + 4].copy_from_slice(&rec.first_seen_ms.to_be_bytes());
            pos += 4;
            // Padding (3 bytes)
            pos += 3;
        }

        let _ = socket.send(&buf[..pos]);
        let _ = count; // suppress unused warning
        self.last_flush_ns = now_ns;
    }

    /// Send a template flowset so the collector knows the record format.
    #[allow(dead_code)]
    fn send_template(&mut self, now_ns: u64) {
        let socket = match &self.socket {
            Some(s) => s,
            None => return,
        };
        let uptime = self.uptime_ms();
        let unix_secs = (now_ns / 1_000_000_000) as u32;

        self.sequence += 1;

        // Template flowset: id=0, then template records
        // Each field: type(2) + length(2) = 4 bytes
        // Template record header: template_id(2) + field_count(2) = 4 bytes
        let template_record_len = 4 + (TEMPLATE_FIELD_COUNT as usize) * 4; // 4 + 36 = 40
        let flowset_len = 4 + template_record_len; // flowset header (4) + template record
        let packet_size = 20 + flowset_len;

        let mut buf = vec![0u8; packet_size];

        // Header
        buf[0..2].copy_from_slice(&NETFLOW_V9_VERSION.to_be_bytes());
        buf[2..4].copy_from_slice(&1u16.to_be_bytes());
        buf[4..8].copy_from_slice(&uptime.to_be_bytes());
        buf[8..12].copy_from_slice(&unix_secs.to_be_bytes());
        buf[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        buf[16..20].copy_from_slice(&self.source_id.to_be_bytes());

        // Template FlowSet header
        let off = 20;
        buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes()); // flowset_id = 0 (template)
        buf[off + 2..off + 4].copy_from_slice(&(flowset_len as u16).to_be_bytes());

        // Template record header
        let toff = off + 4;
        buf[toff..toff + 2].copy_from_slice(&TEMPLATE_ID.to_be_bytes());
        buf[toff + 2..toff + 4].copy_from_slice(&TEMPLATE_FIELD_COUNT.to_be_bytes());

        // Template fields
        let fields: [(u16, u16); 9] = [
            (NF9_IN_BYTES, 4),
            (NF9_IN_PKTS, 4),
            (NF9_PROTOCOL, 1),
            (NF9_L4_SRC_PORT, 2),
            (NF9_IPV4_SRC_ADDR, 4),
            (NF9_L4_DST_PORT, 2),
            (NF9_IPV4_DST_ADDR, 4),
            (NF9_LAST_SWITCHED, 4),
            (NF9_FIRST_SWITCHED, 4),
        ];

        let mut foff = toff + 4;
        for (ftype, flen) in &fields {
            buf[foff..foff + 2].copy_from_slice(&ftype.to_be_bytes());
            buf[foff + 2..foff + 4].copy_from_slice(&flen.to_be_bytes());
            foff += 4;
        }

        let _ = socket.send(&buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_config() -> FlowExportConfig {
        FlowExportConfig {
            collector: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9995)),
            sampling_rate: 3,
            active_timeout_secs: DEFAULT_ACTIVE_TIMEOUT_SECS,
            inactive_timeout_secs: DEFAULT_INACTIVE_TIMEOUT_SECS,
        }
    }

    #[test]
    fn sampling_rate_every_nth() {
        let mut exporter = FlowExporter::new(test_config());
        // Sampling rate = 3: sample every 3rd session
        assert!(!exporter.should_sample()); // 1st
        assert!(!exporter.should_sample()); // 2nd
        assert!(exporter.should_sample()); // 3rd
        assert!(!exporter.should_sample()); // 4th
        assert!(!exporter.should_sample()); // 5th
        assert!(exporter.should_sample()); // 6th
    }

    #[test]
    fn sampling_rate_zero_never_samples() {
        let mut cfg = test_config();
        cfg.sampling_rate = 0;
        let mut exporter = FlowExporter::new(cfg);
        for _ in 0..100 {
            assert!(!exporter.should_sample());
        }
    }

    #[test]
    fn record_flow_buffers() {
        let mut exporter = FlowExporter::new(test_config());
        assert_eq!(exporter.records.len(), 0);
        exporter.record_flow(FlowRecord {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            bytes: 100,
            packets: 1,
            first_seen_ms: 1000,
            last_seen_ms: 1000,
        });
        assert_eq!(exporter.records.len(), 1);
    }

    #[test]
    fn finalize_updates_existing_record() {
        let mut exporter = FlowExporter::new(test_config());
        exporter.record_flow(FlowRecord {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            bytes: 100,
            packets: 1,
            first_seen_ms: 1000,
            last_seen_ms: 1000,
        });
        exporter.finalize_flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            12345,
            80,
            6,
            500,
            5,
            2000,
        );
        assert_eq!(exporter.records.len(), 1);
        assert_eq!(exporter.records[0].bytes, 600);
        assert_eq!(exporter.records[0].packets, 6);
        assert_eq!(exporter.records[0].last_seen_ms, 2000);
        assert_eq!(exporter.records[0].first_seen_ms, 1000);
    }

    #[test]
    fn flush_clears_records_and_increments_sequence() {
        // Use a UDP socket bound to localhost (send will succeed even with
        // no receiver — UDP is fire-and-forget).
        let mut exporter = FlowExporter::new(test_config());

        exporter.record_flow(FlowRecord {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            bytes: 1024,
            packets: 10,
            first_seen_ms: 100,
            last_seen_ms: 200,
        });

        assert_eq!(exporter.records.len(), 1);
        assert_eq!(exporter.sequence, 0);

        // Flush should clear records and increment sequence
        exporter.flush(1_000_000_000);
        assert_eq!(exporter.records.len(), 0);
        assert_eq!(exporter.sequence, 1);
    }

    #[test]
    fn flush_with_no_socket_does_not_clear() {
        let mut exporter = FlowExporter::new(test_config());
        exporter.socket = None;

        exporter.record_flow(FlowRecord {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            bytes: 1024,
            packets: 10,
            first_seen_ms: 100,
            last_seen_ms: 200,
        });

        // Flush with no socket should not clear records (we can't send them)
        exporter.flush(1_000_000_000);
        assert_eq!(exporter.records.len(), 1);
        assert_eq!(exporter.sequence, 0);
    }
}
