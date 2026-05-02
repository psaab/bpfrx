// Tests for flowexport.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep flowexport.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "flowexport_tests.rs"]` from flowexport.rs.

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
