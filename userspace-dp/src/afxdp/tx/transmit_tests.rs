// Tests for afxdp/tx/transmit.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep transmit.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "transmit_tests.rs"]` from transmit.rs.

use super::*;
use crate::afxdp::PROTO_TCP;

#[test]
fn remember_prepared_recycle_tracks_only_shared_fill_recycles() {
    let mut in_flight_prepared_recycles = FastMap::default();

    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &PreparedTxRequest {
            offset: 41,
            len: 64,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &PreparedTxRequest {
            offset: 42,
            len: 64,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        },
    );
    remember_prepared_recycle(
        &mut in_flight_prepared_recycles,
        &PreparedTxRequest {
            offset: 43,
            len: 64,
            recycle: PreparedTxRecycle::FillOnSlotWithOffset {
                slot: 8,
                offset: 1234,
            },
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        },
    );

    assert_eq!(in_flight_prepared_recycles.len(), 2);
    assert_eq!(
        in_flight_prepared_recycles.get(&42),
        Some(&PreparedTxRecycle::FillOnSlot(7))
    );
    assert_eq!(
        in_flight_prepared_recycles.get(&43),
        Some(&PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 1234,
        })
    );
    assert!(!in_flight_prepared_recycles.contains_key(&41));
}

#[test]
fn cancelled_prepared_foreign_fill_routes_to_shared_recycles() {
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();

    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        Some(&mut shared_recycles),
        7,
        PreparedTxRecycle::FillOnSlotWithOffset {
            slot: 8,
            offset: 1234,
        },
        42,
    );

    assert!(free_tx_frames.is_empty());
    assert!(pending_fill_frames.is_empty());
    assert_eq!(shared_recycles, vec![(8, 1234)]);
}

#[test]
fn cancelled_prepared_local_fill_stays_on_pending_fill() {
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();

    recycle_cancelled_prepared_offset_with_shared(
        &mut free_tx_frames,
        &mut pending_fill_frames,
        Some(&mut shared_recycles),
        7,
        PreparedTxRecycle::FillOnSlot(7),
        42,
    );

    assert!(free_tx_frames.is_empty());
    assert_eq!(pending_fill_frames, VecDeque::from([42]));
    assert!(shared_recycles.is_empty());
}

// #hb166 T-6(d): when `transmit_batch` hits an oversized frame mid-batch it
// unwinds the already-staged prefix back onto the head of `pending`. The
// unwind MUST preserve the original front-to-back order so same-flow (in-
// order TCP) segments are not reordered on the error path.
//
// FAIL-ON-REVERT: dropping the `.rev()` from the unwind drain reverses the
// restored prefix, flipping the recovered enqueue_ns order from [1, 2, 4]
// to [2, 1, 4].
#[test]
fn transmit_batch_oversized_unwind_preserves_pending_order() {
    use crate::afxdp::tx::test_support::{
        test_cos_fast_interfaces, test_cos_runtime_with_queues, test_queue_fast_path,
    };
    use crate::afxdp::types::TxRequest;

    let mk = |len: usize, id: u64| TxRequest {
        bytes: vec![0u8; len],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        // enqueue_ns doubles as an identity marker for order assertions.
        enqueue_ns: id,
    };

    let root = test_cos_runtime_with_queues(10_000_000, vec![]);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // A(128), B(128) stage; the oversized item (> tx_frame_capacity()) trips
    // the Drop-unwind; D(128) is never reached (loop returns on the Err).
    let mut pending = VecDeque::from([
        mk(128, 1),
        mk(128, 2),
        mk(tx_frame_capacity() + 1, 3),
        mk(128, 4),
    ]);
    let mut shared_recycles = Vec::new();

    let result = transmit_batch(&mut binding, &mut pending, 0, &mut shared_recycles);
    assert!(matches!(result, Err(TxError::Drop(_))));

    let order: Vec<u64> = pending.iter().map(|r| r.enqueue_ns).collect();
    assert_eq!(
        order,
        vec![1, 2, 4],
        "oversized-unwind must keep the staged prefix in original order (A before B)",
    );
}
