// Shared-recycle target-index resolution tests: `shared_recycle_target_index`,
// `shared_recycle_target_index_for_split` (lookup hit / stale-scan / drop), and
// `record_shared_recycle_unknown_slot_drops` counter accounting. Local fixture
// `test_split_slot_at`.

use super::*;

fn test_split_slot_at(
    left: &[u32],
    current_index: usize,
    current_slot: u32,
    right: &[u32],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current_slot);
    }
    if target_index < current_index {
        return left.get(target_index).copied();
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .copied()
}

#[test]
fn shared_recycle_target_uses_lookup_when_slot_matches() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 20, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(1)
    );
}

#[test]
fn shared_recycle_target_scans_when_lookup_is_stale_or_wrong_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 99, 20];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(2)
    );
}

#[test]
fn shared_recycle_target_drops_unknown_or_out_of_range_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 99);
    let slots = [10, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        None
    );
}

#[test]
fn shared_recycle_split_target_scans_when_lookup_is_stale() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let left = [10, 99];
    let current_index = 2;
    let current_slot = 30;
    let right = [20, 40];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        Some(3)
    );
}

#[test]
fn shared_recycle_split_target_drops_unknown_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 9);
    let left = [10, 30];
    let current_index = 2;
    let current_slot = 40;
    let right = [50, 60];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        None
    );
}

#[test]
fn shared_recycle_unknown_slot_drop_increments_tx_errors() {
    let live = BindingLiveState::new();

    record_shared_recycle_unknown_slot_drops(Some(&live), 2);
    record_shared_recycle_unknown_slot_drops(Some(&live), 0);
    record_shared_recycle_unknown_slot_drops(None, 5);

    assert_eq!(live.tx_errors.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        live.tx_shared_recycle_unknown_slot_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}
