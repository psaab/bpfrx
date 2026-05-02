// #1020: harden_tests for afxdp/umem/mmap.rs — relocated from
// inline `#[cfg(test)] mod harden_tests` to a sibling file per
// the project convention. Loaded via `#[path = "mmap_tests.rs"]`
// from mmap.rs.

use super::*;

#[test]
fn new_rejects_zero_length() {
    let err = match MmapArea::new(0) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn new_rejects_overflowing_aligned_len() {
    // usize::MAX cannot be rounded up to the next 2 MB boundary —
    // checked_add catches it before mmap.
    let err = match MmapArea::new(usize::MAX) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("hugepage alignment"),
        "expected hugepage-alignment error, got: {msg}",
    );
}
