// #5192 A1-b6-F6: test-only drop-order probe for the UMEM lifetime pair.
//
// `WorkerUmemInner` owns both a `xsk_ffi::Umem` (whose `Drop` calls
// `xsk_umem__delete`) and the `MmapArea` that backs it (whose `Drop`
// calls `munmap`). `Umem::new` documents the unsafe contract that the
// area must OUTLIVE the `Umem`, so the `Umem` field has to be
// destroyed first.
//
// Rust destroys struct fields in DECLARATION order and offers no
// compile-time way to assert that order — there is no `const` fact to
// hang a `const _: () = assert!(..)` on, and a comment is not a gate.
// So the invariant is pinned by OBSERVATION instead: both `Drop` impls
// append a tag here under `cfg(test)`, and
// `afxdp::umem::tests::drop_order` asserts the sequence. Swapping the
// two field declarations back reds that test.
//
// Allocation-free on purpose: `record` runs inside `Drop`, and this
// crate installs a counting global allocator under `cfg(test)`
// (`test_alloc::CountingAlloc`) that other tests assert against. A
// `Vec` push here would charge an allocation to whatever hot-path
// test happened to drop a UMEM inside its measurement window.

use std::cell::Cell;

/// Which destructor ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropTag {
    /// `xsk_ffi::Umem::drop` — `xsk_umem__delete`.
    Umem = 1,
    /// `afxdp::umem::MmapArea::drop` — `munmap`.
    MmapArea = 2,
}

/// Ring capacity. The observed sequences are two events long; the
/// slack exists so an unexpected extra drop is visible as a length
/// mismatch rather than being silently discarded.
const CAP: usize = 8;

thread_local! {
    static LOG: Cell<(usize, [u8; CAP])> = const { Cell::new((0, [0u8; CAP])) };
}

/// Append `tag` to this thread's drop log. Silently no-ops once the
/// log is full, and when TLS is already torn down (`try_with`) — this
/// runs from `Drop`, including during thread teardown.
pub(crate) fn record(tag: DropTag) {
    let _ = LOG.try_with(|cell| {
        let (n, mut buf) = cell.get();
        if n < CAP {
            buf[n] = tag as u8;
            cell.set((n + 1, buf));
        }
    });
}

/// Clear this thread's drop log. Call at the top of a probing test so
/// drops from earlier tests on the same thread cannot leak in.
pub(crate) fn reset() {
    let _ = LOG.try_with(|cell| cell.set((0, [0u8; CAP])));
}

/// Snapshot this thread's drop log, oldest first. Allocates — call it
/// from a test body, never from a `Drop` impl.
pub(crate) fn recorded() -> Vec<DropTag> {
    LOG.with(|cell| {
        let (n, buf) = cell.get();
        buf[..n]
            .iter()
            .map(|&b| match b {
                1 => DropTag::Umem,
                2 => DropTag::MmapArea,
                other => unreachable!("unknown drop tag {other}"),
            })
            .collect()
    })
}
