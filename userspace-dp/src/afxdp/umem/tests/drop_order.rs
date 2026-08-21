// #5192 A1-b6-F6 — `WorkerUmemInner` field destruction order.
//
// `xsk_ffi::Umem::new` is `unsafe` on one stated precondition: the
// caller-supplied `area` must "outlive this Umem". `WorkerUmemInner`
// owns both halves of that pair, so it is the type that has to honour
// it, and Rust destroys struct fields in DECLARATION order. Declaring
// `area` first therefore runs `munmap` while the libxdp UMEM object is
// still registered against those pages — a latent use-after-free whose
// only defence today is that `xsk_umem__delete` in the pinned libxdp
// happens not to read the user area. That is an unpinned external
// library's implementation detail, not an invariant this repo controls,
// and this box already runs a different libxdp point release than the
// one the original refutation was written against.
//
// Rust exposes no compile-time drop-order assertion, so the guard is an
// observation: both destructors record into `crate::drop_order_probe`
// under `cfg(test)`. Restoring the old field order reds this test.

use super::*;
use crate::drop_order_probe::{self, DropTag};

#[test]
fn worker_umem_inner_drops_umem_before_mmap_area() {
    drop_order_probe::reset();

    let umem = WorkerUmem::new_for_test(4).expect("build hermetic worker umem");
    assert_eq!(
        drop_order_probe::recorded(),
        Vec::<DropTag>::new(),
        "constructing a WorkerUmem must not destroy either half"
    );

    drop(umem);

    // The whole point: `Umem` (xsk_umem__delete) strictly before
    // `MmapArea` (munmap). Reversed, this is the latent UAF.
    assert_eq!(
        drop_order_probe::recorded(),
        vec![DropTag::Umem, DropTag::MmapArea],
        "WorkerUmemInner must destroy its Umem before the MmapArea backing it; \
         field declaration order in umem/mod.rs is what fixes this"
    );
}

#[test]
fn worker_umem_pool_preserves_the_same_drop_order() {
    // `WorkerUmemPool` is the type production actually constructs
    // (`WorkerUmemPool::new` -> `WorkerUmem::new`), and it wraps the
    // `WorkerUmem` in a struct of its own. Pin that the extra wrapper
    // does not reorder the pair: a future field shuffle in
    // `WorkerUmemPool` cannot change it, but a `Drop` impl added there
    // could, and this catches that.
    drop_order_probe::reset();

    let pool = WorkerUmemPool {
        umem: WorkerUmem::new_for_test(4).expect("build hermetic worker umem"),
        free_frames: VecDeque::new(),
    };
    assert_eq!(drop_order_probe::recorded(), Vec::<DropTag>::new());

    drop(pool);

    assert_eq!(
        drop_order_probe::recorded(),
        vec![DropTag::Umem, DropTag::MmapArea],
        "wrapping a WorkerUmem in WorkerUmemPool must not reorder the UMEM/mmap teardown"
    );
}
