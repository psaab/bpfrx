//! #4971: test-only counting global allocator.
//!
//! Delegates every allocation to the system allocator and, while a
//! thread has ARMED the probe, counts `alloc`/`alloc_zeroed`/`realloc`
//! calls on that thread. Used by the TX hot-path allocation-free
//! regression tests to assert that an expected TX backpressure retry
//! performs ZERO heap allocations per drain pass — reverting the
//! `#4971` fix (`TxError::Retry(String)` / `retry_tail = Vec::new()` /
//! `set_error("…".to_string())` on the retry path) flips the count
//! positive, so the assertion goes RED (an assertion failure, NOT a
//! build break).
//!
//! Counting is per-thread and gated behind a `const`-initialised
//! thread-local so arming/counting never itself allocates (no lazy TLS
//! heap init → no re-entrancy into `alloc`). libtest runs each test on
//! its own thread, so a leaked ARM cannot cross tests; a drop guard
//! also disarms on panic.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

pub struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Run `f` with the per-thread allocation probe armed, returning
/// `(result, alloc_count)`. The count resets on entry; a drop guard
/// disarms even if `f` panics. Not re-entrant (the tests do not nest).
#[cfg(test)]
pub fn count_allocs<R>(f: impl FnOnce() -> R) -> (R, u64) {
    struct Disarm;
    impl Drop for Disarm {
        fn drop(&mut self) {
            ARMED.with(|a| a.set(false));
        }
    }

    ALLOC_COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    let _disarm = Disarm;
    let result = f();
    ARMED.with(|a| a.set(false));
    let count = ALLOC_COUNT.with(Cell::get);
    (result, count)
}
