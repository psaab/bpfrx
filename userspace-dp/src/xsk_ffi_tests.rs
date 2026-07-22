use super::*;

#[test]
fn private_constructor_rings_borrow_umem_ring_boxes() {
    let mut umem_fill: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    let mut umem_comp: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let socket_fill: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    let socket_comp: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let umem_fill_addr = (&*umem_fill) as *const XskRingProd;
    let umem_comp_addr = (&*umem_comp) as *const XskRingCons;
    let socket_fill_addr = (&*socket_fill) as *const XskRingProd;
    let socket_comp_addr = (&*socket_comp) as *const XskRingCons;

    let rings = device_queue_rings_for_create(
        Some((&mut umem_fill, &mut umem_comp)),
        socket_fill,
        socket_comp,
    );

    assert_eq!(rings.fill() as *const XskRingProd, umem_fill_addr);
    assert_eq!(rings.comp() as *const XskRingCons, umem_comp_addr);
    assert_ne!(rings.fill() as *const XskRingProd, socket_fill_addr);
    assert_ne!(rings.comp() as *const XskRingCons, socket_comp_addr);
    assert_eq!((&*umem_fill) as *const XskRingProd, umem_fill_addr);
    assert_eq!((&*umem_comp) as *const XskRingCons, umem_comp_addr);
}

// ── Producer-ring append safety (#2383) ──────────────────────────
//
// `WriteTx::insert` / `WriteFill::insert` must place the k-th total
// item of a reservation at `base_idx + written + n` so a second
// `insert()` APPENDS after the first instead of overwriting it.
// These tests fail-on-revert: reverting the index to `base_idx + n`
// makes the second insert clobber slot base+0.

/// Read TX descriptor slot `i` from the leaked test ring backing.
/// The bridge writes through libxdp at `idx & mask`, so reading the
/// raw ring buffer at `i & mask` observes what `insert` wrote.
fn tx_slot(ring: &XskRingProd, i: u32) -> XdpDesc {
    let idx = (i & ring.mask) as usize;
    unsafe { *(ring.ring as *const XdpDesc).add(idx) }
}

fn fill_slot(ring: &XskRingProd, i: u32) -> u64 {
    let idx = (i & ring.mask) as usize;
    unsafe { *(ring.ring as *const u64).add(idx) }
}

fn desc(addr: u64) -> XdpDesc {
    XdpDesc {
        addr,
        len: addr as u32,
        options: 0,
    }
}

#[test]
fn write_tx_two_inserts_append_not_overwrite() {
    let mut tx = RingTx::new_for_test(-1, 8);
    let base;
    {
        let mut w = tx.transmit(4);
        base = w.base_idx;
        assert_eq!(w.reserved, 4);
        // First insert: one descriptor at base+0.
        assert_eq!(w.insert([desc(0xA0)].into_iter()), 1);
        assert_eq!(w.written, 1);
        // Second insert: must APPEND at base+1, base+2 (NOT base+0).
        assert_eq!(w.insert([desc(0xB1), desc(0xC2)].into_iter()), 2);
        assert_eq!(w.written, 3);
        w.commit();
    }
    // All three distinct slots hold the items in insertion order.
    assert_eq!(tx_slot(&tx.ring, base).addr, 0xA0);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(1)).addr, 0xB1);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(2)).addr, 0xC2);
}

#[test]
fn write_tx_single_insert_writes_base() {
    let mut tx = RingTx::new_for_test(-1, 8);
    let base;
    {
        let mut w = tx.transmit(4);
        base = w.base_idx;
        assert_eq!(w.insert([desc(0x11), desc(0x22)].into_iter()), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
    assert_eq!(tx_slot(&tx.ring, base).addr, 0x11);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(1)).addr, 0x22);
}

#[test]
fn write_tx_insert_bounded_by_remaining_reservation() {
    let mut tx = RingTx::new_for_test(-1, 8);
    {
        let mut w = tx.transmit(2);
        assert_eq!(w.reserved, 2);
        // First insert fills the reservation.
        assert_eq!(w.insert([desc(1), desc(2)].into_iter()), 2);
        assert_eq!(w.written, 2);
        // Second insert has zero remaining capacity — inserts nothing,
        // does not write past the reservation.
        assert_eq!(w.insert([desc(3), desc(4)].into_iter()), 0);
        assert_eq!(w.written, 2);
        // A single oversized insert is also capped at the reservation.
        w.commit();
    }
    let mut tx2 = RingTx::new_for_test(-1, 8);
    {
        let mut w = tx2.transmit(2);
        assert_eq!(w.insert((0..10).map(desc)), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
}

#[test]
fn write_fill_two_inserts_append_not_overwrite() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    let base;
    {
        let mut w = dq.fill(4);
        base = w.base_idx;
        assert_eq!(w.reserved, 4);
        assert_eq!(w.insert([0xA0u64].into_iter()), 1);
        assert_eq!(w.written, 1);
        assert_eq!(w.insert([0xB1u64, 0xC2u64].into_iter()), 2);
        assert_eq!(w.written, 3);
        w.commit();
    }
    let ring = dq.rings.fill();
    assert_eq!(fill_slot(ring, base), 0xA0);
    assert_eq!(fill_slot(ring, base.wrapping_add(1)), 0xB1);
    assert_eq!(fill_slot(ring, base.wrapping_add(2)), 0xC2);
}

#[test]
fn write_fill_single_insert_writes_base() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    let base;
    {
        let mut w = dq.fill(4);
        base = w.base_idx;
        assert_eq!(w.insert([0x11u64, 0x22u64].into_iter()), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
    let ring = dq.rings.fill();
    assert_eq!(fill_slot(ring, base), 0x11);
    assert_eq!(fill_slot(ring, base.wrapping_add(1)), 0x22);
}

#[test]
fn write_fill_insert_bounded_by_remaining_reservation() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    {
        let mut w = dq.fill(2);
        assert_eq!(w.reserved, 2);
        assert_eq!(w.insert([1u64, 2u64].into_iter()), 2);
        assert_eq!(w.written, 2);
        assert_eq!(w.insert([3u64, 4u64].into_iter()), 0);
        assert_eq!(w.written, 2);
        w.commit();
    }
    let mut dq2 = DeviceQueue::new_for_test(-1, 8);
    {
        let mut w = dq2.fill(2);
        assert_eq!(w.insert(0..10u64), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
}

// ── RX consumer-ring release safety (#4997) ──────────────────────
//
// `ReadRx` now holds `ring: &'a mut XskRingCons` (it was a shared
// `&'a XskRingCons` plus a `*const -> *mut` cast in `release()`/drop —
// writing the consumer ring through a pointer derived from `&T` with no
// `UnsafeCell` is UB under Stacked/Tree Borrows, which Miri flags). The
// `release()`/drop calls must still advance the real kernel-facing
// `consumer` pointer through that `&mut`.
//
// This drives the exact production `receive` -> `read` -> `release`
// path on a hermetic test ring and asserts (a) the descriptors read
// back in order and (b) the `consumer` pointer advanced by the released
// count — i.e. `release()` genuinely wrote through the reference.
//
// Fail-on-revert: reverting the field to `&XskRingCons` no longer
// compiles — `bridge_xsk_ring_cons_release` takes `*mut XskRingCons`
// and a `&T` does not coerce to `*mut T` without the removed const
// cast — so the type change is itself compile-pinned; this test
// additionally pins the release/cancel behavior. Miri cannot drive it
// (the libxdp C bridge is `extern "C"` FFI, unsupported under Miri), so
// there is no Miri-gated variant — the `&mut` type + this behavioral
// test are the pins.
#[test]
fn read_rx_release_advances_consumer_through_mut_ref() {
    let mut rx = RingRx::new_for_test(-1, 8);
    rx.push_for_test(desc(0xAA));
    rx.push_for_test(desc(0xBB));

    // consumer pointer starts at 0 (nothing released yet).
    assert_eq!(unsafe { *rx.ring.consumer }, 0);

    {
        let mut r = rx.receive(4);
        let d0 = r.read().expect("first descriptor available");
        let d1 = r.read().expect("second descriptor available");
        assert_eq!(d0.addr, 0xAA);
        assert_eq!(d1.addr, 0xBB);
        assert!(r.read().is_none(), "only two descriptors were pushed");
        r.release();
    }

    // release() must have written through the &mut: the kernel-facing
    // consumer pointer advanced by the two released descriptors.
    assert_eq!(unsafe { *rx.ring.consumer }, 2);
}

// ── libxdp ring ABI contract (#4976) ─────────────────────────────
//
// The authoritative guard is the `const _` block in `xsk_ffi.rs` (fails
// the build on drift) plus the `_Static_assert`s in `csrc/xsk_bridge.c`
// (fail the build if the *installed* libxdp layout drifts). This runtime
// test restates the same contract as a named, discoverable check: if the
// Rust mirror is ever re-laid-out without updating the contract, the const
// block already refuses to compile this crate — but this test also gives a
// human-readable failure naming the exact field that moved.
#[test]
fn xsk_ring_abi_matches_libxdp_contract() {
    use core::mem::{align_of, offset_of, size_of};

    // 64-bit pointer width underpins the fixed pointer-field offsets.
    assert_eq!(size_of::<*const u32>(), 8, "AF_XDP dataplane is 64-bit only");

    for (name, sz, al) in [
        ("XskRingProd", size_of::<XskRingProd>(), align_of::<XskRingProd>()),
        ("XskRingCons", size_of::<XskRingCons>(), align_of::<XskRingCons>()),
    ] {
        assert_eq!(sz, 48, "{name} size drift vs libxdp DEFINE_XSK_RING");
        assert_eq!(al, 8, "{name} align drift vs libxdp DEFINE_XSK_RING");
    }

    // Field offsets — must match libxdp's `DEFINE_XSK_RING` in xsk.h and
    // the `_Static_assert`s in csrc/xsk_bridge.c.
    assert_eq!(offset_of!(XskRingProd, cached_prod), 0, "prod.cached_prod");
    assert_eq!(offset_of!(XskRingProd, cached_cons), 4, "prod.cached_cons");
    assert_eq!(offset_of!(XskRingProd, mask), 8, "prod.mask");
    assert_eq!(offset_of!(XskRingProd, size), 12, "prod.size");
    assert_eq!(offset_of!(XskRingProd, producer), 16, "prod.producer");
    assert_eq!(offset_of!(XskRingProd, consumer), 24, "prod.consumer");
    assert_eq!(offset_of!(XskRingProd, ring), 32, "prod.ring");
    assert_eq!(offset_of!(XskRingProd, flags), 40, "prod.flags");

    assert_eq!(offset_of!(XskRingCons, cached_prod), 0, "cons.cached_prod");
    assert_eq!(offset_of!(XskRingCons, cached_cons), 4, "cons.cached_cons");
    assert_eq!(offset_of!(XskRingCons, mask), 8, "cons.mask");
    assert_eq!(offset_of!(XskRingCons, size), 12, "cons.size");
    assert_eq!(offset_of!(XskRingCons, producer), 16, "cons.producer");
    assert_eq!(offset_of!(XskRingCons, consumer), 24, "cons.consumer");
    assert_eq!(offset_of!(XskRingCons, ring), 32, "cons.ring");
    assert_eq!(offset_of!(XskRingCons, flags), 40, "cons.flags");
}
