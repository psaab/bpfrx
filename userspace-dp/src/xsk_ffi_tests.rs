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
