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

// ── Terminal-op base-cursor advance (#5716) ──────────────────────
//
// All four ring guards stay usable after their terminal op
// (`WriteTx::commit` / `WriteFill::commit` / `ReadRx::release` /
// `ReadComplete::release`). Pre-#5716 none of them advanced `base_idx`
// past the slots the terminal op had handed to the kernel, so a reused
// guard silently aliased them:
//
//   * producers restarted at `base_idx + 0` and OVERWROTE the
//     just-submitted descriptors / fill offsets;
//   * `ReadComplete` restarted at `base_idx + 0` and RE-READ completion
//     addresses it had already reaped;
//   * `ReadRx` kept its positional cursor but sealed itself with a sticky
//     `released` flag, so the post-release reads could never be released
//     and `Drop`'s cancel under-counted — permanently leaking those RX
//     ring slots (`cached_cons` stuck ahead of `*consumer`).
//
// No production caller crosses a terminal op today (every site is
// `create -> insert/read* -> commit/release -> drop`), so these are
// API-hardening guards: they pin the reuse contract before a caller
// relies on it. The single-use path is unchanged and still covered by
// the #2383/#4997 tests above.
//
// Two different producibility questions, with two different answers,
// because someone will ask:
//
//   * The BATCH SIZES below are producible exactly as written. Every
//     production insert passes a variable-length slice
//     (`scratch_prepared_tx.len()` in tx/transmit/write.rs and four sites
//     in cos/queue_service/service.rs, `scratch_fill.len()` in
//     tx/rings.rs, `offsets.len()` plus an arbitrary retry suffix in
//     bind.rs), and every release releases whatever its
//     `while let Some(..) = read()` loop consumed (tx/rings.rs,
//     poll_descriptor/mod.rs). Nothing caps a batch at one or two slots,
//     so a three-slot batch is an ordinary shape rather than one invented
//     for the fixture.
//   * The REUSE ITSELF -- insert -> commit -> insert on one guard -- is
//     NOT producible today. That is the point: it is the forward-looking
//     contract this change states, so a fixture for it tests the stated
//     contract rather than inventing a shape. If a future caller starts
//     streaming through one guard, these are the tests that hold the line.

/// Seed a producer ring so the next reservation begins at `at`. Lets a test
/// place the guard's base cursor at the `u32` wrap boundary instead of only
/// at 0 (libxdp masks the index, so a ring index legitimately wraps `u32`).
fn seed_prod_at(ring: &mut XskRingProd, at: u32) {
    ring.cached_prod = at;
    ring.cached_cons = at.wrapping_add(ring.size);
    unsafe {
        *ring.producer = at;
        *ring.consumer = at;
    }
}

/// Seed a consumer ring so the next peek begins at `at`. Same purpose as
/// [`seed_prod_at`], for the RX / completion side.
fn seed_cons_at(ring: &mut XskRingCons, at: u32) {
    ring.cached_prod = at;
    ring.cached_cons = at;
    unsafe {
        *ring.producer = at;
        *ring.consumer = at;
    }
}

/// The two cursor origins every reuse test runs at: mid-range (0) and the
/// `u32` wrap boundary. At `u32::MAX - 1` the reservation straddles the wrap,
/// so the terminal op's `wrapping_add` advance crosses `u32::MAX` mid guard —
/// the edge of the class these guards claim to cover. With [`REUSE_BATCHES`]
/// the wrap lands *inside* the second batch (indices `u32::MAX`, 0, 1) rather
/// than between two guards.
const CURSOR_ORIGINS: [u32; 2] = [0, u32::MAX - 1];

/// Slot count of the hermetic rings the reuse fixtures run on.
const REUSE_RING_CAPACITY: u32 = 8;

/// The batch sizes each reuse fixture drives through its guard, in order.
///
/// What actually rejects a constant advance is the PER-OPERATION checkpoint,
/// not the number of distinct sizes. With a cursor assertion after every
/// terminal op, two distinct sizes already suffice: a batch of 1 rejects every
/// constant except 1, and a following batch of 3 rejects the constant 1
/// (cumulative 4 against 2). Three sizes are what the fixtures happen to use;
/// they are not load-bearing, and a later reshape to two distinct sizes would
/// keep the guard intact. What is NOT safe is collapsing to a single repeated
/// size, or dropping the intermediate checkpoints — see below.
///
/// The intermediate checkpoints are the load-bearing part. Three applications
/// of `+= 2` land on the same FINAL cursor as the correct advance
/// (2+2+2 == 1+3+2), so a constant is invisible to an end-state-only check.
/// Delete the checkpoints and the guard is gone while still looking like a
/// guard. The last checkpoint specifically is redundant — the first two have
/// already rejected every constant by the time it runs — but it is cheap and
/// states the end state explicitly.
///
/// DETECTED is not BOUND, and that is why this reshape was necessary rather
/// than tidy. The constants that *did* red before this change red on
/// **payload** assertions, never on a cursor one — a re-read descriptor came
/// back with the wrong address (`read_rx` caught `left: 0xBB` against
/// `right: 0xCC`). Measured on the pre-#6832 fixtures, each of the four guards
/// admitted exactly one constant — `WriteTx`/`WriteFill` passed `+= 1`,
/// `ReadRx`/`ReadComplete` passed `+= 2`. So the cursor advance was not
/// half-covered by the old fixtures; it was covered nowhere and merely
/// *detected* in two of the four, through the data a wrong cursor happened to
/// corrupt. That detection survives only while the aliased slots hold
/// distinguishable payloads, and it says nothing whatever about the two guards
/// whose surviving constant left the data intact. The per-batch checkpoints
/// below are the first assertions in this file to bind the advance itself.
const REUSE_BATCHES: [u32; 3] = [1, 3, 2];

/// Total slots a reuse fixture reserves / peeks: the sum of [`REUSE_BATCHES`].
const REUSE_TOTAL: u32 = REUSE_BATCHES[0] + REUSE_BATCHES[1] + REUSE_BATCHES[2];

// FIXTURE SELF-CHECKS, not coverage. Both of these are assertions over test
// constants alone, so no production edit can make either fail and neither
// belongs in a count of what this file binds. They exist to fail the BUILD if
// a later edit to the constants above quietly invalidates the fixtures that
// consume them.
//
// At least two distinct batch sizes, so the runs still distinguish a
// count-sized advance from a repeated-constant one.
const _: () = assert!(
    REUSE_BATCHES[0] != REUSE_BATCHES[1]
        || REUSE_BATCHES[1] != REUSE_BATCHES[2]
        || REUSE_BATCHES[0] != REUSE_BATCHES[2],
    "reuse fixtures need at least two DISTINCT batch sizes to reject a constant advance"
);
// Each slot of a run must land in its own ring slot; otherwise a misplaced
// write could alias onto the very value it was supposed to corrupt.
const _: () = assert!(REUSE_TOTAL <= REUSE_RING_CAPACITY);

/// Distinct non-zero payload for the `j`-th slot of a reuse run. Monotone in
/// `j`, and never 0 (the test ring backing is zero-initialised), so a write
/// that lands on the wrong slot is detectable both at the slot it corrupted
/// and at the slot it skipped.
fn reuse_payload(j: u32) -> u64 {
    0xA000 + j as u64
}

#[test]
fn write_tx_insert_after_commit_appends_past_the_committed_slots() {
    for origin in CURSOR_ORIGINS {
        let mut tx = RingTx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(&mut tx.ring, origin);
        let producer = tx.ring.producer;
        let base;
        {
            let mut w = tx.transmit(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            assert_eq!(
                w.reserved, REUSE_TOTAL,
                "the fixture needs the whole reservation up front — a short \
                 reserve would silently shrink the batches below"
            );
            let mut submitted = 0u32;
            for n in REUSE_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| desc(reuse_payload(first + k)))),
                    n,
                    "origin {origin}: a {n}-descriptor batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // The commit handed `n` slots to the kernel, so the cursor must
                // move by exactly `n`. Asserted after EVERY commit: a constant
                // advance is invisible at the end (2+2+2 == 1+3+2) and shows up
                // only here.
                assert_eq!(
                    w.base_idx,
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the base cursor did not advance by the committed count"
                );
                assert_eq!(
                    w.reserved,
                    REUSE_TOTAL - submitted,
                    "origin {origin}: commit must consume the submitted slots"
                );
                // #6832 fold r2: asserted per commit, not only in aggregate.
                // Three submits of a constant 2 reach the same TOTAL as the
                // correct 1/3/2, so an aggregate-only check cannot see a commit
                // that hands the kernel the wrong NUMBER of slots — which
                // publishes descriptors the caller has not written yet, or
                // strands ones it has.
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the kernel-facing producer did not advance by the \
                     committed count"
                );
            }
        }
        // Every slot holds its own descriptor: no batch overwrote a predecessor
        // the kernel already owns, and none skipped a slot.
        for j in 0..REUSE_TOTAL {
            assert_eq!(
                tx_slot(&tx.ring, base.wrapping_add(j)).addr,
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own descriptor. \
                 The shape this guards: a post-commit insert landing on the \
                 wrong slot, corrupting a descriptor already submitted to the \
                 kernel"
            );
        }
        // The drop-time cancel left cached_prod exactly on the producer (no
        // leaked slots). NB: this pair binds the terminal op's
        // `reserved -= written` bookkeeping, NOT the cursor advance — `Drop`
        // cancels `reserved - written`, so a commit that moved the cursor but
        // left the reservation unshrunk cancels slots the kernel already owns.
        // A wrong *cursor* leaves both equalities intact (measured: `+= 1` here
        // was GREEN before #6832), which is why the per-batch checkpoints above
        // are the ones that bind it. The producer equality below is an end-state
        // restatement of those checkpoints, which are what bind the per-commit
        // submission count.
        assert_eq!(unsafe { *producer }, base.wrapping_add(REUSE_TOTAL));
        assert_eq!(tx.ring.cached_prod, unsafe { *producer });
    }
}

#[test]
fn write_fill_insert_after_commit_appends_past_the_committed_slots() {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(dq.rings.fill_mut(), origin);
        let producer = dq.rings.fill().producer;
        let base;
        {
            let mut w = dq.fill(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            assert_eq!(
                w.reserved, REUSE_TOTAL,
                "the fixture needs the whole reservation up front — a short \
                 reserve would silently shrink the batches below"
            );
            let mut submitted = 0u32;
            for n in REUSE_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| reuse_payload(first + k))),
                    n,
                    "origin {origin}: a {n}-offset batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // Asserted after EVERY commit — see the note in the WriteTx
                // sibling: a constant advance survives an end-state-only check.
                assert_eq!(
                    w.base_idx,
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the base cursor did not advance by the committed count"
                );
                assert_eq!(
                    w.reserved,
                    REUSE_TOTAL - submitted,
                    "origin {origin}: commit must consume the submitted slots"
                );
                // Per commit, not only in aggregate — see the `WriteTx` sibling.
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the kernel-facing producer did not advance by the \
                     committed count"
                );
            }
        }
        let ring = dq.rings.fill();
        for j in 0..REUSE_TOTAL {
            assert_eq!(
                fill_slot(ring, base.wrapping_add(j)),
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own fill offset. \
                 The shape this guards: a post-commit insert overwriting an \
                 offset already submitted to the kernel, leaving two RX slots \
                 aliasing one UMEM frame"
            );
        }
        assert_eq!(unsafe { *producer }, base.wrapping_add(REUSE_TOTAL));
        assert_eq!(ring.cached_prod, unsafe { *producer });
    }
}

#[test]
fn read_complete_read_after_release_does_not_re_reap_released_entries() {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(dq.rings.comp_mut(), origin);
        for j in 0..REUSE_TOTAL {
            dq.push_comp_for_test(reuse_payload(j));
        }
        // Raw pointer captured before the guard borrows the ring (it models
        // kernel-owned mmap state, exactly as `test_cons_ring` sets it up).
        let consumer = dq.rings.comp().consumer;
        assert_eq!(unsafe { *consumer }, origin);
        {
            let mut r = dq.complete(REUSE_TOTAL);
            assert_eq!(r.base_idx, origin, "peek must start at the seeded cursor");
            // Pin the window size at its source. `read()` has no error path —
            // its only `None` is the `read_count >= peeked` bounds check — so
            // the sole alternative cause of an early `None` is a short peek.
            // With `peeked` pinned here, the terminal `None` below means
            // exhaustion and nothing else.
            assert_eq!(
                r.peeked, REUSE_TOTAL,
                "peek must cover every pushed completion entry"
            );
            let mut released = 0u32;
            for n in REUSE_BATCHES {
                for k in 0..n {
                    // A reused reader must continue past what it released.
                    // Handing an address back twice would recycle one UMEM
                    // frame into the fill ring twice.
                    assert_eq!(
                        r.read(),
                        Some(reuse_payload(released + k)),
                        "origin {origin}: entry {} was not reaped in order. \
                         The shape this guards: a reused reader re-reading an \
                         already-released completion address",
                        released + k
                    );
                }
                r.release();
                released += n;
                assert_eq!(
                    r.base_idx,
                    origin.wrapping_add(released),
                    "origin {origin}: after releases summing to {released} entries \
                     the base cursor did not advance by the released count"
                );
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(released),
                    "origin {origin}: the kernel-facing consumer is not at the \
                     released count. The shape this guards: a release that does \
                     not reach the shared consumer pointer"
                );
            }
            assert_eq!(
                r.read(),
                None,
                "origin {origin}: the peek window was pinned at {} entries above \
                 and all of them have been read, so the guard must report \
                 exhaustion",
                REUSE_TOTAL
            );
        }
        // Nothing peeked-but-unread survives: cached_cons matches the real
        // consumer, so no completion-ring slots were leaked.
        assert_eq!(dq.rings.comp().cached_cons, unsafe { *consumer });
    }
}

#[test]
fn read_rx_read_after_release_stays_releasable() {
    for origin in CURSOR_ORIGINS {
        let mut rx = RingRx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(&mut rx.ring, origin);
        for j in 0..REUSE_TOTAL {
            rx.push_for_test(desc(reuse_payload(j)));
        }
        let consumer = rx.ring.consumer;
        {
            let mut r = rx.receive(REUSE_TOTAL);
            assert_eq!(r.base_idx, origin, "peek must start at the seeded cursor");
            // Same reasoning as the `read_complete_...` sibling: `ReadRx::read`
            // has no error path either, so pinning `peeked` at its source is
            // what lets the terminal `is_none()` below mean exhaustion rather
            // than a short peek.
            assert_eq!(
                r.peeked, REUSE_TOTAL,
                "peek must cover every pushed descriptor"
            );
            let mut released = 0u32;
            for n in REUSE_BATCHES {
                for k in 0..n {
                    assert_eq!(
                        r.read()
                            .expect("descriptor inside the pinned peek window")
                            .addr,
                        reuse_payload(released + k),
                        "origin {origin}: descriptor {} was not read in order",
                        released + k
                    );
                }
                r.release();
                released += n;
                // Two independent failure modes are pinned here, and they are
                // caught by different assertions. The base cursor catches an
                // advance that is not the released count. The consumer pointer
                // catches the pre-#5716 sticky `released` flag, which swallowed
                // every release after the first and leaked those slots for the
                // life of the socket — the descriptor reads above do NOT catch
                // that one, because the positional cursor stayed correct under
                // it.
                assert_eq!(
                    r.base_idx,
                    origin.wrapping_add(released),
                    "origin {origin}: after releases summing to {released} \
                     descriptors the base cursor did not advance by the \
                     released count"
                );
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(released),
                    "origin {origin}: the consumer is not at the released \
                     count. The shape this guards: the sticky-flag release, \
                     which swallowed every release after the first and left \
                     those descriptors permanently unreleasable"
                );
            }
            assert!(
                r.read().is_none(),
                "origin {origin}: the peek window was pinned at {} descriptors \
                 above and all of them have been read, so the guard must report \
                 exhaustion",
                REUSE_TOTAL
            );
        }
        // Drop must land cached_cons on the real consumer. A leak shows up
        // here as cached_cons > *consumer.
        assert_eq!(
            rx.ring.cached_cons,
            unsafe { *consumer },
            "origin {origin}: cached_cons is not on the kernel consumer. The \
             shape this guards: cached_cons drifting AHEAD, which leaks those \
             RX ring slots for the life of the socket"
        );
    }
}

#[test]
fn read_rx_drop_releases_a_batch_read_after_an_explicit_release() {
    // B3 (#6832 fold r2): the `Drop` condition itself changed — it was
    // `!self.released && self.read_count > 0` and is now `self.read_count > 0`
    // — and no fixture drove it. The sibling above always releases everything
    // it reads, so it leaves `read_count == 0` at drop and never enters the
    // branch.
    //
    // This one does: it releases the first two batches explicitly, then reads
    // PART of the third and lets `Drop` finish. That is the shape the sticky
    // flag broke. Pre-#5716 `Drop` saw `released == true`, skipped the release
    // entirely, and cancelled `peeked - read_count` against an unshrunk
    // `peeked` — so `cached_cons` ended AHEAD of `*consumer` and those RX ring
    // slots were leaked for the life of the socket. Post-#5716 the release
    // reaches the kernel and the cancel covers exactly the peeked-but-unread
    // remainder.
    for origin in CURSOR_ORIGINS {
        let mut rx = RingRx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(&mut rx.ring, origin);
        for j in 0..REUSE_TOTAL {
            rx.push_for_test(desc(reuse_payload(j)));
        }
        let consumer = rx.ring.consumer;

        // Read part of the final batch and leave the rest peeked-but-unread,
        // so the drop has BOTH a release and a non-zero cancel to do.
        let released_explicitly = REUSE_BATCHES[0] + REUSE_BATCHES[1];
        let dropped_read = REUSE_BATCHES[2] - 1;
        assert!(
            dropped_read > 0 && dropped_read < REUSE_BATCHES[2],
            "fixture: the final batch must be partly read so drop does both a \
             release and a cancel"
        );
        {
            let mut r = rx.receive(REUSE_TOTAL);
            let mut read_so_far = 0u32;
            for n in [REUSE_BATCHES[0], REUSE_BATCHES[1]] {
                for _ in 0..n {
                    r.read().expect("descriptor inside the peek window");
                }
                r.release();
                read_so_far += n;
            }
            assert_eq!(
                unsafe { *consumer },
                origin.wrapping_add(released_explicitly),
                "origin {origin}: fixture precondition — the two explicit \
                 releases must already have reached the kernel"
            );
            for k in 0..dropped_read {
                assert_eq!(
                    r.read()
                        .expect("descriptor inside the peek window")
                        .addr,
                    reuse_payload(read_so_far + k),
                    "origin {origin}: descriptor {} was not read in order after \
                     a release",
                    read_so_far + k
                );
            }
            // No second `release()` — `Drop` owns this batch.
        }
        assert_eq!(
            unsafe { *consumer },
            origin.wrapping_add(released_explicitly + dropped_read),
            "origin {origin}: the consumer is not at \
             {released_explicitly}+{dropped_read}. The shape this guards: a \
             drop that skips the descriptors read after an explicit release, \
             leaving them unreleasable and leaking their RX slots"
        );
        assert_eq!(
            rx.ring.cached_cons,
            unsafe { *consumer },
            "origin {origin}: cached_cons is not on the kernel consumer. The \
             shape this guards: a drop-time cancel that does not cover exactly \
             the peeked-but-unread remainder"
        );
    }
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
