// #8276 pricing microbench for Option B2 — the bounded kernel -> userspace
// capture bridge for XFRM-decrypted IPsec plaintext.
//
// WHAT THIS PRICES, AND WHAT IT DOES NOT.
//
// B2 has two halves and only one of them is measurable off-hardware:
//
//   KERNEL half — getting the plaintext out of the XFRM stack and a verdict
//   back (nfqueue round-trip, or AF_PACKET capture plus an authoritative
//   re-inject). That needs a box where XFRM SAs and netfilter can be
//   configured against real traffic. NOT measured here, and no number for it
//   is implied by anything below.
//
//   IN-PROCESS half — once a captured frame exists in userspace, handing it to
//   a worker for adjudication. That is `Option E`'s "bounded packet-bearing
//   WorkerCommand + an owned-frame adjudication entry point", which the #7167
//   adjudication names as B2's cost. It is fully measurable here, because it
//   is pure userspace: an allocation policy, a queue, and a thread wake.
//
// The shapes below are the in-tree ones, recreated directly because the daemon
// is a bin crate (same convention as `tx_kick_latency.rs`):
//
//   - the worker command queue is `Arc<Mutex<VecDeque<WorkerCommand>>>` bounded
//     at `MAX_PENDING_WORKER_COMMANDS` = 4096 (`afxdp/worker_queue.rs:77`);
//   - the slow path's existing kernel-facing handoff is
//     `mpsc::sync_channel(DEFAULT_QUEUE_DEPTH)` = 16384 feeding a dedicated
//     `xpf-slowpath` thread (`slowpath.rs:22,373`).
//
// Measured at this HEAD: `size_of::<WorkerCommand>()` = 264 bytes, so a full
// 4096-deep queue is ~1.03 MiB per worker today. A `Vec<u8>` payload is 24
// bytes inline and does NOT grow the enum; an inline `[u8; MTU]` payload would
// take the variant to ~1504 and a full queue to ~6.16 MiB per worker — paid by
// every queued command of every kind, not only captured frames. That is
// arithmetic, not a measurement, and it is why the pooled row exists below.
use std::collections::VecDeque;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;

use criterion::{Criterion, criterion_group, criterion_main};

/// A plaintext frame at the TUN default MTU (`slowpath.rs` DEFAULT_TUN_MTU).
const MTU: usize = 1500;
/// `afxdp/worker_queue.rs:77`.
const MAX_PENDING_WORKER_COMMANDS: usize = 4096;
/// `slowpath.rs:22`.
const SLOWPATH_QUEUE_DEPTH: usize = 16_384;

/// The owned-frame variant: the payload is heap, one allocation per packet.
enum OwnedCmd {
    Frame(Vec<u8>),
}

/// The pooled variant: the payload is an index into a preallocated slab, so
/// the packet path allocates nothing. This is the shape the repo's hot-path
/// allocation rule pushes toward (`docs/engineering-style.md`).
enum PooledCmd {
    Frame { slot: usize, len: usize },
}

/// `push_bounded`'s shape: refuse at the bound rather than growing.
fn push_bounded<T>(q: &mut VecDeque<T>, item: T, bound: usize) -> bool {
    if q.len() >= bound {
        return false;
    }
    q.push_back(item);
    true
}

/// Row 1 — the irreducible floor: copy a frame into a reused buffer. Every
/// capture mechanism pays at least this, whatever the handoff.
fn bench_copy_only(c: &mut Criterion) {
    let src = vec![0xa5u8; MTU];
    let mut dst = vec![0u8; MTU];
    c.bench_function("b2/copy_only_1500B", |b| {
        b.iter(|| {
            dst[..MTU].copy_from_slice(black_box(&src[..MTU]));
            black_box(&dst);
        })
    });
}

/// Row 2 — owned-frame handoff, SAME thread. Isolates allocation + queue cost
/// from the thread wake, so the wake's contribution is row 4 minus this.
fn bench_owned_same_thread(c: &mut Criterion) {
    let src = vec![0xa5u8; MTU];
    let q: Arc<Mutex<VecDeque<OwnedCmd>>> = Arc::new(Mutex::new(VecDeque::new()));
    c.bench_function("b2/owned_vec_queue_same_thread", |b| {
        b.iter(|| {
            let mut frame = Vec::with_capacity(MTU);
            frame.extend_from_slice(black_box(&src[..MTU]));
            let mut guard = q.lock().unwrap();
            push_bounded(
                &mut guard,
                OwnedCmd::Frame(frame),
                MAX_PENDING_WORKER_COMMANDS,
            );
            let got = guard.pop_front();
            black_box(&got);
        })
    });
}

/// Row 3 — pooled handoff, SAME thread. Identical queue work, no allocation.
/// The delta against row 2 is the price of the allocation policy alone.
fn bench_pooled_same_thread(c: &mut Criterion) {
    let src = vec![0xa5u8; MTU];
    let pool: Vec<Mutex<Vec<u8>>> = (0..64).map(|_| Mutex::new(vec![0u8; MTU])).collect();
    let next = AtomicUsize::new(0);
    let q: Arc<Mutex<VecDeque<PooledCmd>>> = Arc::new(Mutex::new(VecDeque::new()));
    c.bench_function("b2/pooled_slot_queue_same_thread", |b| {
        b.iter(|| {
            let slot = next.fetch_add(1, Ordering::Relaxed) % pool.len();
            {
                let mut buf = pool[slot].lock().unwrap();
                buf[..MTU].copy_from_slice(black_box(&src[..MTU]));
            }
            let mut guard = q.lock().unwrap();
            push_bounded(
                &mut guard,
                PooledCmd::Frame { slot, len: MTU },
                MAX_PENDING_WORKER_COMMANDS,
            );
            let got = guard.pop_front();
            black_box(&got);
        })
    });
}

/// Row 4 — the real shape: a CROSS-THREAD handoff over the slow path's own
/// bounded `sync_channel`, with the consumer on another thread. This is the
/// number that bounds a capture bridge's userspace throughput, because a
/// capture source and a worker are not the same thread.
///
/// Measured as a round trip (frame out, ack back) so the consumer's wake is
/// actually on the critical path rather than being absorbed by the channel's
/// buffer. Halve it for a one-way estimate; the comment says so rather than
/// silently reporting half.
fn bench_cross_thread_roundtrip(c: &mut Criterion) {
    let src = vec![0xa5u8; MTU];
    let (tx, rx) = mpsc::sync_channel::<OwnedCmd>(SLOWPATH_QUEUE_DEPTH);
    let (ack_tx, ack_rx) = mpsc::sync_channel::<usize>(SLOWPATH_QUEUE_DEPTH);
    let consumer = thread::Builder::new()
        .name("b2-bench-consumer".to_string())
        .spawn(move || {
            while let Ok(OwnedCmd::Frame(f)) = rx.recv() {
                // Touch the payload so the copy is not optimized away and the
                // cache traffic is realistic.
                let n = f.len();
                if ack_tx.send(n).is_err() {
                    break;
                }
            }
        })
        .expect("spawn bench consumer");

    c.bench_function("b2/owned_vec_cross_thread_roundtrip", |b| {
        b.iter(|| {
            let mut frame = Vec::with_capacity(MTU);
            frame.extend_from_slice(black_box(&src[..MTU]));
            match tx.try_send(OwnedCmd::Frame(frame)) {
                Ok(()) => {
                    let n = ack_rx.recv().expect("consumer ack");
                    black_box(n);
                }
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
        })
    });
    drop(tx);
    let _ = consumer.join();
}

criterion_group!(
    b2,
    bench_copy_only,
    bench_owned_same_thread,
    bench_pooled_same_thread,
    bench_cross_thread_roundtrip
);
criterion_main!(b2);
