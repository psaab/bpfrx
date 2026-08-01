//! #5173: the packet's RX queue coordinate and the binding slot it resolves to,
//! in a module that compiles for the HOST as well as for `bpfel-unknown-none`.
//!
//! AF_XDP delivery is queue-bound: `xsk_rcv_check()` in `net/xdp/xsk.c` compares
//! BOTH `xs->dev != xdp->rxq->dev` and `xs->queue_id != xdp->rxq->queue_index`,
//! so a redirect to a socket bound to a different netdev or a different queue is
//! rejected and the packet dropped. The coordinate must therefore survive
//! unchanged between "which queue did this arrive on" and "which XSK do we
//! redirect to".
//!
//! WHY THIS IS A MODULE AND NOT A SET OF SOURCE CHECKS. The first attempt
//! asserted the invariant with tests that read the shim's source TEXT. Hostile
//! review escaped them twice with every guard green: by reducing the coordinate
//! at the CALL SITE, and by adding a raw fallback lookup in a DIFFERENT file,
//! which a file-scoped text check cannot see by construction. Source-spelling
//! tests are the wrong tool for a property that can be compiled or executed
//! instead — so the mapping moved here, where a host test RUNS it.
//!
//! WHAT IS ENFORCED, AND WHAT IS NOT — stated precisely, because the difference
//! is the whole point and because an earlier revision of this comment
//! overstated it:
//!
//!   - **Compile-time.** [`RawRxQueue`] wraps the coordinate with a PRIVATE
//!     field and implements no arithmetic. `queue % 2`, `queue & 3`, `queue >> 1`
//!     do not compile outside this module (E0369), and neither does the tuple
//!     constructor (E0423). A future author who genuinely needs to transform it
//!     must add a visible, reviewable accessor. That property holds only while
//!     the field stays private and no arithmetic impl exists, and BOTH are now
//!     bounded by the parity tests — a hostile round added an arithmetic impl
//!     plus a public field and nothing went red, which with one extra line
//!     reintroduced the defect with no `unsafe` marker anywhere in it.
//!   - **Executed.** [`binding_slot`] is host-compiled and driven over the
//!     `(ifindex, queue)` grid the parity tests cover — queues 0..64 against a
//!     spread of ifindexes up to 65535, so both sides of the stride boundary
//!     are exercised — and the mapping, the bound, and the property that a slot
//!     never leaves its own interface's row are behavioural results rather than
//!     claims about text. NOT covered: ifindexes large enough for
//!     `ifindex * BINDING_QUEUES_PER_IFACE` to overflow `u32` (2^28 and up).
//!     Host and target disagree there — a debug host build PANICS on the
//!     overflow while the release target WRAPS — so the grid deliberately stops
//!     below it. A kernel ifindex is an `int` and the shim gates on its
//!     ingress-interface map before reaching here, so that range is unreachable
//!     in practice; it is also pre-existing on master, same multiply, same
//!     absent bound.
//!   - **NOT closed by a TYPE, and that list is not empty.** The constructor
//!     must accept a bare `u32`, because the value originates in an aya
//!     `XdpContext` that cannot cross into a `core`-only module. So (a) a
//!     reduction applied to the integer BEFORE it is wrapped still compiles,
//!     and (b) so does any construction of the wrapper that goes around the
//!     constructor entirely by fabricating it from raw bytes — a `transmute`,
//!     `mem::zeroed`, `MaybeUninit::assume_init`, a pointer read. (b) is a
//!     CLASS, not a symbol, and naming only `transmute` — as an earlier
//!     revision of this comment did — invites an audit that greps for one word
//!     and misses the rest; the field's visibility is irrelevant to all of
//!     them. A third residual is that [`binding_slot`] types the queue half of
//!     the index and not the ifindex half, so reducing the ifindex is never
//!     rejected by the type system.
//!
//!     What bounds all three is source, in the parity tests, and it is worth
//!     saying HOW because the obvious way does not work: not by enumerating the
//!     fabrication symbols, which would always be one symbol behind, but by
//!     pinning the lookup statement so both coordinates must arrive under a
//!     fixed NAME, and then bounding each of those names to a single binding in
//!     the whole crate. A forged or reduced value that cannot be bound to the
//!     name is a value the pinned statement will not accept.
//!
//! The honest summary: the source-asserted surface cannot reach ZERO while the
//! coordinate originates in aya-dependent code — a parameter of an enclosing
//! closure or helper `fn` still shadows a name without writing a binding, which
//! nothing here catches. What it can do, and now does, is make every known
//! reintroduction of #5173 either fail to compile or fail a pinned statement.
//!
//! Nothing here may depend on `aya`, on a BPF map, or on `std` — that is what
//! keeps it host-compilable, and it is the whole point.

/// Queue stride of the flat binding array. The index is
/// `ifindex * BINDING_QUEUES_PER_IFACE + queue`, so this is the exclusive upper
/// bound on an addressable queue id: at or above it the index would land in the
/// NEXT ifindex's row. Mirrored by `bindingQueuesPerIface` in
/// `pkg/dataplane/userspace/maps_sync.go` and `BindingQueuesPerIface` in
/// `pkg/dataplane/constants.go`, both of which already refuse to publish a
/// higher queue id (#4894).
pub const BINDING_QUEUES_PER_IFACE: u32 = 16;

/// The packet's own RX queue index, as reported by the hardware.
///
/// The field is private and there are no arithmetic impls, so the coordinate
/// cannot be reduced, masked or shifted outside this module. That is the
/// compile-time half of the #5173 invariant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawRxQueue(u32);

impl RawRxQueue {
    /// The ONLY constructor reachable from `lib.rs`. Its single call site — the
    /// read of `(*ctx.ctx).rx_queue_index` — is pinned token-for-token by a
    /// repo-scoped check in the parity tests, because a reduction applied to
    /// the integer before it reaches here is one of the two escapes a newtype
    /// cannot prevent. (The other is going around this constructor altogether
    /// and fabricating the wrapper from raw bytes; no type prevents that, and
    /// the module comment above says how source bounds it.)
    #[inline(always)]
    pub fn from_ctx_field(rx_queue_index: u32) -> Self {
        RawRxQueue(rx_queue_index)
    }

    /// Read the coordinate back for TELEMETRY ONLY (`record_trace`).
    ///
    /// Deliberately not used to compute a binding index: `binding_slot` takes
    /// the wrapper, so the index path cannot be fed a bare integer that has
    /// been through arithmetic.
    #[inline(always)]
    pub fn for_trace(self) -> u32 {
        self.0
    }
}

/// Resolve the binding slot for a packet arriving on `rx_queue` of
/// `ingress_ifindex`, or `None` when the queue is outside the array's stride.
///
/// `None` is the correct answer for an out-of-stride queue and the ONLY correct
/// answer: clamping or reducing the coordinate back into range is the #5173
/// mis-steer in another form. The publish side already refuses such queue ids
/// (#4894); this is the matching read-side bound, required because
/// `rx_queue_index` comes from the hardware and nothing else clamps it.
///
/// What an out-of-stride read WOULD have done, recorded precisely because an
/// earlier comment got it wrong and the error propagated into review: it would
/// address row `(ifindex + q/16, q%16)`. If that row is empty the shim takes its
/// own binding-missing path and attempts no redirect. If it holds a live socket,
/// that socket is bound to a different netdev AND a different queue, so
/// `xsk_rcv_check()` returns `-EINVAL`, `xdp_redirect_map_err` is counted and
/// the driver discards — while the shim's last recorded trace stage stays
/// REDIRECT, making it a drop MIS-TRACED as having reached redirect. Neither
/// outcome is a cross-interface delivery.
#[inline(always)]
pub fn binding_slot(ingress_ifindex: u32, rx_queue: RawRxQueue) -> Option<u32> {
    if rx_queue.0 >= BINDING_QUEUES_PER_IFACE {
        return None;
    }
    Some(ingress_ifindex * BINDING_QUEUES_PER_IFACE + rx_queue.0)
}
