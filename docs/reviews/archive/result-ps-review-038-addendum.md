# Triage result — ps-review-038-addendum.md (A1_b2 RETRY findings)

**Cohort:** A1_rust_dataplane_packet-b2 retry (late-arriving addendum; NOT triaged elsewhere)
**Base verified against:** current `origin/master` = `3bbe3d39ce9893c30d399275d699e9e6a37267c2`
**Method:** read-only source verification (no fix, no PR, no git-mutate)
**Findings in addendum:** 5 (1 High, 2 Medium, 1 Low, 1 Medium/Low)
**Outcome:** **5 / 5 NOT-MATERIAL.** The headline HIGH memory-safety claim (A1-R1) is
REFUTED by an in-function bounds check the reviewer never located. No issues to file.

---

## A1-R1 — TX completion ring OOB write (claimed HIGH / High confidence) → **NOT-MATERIAL**

### The claim
A kernel-supplied `u64` completion-ring offset is pushed UNCHECKED into `free_tx_frames`,
later used via `slice_mut_unchecked(offset, len)` → OOB write. Labeled memory-safety / oob-write.

### Ground truth
The name `slice_mut_unchecked` is misleading and the reviewer took it at face value. It is
"unchecked" only with respect to the **borrow-aliasing** invariant (it hands out a `&mut [u8]`
from a `&self` shared borrow); it **DOES bounds-check**.

`userspace-dp/src/afxdp/umem/mmap.rs:146-156`:
```rust
pub(in crate::afxdp) unsafe fn slice_mut_unchecked(&self, offset: usize, len: usize)
    -> Option<&mut [u8]> {
    let end = offset.checked_add(len)?;   // overflow-safe
    if end > self.len {                   // <-- BOUNDS CHECK
        return None;                      // out-of-range → None, NO write
    }
    Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
}
```
The `# Safety` doc (mmap.rs:137-145) states explicitly that the *unchecked* obligation on the
caller is the **aliasing** one ("no other borrow into the same range is live"), upheld by the
AF_XDP single-writer discipline — not bounds.

**Every production caller handles the `None`:**
- `tx/transmit/rewrite.rs:30-59` — file header literally reads *"Drop semantics on
  slice-out-of-range"*; on `None` it orphan-recycles every staged frame and returns `TxError::Drop`.
- `tx/transmit/verify.rs:16-57` — read-only re-validation, `TxError::Drop` on out-of-range.
- `tx/transmit/mod.rs:129-145` (`transmit_batch`) — `else { push_front(offset); … return
  TxError::Drop("tx frame slice out of range …") }`.
- `tx/tcp_segmentation.rs:151-162` — `else { push_front(tx_offset); … return None }`.
- `cos/ecn.rs:226-227` — `else { return false }`.
- `tx/rings.rs:107-113` (fill-ring poison) — behind `cfg!(feature="debug-log")`, `if let Some(frame)`.

The completion-ring drain (`reap_tx_completions`, `rings.rs:20-71` → `recycle_completed_tx_offset`
:220-235 → `free_tx_frames.push_back(offset)`) DOES push the kernel offset into `free_tx_frames`
without an eager bounds check — that half of the claim is factually true. But the offset is
**bounded-by-construction** and **re-checked at every use site**:

1. **Bounded-by-construction:** the XSK completion ring only ever returns addresses that
   userspace previously enqueued on the TX ring, and those come from `free_tx_frames`, which is
   seeded only with valid in-UMEM frame offsets. The kernel additionally validates TX-ring `addr`
   against the registered UMEM at submit time. For the completion ring to yield an out-of-bounds
   value the kernel would have to *fabricate* an address it was never given.
2. **Defense-in-depth already present:** even in that fabricated-driver-bug case, the value can
   only reach memory through `slice_mut_unchecked` (→ `None` → frame dropped) or be re-submitted to
   the kernel fill/TX ring (→ kernel re-validates vs UMEM registration). There is **no path** where
   a raw completion/`free_tx_frames` offset indexes memory unchecked — confirmed by grepping
   `get_unchecked*`: the only hits are `mpsc_inbox.rs` (`pos & self.mask`, masked in-bounds) and
   `umem/mod.rs:139` `frame(BufIdx(idx))` (Option-returning), neither on the completion offset.

### Why not HIGH / MED
The finding's own "Refutation attempt" hedged ("If raw offset stored — not safe … Need to verify
the exact conversion path") and the reviewer did not verify. The disproving check is even simpler
than the `BufIdx` conversion they speculated about: the bounds check lives inside
`slice_mut_unchecked` itself. There is no reachable OOB write — a bad offset yields a dropped TX
frame, not memory corruption. The only thing the suggested fix would *add* is frame-**alignment**
validation (`offset % frame_size == 0`); a misaligned-but-in-bounds offset is a frame-accounting
oddity, not a memory-safety defect (still bounded by `end > self.len`). Not filed.

**Disposition: NOT-MATERIAL** — disproving bounds check at `umem/mmap.rs:151-153`; invariant =
kernel-completion-offset bounded-by-construction + re-checked at every `slice_mut_unchecked` use.

---

## A1-R2 — TX tcp_segmentation MTU→u16 truncation (claimed MED / High) → **NOT-MATERIAL**

### The claim
`total_ip_len = mtu as u16` / `v6_payload_len = (mtu - 40) as u16`; `InterfaceMtu::try_from_snapshot`
lacks an upper bound, so MTU > 65535 truncates the IP wire length.

### Ground truth
The cited evidence is **fabricated** — that code does not exist. Actual
(`tx/tcp_segmentation.rs`):
```
137: let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
138: let frame_len = eth_len + total_ip_len;
139: if frame_len > tx_frame_capacity() { …recycle…; return None; }   // <-- guard
196: .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
242: let v6_payload_len = (ip_header_len - 40) + tcp_header_len + chunk_len;
```
`tx_frame_capacity()` = `UMEM_FRAME_SIZE` = **4096** (`afxdp/mod.rs:203,399`). The line-139 guard
runs **before** the `as u16` casts at 196/245 and returns `None` if `frame_len > 4096`, so
`total_ip_len` is always < 4096 at the cast — nowhere near the u16 ceiling. Independently,
`chunk_len ≤ segment_payload_max = mtu - headers` AND `chunk_len ≤ data.len()`, and `data` is the
TCP payload of a received packet living in one UMEM frame (≤ 4096). Even with a pathological
MTU of 70000 the segmentation simply bails at line 139; no truncated wire length is emitted.

An upper bound on `InterfaceMtu` would be harmless defense-in-depth but there is **no reachable
truncation bug** here. Not filed.

**Disposition: NOT-MATERIAL** — evidence fabricated; `frame_len > tx_frame_capacity()` (4096)
guard at tcp_segmentation.rs:139 bounds `total_ip_len` below the u16 cast; input data
bounded by the 4096-byte UMEM frame.

---

## A1-R3 — TX phase ordering: REWRITE before VERIFY (claimed MED / Medium) → **NOT-MATERIAL**

### The claim
`transmit_prepared_queue` runs REWRITE (unchecked packet modifications) before VERIFY (checked
bounds), so a bad offset corrupts memory in REWRITE before VERIFY detects it. Swap to verify→rewrite.

### Ground truth
REWRITE is **not** unchecked. `rewrite::apply_dscp_rewrites_to_staged`
(`tx/transmit/rewrite.rs:30-60`) obtains its frame via `slice_mut_unchecked(req_offset, req_len)`,
which bounds-checks and returns `None` on out-of-range; the `else` branch orphan-recycles and
returns `TxError::Drop` **before any write**. The actual DSCP mutation
(`apply_dscp_rewrite_to_frame`) operates on the already-bounds-validated `frame` slice.

VERIFY (`verify.rs:16-57`) is a **redundant read-only re-check** using `slice(...).is_none()`. Its
own header (verify.rs:1-7) says it "guards against any window where a previous phase mutated state
in a way that could invalidate the slice bounds" — belt-and-suspenders, not the sole bounds gate.
The DSCP rewrite touches one TOS byte; it changes neither `req.offset` nor `req.len`, so it cannot
invalidate the bounds VERIFY re-checks. The orchestrator doc (`transmit/mod.rs:275-282`) notes the
phase split is *"pure code motion … semantics, ordering, and drop accounting byte-identical to the
pre-split function"* — the ordering was already reviewed pre-#1354. Swapping the order would change
nothing safety-wise. Not filed.

**Disposition: NOT-MATERIAL** — REWRITE self-bounds-checks via `slice_mut_unchecked`→`None`→`Drop`
(rewrite.rs:30-59); VERIFY is a redundant re-check, not the only bounds gate; premise "unchecked
modifications" is false.

---

## A1-R4 — worker/lifecycle raw-pointer UMEM reborrow (claimed LOW / Medium) → **NOT-MATERIAL**

### The claim
The `unsafe { &*area }` reborrow relies on an **undocumented** Rc invariant; fragile — should be
documented or converted to a safe API.

### Ground truth
The invariant is **already documented** in full at `worker/lifecycle.rs:57-67`: the pointee
(`MmapArea` inside `Rc<WorkerUmemInner>`) outlives the whole poll call; nothing on the poll path
drops/replaces `binding.umem`; the only `&mut WorkerUmemInner` escape (`WorkerUmem::umem_mut` via
`Rc::get_mut`) runs solely at bind time (`bind.rs`), never while polling — so shared reborrows can
never alias a mutable reference; the raw pointer merely decouples the immutable UMEM-area borrow
from the `&mut BindingWorker` borrows. That is exactly the documentation the finding asks for. The
remaining "convert to safe API" is a refactor preference, not a defect. Not filed.

**Disposition: NOT-MATERIAL** — the requested documentation already exists at lifecycle.rs:57-67
(Rc/aliasing/bind-time-only-`get_mut` reasoning spelled out).

---

## A1-R5 — Empty application_terms = permit-all (claimed MED / Low) → **NOT-MATERIAL (already fixed)**

### The claim
When Go fails to resolve a named application (typo / missing `junos-*`), it emits empty
`application_terms`, which Rust treats as "match any" = permit-all. Fix: Go should emit a
never-match sentinel, or Rust should distinguish empty-from-error vs empty-from-any; fail-closed.

### Ground truth
The proposed fix is **already implemented** (#2124, extended by #3261/#3727/#4394):
- **Go side** poisons a rule whose named-app expansion fails with a reserved `__unsupported__`
  sentinel term (`pkg/policymatch/policymatch.go:511,819`; `expandUserspacePolicyApplications`;
  tests `app_set_failclosed_3727_test.go`, `content_reject_4394_test.go`,
  `protocol_omitted_3323_test.go`). The emitted term is **non-empty**.
- **Rust side** `parse_applications` (`policy.rs:1417`) detects the unparseable/`__unsupported__`
  term and returns `SnapshotIntegrityError::UnrepresentableApplicationProtocol { rule_id }`
  (`policy.rs:929-935`), which **rejects the whole snapshot** — the integrity preflight keeps the
  previous good state (fail-CLOSED, action-agnostic: never turns deny→pass nor permit→match-any;
  see the #2124 doc at policy.rs:19-29).

Empty `application_terms` therefore remains ONLY the genuine Junos `application any` case
(regression-guarded by `policy_tests.rs:831 empty_application_terms_stay_match_any`). The finding's
"empty-from-error indistinguishable from empty-from-any" premise is false — Go emits a
distinguishing sentinel exactly as the finding recommends. Not filed.

**Disposition: NOT-MATERIAL / already-fixed** — #2124 `__unsupported__` sentinel + whole-snapshot
reject (policy.rs:24, 929-935; policymatch.go:511,819) already fail-closes the resolution-failure
path.

---

## Summary table

| ID | Claim | Severity claimed | Disposition | Disproving evidence |
|----|-------|-----------------|-------------|---------------------|
| A1-R1 | TX completion offset → `slice_mut_unchecked` OOB write | HIGH | **NOT-MATERIAL** | `slice_mut_unchecked` bounds-checks `end > self.len → None` (mmap.rs:151-153); every caller drops on `None`; offset bounded-by-construction |
| A1-R2 | MTU>65535 → `total_ip_len as u16` truncation | MED | **NOT-MATERIAL** | evidence fabricated; `frame_len > 4096` guard (tcp_segmentation.rs:139) precedes cast; input ≤ 4096-byte frame |
| A1-R3 | REWRITE (unchecked) before VERIFY | MED | **NOT-MATERIAL** | REWRITE bounds-checks via `slice_mut_unchecked`→Drop (rewrite.rs:30-59); VERIFY is redundant |
| A1-R4 | undocumented Rc reborrow invariant | LOW | **NOT-MATERIAL** | invariant documented at lifecycle.rs:57-67 |
| A1-R5 | empty application_terms = permit-all | MED/LOW | **NOT-MATERIAL (fixed)** | Go `__unsupported__` sentinel + Rust whole-snapshot reject, #2124 (policy.rs:929-935) |

**Nothing filed.** The headline HIGH is a false alarm rooted in trusting the misleading
`_unchecked` suffix; the addendum is entirely negative, consistent with the note that the A1_rust
batches were "mostly-negative."
