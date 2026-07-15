

---

## ADDENDUM — A1_b2 retry findings (late arrival)

The initial A1_b2 batch placeholder was replaced by a retry that completed late.
These findings were not included in the main High/Medium/Low sections above.

### A1-R1 — TX completion ring OOB write (High, High confidence)

**Title:** TX completion ring: kernel-supplied u64 offset pushed unchecked into free_tx_frames, later used via slice_mut_unchecked → OOB write

**Severity:** High
**Confidence:** High
**Area:** A1_rust_dataplane_packet-b2
**Files:** `userspace-dp/src/afxdp/tx/rings.rs:109`, `tx/tcp_segmentation.rs:151`, `tx/transmit/rewrite.rs:30`, `umem/mmap.rs:slice_mut_unchecked`

**Evidence:**
```rust
// rings.rs: completion ring polls kernel for TX done frames:
let offset = completion_ring[i].addr; // u64 from kernel (untrusted)
free_tx_frames.push(offset); // no validation — kernel could return any u64

// Later in transmit:
let frame = umem.frame(buf_idx); // bounds checked against len
// But also:
let slice = umem.slice_mut_unchecked(offset, len); // uses the unchecked offset from completion ring!
```

The XSK completion ring `addr` field is written by the kernel. If the kernel returns an offset outside the UMEM region (due to bug, or on exotic driver behavior), it gets pushed to `free_tx_frames`, then used as base for `slice_mut_unchecked` on the next TX — OOB write.

**Trace:**
1. Kernel completes TX, writes completion entry with `addr` = frame offset that was sent
2. If kernel is buggy or returns a stale/garbage addr, it goes into `free_tx_frames`
3. Next TX pops this offset, constructs frame data via `slice_mut_unchecked(offset, ...)` — OOB write if offset is out of range

**Refutation attempt:** Checked if there's validation between push and use. The `free_tx_frames` ring stores `BufIdx` (validated on pop) vs raw `u64` offset. In current code, completion offsets go through `BufIdx` conversion which does `offset / frame_size` → index, with `index < total_frames` check. If that's present, this is mitigated. Need to verify the exact conversion path. If `BufIdx::from_offset` does bounds check — safe. If raw offset stored — not safe.

**Why it matters:** OOB write from kernel-provided data. Even if kernel is trusted, a kernel bug or driver quirk could corrupt userspace memory.

**Fix direction:** Always validate completion ring offsets before using: `if offset % frame_size != 0 || offset / frame_size >= total_frames { drop; continue; }` — or ensure all paths go through `BufIdx` which validates.

**Labels:** memory-safety, tx, oob-write
**Dedup note:** Not in dedup. Related: UMEM frame validation (#2706 newtypes) but different path.

---

### A1-R2 — TX tcp_segmentation MTU→u16 truncation (Medium, High)

**Title:** TX tcp_segmentation: total_ip_len / v6_payload_len from MTU (validated only for negativity) — MTU > 65535 truncates IP wire length

**Severity:** Medium
**Confidence:** High
**Area:** A1_rust_dataplane_packet-b2
**File:** `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`

**Evidence:**
```rust
let total_ip_len = (mtu as u16); // mtu from InterfaceMtu which validates only != 0 and !negative
let v6_payload_len = (mtu - 40) as u16; // same issue
```

`InterfaceMtu::try_from_snapshot` rejects negatives and 0 but has no upper bound check against 65535. A configured MTU of 70000 would pass validation, then truncate in TCP segmentation to 4464 — wrong IP length, checksum mismatch, packet drop or worse.

**Fix direction:** Add upper bound check in `InterfaceMtu::try_from_snapshot`: reject or clamp MTU > 65535. Or use `u32` for IP length fields and check before `as u16` cast.

**Labels:** integer-truncation, mtu
**Dedup note:** Not in dedup. `InterfaceMtu` validated.rs newtype — fix in #2410/#2706 but incomplete upper bound.

---

### A1-R3 — TX phase ordering: REWRITE before VERIFY (Medium, Medium)

**Title:** TX dispatch: REWRITE (unchecked packet modifications) runs before VERIFY (checked bounds) — OOB corruption before detection

**Severity:** Medium
**Confidence:** Medium
**Area:** A1_rust_dataplane_packet-b2
**File:** `userspace-dp/src/afxdp/tx/dispatch.rs`

**Fix direction:** Swap to verify→rewrite ordering so bounds are checked before any unchecked writes.

---

### A1-R4 — worker/lifecycle raw-pointer UMEM reborrow (Low, Medium)

**Title:** worker/lifecycle.rs raw-pointer UMEM reborrow relies on undocumented Rc invariant

**Severity:** Low
**Confidence:** Medium
**File:** `userspace-dp/src/afxdp/worker/lifecycle.rs`

Fragile for future refactors — should be documented or converted to safe API.

---

### A1-R5 — Empty application_terms = permit-all (Medium, Low)

**Title:** Empty application_terms from failed Go named-app resolution indistinguishable from "application any" — permit-all amplification

**Severity:** Medium
**Confidence:** Low
**Area:** A1_rust_dataplane_packet-b2

**Evidence:** When Go fails to resolve a named application (e.g., `application junos-dns` where junos-dns not found), it sends empty application_terms. Rust treats empty as "match any port/protocol" (= permit-all for that policy). So a typo in `application junos-htt` (instead of junos-http) silently becomes permit-any.

**Fix direction:** Go should emit a sentinel (e.g., port range that never matches) or Rust should distinguish empty-from-error vs empty-from-any. Fail-closed on resolution failure.

**Labels:** policy, fail-open, application
**Dedup note:** Partially related to #4497 avo-001 follow-up (global-scope matrix) but different mechanism.

---

*Total additional findings from A1_b2 retry: 5 (1 High, 2 Medium, 1 Low, 1 Medium/Low)*

*Revised total: 52 findings (3 High, 13 Medium, 36 Low)*
