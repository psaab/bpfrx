**Verdict for #967 (PSHUFB SIMD header rewrite): PLAN-KILL**

Here is the adversarial review evaluating the four criteria against the codebase reality:

### 1. Does the codebase-reality claim hold?
**Yes, entirely.** I reviewed `userspace-dp/src/afxdp/frame/mod.rs`.
- The `rewrite_forwarded_frame_in_place` path (via `rewrite_prepare_eth` at line ~481) *does* use `copy_within()` for VLAN tag shifts.
- MAC addresses are written using scalar 6-byte memory copies (`core::ptr::copy_nonoverlapping` inside `write_eth_header_slice` at line ~1484).
- **However**, the author of #967 fundamentally misattributed the 13.43% CPU cost to these header operations. The `__memmove_evex_unaligned_erms` symbol is glibc's AVX-512 hardware-accelerated memmove (`EVEX` prefix = AVX-512). This heavy cost comes from `build_forwarded_frame_into_from_frame` (line ~208), which executes a bulk `copy_nonoverlapping` of the *entire packet payload* (up to 1.5KB) between ingress and egress UMEMs for cross-worker handoffs. It is completely unrelated to the in-place header rewrite path.

### 2. Is there a real callsite where the SIMD proposal would help?
**No.** While you technically *could* shoehorn a 256-bit `vpshufb` (`_mm256_shuffle_epi8`) into the header rewrite path, it would be optimizing a non-bottleneck. Replacing the 1.5KB bulk payload copy (the actual 13% bottleneck) with a 32-byte header shuffle instruction is mathematically and architecturally nonsensical, and replacing AVX-512 EVEX instructions with AVX2 PSHUFB would be a downgrade.

### 3. Is the perf cost ≥ 2% on real measurement?
**No. It fails the threshold by a wide margin.** 
The header-rewrite-in-place path is not even visible in the top symbols; it sits below the 0.95% SKB fallback noise floor. Optimizing a callsite that consumes `<1%` of the CPU budget will yield zero measurable movement on the smoke matrix. 

### 4. Is the implementation cost worth xpf's scale?
**Absolutely not.** xpf targets 22+ Gb/s across a 6-worker cluster, not a 400 Gb/s enterprise core router. Introducing brittle, CPU-specific SIMD intrinsics (requiring scalar fallbacks and complicating verifier bounds) to shave literal nanoseconds off a sub-1% code path is a massive waste of engineering resources and a textbook architectural distraction.

### Conclusion
The author of #967 saw scalar `[u8; 6]` assignments in the codebase and immediately cried "SIMD!" without properly analyzing the `perf` profile. They conflated the cross-worker architectural memmove bottleneck (#776) with header manipulation. The issue targets a non-existent bottleneck and should be killed.
