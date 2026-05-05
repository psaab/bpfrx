Here is the adversarial plan review focusing specifically on #969, based on the `simd-triage/plan.md` doc and the codebase reality:

### Verification of #969 (AVX2 gather FIB)

**1. Does the codebase-reality claim hold?**
**Yes, absolutely.** I verified this by scanning the codebase. The `bpf/` directory contains 73 invocations of the kernel kfunc `bpf_fib_lookup` across `xdp_forward.c`, `xdp_conntrack.c`, `xdp_nat64.c`, and `xdp_zone.c`. Conversely, `userspace-dp/` contains **zero** matches for `lpm` and only mentions `fib_lookup` in comments describing when the kernel `bpf_fib_lookup` is retried for pending neighbor resolution. The dataplane delegates FIB entirely to the highly-optimized kernel eBPF kfunc and relies on session-table hash lookups in the hot path. The claim that xpf userspace walks a sequential routing trie 64 times is hallucinated.

**2. Is there a real callsite where the SIMD proposal would help?**
**No.** There is no userspace DIR-24-8 or LPM trie to optimize. Even if one were introduced, as the plan correctly identifies, AVX2 gather (`_mm256_i32gather_epi32`) instructions were heavily de-optimized on Intel architectures (Skylake-X, Ice Lake, Sapphire Rapids) due to Spectre/Meltdown mitigations. Executing a gather on modern hardware is notoriously a performance trap and often executes slower than sequential scalar loads. It would be the wrong instruction for a non-existent callsite.

**3. Is the perf cost ≥2% on real measurement?**
**No.** The provided perf profile captures the actual bottlenecks at 22 Gbps (13.43% on libc AVX-512 cross-worker `memmove`, 9.45% on RX poll, 4.20% on TX dispatch). There is no user-space routing or LPM symbol in the profile, let alone one consuming ≥2% CPU. The bottleneck #969 attempts to solve does not exist in the measurement.

**4. Is implementation cost worth xpf's scale?**
**No.** xpf targets 22+ Gb/s on 6 workers, not massive-scale 100G+ enterprise routing with 100k+ prefixes. To implement #969, xpf would need to architecturally rip FIB lookup out of the kernel (breaking l3mdev and standard Linux routing integration), implement a custom DIR-24-8 data structure in userspace, and maintain complex synchronization—all to inject a CPU-specific SIMD intrinsic that is known to perform poorly on recent hardware, addressing a bottleneck that doesn't exist.

### Verdict

**PLAN-KILL**

**Rationale:** #969 is a textbook example of "Speculative Architecture by Template." It proposes a complex, hardware-specific optimization (AVX2 gather) for a data structure (userspace LPM trie) that does not exist in the codebase, to solve a bottleneck that doesn't show up in the perf data. The userspace dataplane delegates FIB lookups to the eBPF kernel layer via `bpf_fib_lookup`. The proposal is fundamentally disconnected from the actual architecture and current bottlenecks (#776, #777, #781). Close the issue.
