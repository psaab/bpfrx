**Verdict for #968: PLAN-KILL**

The codebase reality claims in the plan doc are entirely accurate, and the proposal for Issue #968 is an architectural mismatch that targets a non-existent bottleneck. 

Here is the adversarial verification:

1. **Codebase Reality Holds**: 
   - **SYN Cookies**: A review of `bpf/xdp/xdp_screen.c` (e.g., lines 138, 282, 419, 555) confirms that SYN cookie generation and validation are entirely delegated to kernel kfuncs (`bpf_tcp_raw_gen_syncookie_ipv4`, `bpf_tcp_raw_check_syncookie_ipv4`, etc.). The userspace dataplane does not generate its own SYN cookies. 
   - **Flow Hashing & Crypto**: Searches across `userspace-dp/src` confirm there is no software crypto executing in the per-packet hot path. Any flow hashing in userspace (such as for Stochastic Fairness Queueing in `afxdp/cos/flow_hash.rs` or session lookups) utilizes fast, non-cryptographic hashes like `FxHasher`. The architectural documentation explicitly forbids cryptographic hashes in the dequeue path due to cost (`docs/userspace-dataplane-architecture.md`). 

2. **No Applicable Callsite**: Because the operations #968 seeks to accelerate (software SYN cookie generation and RSS hashing) do not exist within the userspace dataplane, there is nowhere to wire AES-NI or SHA-Ext intrinsics.

3. **Perf Cost is Nowhere Near 2%**: The fresh perf data validates this. The primary costs are cross-worker memory copies (`__memmove_evex_unaligned_erms` at 13.43%) and RX polling (9.45%). There are no cryptographic or hashing symbols measurable anywhere near the 2% threshold on the critical path.

4. **Implementation Cost vs. Scale**: The implementation cost is not justified. Since there is no workload in `xpf` where software crypto is the bottleneck on the per-packet path, attempting to force AES-NI/SHA-Ext into the codebase would strictly add complexity and maintenance burden for zero performance return at the target 22+ Gb/s scale. 

**Recommendation:** Close #968 immediately with a kill rationale pointing out that the premise assumes the codebase is doing things it fundamentally does not do. Point the author toward the actual bottlenecks (#776, #777, #781).
