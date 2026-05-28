## Verdict: PLAN-NEEDS-MINOR
## Confidence: 1.0

### Findings

1. **[MAJOR] Local `honored_mask` Compiler Warning & Phase 2 Bypass Defect**
   - **Severity**: Major (functional contract bypass + compiler warning).
   - **Quote**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:806` (`let mut honored_mask: u64 = 0;`) and `mod.rs:900` (`honored_mask |= 1u64 << queue_idx;`).
   - **Disposition**: The compiler correctly warns that `honored_mask` is never read because every Phase 1 success returns `Some(ExactCoSQueueSelection)` immediately, terminating the function and resetting the local variable to `0` on the next invocation. When Phase 1 eventually breaks to Phase 2 (`mod.rs:893`), `honored_mask` is guaranteed to be `0`. Consequently, the Phase 2 bypass check `(honored_mask & (1u64 << queue_idx)) != 0` (`mod.rs:938`) is always false. This allows already-honored small queues to be serviced again in best-effort Phase 2, stealing residual capacity from larger, non-honored queues and violating the documented contract.
   - **Required Fix**: Statically limit exact queues to `< 64` and persist `honored_mask` as a field inside `CoSInterfaceRuntime` (resetting it to `0` only during epoch budget refill), or clean up the dead local variable and redundant Phase 2 check if token-depletion is proven sufficient.

2. **[MINOR] Transparent-Root (`shaping_rate_bytes == 0`) Fallback is Correct and Essential**
   - **Severity**: Minor.
   - **Quote**: `plan.md` skeleton diff:
     ```rust
     let pass1 = if root.shaping_rate_bytes == 0 {
         /* legacy quantum_sum * fraction */
     } else {
         /* shaper-delivered bytes * fraction */
     };
     ```
   - **Disposition**: Keeping the `quantum_sum` fallback is correct because the Go compiler (`pkg/config/compiler_class_of_service.go:331+`) has no validation logic that prevents `oversubscription-policy guarantee-rate` from being applied when a root `shaping-rate` is omitted. Without this fallback, `pass1` would be set to `0`, starving Phase 1 entirely.

3. **[MINOR] Missing Negative and High-Fraction Boundary Unit Tests**
   - **Severity**: Minor.
   - **Disposition**: The proposed test plan lacks boundary test coverage for:
     - `fraction == 0.0` or `Proportional` policy, proving it bypasses waterfill completely.
     - Proportionality limits (e.g. testing `fraction` in $\{0.2, 0.5, 0.7, 1.0\}$ and asserting the refill budget scales exactly linearly).
   - **Required Fix**: Add these boundary cases as unit tests in `userspace-dp/src/afxdp/cos/queue_service/tests.rs`.

### Worked counter-example for the fix

Under the smoke fixture:
- Root shaping rate = $25\text{ Gbps} = 3,125,000,000\text{ B/s}$.
- Epoch duration (`COS_GUARANTEE_VISIT_NS`) = $200µs = 200,000\text{ ns}$.
- Aggregate epoch capacity delivered by the root shaper:
  $$\text{cap\_per\_epoch} = 3.125\text{ GB/s} \times 200µs = 625,000\text{ bytes}$$
- Phase 1 budget with `guarantee-rate` fraction 0.7:
  $$\text{pass1} = 625,000\text{ bytes} \times 0.7 = 437,500\text{ bytes}$$

Individual per-queue quanta ($q_i = R_i \times 200µs$):
- `iperf-100m`: $q_1 = 2,500\text{ bytes}$
- `iperf-1g`: $q_2 = 25,000\text{ bytes}$
- `iperf-3g`: $q_3 = 75,000\text{ bytes}$
- `iperf-6g`: $q_4 = 150,000\text{ bytes}$
- `iperf-9g`: $q_5 = 225,000\text{ bytes}$

Phase 1 walk:
1. `iperf-100m` is runnable: $q_1 = 2,500 \le 437,500 \implies$ Honored. Remaining: $435,000\text{ bytes}$.
2. `iperf-1g` is runnable: $q_2 = 25,000 \le 435,000 \implies$ Honored. Remaining: $410,000\text{ bytes}$.
3. `iperf-3g` is runnable: $q_3 = 75,000 \le 410,000 \implies$ Honored. Remaining: $335,000\text{ bytes}$.
4. `iperf-6g` is runnable: $q_4 = 150,000 \le 335,000 \implies$ Honored. Remaining: $185,000\text{ bytes}$.
5. `iperf-9g` is runnable: $q_5 = 225,000 > 185,000 \implies$ **BREAK to Phase 2**.

This mathematically proves:
- All 4 small exact classes ($100m, 1g, 3g, 6g$) are guaranteed $\ge 95\%$ rate because they are honored in Phase 1 before the budget exhausts.
- The remaining $185,000\text{ bytes}$ of the Phase 1 budget plus the $187,500\text{ bytes}$ of residual tokens are correctly distributed to the larger classes in Phase 2.

### Verdict rationale

The proposed fix correctly models the Phase 1 budget as a fraction of the actual shaper capacity per epoch, solving the rate equalization bug. However, the local `honored_mask` is completely dead code, causing compiler warnings and allowing already-honored small queues to steal residual capacity in Phase 2. The plan must clarify the transparent-root fallback, add contract boundary unit tests, and resolve the `honored_mask` bypass before sign-off.
