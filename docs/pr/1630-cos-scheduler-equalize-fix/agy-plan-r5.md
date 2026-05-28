# AGY Adversarial Plan Review (Round 5) — Issue #1630

**Verdict**: **PLAN-READY**
**Confidence**: **1.0** (Comprehensively verified)

---

## §1 Hostile Task 1: Saturation Trace (3 Lease Epochs) Under v6

We trace a fully saturated backlogged workload using the **v6** cursor-preservation semantics.

### Parameters
* **Root capacity ($cap$)**: $625,000\text{ bytes}$ per $200\,\mu\text{s}$ epoch (at $25\text{ Gbps}$).
* **Phase 1 budget ($pass1$)**: $625,000 \times 0.7 = 437,500\text{ bytes}$.
* **Exact ascending classes**: `100m`, `1g`, `3g`, `6g`, `9g`, `12g`, `15g`, `18g`, `21g`, `24g`.

### Lease Epoch 1 ($t \in [100,000\text{ ns}, 300,000\text{ ns})$)
* Initial state: `pass1_remaining = 437,500`, `waterfill_phase2_cursor = 0` (pointing to `24g`).
* **Phase 1 Ascending Walk**:
  * Honors `100m` ($2,500\text{ B}$), `1g` ($25,000\text{ B}$), `3g` ($75,000\text{ B}$), and `6g` (processed in two selections due to `TX_BATCH_SIZE` limits: $96,000\text{ B} + 54,000\text{ B} = 150,000\text{ B}$).
  * Total consumed Phase 1 budget = $252,500\text{ B}$.
  * `pass1_remaining` is decremented to $185,000\text{ B}$.
  * `9g` requires $225,000\text{ B} > 185,000\text{ B}$ $\rightarrow$ **BREAK to Phase 2**.
* **Phase 2 Descending Walk**:
  * First Phase 2 call: starts at `phase2_cursor = 0` (maps to `24g` at index $10 - 1 - 0 = 9$). Serviced up to $96,000\text{ B}$. `phase2_cursor` is updated to $1$.
  * Subsequent calls in Epoch 1 (with $elapsed < 200\,\mu\text{s}$ and $pass1\_remaining = 185,000 > 0$): Phase 1 skips small classes (0 lease tokens) and breaks on `9g`. Phase 2 descending walk continues:
    * Call 7: `phase2_cursor = 1` $\rightarrow$ services `21g`, cursor updates to $2$.
    * Call 8: `phase2_cursor = 2` $\rightarrow$ services `18g`, cursor updates to $3$.
    * Call 9: `phase2_cursor = 3` $\rightarrow$ services `15g`, cursor updates to $4$.
  * Let's assume Epoch 1 ends here. `phase2_cursor` is at $4$ (pointing to `12g` next).

### Lease Epoch 2 ($t \in [300,000\text{ ns}, 500,000\text{ ns})$)
* At $t = 301,000\text{ ns}$, `elapsed_since_refresh >= VISIT_NS` is true $\rightarrow$ **time-based refresh triggers**.
* `pass1_remaining` is reset to $437,500\text{ B}$.
* **CRITICAL**: `waterfill_phase2_cursor` is NOT reset by the time-refresh. It remains at $4$.
* Leases replenish. Phase 1 honors `100m` to `6g` again, consuming $252,500\text{ B}$, leaving `pass1_remaining = 185,000`. Breaks on `9g`.
* **Phase 2 Descending Walk**:
  * Starts at `phase2_cursor = 4` (maps to `12g` at index $10 - 1 - 4 = 5$).
  * `12g` is selected first, and `phase2_cursor` is updated to $5$.
  * Subsequent calls within Epoch 2 advance the cursor to $5$ (`9g`), then wrap back to $0$ (`24g`), $1$ (`21g`), and $2$ (`18g`).
  * Let's assume Epoch 2 ends with the cursor at $2$.

### Lease Epoch 3 ($t \in [500,000\text{ ns}, 700,000\text{ ns})$)
* At $t = 501,000\text{ ns}$, **time-based refresh triggers**. `pass1_remaining` is reset to $437,500\text{ B}$.
* `waterfill_phase2_cursor` remains at $2$.
* Phase 1 honors small classes. Breaks on `9g`.
* **Phase 2 Descending Walk**:
  * Starts at `phase2_cursor = 2` (maps to `18g`). Services `18g`, updates cursor to $3$ (`15g`).

### Verdict
The Phase-2 cursor rotates across epoch boundaries. All 6 large classes get roughly equal slices of residual capacity over multiple epochs, maintaining fairness.

---

## §2 Hostile Task 2: Simultaneous Time-Refresh and `pass1 == 0`

If a selection perfectly depletes `pass1_remaining` at the exact millisecond `elapsed_since_refresh >= VISIT_NS`:
* Both conditions evaluate to `true`.
* The refill block is entered.
* `pass1_remaining` is refilled and `waterfill_epoch_start_ns` is anchored to `now_ns`.
* Because `exhausted` is `true`, the condition `if exhausted { root.waterfill_phase2_cursor = 0; }` is evaluated as `true`.
* The Phase-2 cursor is reset to 0.

This is correct. Perfect exhaustion of the budget represents a natural boundary of the waterfill allocation cycle. Giving dominance to the exhaustion path is logical and preserves legacy cycle-restart behavior when both events align.

---

## §3 Hostile Task 3: Preservation of Pre-fix Exhausted-Path Semantics

* **Exhausted Refill**: Pre-fix, `waterfill_phase2_cursor` was set to 0 whenever `waterfill_pass1_remaining_bytes == 0`. In v6, the `if exhausted { root.waterfill_phase2_cursor = 0; }` gate reproduces this behavior.
* **Fall-through Reset**: Pre-fix, if no selection was made in either phase, the selector hit lines 1002-1006, resetting `pass1` and `phase2_cursor` to 0. In v6, this block is untouched.

The legacy exhausted paths and fall-throughs are preserved.

---

## §4 Hostile Task 4: Sufficiency of Test 5 (Multi-Epoch Saturation)

* **Under v4**: There is no time-based refresh. The leftover budget gets stuck at a small positive value. In Epoch 3, the budget is too small to fit any quantum, and Phase 1 immediately breaks to Phase 2. Small classes stop being serviced entirely. Test 5's assertion that all small classes are honored at least once per epoch over 5 epochs fails.
* **Under v6**: Time-based refresh replenishes the budget to $437.5\text{ KB}$ every $200\,\mu\text{s}$, guaranteeing that the small queues are honored in all 5 epochs. Test 5 passes.

Test 5 is concrete and isolates the v4 failure mode.

---

## §5 Hostile Task 5: Sufficiency of Test 4 (Cursor Preservation)

* **Under v5**: The time-based refresh block unconditionally reset `waterfill_phase2_cursor = 0`. Under Test 4, forcing a time-refresh on a mid-walk cursor state (e.g., 3) would reset it to 0, failing the preservation assert.
* **Under v6**: The cursor is only reset `if exhausted`. A pure time-refresh leaves the cursor at 3. Test 4 passes.

Test 4 distinguishes v5 from v6.

---

## §6 Hostile Task 6: Drift Between Global and Worker-Local Timestamps

* **Mechanics**: Per-class leases rotate every $200\,\mu\text{s}$ using global seqlocks. The worker-local waterfill epoch refreshes every $200\,\mu\text{s}$ using its own `waterfill_epoch_start_ns`.
* **Impact of Drift**: An offset (e.g., $10\,\mu\text{s}$) merely shifts the specific selector call that observes the replenished lease tokens. Over any macroscopic window (e.g., $30\text{ s}$), both execute exactly 5,000 refreshes per second. No rate limits are violated.
* **Architectural Invariant**: Forcing lock-step coordination between global class leases and worker-local runtime states would introduce cross-core cache line bouncing and synchronization overhead on the datapath. The drift is functionally harmless and structurally necessary for high packet rates.

---

## §7 Hostile Task 7: Plan Cleanliness

Stale text and legacy mechanics (such as the persistent bitmask and the $>64$ queue fallback gates) from v3/v4/v5 have been purged. The references to `honored_mask` are restricted to proposing Hunk C (the optional dead-code deletion). The plan is clean and represents the convergent v6 design.
