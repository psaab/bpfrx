I will view the first 800 lines of the plan under review to understand the scope, options, and findings we need to pressure-test.
I will examine the `cos.rs` file within the designated worktree to verify the claims regarding the synthetic default queue construction and the `contributes_usable_cos_state` gate.
I will view `userspace-dp/src/afxdp/cos/admission.rs` around lines 476-530 to verify the admission AQM behavior.
I will view the push operations code to verify how non-exact queues promote lazily.
I will view the rest of the promotion logic in `push.rs` to verify how MQFQ promotion is executed and its exact resource allocations.
I will view `pkg/config/compiler_protocols.go` around line 842 to understand how the compiler handles the class of service configuration.
I will run a grep search in the config packages to locate where the shaping rate is compiled and translated into the dataplane configuration.
I will view the relevant section of `compiler_class_of_service.go` in the worktree to verify the mapping of `shaping-rate`.
I will view `docs/cos-traffic-shaping.md` around lines 795-815 to verify the documented contract of the default synthetic queue.call:default_api:view_file{AbsolutePath:/home/ps/git/bpfrx/.claude/worktrees/research-1828-sq/docs/cos-traffic-shaping.md,EndLine:815,StartLine:795,toolAction:Viewing traffic-shaping doc in the worktree,toolSummary:View docs/cos-traffic-shaping.md}
I will view `docs/cos-traffic-shaping.md` around lines 795-815 to verify the documented contract of the default synthetic queue.
I will view `docs/fairness-regimes.md` around lines 580-590 and 810-820 to verify the documented contract of the fairness regimes.
I will view the other section in `docs/fairness-regimes.md` around lines 810-820.
I will search for references to `promote_cos_queue_flow_fair` to verify that every constructed queue (including the synthetic default queue) indeed goes through this flow-fair eligibility promotion.
I will view `userspace-dp/src/afxdp/cos/admission.rs` around lines 380-420.
I will search for `build_cos_interface_runtime` to check how the runtime queues are initialized.
I will view `userspace-dp/src/afxdp/cos/builders.rs` to see how the runtime queues are initialized.
I will search for `struct CoSInterfaceConfig` and `struct CoSQueueConfig` in the Rust files to locate their field definitions.
I will search for any occurrences of `CoSInterfaceConfig` in the Rust files.
I will view `userspace-dp/src/afxdp/types/cos.rs` to see the fields of `CoSInterfaceConfig` and `CoSQueueConfig`.
I will view `userspace-dp/src/afxdp/forwarding_build/cos.rs` from lines 250 to 280.
I will search for the admission policy logic (such as aggregate delay clamp, BDP-aware caps, ECN marking) in `cos/admission.rs` to verify the "admission AQM" claim.
I will view `userspace-dp/src/afxdp/cos/admission.rs` from lines 100 to 230 to examine BDP-aware flow limits and aggregate delay clamp.
I will search for the definition of `fn flow_fair` to see how eligibility/promotion maps to `flow_fair()`.
I will view the `flow_fair` method implementation in `types/cos.rs`.
I will view `cos/admission.rs` at the beginning of the file to see the entry point for the admission checks.
I will view `cos/admission.rs` from lines 51 to 100 to locate the admission check function definition.
I will search for the admission accept functions in the `cos` folder.
I will grep for `cos_queue_accepts_prepared` across the `userspace-dp/src` directory to locate the definition.
I will view `userspace-dp/src/afxdp/tx/cos_classify.rs` around lines 770-830.
I will view the next lines of `cos_classify.rs` to understand the admission and ECN-marking logic on enqueue.
I will search `pkg/config/schema.go` for the class-of-service interface unit children to verify the context of unit-level knobs.
I will view `pkg/config/schema.go` from line 870 to 910.
I will search for `SchemaValidate` in `pkg/config` to verify the order of validation and template expansion.
I will view `pkg/config/schema_validate_test.go` from line 10 to 35.
PLAN-READY-WITH-FINDINGS

### Findings & Evidence

1. **[Severity: Info] Verification of MQFQ lazy promotion recursion and counter safety**
   - **Evidence**: `userspace-dp/src/afxdp/cos/queue_ops/push.rs:43-55` and `userspace-dp/src/afxdp/cos/queue_ops/push.rs:87-96`
   - **Detail**: The lazy promotion helper `maybe_promote_best_effort` executes before any enqueue actions. Once it calls `promote_to_flow_fair`, `queue.flow_fair_state` is set to `Some`, ensuring subsequent recursive pushes short-circuit immediately. The manual decrement of `queue.hot.local_item_count` prior to re-pushing correctly cancels out the increment in `cos_queue_push_back`, preventing counter drift.

2. **[Severity: Minor] Empirical validation check for cookbook fairness claims (Q5)**
   - **Evidence**: `userspace-dp/src/afxdp/cos/queue_ops/push.rs:43-55` and `docs/cos-traffic-shaping.md:804-807`
   - **Detail**: To validate the cookbook's claim that a bare `shaping-rate` config delivers per-flow fairness on the synthetic best-effort queue, the smoke test must explicitly verify that `xpf_userspace_cos_active_flow_count` goes above 1 during a multi-flow run (e.g., `-P 12`). Without this telemetry check, the test could succeed while the queue remains silently stuck in uncontended FIFO mode.

3. **[Severity: Minor] Post-expansion AST validation gate for commit check rules (Q1)**
   - **Evidence**: `pkg/config/schema_validate_test.go:17-19`
   - **Detail**: The compile/validation check rejecting the combination of `smart-queueing` and `scheduler-map` must execute on the final, post-group-expanded AST. If executed on the raw pre-expanded AST, a user could bypass this restriction by configuring `smart-queueing` on the unit and inheriting a `scheduler-map` via `apply-groups` templates (`pkg/config/ast_groups.go`).

4. **[Severity: Minor] Scale mismatch in presence-only WAN defaults (Q7)**
   - **Evidence**: `userspace-dp/src/afxdp/cos/admission.rs:94` and `docs/cos-traffic-shaping.md:521-526`
   - **Detail**: Industry-standard defaults (5 ms target / 100 ms interval) assume low-latency links. On typical WAN uplinks where baseline RTT approaches or exceeds 100 ms, the 100 ms interval will cause premature and aggressive drops. The cookbook in `docs/cos-wan-sqm.md` must warn operators to scale `codel-interval` to match high baseline RTTs.

---

### Answers to Open Questions (§12 Q1-Q7)

* **Q1 (interaction rule)**: Reject-don't-merge is correct. Treating `smart-queueing` as a default-filler for scheduler-map queues creates silent behavioral regressions if a map is added or modified later. Schedulers in a scheduler-map must configure `codel-target` directly.
* **Q2 (spelling)**: Sibling unit-level spelling `smart-queueing` is correct. Hanging it off `shaping-rate` is grammatically complex as it nests under a value-bearing leaf, whereas unit-level sibling placement aligns cleanly with `scheduler-map` (see `pkg/config/schema.go:888-900`).
* **Q3 (doc placement)**: Creating a new `docs/cos-wan-sqm.md` is correct. Placing this operator guide inside the 1172-line engine design document (`docs/cos-traffic-shaping.md`) would make it undiscoverable.
* **Q4 (close-out shape)**: Keep #1828 open. It tracks user-facing configuration surface, whereas #1829 owns the engine-side AQM logic and telemetry evidence.
* **Q5 (cookbook honesty)**: The validation check must verify `xpf_userspace_cos_active_flow_count > 1` during the multi-flow run to guarantee that lazy promotion was triggered.
* **Q6 (Option D triage)**: Overhead compensation is technically required for accurate shaping on low-rate WAN links (e.g., PPPoE/DSL), but it is not a blocker for the high-rate Ethernet environment of the loss cluster. File a separate follow-up issue at close-out.
* **Q7 (defaults)**: Default to 5 ms target / 100 ms interval for standard compatibility, but rely on Deliverable 1's cookbook to guide operators on raising the interval for high-latency WAN links.
