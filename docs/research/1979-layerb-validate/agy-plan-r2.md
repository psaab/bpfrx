# Verdict: PLAN-READY (with critical alignment notes)

The research plan in [plan.md](file:///home/ps/git/bpfrx/docs/research/1979-layerb-validate/plan.md) is technically sound, extremely thorough, and correctly integrates the feedback from previous rounds. The core logic of using a custom compiler pre-walk for Tier-3 TCP MSS validation is correct and handles a very real correctness trap. 

Below is the verification of your specific target points and findings:

---

### 1. Shorthand-Key Verification
* **Status:** **MINOR RISK OF IMPLEMENTOR ERROR**
* **Finding:** While §5 Tier-2 and §6 of [plan.md](file:///home/ps/git/bpfrx/docs/research/1979-layerb-validate/plan.md) correctly spell out the full timeout keys (`established-timeout`, `initial-timeout`, `closing-timeout`, and `time-wait-timeout`), §10 Recommendation still contains shorthand notation:
  > - `tcp-session`: type **all four** timeouts (`established`/`initial`/`closing`/`time-wait`) at `[0, MaxDurationSeconds]`
  
  Additionally, Table 4 (Item #3) uses the parenthetical `(+ initial/closing/time-wait — see §4a)`.
* **Impact:** An implementor scanning §10 or the Table in §4 might mistakenly declare schema keys like `established` or `initial` instead of the fully-suffixed compiler keys expected in [compiler_security.go](file:///home/ps/git/bpfrx/pkg/config/compiler_security.go#L589-L597).
* **Action:** Update §10 Recommendation and Table 4 to explicitly list the fully-spelled-out keys (`established-timeout`, `initial-timeout`, `closing-timeout`, `time-wait-timeout`) so there is absolutely zero ambiguity.

---

### 2. BPF `uint32` Truncation & Dead-Path Verification
* **Claim Verification (`SetFlowTimeout` is a no-op stub):** **CORRECT.** 
  In the active userspace dataplane startup path ([manager.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/manager.go#L562)), configuration is compiled via `CompileUserspaceShim`. This instantiates a `userspaceShimCompileDataplane` wrapper which implements [SetFlowTimeout](file:///home/ps/git/bpfrx/pkg/dataplane/loader.go#L391) as a literal no-op stub:
  ```go
  func (d userspaceShimCompileDataplane) SetFlowTimeout(uint32, uint32) error    { return nil }
  ```
  The legacy eBPF dataplane manager implementation of `SetFlowTimeout` (which writes to the `flow_timeouts` BPF map) is indeed part of the legacy backend currently being retired/removed in #1476.
* **Timeout Range (`[0, MaxDurationSeconds]` vs `[0, u32max]`):** **CORRECT.**
  The wire-reaching timeout fields (`tcp_session_timeout`, `udp_session_timeout`, and `icmp_session_timeout`) are deserialized on the Rust side ([snapshot.rs](file:///home/ps/git/bpfrx/userspace-dp/src/protocol/snapshot.rs#L151-L155)) as `u64` integers. 
  Because Rust's `SessionTimeouts::from_seconds` multiplies the value by `1e9` without checked arithmetic, values exceeding `MaxDurationSeconds` will cause overflow. Therefore, clamping them to `[0, MaxDurationSeconds]` is required to match the Layer A coercion bounds in `userspace/flow.go`.
* **Resolution (Accept Q8 Dead-Path Note):** **ACCEPTED.**
  The sibling timeouts (`initial-timeout`, `closing-timeout`, and `time-wait-timeout`) only exist in [TCPSessionConfig](file:///home/ps/git/bpfrx/pkg/config/types_security.go#L109-L117) and are never serialized or sent on the wire to the userspace dataplane. The `uint32` cast truncation in [compileFlowTimeouts](file:///home/ps/git/bpfrx/pkg/dataplane/compiler.go#L1006-L1012) only affects the retired eBPF map write. Thus, retaining the uniform `[0, MaxDurationSeconds]` bound for UX consistency across all `tcp-session` timeout keys is clean and risk-free.

---

### 3. Codex r1 MAJOR Folds Verification

* **Tier-3 compiler pre-walk vs SchemaValidate addition:** **SOUND.**
  Adding custom AST validation logic directly to [CompileConfig](file:///home/ps/git/bpfrx/pkg/config/compiler.go#L225) (using a new `validateTCPMSSRanges` helper) is the correct architectural pattern. Since the `tcp-mss` grammar leaves are opaque container nodes, the generic declarative `SchemaValidate` cannot walk them or validate their internal shape. 
  Leveraging the existing [validateVRRPTrackInterfaceAST](file:///home/ps/git/bpfrx/pkg/config/compiler_interfaces.go#L765-L783) pattern and supporting the `lenient` flag ensures that legacy configuration loading/HA-sync does not trigger hard errors that would prevent the node from booting.
* **Precedence of `parseMSSValue` validation:** **CORRECT.**
  In [compiler_interfaces.go](file:///home/ps/git/bpfrx/pkg/config/compiler_interfaces.go#L729-L744), the compiler selects the MSS value using the child `mss` node first, falling back to the flat key list. If the pre-walk validator checked both positions, valid configs like `gre-in 70000 { mss 1360 }` (where the compiler safely uses `1360` and discards `70000`) would be false-rejected. Reusing the selector logic guarantees that the validator only inspects what the compiler will actually apply.
* **Sampling rate bounds framing:** **ACCEPTABLE.**
  Since Layer A normalizes `InputRate <= 0` to `1`, establishing a `[0, u32max]` commit-check range matches the runtime parser behavior. Restricting the lower bound to `1` would introduce behavior drift by rejecting historical/valid configurations that set the input rate to `0`. Allowing the user to opt-in to this drift is the appropriate framing.


---
## Claude note
AGY r2 verdict: PLAN-READY. Independently verified the dead-path (CompileUserspaceShim
→ no-op SetFlowTimeout stub) and the u64 wire types requiring [0,MaxDurationSeconds];
accepted Q8. Its only finding (shorthand keys in §10 + Table 4) is folded — both now
spell out established-timeout/initial-timeout/closing-timeout/time-wait-timeout.
