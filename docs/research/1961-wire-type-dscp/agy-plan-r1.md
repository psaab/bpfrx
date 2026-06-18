# AGY Adversarial Plan Review

**Verdict:** **PLAN-READY** (with recommendation to collapse directly to `/engineer` implementation).

Below is the adversarial review of the proposed [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1961-research-wire-type/docs/research/1961-wire-type-dscp/plan.md) (branch `research/1961-wire-type-dscp`).

---

### 1. Root Cause Validation & Rust Serde Adapter Check

The hypothesis that the `virtio no transit` issue is caused by a JSON wire-type mismatch is **correct**. 
* **Go encoding:** In Go, the default JSON encoding for `[]byte` and `[]uint8` is a base64-encoded string (e.g., `"dscp_values":"Lg=="`).
* **Rust expectations:** Standard Rust Serde sequence types expect a JSON array/sequence of values (e.g. `[46]`) when deserializing into `Vec<u8>`.
* **Serde adapter check:** A grep search for `deserialize_with` or custom `Deserialize` traits in `userspace-dp` returned **0 results**. There is no base64 adapter logic or dependency configured on the Rust helper side.
* **Failure vector:** As shown in [mod.rs:L66-67](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/mod.rs#L66-L67):
  ```rust
  let request: ControlRequest =
      serde_json::from_str(line.trim_end()).map_err(|e| format!("decode request: {e}"))?;
  ```
  Since standard `serde` receives `"Lg=="` instead of a sequence, deserialization fails, throwing `invalid type: string "Lg==", expected a sequence`. This error is returned as `Err` from `handle_stream` and discarded at the accept loops in [lifecycle.rs:L220-221](file:///home/ps/git/bpfrx/userspace-dp/src/server/lifecycle.rs#L220-L221) and [lifecycle.rs:L239](file:///home/ps/git/bpfrx/userspace-dp/src/server/lifecycle.rs#L239):
  ```rust
  let _ = handle_stream(stream, &state_file, state.clone(), running.clone());
  ```
  The socket closes immediately with zero response bytes, which triggers the Go decoder EOF in [process.go:L208](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/process.go#L208).

### 2. Field Audit Completeness

A search for literal `[]` slices in [protocol.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol.go) and primitive numeric slice fields in the entire Go dataplane was conducted. The audit of 3 affected fields is **100% complete**:
1. `CoSDSCPClassifierEntrySnapshot.DSCPValues` in [protocol.go:L191-195](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol.go#L191-L195):
   ```go
   type CoSDSCPClassifierEntrySnapshot struct {
   	ForwardingClass string  `json:"forwarding_class,omitempty"`
   	LossPriority    string  `json:"loss_priority,omitempty"`
   	DSCPValues      []uint8 `json:"dscp_values,omitempty"`
   }
   ```
2. `CoSIEEE8021ClassifierEntrySnapshot.CodePoints` in [protocol.go:L202-206](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol.go#L202-L206):
   ```go
   type CoSIEEE8021ClassifierEntrySnapshot struct {
   	ForwardingClass string  `json:"forwarding_class,omitempty"`
   	LossPriority    string  `json:"loss_priority,omitempty"`
   	CodePoints      []uint8 `json:"code_points,omitempty"`
   }
   ```
3. `FirewallTermSnapshot.DSCPValues` in [protocol.go:L410-418](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol.go#L410-L418):
   ```go
   type FirewallTermSnapshot struct {
       ...
   	DSCPValues      []uint8  `json:"dscp_values,omitempty"`
   ```

No other `[]byte` or `[]uint8` fields exist on the control plane wire interface.

### 3. Q1: Treating Virtio Forwarding as "UNPROVEN"

Treating the virtio forwarding path as **UNPROVEN** is **correct and critical**. 
* **Reasoning:** Since `apply_snapshot` failed on bootstrap configurations containing classifiers/firewall filters, the helper has never transitioned to `enabled:true` or `forwarding_armed` on virtio VMs. Thus, the packet-loop binding and rx/tx logic have never successfully run on virtio.
* **Risk:** Virtio-net uses `XDP_COPY` mode (or auto-mode falling back to copy) where kernel NAPI drives packet delivery. We must prove via a live transit test that standard forwarding actually delivers packets on copy-mode virtio interfaces once armed, rather than silently failing due to driver/NAPI issues.

### 4. Fix Shape & Wire Compatibility

#### Fix Shape: **Option A (Named Custom Type) is Superior**
We strongly recommend implementing **Option A**:
```go
type DSCPValueList []uint8
```
* **Why Option A is better:** Go assignability rules permit direct assignment of unnamed slice types (such as `[]uint8` literals or return values from `append`) to a named type if their underlying types are identical. Consequently, changing the type in [protocol.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol.go) requires **zero code modifications** in assignment files such as [cos.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/cos.go) and [filters.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/filters.go).
* **Option B (`[]uint16`) Disadvantages:** Option B forces element-wise conversions across all Go builders and tests, and does not allow decoding base64-encoded strings if reading legacy state/configurations.

#### Wire Compatibility & HA Upgrade (#1917)
* **New Go $\rightarrow$ Old Rust:** Works. The old Rust helper already expects a sequence (`Vec<u8>`) on [security.rs:L104-105](file:///home/ps/git/bpfrx/userspace-dp/src/protocol/security.rs#L104-L105) and [cos.rs:L46-47](file:///home/ps/git/bpfrx/userspace-dp/src/protocol/cos.rs#L46-L47).
* **Old Go $\rightarrow$ New Rust:** Fails (helper rejects base64 string). However, this combination was already broken.
* **Defensive Unmarshaler:** Implementing custom `UnmarshalJSON` for the named type `DSCPValueList` in Go to tolerate both base64 strings (for backwards compatibility) and numeric arrays ensures any persisted state files (which store `ConfigSnapshot` via [helpers.rs:L847](file:///home/ps/git/bpfrx/userspace-dp/src/server/helpers.rs#L847)) can be loaded without issues.

### 5. Test Design Gaps

* **Gap:** The Go-side unit tests in [protocol_test.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/protocol_test.go) should explicitly assert both roundtrip directions:
  1. Marshaling a snapshot results in a numeric JSON array (`"dscp_values":[46]`) rather than a base64 string.
  2. Unmarshaling a legacy JSON payload containing a base64 string (`"dscp_values":"Lg=="`) succeeds and decodes to `[]uint8{46}`.
* **Rust integration test:** A test payload with inline JSON should be added to `userspace-dp` asserting that `ControlRequest` containing numeric lists for these fields parses correctly.

### 6. Actionable Error and Logging Hardening

1. **Q3 (Rust Logging):** The accept loop must print or log errors from `handle_stream` rather than discarding them:
   ```rust
   if let Err(err) = handle_stream(stream, &state_file, state.clone(), running.clone()) {
       eprintln!("xpf-userspace-dp: handle stream error: {err}");
   }
   ```
2. **Q4 (Go Client Error):** When Go processes a socket disconnect (`io.EOF`) without receiving response bytes, it should enrich the error message:
   ```go
   if errors.Is(err, io.EOF) {
       return ControlResponse{}, fmt.Errorf("control socket closed without response (EOF); check helper logs for panics or deserialization errors: %w", err)
   }
   ```

### 7. Verdict & Path Selection (Q8)

* **Verdict:** **PLAN-READY**
* **Recommendation:** Skip the rest of `/research` and collapse the work into `/engineer`. The root cause is completely verified, the implementation details are mechanical, and the live transit test can be incorporated as the final validation step of the engineering PR.
