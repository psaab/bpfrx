# AGY Adversarial Review: Operator-Visible WireGuard Telemetry (Issue #1865)

I have performed a hostile review of the telemetry implementation plan for GitHub issue #1865 against the active codebase in the `/home/ps/git/bpfrx/.claude/worktrees/1865-research` working tree.

---

### Verdict
**PLAN-NEEDS-MAJOR-REVISION**

**Justification:** While the proposed telemetry model and counter mapping are structurally sound, the plan contains a critical architectural gap in engine-reload reuse logic that would cause the control thread to run on stale TUN interfaces if logical interface assignments shift across a config commit. Additionally, the plan introduces a classic Go JSON serialization bug where a freshly-completed handshake age (`0` seconds) would be omitted from the status payload, along with an inefficient Prometheus modeling choice (age gauge rather than absolute epoch timestamp). These defects must be corrected in the plan before writing any code.

---

## Technical Findings & Concrete Evidence

### 1. The reload-reuse TOCTOU & stale TUN control thread race
* **Location:** [forwarding_build/wg.rs:87-94](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L87-L94)
* **Defect:** `wg_identity_unchanged` verifies listen ports, keys, endpoints, and allowed IPs, but it **fails to assert** that `prev.logical_ifindex == next.logical_ifindex`.
* **Impact:** In the event of a configuration change that renumbers logical interfaces but keeps the WireGuard identities identical, `populate_wg_engines` will reuse the `WgEngine` Arc verbatim. Consequently, `spawn_wg_control_threads` ([coordinator/mod.rs:477-484](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/mod.rs#L477-L484)) will see that the engine Arc pointer hasn't changed and will **not** stop or recreate the control thread. The active control thread will continue reading and writing from the old TUN device name (opened at start time via `open_tun` in [wg_control.rs:121](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L121)), bypassing the newly assigned logical interface.
* **Fix:** Update `wg_identity_unchanged` to check `prev.logical_ifindex == next.logical_ifindex`.

### 2. Go JSON `omitempty` zero-omission serialization hazard
* **Location:** [protocol.go:544-734](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/pkg/dataplane/userspace/protocol.go#L544-L734) and plan §3.2
* **Defect:** The plan specifies that `last_handshake_age_secs` is mapped as a flat `uint64` field with `omitempty` (or Rust `skip_serializing_if = "Option::is_none"`).
* **Impact:** In Go, `omitempty` omits the field if its value is the type's zero value (`0`). If a handshake is completed and its age is `0` seconds, Go's JSON encoder will omit `last_handshake_age_secs` entirely from the wire. The client (operator or monitoring script) will interpret the absence of the key as "never handshaked," completely masking a successful, newly established session.
* **Fix:** Define `last_handshake_age_secs` in Rust `ProcessStatus` as `Option<u64>` and in Go `ProcessStatus` as `*uint64` (a pointer). This ensures that `0` is serialized (pointer is non-nil) and only `nil` (representing "never") is omitted from the JSON payload.

### 3. Prometheus modeling anti-pattern (age gauge vs. epoch timestamp)
* **Location:** [metrics.go:263-265](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/pkg/api/metrics.go#L263-L265) and plan §3.4
* **Defect:** Exposing `xpf_userspace_wg_last_handshake_age_seconds` directly as a gauge.
* **Impact:** Gauges representing "age" or "time since" constantly change on every scrape, even if no new handshake event has occurred. This creates constant value churn, prevents Prometheus from compressing the time-series data efficiently, and introduces clock-skew/NTP dependencies during scrapes.
* **Fix:** Expose `xpf_userspace_wg_last_handshake_time_seconds` as a gauge containing the absolute epoch timestamp (in seconds) of the last completed handshake. Let PromQL compute the age on the dashboard side via `time() - xpf_userspace_wg_last_handshake_time_seconds`.

### 4. Hex vs. Base64 encoding inconsistency
* **Location:** [snapshot.rs:361-362](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/protocol/snapshot.rs#L361-L362) and plan §3.2
* **Defect:** The plan proposes that `WgTunnelStatus.peer_pubkey` is serialized as a base64 string on the wire by the Rust helper. However, the `base64` crate is not a dependency in `userspace-dp`'s [Cargo.toml](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/Cargo.toml), and all other public keys inside the Rust daemon (e.g. `wg_peer_pubkey_hex` in `TunnelEndpointSnapshot`) are kept as hex strings.
* **Impact:** Forcing the Rust helper to encode the public key in base64 would require adding the `base64` dependency to `userspace-dp`'s cargo manifest, creating minor dependency bloat.
* **Fix:** Serialize the key as a hex-encoded string on the wire from Rust (matching existing conventions), and let the Go side ([metrics_userspace.go](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/pkg/api/metrics_userspace.go)) convert it to base64 prior to exporting to Prometheus or rendering via the CLI.

---

## Response to Section 11 Reviewer Questions

1. **Path A vs. B vs. C:** 
   * **Recommendation:** **Path B (Path A + minimal CLI)**. The CLI status interface is the exact operational tool required to resolve the debugging visibility gap highlighted by the #1736 incident. 
   * **Disposition on C:** **Kill Path C**. Surprise-flood debugging should not rely on a formatting ring buffer that introduces heap allocations and lock contention on hot drop paths, violating the `Latency is sacred` first principle in [engineering-style.md:16](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/docs/engineering-style.md#L16).

2. **Keying (Per-tunnel name vs. endpoint ID):** 
   * **Agreement:** **Yes**. Using the interface name (`tunnel`) resolved via `ifindex_to_name` is robust against positional renumbering. However, this is only safe if `wg_identity_unchanged` is modified to include `logical_ifindex` checks as described in Finding 1.

3. **Counter inventory & unconfirmed-vs-no-session split:**
   * **Agreement:** **Yes**. Folding `encap_drops_other` is acceptable since those are unreachable anomalies. 
   * **Unconfirmed split:** Implementing the unconfirmed split as counter-only (incrementing `encap_drops_unconfirmed` internally inside `try_encap` while keeping the returned enum value as `EncapError::NoSession`) is correct. The caller's behavioral reaction (triggering a handshake) should be identical in both cases, so adding a new error variant would only add needless control-flow complexity.

4. **No-carry-across-rebuild counter semantics:**
   * **Agreement:** **Yes**. An identity change (key rotation, listen port change) represents a cryptographic epoch boundary. Resetting the counters to 0 here is clean and accurate. Prometheus's `rate()` handles monotonic resets naturally.

5. **Bytes semantics (Inner-IP vs. Wire-record):**
   * **Agreement:** **Inner-IP bytes**. Egress and ingress byte counts should be symmetric and directly comparable to traffic metrics observed at the logical interface boundary, rather than including varying encryption padding overhead.

---

### Summary of Completed Turn
I have read the research plan and the active Rust/Go codebase files under the `/home/ps/git/bpfrx/.claude/worktrees/1865-research` working tree. I verified all counter increment boundaries, checked for potential race conditions across reloads, analyzed the Go/Rust serialization structures, and evaluated the Prometheus modeling surfaces. I compiled these findings into a detailed review report and delivered the required verdict. As per the hostile plan review contract, I did not modify or create any files in the workspace.
