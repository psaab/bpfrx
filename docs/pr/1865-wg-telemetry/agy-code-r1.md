I will begin by listing the current permissions to see what actions and directories I have access to.
I will request read permissions for the target worktree directory so that I can view files directly.
I will run a command to inspect the git log of the target range in the worktree to understand the six commits.
I will read the plan file at `docs/pr/1865-wg-telemetry/plan.md` to understand the expected behavior and counters inventory.
I will run a command to list the files changed in the commits of interest.
I will run a command to count the lines in the git diff to understand its size.
I will view `userspace-dp/src/afxdp/wg/counters.rs` to inspect the counter definitions and helpers.
I will run a command to view the diff for `userspace-dp/src/afxdp/wg/engine.rs`.
I will search for `try_encap` in the engine file to get its exact line range.
I will view lines 690 to 860 of `userspace-dp/src/afxdp/wg/engine.rs` to review the full `try_encap` body.
I will view lines 851 to 1050 of `userspace-dp/src/afxdp/wg/engine.rs` to review the full `try_decap` function body.
I will run a command to view the git diff for `userspace-dp/src/afxdp/wg/handshake_session.rs`.
I will run a command to view the git diff for `userspace-dp/src/afxdp/coordinator/wg_control.rs`.
I will search for `hs_requests_armed` in the codebase to find where it is incremented and ensure it matches the plan inventory.
I will view `userspace-dp/src/afxdp/wg/engine.rs` around line 402 to inspect the `hs_requests_armed` increment site.
I will search for `encap_mtu_drops` in the codebase to find both of its increment sites.
I will view lines 75 to 105 of `userspace-dp/src/afxdp/frame/wg.rs` to review the transit MTU guard counter increment.
I will view lines 106 to 140 of `userspace-dp/src/afxdp/frame/wg.rs` to see what happens on the success path of transit encap.
I will run a command to view the git diff for `userspace-dp/src/afxdp/coordinator/status.rs`.
I will grep search for `linux_name` in coordinator files to see the row-label fallback convention mentioned in the plan.
I will view lines 820 to 835 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see how the fallback label is constructed there.
I will search for the definition of the `TunnelEndpoint` struct to see what fields are available on it.
I will search for `struct TunnelEndpoint` in the Rust files.
I will view `userspace-dp/src/afxdp/types/forwarding.rs` around line 166 to see the fields of `TunnelEndpoint`.
I will search for `ifindex_to_name` to see how it is populated and if it reflects the `linux_name` else `interface` convention.
I will view lines 680 to 695 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see how `ifindex_to_name` is populated.
I will search for insertions or mutations of `ifindex_to_name` in the coordinator module to understand how the map gets its values.
I will search for `ifindex_to_name` across all Rust source files to see where it gets populated or updated.
I will view lines 35 to 60 of `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` to see how `ifindex_to_name` is populated.
I will view `userspace-dp/src/protocol/control.rs` around the definition of `WgTunnelStatus`.
I will search for `WgTunnelStatus` in `userspace-dp/src/protocol/control.rs` to see its definition.
I will view lines 300 to 335 of `userspace-dp/src/protocol/control.rs` to inspect the `wg_tunnels` field on `ProcessStatus`.
I will view lines 445 to 580 of `userspace-dp/src/protocol/control.rs` to review the fields of `WgTunnelStatus`.
I will search for the struct definition in the Go protocol file to compare it with the Rust counterpart.
I will view lines 720 to 815 of `pkg/dataplane/userspace/protocol.go` to inspect the Go struct definition.
I will view lines 60 to 90 of `userspace-dp/src/server/lifecycle.rs` to verify that the new field is properly initialized in the `ProcessStatus` initializer.
I will view lines 90 to 130 of `userspace-dp/src/server/lifecycle.rs` to see the complete initialization of `ProcessStatus`.
I will view lines 130 to 160 of `userspace-dp/src/server/lifecycle.rs` to see if the new fields are properly initialized.
I will run a command to view the git diff for `userspace-dp/src/server/helpers.rs`.
I will run a command to view the git diff for `pkg/api/metrics.go`.
I will run a command to view the git diff for `pkg/api/metrics_descriptors.go`.
I will run a command to view the git diff for `pkg/api/metrics_userspace.go`.
I will run a command to view the git diff for `pkg/api/metrics_descriptor_coverage_test.go`.
I will search for `func TestCollectorDescriptorCoverage` to locate and examine the coverage test code.
I will view lines 364 to 520 of `pkg/api/metrics_descriptor_coverage_test.go` to inspect the coverage test logic.
I will run a command to view `pkg/api/metrics_wireguard_test.go`.
I will run a command to view the git diff for `pkg/cmdtree/tree.go`.
I will run a command to view the git diff for `cmd/cli/show.go`.
I will view lines 390 to 430 of `cmd/cli/show.go` to see how other subcommands of `show security` are dispatched and if prefix resolution is handled.
I will view `pkg/cli/cli_show_security_dispatch.go` to see how subcommands are dispatched or matched.
I will view `pkg/cli/cli_show_security_wireguard.go` to inspect the local CLI formatting, timestamp logic, and edge cases.
I will view `pkg/dataplane/userspace/wgfmt.go` to inspect the formatting logic.
I will run a command to view the git diff for `pkg/grpcapi/server_show.go`.
I will run a command to view the git diff for `pkg/grpcapi/server_show_security_text.go`.
I will run a command to view the git diff for `pkg/dataplane/userspace/wg_status_test.go`.
I will search for the matching Rust-side wire pin in `protocol/tests.rs` to verify compatibility.
I will view lines 1410 to 1500 of `userspace-dp/src/protocol/tests.rs` to review the Rust-side wire-pin compatibility test.
I will run a command to view the git diff for `userspace-dp/src/afxdp/wg/tests.rs`.
I will run a command to view the diff for the docs files.
I will run a command to view the diff for these CLI/formatter tests.
I will run a command to view the git diff for `userspace-dp/src/afxdp/wg/mod.rs`.
I will run a command to view the git diff for `_Log.md`.
I will view the git log in detail to see all commits.
I will check the files in `docs/pr/1865-wg-telemetry/` to see if there is any other review log or files we should be aware of.
I will read `docs/pr/1865-wg-telemetry/claude-smr-code-r1.md` to see what findings were reported in the SMR r1 review.
I will run the Rust tests in the userspace-dp crate to confirm they all compile and pass successfully.
I will run the Go tests for the modified packages in the worktree.
I will run the WG and protocol unit tests specifically to verify that all tests in the telemetry and protocol submodules pass.
I will run the Rust WG unit tests specifically.
I will run the Rust protocol unit tests specifically.
# Code Review Verdict: MERGE-READY

After performing a rigorous, hostile, line-by-line audit of the implementation branch `engineer/1865-wg-telemetry` against the converged design plan in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/docs/pr/1865-wg-telemetry/plan.md), I have found **zero** logical, safety, wire, performance, or semantic defects. The test suites compile and pass successfully, and the telemetry surface maps exactly to the expected specifications.

Below is the detailed review report organized by the seven items on the hostile hunt list.

---

### 1. Counter Inventory and Increment Verification

Every single counter is accounted for, maps exactly to the design inventory, and covers all return paths with no double-counting.

*   **Encap Paths (`try_encap` in [engine.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs)):**
    *   **`EncapError::UnknownPeer`** is mapped to `encap_drops_other` via the `count_encap_err` helper at [engine.rs:720](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L720).
    *   **`EncapError::NoSession` (no current session)** increments `encap_drops_no_session` inline at [engine.rs:725](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L725) and returns early.
    *   **`EncapError::NoSession` (unconfirmed session)** increments `encap_drops_unconfirmed` inline at [engine.rs:742](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L742) and returns early.
        *   *Audit:* This preserves the wire error code `NoSession` while successfully creating a counter-only split to isolate the transient responder confirmation window.
    *   **`EncapError::BufferTooSmall`** (stack bounds checks and header serialization check) is mapped via the helper to `encap_drops_other` at [engine.rs:764](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L764), [engine.rs:767](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L767), and [engine.rs:773](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L773).
    *   **`EncapError::RekeyRequired`** is mapped via the helper to `encap_drops_rekey_required` at [engine.rs:771](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L771).
    *   **`EncapError::CryptoFailed`** is mapped via the helper to `encap_drops_other` at [engine.rs:837](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L837).
    *   **Success Path** bumps `encap_packets` and adds unpadded bytes to `encap_bytes` at [engine.rs:840-843](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L840-L843).
*   **Decap Paths (`try_decap` in [engine.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs)):**
    *   Structural header parse failures are mapped to `decap_drops_malformed_header` at [engine.rs:863](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L863).
    *   Counter limits (`REJECT_AFTER_MESSAGES`) map to `decap_drops_counter_ceiling` at [engine.rs:870-872](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L870-L872).
    *   Session lookups map to `decap_drops_unknown_session` at [engine.rs:880](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L880).
    *   Truncated packets (`ShortRecord`) map to `decap_drops_malformed_header` at [engine.rs:896](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L896).
    *   Scratch size constraints map to `decap_drops_buffer` at [engine.rs:900](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L900).
    *   Initial replay window checks map to `decap_drops_replay` at [engine.rs:905](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L905).
    *   AEAD failures (`CryptoFailed`) map to `decap_drops_crypto` at [engine.rs:911](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L911).
    *   Replay state machine updates (`Repeat` / `OutOfWindow`) map to `decap_drops_replay` at [engine.rs:938](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L938) and [engine.rs:942](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L942).
    *   **Keepalive check (`n == 0`)** bumps `decap_keepalives` inline and returns `MalformedInner` directly at [engine.rs:959-960](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L959-L960). It bypasses the mapper so that keepalives never register as drops.
    *   **Inner Policy Closure Errors** are mapped uniformly in the `Err(e)` branch via the `count_decap_err` helper at [engine.rs:1021](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L1021) (which handles `AllowedIpsViolation`, `MalformedInner`, and `UnknownSession`).
    *   **Success Path** bumps `decap_packets` and increments `decap_bytes` at [engine.rs:1007-1010](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L1007-L1010).
*   **Handshake Wrappers (`consume_*` / `create_*` in [handshake_session.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs)):**
    *   `create_initiation` bumps `hs_initiations_created` on Ok and `hs_initiation_build_failures` on Err at [handshake_session.rs:556-560](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs#L556-L560).
    *   `consume_response` bumps `hs_completions_initiator` and stamps the handshake completion on Ok at [handshake_session.rs:570-572](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs#L570-L572). Errors are mapped to `hs_rx_drops_*` at [handshake_session.rs:575](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs#L575).
    *   `consume_initiation_create_response` bumps `hs_responses_created` and stamps the handshake completion on Ok at [handshake_session.rs:596-598](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs#L596-L598). Errors are mapped to `hs_rx_drops_*` at [handshake_session.rs:601](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/handshake_session.rs#L601).
        *   *Audit:* The single `hs_responses_created` increment site acts as the responder-side completion event (no double-counting).
*   **Call Sites:**
    *   `tun_rx_drops_no_endpoint` is correctly bumped when draining TUN frames off an unconfigured responder in [wg_control.rs:251](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L251).
    *   `hs_send_errors` is incremented for both initiation and response socket send errors in [wg_control.rs:436](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L436) and [wg_control.rs:481](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L481).
    *   `hs_rx_cookie_unsupported` is incremented on type-3 cookie packets in [wg_control.rs:505](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L505).
    *   `tun_write_errors` is incremented when packet delivery to the TUN fails in [wg_control.rs:517](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L517).
    *   `rx_unknown_type` is incremented when the type byte is invalid in [wg_control.rs:536](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L536).
        *   *Audit:* Zero-length UDP packets are consumed by the `Ok(_) => break` recv arm at [wg_control.rs:197](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L197) prior to type dispatch, so they are cleanly excluded from `rx_unknown_type`.
    *   `encap_mtu_drops` is incremented at both MTU guards:
        *   Control egress guard at [wg_control.rs:572](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L572).
        *   Transit egress guard at [wg.rs:89](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/frame/wg.rs#L89).
    *   `transport_send_errors` is incremented on transport send errors in [wg_control.rs:581](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/wg_control.rs#L581).

---

### 2. Keepalive Classification Placement and Parity

The persistent keepalive check (`n == 0`) is correctly classified at [engine.rs:958-961](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L958-L960):
*   It sits **after** `session.mark_confirmed()` at [engine.rs:920](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L920) and the replay window check `check_and_update` at [engine.rs:928](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L928).
*   It sits **before** AllowedIPs lookup and inner IP parsing at [engine.rs:983](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L983).
*   **Parity Proof:** Under both pre- and post-PR code, a zero-length transport record returns `Err(DecapError::MalformedInner)`.
*   **Out-Buffer Wipe Contract:** In the original code, the error resulted in taking the `Err(e)` branch of the inner closure, executing `out[..0].fill(0)` (a no-op since length is zero). The new code returns `Err(DecapError::MalformedInner)` immediately without calling `out[..0].fill(0)`, maintaining identical behavior with zero leakage risk.

---

### 3. Wire Format Compatibility

*   **Empty-Vec Skip Invariant:** In [control.rs:320](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/protocol/control.rs#L320), the `wg_tunnels` field is decorated with `#[serde(rename = "wg_tunnels", default, skip_serializing_if = "Vec::is_empty")]`. On the Go side in [protocol.go:739](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/dataplane/userspace/protocol.go#L739), it is mirrored as `json:"wg_tunnels,omitempty"`. When no WG tunnels are configured, the key is omitted entirely, guaranteeing that non-WG wire structures remain byte-identical.
*   **Tag Matching:** All 35 counters and 6 state fields match character-for-character between Rust serde renames and Go tags. This is fully validated by `TestProcessStatusWgTunnelsPopulatedDecode` in [wg_status_test.go:20](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/dataplane/userspace/wg_status_test.go#L20) and `process_status_wg_tunnels_roundtrip_and_compat` in [tests.rs:1418](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/protocol/tests.rs#L1418) using a matching 1..35 value ladder.
*   **Lifecycle Initializer:** In [lifecycle.rs:141](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/server/lifecycle.rs#L141), `wg_tunnels` is correctly initialized as `Vec::new()`.

---

### 4. Coordinator Status Mapping and Fallback

*   **Stamp-0 Guard:** The wall-clock conversion in [status.rs:670-676](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/status.rs#L670-L676) checks `if stamp == 0 { 0 }`. Monotonic-to-wall conversion does not run on stamp 0, preventing boot-relative timestamp leakage.
*   **Pre-Epoch Clamp:** The conversion maps negative timestamps to 0 via `.map(|dt| dt.timestamp().max(0) as u64)` at [status.rs:674](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/status.rs#L674), avoiding underflow and wrapped values.
*   **Ordering / Cardinality:** Rows are sorted by tunnel ID for deterministic serialization at [status.rs:643](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/status.rs#L643).
*   **Fallback Name:** Missing names are safely mapped to `wg-endpoint-{id}` at [status.rs:666](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/coordinator/status.rs#L666), ensuring rows are never silently discarded.

---

### 5. Prometheus Modeling and Descriptor Coverage

*   **Label Sets:** All metrics are properly collapsed under the `{tunnel}` label plus appropriate `{role}`, `{direction}`, `{reason}`, and `{kind}` enums.
*   **Never-Handshaked Gauge Gating:** The collector only emits the `xpf_userspace_wg_last_handshake_time_seconds` gauge if `t.LastHandshakeUnixSecs > 0` at [metrics_userspace.go:139-147](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/api/metrics_userspace.go#L139-L147), preventing display churn of epoch 0.
*   **Descriptor Coverage:** Verified via `TestEmitWireguardTelemetryNeverHandshakedGauge` in [metrics_wireguard_test.go:189](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/api/metrics_wireguard_test.go#L189) and registration in `TestCollectorDescriptorCoverage` in [metrics_descriptor_coverage_test.go:491](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/api/metrics_descriptor_coverage_test.go#L491).

---

### 6. CLI Dispatch and Presenter Formatting

*   **Prefix Resolution:** Handled correctly via the `resolveCommand` lookup at [cli_show_security_dispatch.go:100](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/cli/cli_show_security_dispatch.go#L100).
*   **Nil-Config Allowlist:** `wireguard` is added to the `cfg == nil` allowlist at [cli_show_security_dispatch.go:107](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/cli/cli_show_security_dispatch.go#L107), allowing tunnel diagnostics to be queried on a broken/unconfigured node.
*   **Remote Topic Mapping:** Mapped to `"wireguard"` and `"wireguard-detail"` topics at [server_show.go:412-417](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/grpcapi/server_show.go#L412-L417).
*   **Formatter Edge Cases:**
    *   Empty endpoint string prints `(responder-only; learned at runtime)` at [wgfmt.go:35-37](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/dataplane/userspace/wgfmt.go#L35-L37).
    *   Future timestamps are clamped to `0 seconds ago` at [wgfmt.go:139-141](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/pkg/dataplane/userspace/wgfmt.go#L139-L141).

---

### 7. Hot-Path Performance

*   **Zero Non-WG Traffic Cost:** Gated behind the existing `tunnel_endpoint_id != 0` check in transit forwarding. Non-WG traffic is completely unaffected.
*   **Zero New Allocations:** Telemetry counts use `AtomicU64` increments (`Ordering::Relaxed`). `try_encap` leverages stack-allocated `MaybeUninit` structures at [engine.rs:792](file:///home/ps/git/bpfrx/.claude/worktrees/1865-engineer-wg/userspace-dp/src/afxdp/wg/engine.rs#L792) to avoid heap allocation. No new heap allocations are introduced.

---

### Summary of Verification Output

All tests passed successfully on the worktree.
*   **Rust tests:** 128 `afxdp::wg` unit tests and 41 `protocol` tests pass successfully.
*   **Go tests:** `pkg/dataplane/userspace`, `pkg/api`, and `pkg/grpcapi` pass successfully (including the cross-language wire pins and Prometheus emitters).
