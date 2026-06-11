I will start by listing files in `/home/ps/git/bpfrx/.claude/worktrees/1865-research` or searching for `plan.md` to see the structure of the repository and locate the plan.
I will read the design/plan file to understand the current v2 plan and the comments/verdicts.
I will read `userspace-dp/src/afxdp/coordinator/mod.rs` lines 540 to 620 to inspect the `attachment_changed` logic and verify the refutation of Finding 1.
I will search the repository to find where `wg_identity_unchanged` is defined.
I will view `userspace-dp/src/afxdp/forwarding_build/wg.rs` lines 40 to 110 to inspect `wg_identity_unchanged` and understand how the engine Arc is preserved/reused.
I will grep for `stop_remove_wg_control_entry` in the coordinator to see how control thread teardown works.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` from lines 630 to 680.
I will read the next lines of `spawn_one_wg_control_thread` to see how it obtains and records the spawned tunnel name and ifindex.
I will grep for `try_decap` to find the exact file and lines where it is defined.
I will view `userspace-dp/src/afxdp/wg/engine.rs` starting around line 820 to line 950 to see the existing structure of `try_decap`.
I will view lines 951 to 980 of `userspace-dp/src/afxdp/wg/engine.rs` to see the end of `try_decap`.
I will grep for `inner_src_ip` to inspect its behavior on empty/zero-length slices.
I will view `userspace-dp/src/afxdp/wg/engine.rs` lines 1080 to 1120.
I will search `wg_control.rs` for `try_decap` calls to understand the dispatch site.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` from lines 460 to 520 to see the call to `try_decap`.
I will view the caller of `handle_inbound_datagram` in `wg_control.rs`. Let's grep for `handle_inbound_datagram`.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` from lines 150 to 220 to see the inbound packet processing loop.
I will search for `enum DecapError` to see where it is defined and what uses it.
I will view lines 110 to 140 of `userspace-dp/src/afxdp/wg/engine.rs` to see `DecapError`.
I will view lines 141 to 150 of `userspace-dp/src/afxdp/wg/engine.rs`.
I will search for `monotonic_timestamp_to_datetime` to check its signature and implementation.
I will view `userspace-dp/src/afxdp/neighbor.rs` lines 1 to 40 to see `monotonic_timestamp_to_datetime`.
I will view the code in `userspace-dp/src/afxdp/coordinator/status.rs` around line 421 to see how `monotonic_timestamp_to_datetime` is used.
I will grep for `omitempty` in the Go directory `pkg` to see the serialization style used for fields in status or telemetry.
I will search for `protocol.go` in the codebase to see how it unmarshals status payloads.
I will search for `struct` in any files named `protocol.go` using a glob in the `Includes` parameter.
I will list the files in `/home/ps/git/bpfrx/.claude/worktrees/1865-research/pkg/dataplane/userspace` to find the exact filename.
I will grep for `type ProcessStatus` in `protocol.go` to find where the status structure is defined.
I will view `pkg/dataplane/userspace/protocol.go` from lines 540 to 600 to see how `ProcessStatus` is structured.
I will view lines 601 to 650 of `pkg/dataplane/userspace/protocol.go` to see the rest of the `ProcessStatus` struct fields.
I will search for `keepalive` in the Rust source files to see if sending keepalives is implemented or scheduled.
I will search for `keepalive` in the entire `userspace-dp` directory (case-insensitive).
I will search for `keepalive` in `userspace-dp/src/afxdp/wg/peer.rs`.
I will view `userspace-dp/src/afxdp/wg/peer.rs` lines 40 to 70 to read the comments about persistent keepalives.
I will grep for `wg_send_to` in `wg_control.rs`.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` lines 415 to 445 to see the `drive_initiation` logic and the error path for `wg_send_to`.
I will search for `fn create_initiation` in the codebase to see how it's defined and if it is engine-internal.
I will grep for `create_initiation` in `userspace-dp/src/afxdp/wg/` to see where the public API on `WgEngine` delegates.
I will view `userspace-dp/src/afxdp/wg/handshake_session.rs` lines 260 to 290 to see how `create_initiation` is structured.
I will search for MTU guards in `wg_control.rs` to see where they are situated.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` lines 525 to 555 to inspect the MTU guard.
I will grep for `frame/wg.rs` or search for the file location to view its MTU guard.
I will view `userspace-dp/src/afxdp/frame/wg.rs` lines 75 to 115.
I will view `userspace-dp/src/afxdp/frame/wg.rs` lines 40 to 74 to see how the engine and forwarding references are passed to `wg_encap_frame`.
I will search for `collectUserspaceStatus` in the codebase to understand where metrics emission is defined and how it accesses the userspace status.
I will view `pkg/api/metrics_userspace.go` lines 1 to 100 to see how status collection and metrics generation are handled.
I will search for `neighborWarmDropsTotal` in `pkg/api/metrics.go` to see the descriptor declaration format.
I will view `pkg/api/metrics.go` from lines 260 to 300 to see where descriptors are defined.
I will view `pkg/api/metrics.go` lines 450 to 510 to see the Prometheus constructor syntax.
I will search for `NewDesc` in `pkg/api/metrics.go` to find where the descriptors are constructed.
I will search for `func ` in `pkg/api/metrics.go` to find functions and locate the constructor.
I will search for `type xpfCollector struct` in `pkg/api/` to see where it is defined.
I will view `pkg/api/metrics.go` lines 14 to 100 to locate where collector descriptor fields are initialized.
I will search for the initialization of `xpfCollector` to see the constructor.
I will search for `&xpfCollector` in `pkg/api/` to find the instantiation code.
I will view `pkg/api/metrics_descriptors.go` lines 1 to 100 to see how the Prometheus descriptors are instantiated.
I will search for `protocol/tests.rs` or search for test files under `protocol` in `userspace-dp`.
I will search the repository to find the exact path for the wire protocol tests (`protocol/tests.rs`).
I will search for `protocol` in `userspace-dp/src` to find where the wire protocol is defined in Rust.
I will list the contents of the `userspace-dp/src/protocol` directory.
I will view `userspace-dp/src/protocol/tests.rs` lines 1050 to 1100.
I will view `userspace-dp/src/protocol/control.rs` around line 70 to see where `ProcessStatus` is defined.
I will view `userspace-dp/src/protocol/control.rs` lines 50 to 90 to see `ProcessStatus` in Rust.
I will search for `ProcessStatus` instantiation or usage in `userspace-dp/src` to find where the `ProcessStatus` struct-literal is constructed.
I will view `userspace-dp/src/server/lifecycle.rs` lines 65 to 95 to verify the `ProcessStatus` initialization.
I will view lines 96 to 120 of `userspace-dp/src/server/lifecycle.rs`.
I will view `userspace-dp/src/main_tests.rs` lines 640 to 650.
I will view lines 121 to 140 of `userspace-dp/src/server/lifecycle.rs` to see if there is any `..Default::default()` or if the initializer is completely explicit.
I will view lines 141 to 155 of `userspace-dp/src/server/lifecycle.rs`.
I will view lines 156 to 170 of `userspace-dp/src/server/lifecycle.rs`.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around lines 820 to 840 to verify the name fallback logic and check the formatting of `wg_tombstone_respawn_coherent`.
I will search for `wg_engines` in `status.rs` to see how it accesses engines to build status snapshots.
I will search for `forwarding` in `status.rs` to find where the status snapshot collects data from the datapath/forwarding state.
I will view `userspace-dp/src/afxdp/coordinator/status.rs` lines 250 to 300.
I will search for `fn status` in `status.rs` to locate the status snapshot method.
I will search for `ProcessStatus` in `status.rs` to find how the status struct is returned/populated.
I will list files in `userspace-dp/src/server` to see where runtime status snapshot generation is defined.
I will search for `ProcessStatus` in `server/helpers.rs` to see where the status is refreshed or populated.
I will grep for `refresh` or `fn ` in `server/helpers.rs` to find the status snapshot/refresh logic.
I will view `userspace-dp/src/server/helpers.rs` lines 16 to 100 to see the status refresh logic.
I will search for `struct ServerState` definition to see the type of `afxdp`.
I will view `userspace-dp/src/server/state.rs` lines 25 to 65.
I will search for `show security` command nodes in Go files to verify the command structure.
I will list the files in `pkg/cli` to check the file naming conventions for CLI commands.
I will search for `metrics_descriptor_coverage_test.go` to locate it and inspect the pedantic-registry canary tests.
I will search for `coverage` in Go files to locate the pedantic registry coverage test.
I will grep search for `Coverage` in the `pkg/api/` folder to locate the descriptor coverage test.
I will view `pkg/api/metrics_descriptor_coverage_test.go` lines 1 to 65.
I will view lines 66 to 120 of `pkg/api/metrics_descriptor_coverage_test.go` to see the structure of the fake ProcessStatus used for the coverage test.
I will search for the main `TestDescriptorCoverage` test in `metrics_descriptor_coverage_test.go`.
I will search for `func Test` in `metrics_descriptor_coverage_test.go` to find the test functions.
I will view `TestCollectorDescriptorCoverage` starting at line 344 to line 410.
I will search for the definition of `populatedCoverageStatus` in the test file.
I will view `populatedCoverageStatus` lines 145 to 220 in `metrics_descriptor_coverage_test.go`.
I will view lines 221 to 300 of `pkg/api/metrics_descriptor_coverage_test.go`.
# AGY Adversarial Re-Review Verdict: PLAN-READY

## 1. Finding 1 Verification & Withdrawal

Finding 1 (*stale-TUN via `wg_identity_unchanged` missing `logical_ifindex`*) is **withdrawn**. 

After tracing the coordinator's liveness check and config builder pathways, we verify that the refutation is correct. The stale-TUN cleanup is handled at the thread lifecycle layer rather than the crypto configuration layer, which is mathematically and architecturally correct under the `#1866` design.

### Proof & Evidence:
1. **Thread pruning on attachment changes:** 
   In [userspace-dp/src/afxdp/coordinator/mod.rs:570-587](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/mod.rs#L570-L587), the stale prune check evaluates interface renaming or index reassignment at status-refresh time:
   ```rust
   let attach_ok = self
       .forwarding
       .tunnel_endpoints
       .get(id)
       .is_some_and(|ep| {
           ep.logical_ifindex == entry.spawned_ifindex
               && self
                   .forwarding
                   .ifindex_to_name
                   .get(&ep.logical_ifindex)
                   .is_some_and(|name| *name == entry.spawned_tunnel_name)
       });
   if attach_ok {
       None
   } else {
       Some("attachment_changed")
   }
   ```
   If either index or interface name changes, the entry is pruned with `attachment_changed` and stopped/joined synchronously via `stop_remove_wg_control_entry` ([mod.rs:593-595](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/mod.rs#L593-L595)).

2. **Engine reuse on identical crypto identity:**
   In [userspace-dp/src/afxdp/forwarding_build/wg.rs:56-66](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L56-L66), config changes preserve the engine `Arc` when cryptographic parameters match:
   ```rust
   if wg_identity_unchanged(prev_endpoint, endpoint) {
       state.wg_engines.insert(id, prev_engine.clone());
       continue;
   }
   ```
   If `logical_ifindex` were added to `wg_identity_unchanged` ([wg.rs:87-94](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L87-L94)), any interface rename or recreate would rebuild the engine and terminate active transport sessions, violating the `#1866 D5` design contract.

Therefore, the separation of cryptographic identity stability and control thread attachment is correctly implemented. No stale-TUN window exists.

---

## 2. Re-Review of Plan v2 Deltas

### 2.1 Keepalive Classification (`decap_keepalives`)
* **Mechanism:** Zero-length transport records (`n == 0` after decrypt) bypass AllowedIPs checks and inner IP parsing (which would fail and throw `DecapError::MalformedInner` false alarms).
* **Datapath Safety:** The check is performed *after* the replay gate updates, so replay protection remains robust. It returns an `Err(DecapError::MalformedInner)` (or equivalent) to the caller, ensuring `dispatch_inbound` continues to evaluate `authenticated = false`.
* **Verdict:** Excellent. Surfacing keepalives via `decap_keepalives` while suppressing the `decap_drops_malformed_inner` counter increments eliminates scrape noise for persistent keepalive configurations without changing core datapath behavior.

### 2.2 Rename & Egress Handshake Instrumentation
* Rename of handshake building counters from `*_sent` to `*_created` is honest. 
* Capturing the `wg_send_to` error at [wg_control.rs:466](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L466) (previously discarded via `let _ =`) and logging build failures at [wg_control.rs:427](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L427) ensures that failures to send responder messages are visible as `hs_send_errors` and `hs_initiation_build_failures`.

### 2.3 `last_handshake_unix_secs` with `0-as-never`
* **Conflation Avoidance:** Using absolute epoch wall-clock seconds instead of relative age prevents Prometheus gauge churn. 
* **Go Serialization Interaction:** A u64 type in Go with `omitempty` will omit the value `0`. Since epoch 0 (1970) is not a valid handshake completion time, `0` serves as a perfect sentinel for "never". If a handshake was completed 0 seconds ago, it has a large current epoch value (e.g. `1781203040`), which is non-zero and serializes correctly.

### 2.4 Missing-Name Fallback
* Keying rows by tunnel name resolved via `ifindex_to_name` is robust against positional renumbering.
* The fallback path mirroring `wg_tombstone_respawn_coherent` (`linux_name` -> `interface` -> `wg-endpoint-<id>`) guarantees that status rows are never dropped during broken bring-up phases.

### 2.5 Runt Exclusion
* Verified that zero-length UDP packets hit `Ok(_) => break` at [wg_control.rs:197](file:///home/ps/git/bpfrx/.claude/worktrees/1865-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L197). This safely discards runts without running type dispatch, correctly preventing fake `rx_unknown_type` drop increments.

---

## 3. Answer to Round-2 Questions (Section 11)

1. **Objection to `last_handshake_unix_secs` with 0-as-never?**
   * **No.** It is a superior design compared to relative age gauges. It avoids scrape-churn, maps cleanly to Go's `omitempty` JSON tag, and prevents the "completed 0 seconds ago" vs. "never handshaked" conflation.

2. **Objection to keepalive counter classified inside `try_decap` with unchanged external behavior?**
   * **No.** Intercepting `n == 0` within `try_decap` to increment `decap_keepalives` while returning `Err` preserves the exact external signature needed by the integration layer (preventing unauthorized endpoint learning/roaming on raw keepalive packets) while correcting the telemetry statistics.

---

## 4. Conclusion

The v2 plan is logically sound, safe against datapath hot-path regressions, and fully resolves all feedback from Round 1. The implementation can proceed directly.
