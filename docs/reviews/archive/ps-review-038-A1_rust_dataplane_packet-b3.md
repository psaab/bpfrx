# paladin-038 A1_rust_dataplane_packet — batch 3/3 (b3)

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A1_rust_dataplane_packet
Batch file list (40 files):
- userspace-dp/src/fairness_eval/args.rs
- userspace-dp/src/fairness_eval/inputs.rs
- userspace-dp/src/fairness_eval/mod.rs
- userspace-dp/src/fairness_eval/per_worker.rs
- userspace-dp/src/fairness_eval/report.rs
- userspace-dp/src/fairness_eval/rss.rs
- userspace-dp/src/fairness_eval/verdict.rs
- userspace-dp/src/fairness_eval/windowing.rs
- userspace-dp/src/hot_hash_seed.rs
- userspace-dp/src/hot_hash_seed_tests.rs
- userspace-dp/src/io_uring_write.rs
- userspace-dp/src/ip_proto.rs
- userspace-dp/src/main_tests.rs
- userspace-dp/src/prefix.rs
- userspace-dp/src/prefix_set.rs
- userspace-dp/src/prefix_set_tests.rs
- userspace-dp/src/server/handlers/binding.rs
- userspace-dp/src/server/handlers/export.rs
- userspace-dp/src/server/handlers/forwarding.rs
- userspace-dp/src/server/handlers/ha.rs
- userspace-dp/src/server/handlers/inject_packet.rs
- userspace-dp/src/server/handlers/mod.rs
- userspace-dp/src/server/handlers/neighbors.rs
- userspace-dp/src/server/handlers/queue.rs
- userspace-dp/src/server/handlers/rebind.rs
- userspace-dp/src/server/handlers/session_deltas.rs
- userspace-dp/src/server/handlers/snapshot.rs
- userspace-dp/src/server/handlers/stop_workers.rs
- userspace-dp/src/server/handlers/sync_session.rs
- userspace-dp/src/server/helpers.rs
- userspace-dp/src/server/lifecycle.rs
- userspace-dp/src/server/mod.rs
- userspace-dp/src/server/state.rs
- userspace-dp/src/server/tests.rs
- userspace-dp/src/slowpath.rs
- userspace-dp/src/state_writer.rs
- userspace-dp/src/tcp_flags.rs
- userspace-dp/src/tcp_flags_tests.rs
- userspace-dp/src/test_zone_ids.rs
- userspace-dp/src/xsk_ffi.rs

---

## Module-by-module log

### userspace-dp/src/fairness_eval/args.rs
Checked CLI parsing for integer truncation, silent fallbacks, validation of n_workers/cos_ifindex/cos_queue_id/shaper_rate. Found silent `unwrap_or(default)` fallback on 4 flags (see Finding 1). No direct dataplane policy bypass.

### userspace-dp/src/fairness_eval/inputs.rs
Checked TSV parsers for silent drops, injection, resource exhaustion. Found silent `continue` on malformed rows (Finding 2). No integer truncation beyond safe u64/u32 parse.

### userspace-dp/src/fairness_eval/mod.rs
Checked per-flow quantiles, steady-state windowing anchoring, CoV computation, distribution aggregation. Logic matches docs/fairness-regimes.md required metrics (V-5/V-6/V-9). No truncation, no unsafe.

### userspace-dp/src/fairness_eval/per_worker.rs
Checked iface filtering, legacy 3-col fallback, zero-fill dead workers, steady_window_bounds fallback, guard_sum_tolerances, trim_distribution. All paths reviewed. No new issue. Negative result: `aggregate_per_worker` correctly fails on out-of-range worker_id, `steady_window_bounds` correctly handles empty input with degenerate (warmup,0) window, median_per_worker_zero_fills absent workers.

### userspace-dp/src/fairness_eval/report.rs
Checked per_flow_quantiles_mbps nearest-rank, steady_state_window, saturation_series, Report serialization. No integer truncation (f64 conversion safe). Negative result: quantile pick uses safe ceil/min, empty case returns zeros.

### userspace-dp/src/fairness_eval/rss.rs
Checked RSS expectation parsing, balanced check, max share, cstruct_max. All parse paths validate range via parse_fraction_or_percent / parse_nonnegative_number_or_percent. Negative result: no truncation, no fail-open.

### userspace-dp/src/fairness_eval/verdict.rs
Checked overcount trim fail-closed gate, Gate1/2/3, harness guard, direction_multiplier, cstruct_raw vs trimmed. Verified fix for V-4 (trim never loosens Gate2) is present and tested. Division by zero guarded by `n_total_workers>0`. Negative result: no new bug.

### userspace-dp/src/fairness_eval/windowing.rs
Checked extract_window warmup/final_burst validation, omitted interval filtering, observed bucket count vs declared duration, per-stream seeding from connected[]. Verified V-7 truncated-run rejection, Min 60s steady state + 5s slack. Negative result: no truncation, no overflow.

### userspace-dp/src/hot_hash_seed.rs
Checked getrandom retry/EINTR handling, fallback entropy (CLOCK_MONOTONIC+pid+stack addr), never-zero invariant, OnceLock single-init, unsafe getrandom/clock_gettime usage. All unsafe blocks bounded and correct length calculations. Negative result: no memory safety issue, no seed reuse across fork, no truncation.

### userspace-dp/src/hot_hash_seed_tests.rs
Checked deterministic tests for never-zero and well-mixed. Negative result: tests cover load-bearing invariants.

### userspace-dp/src/io_uring_write.rs
Checked write_all tag handling (never zero, wrapping_add), reap_matching stale CQE drain, EINTR retry vs permanent error fast-fail (#2478), packet vs positioned short-write handling, zero-result handling. All paths reviewed, fake tests cover V-4/V-7 regressions. Negative result: no truncation, no UAF, wrap handling correct.

### userspace-dp/src/ip_proto.rs
Checked IANA constants, has_l4_ports (TCP|UDP only, SCTP excluded intentionally), proto_number normalization (trim+lowercase, junos-* aliases, numeric fallback). Negative result: constants match registry, no truncation (u8).

### userspace-dp/src/main_tests.rs
Checked same_binding_plan, queue_planner, plan_key invariants, VLAN dedup, orphan VLAN re-key, non-data filtering. These are test files, not dataplane. Negative result: tests exercise #2915/#2916/#3007/#3091/#3175 invariants, no production code.

### userspace-dp/src/prefix.rs
Checked PrefixV4/V6 from_net (network & mask), contains, directed_broadcast, mask_v4/mask_v6 shift safety. Verified shift-by-32 avoided via prefix_len==0 guard, remaining shift safe because ipnet guarantees prefix_len <=32/128. Negative result: no truncation, no panic on valid input.

### userspace-dp/src/prefix_set.rs
Checked from_prefixes/from_v3_literals MatchAny/MatchNone collapse, Linear vs Trie threshold, Trie insert/contains walk (MSB-first, covers short-circuit), /0 filtering, duplicate handling. Negative result: Trie walk 0..32/0..128 safe, prefix_len as usize safe (0..128).

### userspace-dp/src/prefix_set_tests.rs
Checked LCG deterministic random tests, linear vs trie equivalence, nested prefix short-circuit, zero prefix handling, duplicate dedup. Negative result: coverage adequate.

### userspace-dp/src/server/handlers/binding.rs
Checked set_binding_state missing payload, unknown slot, registration_changed -> reconcile, wait_for_binding_settle. Mirrors pre-split logic. Negative result: no truncation, no resource leak, error paths set ok=false.

### userspace-dp/src/server/handlers/export.rs
Checked owner_rg_kick lock-free split (#2962) and all_kick/all_push split (#4054). Verified max as usize widening safe, error handling returns None on snapshot_all_sessions_export failure. Negative result: no blocking under lock, no truncation.

### userspace-dp/src/server/handlers/forwarding.rs
Checked set_forwarding_state armed vs capabilities, forwarding_unsupported_error, reconcile_status_bindings discard, wait_for_binding_settle. Negative result: no truncation.

### userspace-dp/src/server/handlers/ha.rs
Checked update_ha_state missing payload, clone groups, update_ha_state propagation, refresh_status, persist_state. Negative result: no truncation (groups Vec<HAGroupStatus>), no fail-open.

### userspace-dp/src/server/handlers/inject_packet.rs
Checked missing packet request, inject_test_packet error propagation. Negative result: trivial handler, no integer cast.

### userspace-dp/src/server/handlers/mod.rs
Checked control request size cap (#2523/#2744), take(MAX+1) bounding, newline-terminated largest legitimate request acceptance, oversize rejection, decode, two-phase export_wait/all_export off-lock wait, status attach deferral, write_state gating, suppress_status. Verified fail-closed on oversize, no allocation unbounded. Negative result: no truncation, correct lock handling.

### userspace-dp/src/server/handlers/neighbors.rs
Checked neighbor filtering (ifindex<=0 skip, ip parse, mac parse, state usable), apply_manager_neighbors replace flag, refresh_status. Negative result: no truncation, no injection.

### userspace-dp/src/server/handlers/queue.rs
Checked set_queue_state missing payload, unknown queue, registration_changed detection, per-binding update, reconcile, wait. Negative result: no truncation.

### userspace-dp/src/server/handlers/rebind.rs
Checked rebind must NOT call afxdp.stop() (preserves synced sessions, #1921), clearing bound/xsk_registered/zero_copy/socket_fd/ready/last_error, reconcile_status_bindings discard. Negative result: matches documented invariant, test in server/tests.rs pins it.

### userspace-dp/src/server/handlers/session_deltas.rs
Checked drain max default 256, .max(1) as usize safe, drain_session_deltas, refresh_status, persist. Negative result: no truncation issue (u32->usize widening).

### userspace-dp/src/server/handlers/snapshot.rs
Checked apply preflight policy validation (#1606), scratch counter store, zone_name_to_id_from_snapshot (#3402), prev_*_generation save/restore (#3766), same_plan detection via sha256 key, needs_reconcile gating, refresh_runtime_snapshot vs refresh_runtime_snapshot_disarmed, failure restore, defer_workers prune, replan_queues, reconcile error handling (#3789), version gate, fib_generation rollback guard (#3767). Negative result: no truncation, fail-closed on integrity errors.

### userspace-dp/src/server/handlers/stop_workers.rs
Checked stop_workers clears bound/xsk_registered/xsk_bind_mode/zero_copy/socket_fd/ready/last_error. Negative result: matches expected teardown.

### userspace-dp/src/server/handlers/sync_session.rs
Checked upsert/delete dispatch, build_synced_session_entry/key, zone fallback, parse errors. Negative result: no truncation beyond safe serde u16/u8.

### userspace-dp/src/server/helpers.rs
Checked refresh_status aggregation (coalesced counters, neighbor telemetry, WG tunnels, per_binding, flow_cache_capacity, cos, policy/nat/filter counters, event_stream stats, fabric_link_skipped), forwarding_unsupported_error, build_synced_session_key/entry (ip parse, mac parse, tx_ifindex max(0) logic, nat src/dst, zone_id prefer, log flags, policy_id/counter/timeout, generation), parse_session_sync_mac (6 octets, hex), reconcile_status_bindings (should_run_afxdp early return via refresh_bindings zero_unbound_slot #2794), should_run_afxdp, same_plan_apply_needs_binding_reconcile, set_bindings_forwarding_armed, wait_for_binding_settle, bindings_settled, snapshot_binding_plan_key (workers, ring_entries, shared_umem canonical sort, iface vlan/parent, fabric rx_queues via effective_rx_queues, orphan VLAN parent rx_queue_count), include_userspace_binding_interface, vlan_child_parent_netdev, snapshot_has_parent_candidate, plan_key_rx_queues, replan_queues (dedup VLAN child onto parent, orphan re-key, seen_linux, effective_rx_queues, fabric inclusion), replan_bindings_from_candidates (queue_count min, slot assignment, worker_id = queue_id % workers), summarize_queues, linux_ifname, effective_rx_queues, rx_queue_count sysfs with thread-local override, write_state via StateWriter persist. Verified truncation fixes (#2410) are not in this file but via validated.rs; serde u16 overflow fails closed (not silent). Integer handling reviewed: no remaining as u16 truncation on config. One historical pattern noted (`tx_ifindex.max(0)` preserves non-negative but discards negative - intentional for tunnel case).

### userspace-dp/src/server/lifecycle.rs
Checked SOCKBUF_TARGET 64MiB raise-only (#2970), remove_stale_socket fail-closed on non-socket (#2974, symlink not followed), run sysctl raising, busy_poll sysctls, control/session socket bind, listener nonblocking, state init, event_stream start, ctrlc handler, session_thread concurrent accept, status write, thread join, remove_kernel_rst_suppression, cleanup, derive_session_socket_path/event_socket_path, validate_ring_entries_arg power-of-two range check, parse_args. Verified no truncation beyond pid as i32 (PID <= 4M fits). Negative result: robust.

### userspace-dp/src/server/mod.rs
Checked module declarations and re-exports only. Negative result: no logic.

### userspace-dp/src/server/state.rs
Checked Args/ServerState/PollMode structs, from_str. Negative result: trivial.

### userspace-dp/src/server/tests.rs
Checked oversize rejection, legitimate feed above old 16MiB cap, ping/status, suppress_status, HA missing/persist, forwarding arm, sync_session missing/unknown op/delete/upsert/mac/ip reject, rebind preserves synced sessions (#1921), bump_fib missing/update/version gate/rollback/persist, apply_snapshot missing/preflight/3766/3789, binding/queue set missing/unknown/toggle, stop_workers clears, inject_packet missing, pure helpers, reconcile_disarmed clears (#2794), should_run_afxdp, bindings_settled, same_binding_plan, wg disarmed, export lock-free (#2962/#4054), fabric persist (#3773). Negative result: tests cover critical invariants.

### userspace-dp/src/slowpath.rs
Checked SlowPathStatus, EnqueueOutcome MtuExceeded (#2471), TUNSETIFF/IFF_TUN/IFF_NO_PI, DEFAULT_TUN_MTU, SlowPathReinjector new/spawn, mtu(), enqueue (live_mtu gate, rate_limiter, queued_packets, try_send Full/Disconnected), status snapshot, RateLimiter token bucket (dual bucket, fractional f64, cap at 1s, zero rate admits nothing, boundary 2x burst fix #2912), SharedStatus apply_mtu_status degraded, slow_path_worker open_tun + apply_mtu_status + active + io_uring vs sync fallback + loop recv + write_packet_io_uring_or_sync, write_packet_sync -> write_packet_atomic, write_packet_atomic (EINTR retry whole packet, partial -> drop, short write error), NONBLOCK_WOULDBLOCK_RETRY_BUDGET 1024, WOULDBLOCK_EXHAUSTED_ERRNO ENOBUFS, write_packet_atomic_nonblocking (EINTR + WouldBlock retry whole packet bounded, partial -> EMSGSIZE drop), write_packet_nonblocking, write_packet_io_uring, write_packet_io_uring_or_sync -> decide_sync_fallback, decide_sync_fallback safe_to_retry gate (#2477), open_tun O_CLOEXEC, TUNSETIFF, set_if_up, set_ipv4_sysctl rp_filter 0, read_all_rp_filter, rp_filter_all_warning, ioctl_then_close errno capture (#2479), set_if_up capture, set_if_mtu invalid MTU reject, socket before ifreq (#2439), ioctl_then_close seam, set_ipv4_sysctl, Ifru/IfReq, IfReq::new empty/long name reject, name_string. Verified packet-fd semantics preserved (no remainder write). Negative result: no truncation beyond safe i32 mtu, u64 packet_len.

### userspace-dp/src/state_writer.rs
Checked ProcInstance pid+start_time, real_proc_start_time field 22 parse after last ')', start-time seam, self_instance OnceLock, instance_is_alive full instance match (#2957/#3009), WriteMode IoUring/SyncFallback, WriteRequest, WriterStatus, StateWriter new thread, persist channel, status, PersistOutcome io_uring_failed/demotion_cause, persist_with_mode, apply_outcome runtime demotion permanent (#2958), persist_with_io_uring unique temp O_EXCL pid_start_seq, persist_sync, cleanup_on_error, finalize_durably fsync file+rename+fsync parent dir (#2147/#1968), sync_parent_dir, write_all_with_ring, TEMP_SEQ AtomicU64, temporary_path pid_start_seq, instance_from_temp_name strict parse (numeric pid/start/seq, legacy bare-pid rejected), sweep_stale_temps scoped to dest prefix, instance_is_alive gate, orphan removal logging. Negative result: no truncation, no TOCTOU on temp (O_EXCL), correct PID reuse handling.

### userspace-dp/src/tcp_flags.rs
Checked TCP_FIN/SYN/RST/PSH/ACK/URG constants match RFC 9293, TCP_FLAGS_CTRL_MASK 0x17, predicates has_syn/ack/rst/fin/urg/psh, is_ack_only, is_initial_syn, is_syn_ack, is_closing. Verified equivalence to original inline expressions. Negative result: no truncation.

### userspace-dp/src/tcp_flags_tests.rs
Checked constants wire values, single-bit predicates exhaustive 0..255, is_ack_only, is_initial_syn, local_delivery_skip, is_syn_ack, is_closing. Negative result: exhaustive coverage.

### userspace-dp/src/test_zone_ids.rs
Checked TEST_*_ZONE_ID constants 1..8, comments about StableZoneID [1,65533]. Negative result: test-only, arbitrary values, no truncation.

### userspace-dp/src/xsk_ffi.rs
Checked XskRingProd/Cons repr(C), opaque types, bridge FFI declarations, XdpDesc, Errno display/debug, BufIdx, UmemConfig default, UmemChunk, SocketConfig bind flags, XskCreateMode, IfInfo invalid/from_ifindex/set_queue/ifname_cstring, Umem new (unsafe area, zeroed rings, bridge_xsk_umem_create, error handling), frame (pitch*idx overflow check via checked_sub, offset as isize - see Finding 3), len_frames (area_len / frame_size -> u32 try_from), fd, as_raw_ptr, new_for_test, Drop, test helpers (leaked ring backing), Socket/User placeholders, DeviceQueueRings Owned vs BorrowedPrivateUmem, fill/complete/available/pending/needs_wakeup/statistics_v2/bind, Drop, AsRawFd, RingRx/Tx receive/transmit/available/needs_wakeup, ReadRx read/release Drop cancel, WriteTx insert commit Drop cancel, WriteFill same, ReadComplete, reserve_up_to partial reservation, create_xsk_binding_private/shared/impl (libxdp_flags=1 inhibit prog load, diagnostic eprintln, device_queue_rings_for_create), tests for append-not-overwrite, bounded reservation. Reviewed unsafe blocks: all bounded by caller guarantees, raw pointer handling correct, NonNull usage. One low-severity truncation concern in Umem::frame offset as isize (Finding 3).

---

## Findings

### Finding 1: fairness_eval CLI numeric args silently fall back to defaults on typo/overflow

Title: fairness_eval CLI `--n-workers`/`--warmup-secs`/`--final-burst-secs`/`--shaper-rate-bps` silently ignore parse errors and overflows

Severity: Low
Confidence: High
Evidence: userspace-dp/src/fairness_eval/args.rs:63-75
```
            "--warmup-secs" => {
                warmup_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            "--final-burst-secs" => {
                final_burst_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--n-workers" => {
                n_workers = args.next().and_then(|s| s.parse().ok()).unwrap_or(6);
            }
            "--shaper-rate-bps" => {
                shaper_rate_bps = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
```
Trace:
- Operator invokes `fairness-eval --n-workers 99999999999 --shaper-rate-bps 25G` (typo or overflow).
- `args.next()` yields `Some("99999999999")`, `s.parse::<u32>()` fails (overflow) → `None` → `unwrap_or(6)` keeps default 6.
- Similarly `--shaper-rate-bps 25G` fails parse → defaults to 0 → `--expect-saturation` then fails with "requires --shaper-rate-bps >0" (exit 2) but without that flag the run proceeds with 0, producing `structural_cap_bps=0`, `saturated=false`, and a misleading PASS because Gate 3 is not enforced.
- `--n-workers 0` (explicit zero) parses as 0 (valid u32) → no error, flows into `per_worker::aggregate_per_worker` with `0..0` workers → empty distribution, `max_worker_flow_share` returns 0, verdict PASS on empty data.
- In contrast `--cos-ifindex`/`--cos-queue-id` use `parse_required_numeric_arg` which exits 2 on error — correct behavior.

Why it matters: Fairness evaluation is the gate for CoS changes (#1630, #1614). A typo in the harness invocation silently changes the denominator `Nᵥ` (n_workers) or the structural cap (shaper_rate), producing a false PASS/FAIL that masks a real fairness regression or blocks a good change. The failure mode is silent — no warning.

Fix direction: Replace `.and_then(|s| s.parse().ok()).unwrap_or(default)` with `parse_required_numeric_arg` (or a `parse_optional_numeric_arg` that errors on parse failure but defaults on missing). Add explicit validation `n_workers >0` always (not only under `--expect-saturation`), matching the `if expect_saturation && n_workers==0` guard already present at line 120. Ensure `--warmup-secs`/`--final-burst-secs` also validated.

Labels: test-coverage, integer-truncation, observability

Dedup note: Checked dedup index entries #4278/#4277/#4276/#4275/#4274/#4273/#4272 (fairness-eval metric fixes), #4249, #4248, #4247, #4246, #4245 (CoS fairness). None mention CLI arg parsing silent fallback. Not a duplicate of #4572 (heartbeat zero-init overflow) or any open fairness-eval issue.

---

### Finding 2: fairness_eval TSV parsers silently skip malformed rows without warning

Title: fairness_eval `parse_binding_flows_tsv`/`parse_cos_flows_tsv` silently drop malformed rows

Severity: Low
Confidence: Medium
Evidence: userspace-dp/src/fairness_eval/inputs.rs:176-235 and 251-274
```
        let ts: u64 = match parts[0].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
...
        let slot: u32 = match parts[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
...
        // Other formats: silently skipped.
    }
    Ok(rows)
```
and
```
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 5 {
            continue;
        }
```
Trace:
- A corrupted Prometheus scrape TSV line (e.g., truncated write, partial flush) has 5 columns but non-numeric timestamp → `continue`, row dropped.
- If the corruption affects a specific worker's rows systematically (e.g., one worker's metric exposition truncated), that worker's samples are undercounted, median shifts, `distribution_a_i` skews, CoV gate may PASS when it should FAIL or vice versa.
- No counter or warning emitted; operator sees clean PASS/FAIL with no indication of data loss.
- Same pattern in `parse_cos_flows_tsv`.

Why it matters: Fairness evaluation is a CI gate for multi-Gb/s forwarding changes. Silent data loss in the input can hide a real regression (false PASS) or cause spurious failures (false FAIL) that waste investigation time. The tool should be fail-closed on malformed data or at least warn.

Fix direction: Count skipped rows, emit `eprintln!("fairness-eval: WARNING — skipped {} malformed TSV rows")` if non-zero. For 3-col vs 6-col legacy detection already warns; extend same pattern to parse failures. Optionally add `--strict` mode that errors on malformed rows.

Labels: observability, test-coverage

Dedup note: Checked dedup entries #4278-#4240 (fairness harness), #4422 (test-coverage backlog), #4499 (test-coverage follow-ups). None mention silent TSV row skipping. Not duplicate of any open issue.

---

### Finding 3: xsk_ffi Umem::frame offset as isize truncation on 32-bit or extreme frame_size

Title: `Umem::frame` casts u64 offset to isize without bounds check

Severity: Low
Confidence: Low
Evidence: userspace-dp/src/xsk_ffi.rs:372-385
```
    pub fn frame(&self, idx: BufIdx) -> Option<UmemChunk> {
        let pitch = self.config.frame_size;
        let area_len = self.umem_area.len() as u64;
        let offset = u64::from(pitch) * u64::from(idx.0);
        if area_len.checked_sub(u64::from(pitch)) < Some(offset) {
            return None;
        }
        let base = unsafe { self.umem_area.cast::<u8>().as_ptr().offset(offset as isize) };
        let slice = core::ptr::slice_from_raw_parts_mut(base, pitch as usize);
        let addr = unsafe { NonNull::new_unchecked(slice) };
        Some(UmemChunk { addr, offset })
    }
```
Trace:
- `pitch` is `frame_size: u32` (typically 4096, but configurable via `UmemConfig`).
- `idx.0` is `u32` (up to 2^32-1).
- `offset = pitch * idx` can be up to ~1.76e13 (4096*2^32) which fits in 64 bits but exceeds `isize::MAX` on 32-bit (2^31-1) and approaches `isize::MAX` on 64-bit (9e18).
- `offset as isize` on 32-bit truncates/wraps (e.g., 0x1_0000_0000 → 0), producing a base pointer that aliases frame 0 instead of the correct high frame.
- Current deployments are 64-bit only (Linux x86_64, `isize` 64-bit), `frame_size` 4096, `umem_area.len()` typically `frames * 4096` where frames = `ring_entries * 3` (max ring_entries 16384 → frames ~49152 → area ~200MB, offset <200MB < isize::MAX). So not reachable today.
- However the function is `pub` and takes arbitrary `UmemConfig`/`UmemChunk`, no documented precondition on frame_size or idx range.

HPC/invariant check: Cache-line alignment not relevant. Atomic ordering not relevant. The `checked_sub` guard correctly rejects OOB idx, but does not guard against `offset as isize` truncation. On 64-bit with current constants, `offset` < `area_len` < 1GiB << `isize::MAX`, so safe today.

Why it matters: If this helper is ever reused in a 32-bit build, or with a larger frame_size (e.g., jumbo UMEM), the silent truncation would cause two `BufIdx` to alias the same UMEM frame, leading to packet corruption or use-after-free-like double-use of a frame.

Fix direction: Add explicit `isize::try_from(offset)` check or use `offset.try_into().ok()?` to return `None` on overflow. Or use `ptr.add(offset as usize)` instead of `offset(offset as isize)` — `add` takes `usize` and is the idiomatic non-negative offset API. Example: `self.umem_area.cast::<u8>().as_ptr().add(offset as usize)`.

Labels: memory-safety, integer-truncation

Dedup note: Checked dedup entries #4572 (workers truncation), all closed issues around integer truncation (#4526, #4525). None mention xsk_ffi Umem::frame offset truncation. Not duplicate.

---

## Summary

Reviewed 40 files in A1_rust_dataplane_packet batch 3/3. Three Low-severity findings:

1. Silent fallback on fairness_eval CLI numeric args hides typos/overflows.
2. TSV parsers silently skip malformed rows without warning.
3. Umem::frame offset as isize could truncate on 32-bit/extreme frame_size (defense-in-depth).

All other modules show correct handling of their invariants:
- fairness_eval windowing/verdict/rss/per_worker logic matches documented gates (V-3/V-4/V-5/V-6/V-7/V-9) with fail-closed behavior.
- hot_hash_seed getrandom/fallback/never-zero/OnceLock correct.
- io_uring_write stale CQE drain, EINTR retry, permanent error fast-fail, packet vs positioned short-write handling correct.
- prefix/prefix_set trie/linear logic correct, mask_v4/v6 shift safe via ipnet validation.
- server lifecycle/handlers/helpers correctly implement #1921 (no stop in rebind), #2515/#2794 (full survivor clear), #2962/#4054 (off-lock export), #3766/#3789 (fail-closed snapshot), #2523/#2744 (size cap), #2970 (raise-only sysctls), #2974 (non-socket unlink refusal), #2957/#3009 (PID+starttime orphan handling).
- slowpath rate limiter token bucket, packet-fd write atomicity (#2407/#2438), MTU degraded handling (#2471), rp_filter warning (#2378), ioctl errno capture (#2479) correct.
- state_writer crash safety (O_EXCL unique temp, fsync file+parent dir, orphan sweep with full instance liveness) correct.
- ip_proto/tcp_flags constants and predicates correct.
- xsk_ffi unsafe blocks correctly bounded.

No zone-policy, global-policy, host-inbound, or default-deny bypass found in this batch (these modules are supporting infra, not policy matching). No VRRP/HA failover or cold-boot bug found in this batch. Integer truncation on config casts is handled correctly via serde range checks (fail-closed) and validated.rs validators (VlanId, TunnelTtl, QueueId, InterfaceMtu); remaining as-casts are widening or clamped. No DDNS/observability resource leak found beyond the minor TSV silent-skip.
