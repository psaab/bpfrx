Base commit reviewed: 34f1c7eccc509ee844d62b01aebae556fba41c41
Output path: /tmp/ps-review-012.md
Agent/scope: Agent RUST-COLD, Rust control/cold-path and protocol modules:
userspace-dp/src/policy.rs, userspace-dp/src/protocol/**,
userspace-dp/src/screen/**, userspace-dp/src/afxdp/wg/**,
userspace-dp/src/server/**.

Duplicate-suppression summary:
- Suppressed prior broad `policy.rs` / `SnapshotIntegrityError` dumping-ground split. Findings below only call out narrower parser and matcher seams.
- Suppressed prior screen SYN-flood inline-block finding and correctness findings under screen. Findings below target the packet extractor and test layout instead.
- Suppressed WireGuard correctness/bug-fix findings (TAI64N, cookie DoS correctness, crypto/session bugs). Findings below are module-boundary/refactor only.
- Suppressed server export-lock findings already covered by #2962/#4054 and prior reports.
- Hot paths constrained by prior perf/HPC findings: policy rule match, screen packet extraction/check, WireGuard encap/decap, AF_XDP status refresh must not introduce per-packet allocation, dynamic dispatch, or lost inlining.

File-size / Shape Inventory:
- userspace-dp/src/policy.rs: 4,224 LOC. Largest functions: parse_policy_state_with_counters 523 LOC, SnapshotIntegrityError::fmt 265 LOC, evaluate_policy_result_l3_aware 192 LOC, try_match_rule 179 LOC, evaluate_junos_host_policy_l3_aware 112 LOC. Mixes cold snapshot parsing, error formatting, policy indexes, hot evaluation.
- userspace-dp/src/screen/tests.rs: 5,121 LOC. Single test file with stateless checks, extractor vectors, flood/rate tests, SYN-cookie tests, scan/sweep tests, missing-profile tests, fabric-skip tests.
- userspace-dp/src/afxdp/wg/tests.rs: 3,806 LOC. Single WG integration test file spanning handshake, cryptokey routing, encap/decap, replay, timers, rekey, concurrent reconcile.
- userspace-dp/src/protocol/tests.rs: 2,334 LOC. Parent-level wire tests across status, snapshot, CoS, NAT, WG, session sync, fixture regeneration.
- userspace-dp/src/screen/mod.rs: 1,513 LOC. Largest functions: check_packet_with_zone_id_opts 331 LOC, update_profiles 97 LOC, check_flowless_screens_opts 85 LOC.
- userspace-dp/src/afxdp/wg/engine.rs: 1,763 LOC. Largest functions: try_decap 216 LOC, encap_inner 173 LOC, reconcile_peers 117 LOC.
- userspace-dp/src/afxdp/wg/cookie.rs: 1,435 LOC. Responder cookies, load gate, reply budget, per-source limiter, initiator cookie, and inline tests.
- userspace-dp/src/protocol/binding.rs: 1,144 LOC. BindingStatus alone spans lines 292-768; BindingCountersSnapshot mirrors a subset at lines 807-926.
- userspace-dp/src/protocol/control.rs: 1,026 LOC. ProcessStatus spans lines 100-589; WgTunnelStatus spans 679-830.
- userspace-dp/src/server/helpers.rs: 1,201 LOC. refresh_status 311 LOC, build_synced_session_entry 153 LOC, replan_queues 107 LOC.
- userspace-dp/src/server/lifecycle.rs: 732 LOC. run 298 LOC.
- userspace-dp/src/server/handlers/mod.rs: 293 LOC. handle_stream 250 LOC after prior handler split.
- userspace-dp/src/server/handlers/snapshot.rs: 296 LOC. apply 225 LOC.
- Other inspected files were smaller or already cohesive: protocol/cos.rs 494, protocol/nat.rs 369, protocol/security.rs 592, protocol/snapshot.rs 829, screen/rate.rs 609, screen/scan.rs 1,045, screen/syncookie.rs 600, WG handshake/session/peer/timers/framing/dscp/mss/scratch/allowed_ips/counters, server per-verb handlers.

File-by-file inspection log:
- policy.rs: inspected error display, parse_policy_state_with_counters, evaluate_junos_host_policy_l3_aware, try_match_rule.
- protocol/: inspected binding.rs, control.rs, snapshot.rs, tests.rs, smaller leaves by inventory.
- screen/: inspected extract.rs, mod.rs, scan.rs shape, tests.rs grouping.
- afxdp/wg/: inspected engine.rs, cookie.rs, tests.rs, handshake_session.rs shape, smaller leaves by inventory.
- server/: inspected README, helpers.rs, lifecycle.rs, handlers/mod.rs, handlers/snapshot.rs, tests.rs, smaller per-verb handlers by inventory.

High Confidence Findings

Title: `parse_policy_state_with_counters` is a 523-LOC cold parser pipeline inside the hot policy module
Severity (maintainability + build-cost + review-cost impact): High. Every snapshot-integrity change competes with hot policy evaluation in a 4,224-LOC file, and the function already carries at least six responsibilities.
Confidence: High
Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical / safe, because this is config-apply preflight, not per-packet evaluation.
Evidence (file/line references, LOC/complexity metrics, quoted snippets):
- userspace-dp/src/policy.rs:2519 starts a 523-LOC function.
- Responsibilities fused: default-policy parse, rule-id/policy-id uniqueness, zone universe, address-book compilation, rule literal parsing, application compilation, rule indexing, counter-map setup.
- Snippet:
  ```
  userspace-dp/src/policy.rs:2519
  pub(crate) fn parse_policy_state_with_counters(
  ...
  userspace-dp/src/policy.rs:2530
      let default_action = if default_policy.is_empty() {
  userspace-dp/src/policy.rs:2561
      let mut seen_rule_ids: FxHashSet<String> = FxHashSet::default();
  userspace-dp/src/policy.rs:2601
      let mut concrete_zone_ids: Vec<u16> = zone_name_to_id.values()...
  userspace-dp/src/policy.rs:2642
      for snap in address_books {
  userspace-dp/src/policy.rs:2695
      for snap in rules {
  ```
Proposed decomposition (new modules + what moves + the seam):
- Add `policy/compile.rs` or `policy/parser/mod.rs` for `parse_policy_state_with_counters`.
- Split cold helpers into `policy/parser/defaults.rs`, `policy/parser/identity.rs`, `policy/parser/books.rs`, `policy/parser/rules.rs`, and `policy/parser/index.rs`.
- Keep public entry point name unchanged and re-export it from `policy.rs` until callers move.
Hot-path preservation analysis (inlining, alloc, dispatch, layout, locality, lock scope — which apply, and how to verify no regression):
- No per-packet path should call the new parser modules. Verify with `rg "parse_policy_state_with_counters"` and `cargo asm`/`objdump -d` on policy evaluation symbols showing no change.
- Keep `PolicyState`, `PolicyRule`, `PrefixSet*`, and hot matcher helpers in the current hot module or in same-crate modules with no trait-object abstraction.
- No layout changes to policy structs in this PR; if moved, preserve derives and any compile-time invariants.
Tests + gate (what moves; which behavioral gate proves the move safe):
- Move parser-focused unit tests with the parser submodules; keep integration callers unchanged.
- Run `cargo test --bin xpf-userspace-dp policy::`, full `make test`, and apply-snapshot failure tests in `userspace-dp/src/server/tests.rs`.
Why it matters:
- The current function is a review sink: security fail-closed invariants for unrelated domains are interleaved in one body, making future parser changes risky.
Fix direction (ordered, incremental steps; safe to land as small PRs):
1. Extract identity and address-book preflight into pure helpers with unchanged return types.
2. Extract one `compile_rule_snapshot` helper returning `(PolicyRule, RuleIndexShape)`.
3. Extract index insertion into `policy/parser/index.rs`.
4. Move parser tests alongside the extracted helpers.
Labels (suggested issue labels, including `refactor`, `hot-path`, `x-hpc` where a layout/atomics/cache invariant is in play): refactor, policy, cold-path
Dedup note (why this is not a known issue / prior finding):
- This is not the prior broad `policy.rs` / `SnapshotIntegrityError` dumping-ground split. It is specifically the cold parser pipeline and does not ask to split the integrity enum.

Title: `screen/extract.rs::extract_screen_info` is a 305-LOC hot parser that fuses IPv4, IPv6 extension walking, and TCP option extraction
Severity (maintainability + build-cost + review-cost impact): High. This is security-sensitive hot parsing code; fixes for one wire format are reviewed inside a single long branchy function that also parses unrelated formats.
Confidence: High
Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): B requires-guardrails.
Evidence (file/line references, LOC/complexity metrics, quoted snippets):
- userspace-dp/src/screen/extract.rs:42 starts a 305-LOC hot extractor.
- Responsibilities fused: ScreenPacketInfo initialization, IPv4 IHL/options/source-route detection, IPv6 extension-header walk/fragment handling, TCP seq/ack/MSS parse.
- Snippet:
  ```
  userspace-dp/src/screen/extract.rs:79
      if addr_family == libc::AF_INET as u8 {
  userspace-dp/src/screen/extract.rs:122
          // scan the IPv4 options region...
  userspace-dp/src/screen/extract.rs:166
      } else if addr_family == libc::AF_INET6 as u8 {
  userspace-dp/src/screen/extract.rs:196
          for _ in 0..8 {
  userspace-dp/src/screen/extract.rs:245
              NEXTHDR_FRAGMENT => {
  userspace-dp/src/screen/extract.rs:309
      if protocol == PROTO_TCP ...
  ```
Proposed decomposition (new modules + what moves + the seam):
- Keep `extract.rs` as the public entry point.
- Add private same-module helpers: `parse_ipv4_screen_fields`, `walk_ipv6_screen_headers`, `scan_ipv4_source_route_options`, `extract_tcp_screen_fields`.
- Keep helpers in the same crate/module subtree and mark hot ones `#[inline(always)]` only after checking codegen.
Hot-path preservation analysis:
- Guardrails: no allocation, no trait objects, no `Vec`, no function pointers, no new packet copies, no endian conversion scattering.
- Module boundary is same crate, but helper calls can still lose inlining. Verify `cargo asm` or `objdump -d` for `extract_screen_info` before/after and `perf stat` on screen smoke traffic for branch-miss/icache regressions.
- Preserve byte-order locality: IPv4/v6 field reads must remain in parser helpers, not spread into screen checks.
Tests + gate:
- Move extractor tests currently in `screen/tests.rs` around lines 1050-1859 into `screen/extract_tests.rs`.
- Run `cargo test --bin xpf-userspace-dp screen::extract`, full screen subset, and NAT/filter/screen end-to-end smoke where available.
Why it matters:
- The function is exactly where truncated-header fail-closed invariants live. A targeted split would make IPv4, IPv6, and TCP-option regressions reviewable without changing packet semantics.
Fix direction:
1. Extract TCP option parse first; it is tail-isolated and easiest to assembly-diff.
2. Extract IPv4 option scan behind a private inline helper.
3. Extract IPv6 extension walk returning `{tcp_offset, frag fields, routing flag}`.
4. Move related tests with each helper.
Labels: refactor, screen, hot-path, x-hpc
Dedup note:
- Not the prior SYN-flood inline enforcement finding. This targets packet-field extraction and applies even with SYN-flood code unchanged.

Title: WireGuard `engine.rs` fuses cold peer reconciliation with hot transport encap/decap in one 1,763-LOC engine module
Severity: High. WG control-plane churn, session lifecycle, and crypto fast path are reviewed in one file; hot transport edits risk incidental cold-path changes and vice versa.
Confidence: High
Refactor class: B requires-guardrails.
Evidence:
- userspace-dp/src/afxdp/wg/engine.rs:1-24 documents the engine owns peer table, AllowedIPs, session demux, encap/decap, and handshake construction.
- userspace-dp/src/afxdp/wg/engine.rs:832 starts `reconcile_peers` (117 LOC, slow path).
- userspace-dp/src/afxdp/wg/engine.rs:1206 starts `encap_inner` (173 LOC, hot path).
- userspace-dp/src/afxdp/wg/engine.rs:1386 starts `try_decap` (216 LOC, hot path).
- Snippet:
  ```
  userspace-dp/src/afxdp/wg/engine.rs:814
      /// Reconcile the engine's peer table against a new config snapshot.
  userspace-dp/src/afxdp/wg/engine.rs:832
      pub(crate) fn reconcile_peers(&self, configs: &[WgPeerConfig]) {
  userspace-dp/src/afxdp/wg/engine.rs:1206
      fn encap_inner(...)
  userspace-dp/src/afxdp/wg/engine.rs:1380
      /// Hot-path decap.
  userspace-dp/src/afxdp/wg/engine.rs:1386
      pub(crate) fn try_decap(...)
  ```
Proposed decomposition:
- Convert `wg/engine.rs` into `wg/engine/mod.rs`.
- Move cold peer/config reconciliation into `wg/engine/reconcile.rs`.
- Move hot transport functions and their tiny helpers into `wg/engine/transport.rs`.
- Move public DTO/error types into `wg/engine/types.rs` only if that does not force broad imports; otherwise keep types in `mod.rs`.
Hot-path preservation analysis:
- `try_encap`, `encap_inner`, and `try_decap` must remain monomorphized concrete methods, no trait objects or boxed transport abstractions.
- Keep no locks held across crypto beyond the existing `Arc<WgSession>` / replay-window pattern; do not introduce shared coordinator locks on transport.
- Verify with `cargo asm`/`objdump -d` on `WgEngine::try_decap` and `WgEngine::encap_inner`; run perf counters for decap/encap microbench or existing WG tests under release.
Tests + gate:
- Move reconcile tests from `wg/engine_tests.rs` to `engine/reconcile_tests.rs`; keep encap/decap tests with transport.
- Run WG test subset, native GRE/WG userspace validation where available, and `make test-failover` if HA/WG status is touched.
Why it matters:
- The file already states hot path discipline, but the module boundary does not enforce it. A split makes it harder for slow reconcilers to grow into the crypto hot path.
Fix direction:
1. Create `engine/mod.rs` with the existing struct and re-exports.
2. Move only `reconcile_peers` first; no hot code motion.
3. Move transport functions after a disassembly baseline is captured.
4. Split tests by module.
Labels: refactor, wireguard, hot-path, x-hpc
Dedup note:
- Not a WireGuard correctness bug-fix finding. This is structural hot/cold separation around the engine file.

Title: Server `refresh_status` is a 311-LOC telemetry aggregator under the control-state lock
Severity: High. A single cold-path function updates dozens of unrelated status families, making new telemetry changes hard to review and increasing the risk of accidentally adding expensive work under the global server lock.
Confidence: High
Refactor class: A mechanical / safe, with possible C lock-scope follow-up.
Evidence:
- userspace-dp/src/server/helpers.rs:16 starts a 311-LOC function.
- Responsibilities fused: binding refresh, WG/GRE liveness reconciliation, writer status, neighbor telemetry, generated-reply counters, WG tunnel rows, worker runtime aggregation, queue summaries, policy/NAT/filter counters, event-stream stats, fabric diagnostics.
- Snippet:
  ```
  userspace-dp/src/server/helpers.rs:16
  pub(crate) fn refresh_status(state: &mut ServerState) {
  userspace-dp/src/server/helpers.rs:24
      if should_run_afxdp(&state.status) { ... reconcile_wg_control_liveness ... }
  userspace-dp/src/server/helpers.rs:44
      let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
  userspace-dp/src/server/helpers.rs:148
      let r = state.afxdp.neighbor_resolver_counters();
  userspace-dp/src/server/helpers.rs:176
      state.status.wg_tunnels = state.afxdp.wg_tunnel_statuses();
  userspace-dp/src/server/helpers.rs:297
      if let Some(es_stats) = state.afxdp.event_stream_stats() {
  ```
Proposed decomposition:
- Add `server/status/mod.rs`.
- Split into `refresh_runtime_liveness`, `refresh_neighbor_status`, `refresh_worker_status`, `refresh_security_counters`, `refresh_event_stream_status`, `refresh_fabric_status`.
- Keep `refresh_status(&mut ServerState)` as a thin orchestration wrapper initially.
Hot-path preservation analysis:
- Control/status path only; per-packet hot path unaffected unless helpers call new expensive AFXDP traversals. Preserve the existing `XPF_DEBUG_NEIGHBOR_KEYS` gate.
- Do not add locking inside worker hot paths. Any future lock-scope narrowing should snapshot AFXDP telemetry outside `ServerState` only after proving existing methods are lock-free or bounded.
Tests + gate:
- Existing server tests that attach status should remain unchanged.
- Add narrow unit tests for each status family if extraction reveals missing coverage.
- Run `cargo test --bin xpf-userspace-dp server::` and `make test` before PR.
Why it matters:
- Status telemetry is growing quickly; this function has become a dumping ground where unrelated counters are easy to miswire.
Fix direction:
1. Move related assignment blocks into private helpers with identical order.
2. Add a small `StatusRefreshContext` only if it removes repeated `state.afxdp` calls without borrowing surprises.
3. Consider later off-lock snapshots for expensive debug families as a separate issue.
Labels: refactor, server, control-plane
Dedup note:
- Not the prior export-under-lock findings. This is the general status-refresh aggregator; it avoids changing export wait/push behavior.

Medium Confidence Findings

Title: Protocol status DTOs are still god structs after the first protocol split
Severity: Medium-High. The protocol layer is cold, but BindingStatus and ProcessStatus are large cross-domain wire contracts where unrelated telemetry changes touch the same structs, fixtures, and reviewers.
Confidence: Medium
Refactor class: A mechanical / safe.
Evidence:
- userspace-dp/src/protocol/binding.rs is 1,144 LOC. `BindingStatus` spans userspace-dp/src/protocol/binding.rs:292-768 (about 477 LOC).
- userspace-dp/src/protocol/control.rs is 1,026 LOC. `ProcessStatus` spans userspace-dp/src/protocol/control.rs:100-589 (about 490 LOC). `WgTunnelStatus` spans 679-830 (152 LOC).
- Snippet:
  ```
  userspace-dp/src/protocol/binding.rs:292
  pub(crate) struct BindingStatus {
  userspace-dp/src/protocol/binding.rs:423
      pub screen_drops: u64,
  userspace-dp/src/protocol/binding.rs:548
      pub tx_packets: u64,
  userspace-dp/src/protocol/binding.rs:664
      pub debug_pending_fill_frames: u32,
  userspace-dp/src/protocol/control.rs:100
  pub(crate) struct ProcessStatus {
  userspace-dp/src/protocol/control.rs:447
      pub wg_tunnels: Vec<WgTunnelStatus>,
  ```
Proposed decomposition:
- Keep JSON field names stable but split source modules: `protocol/status/binding.rs`, `protocol/status/process.rs`, `protocol/status/wg.rs`, `protocol/status/neighbor.rs`.
- Consider nested Rust helper structs only for construction/projection, not wire JSON, unless Go side accepts a protocol version bump.
- Move `BindingCountersSnapshot` projection beside binding status.
Hot-path preservation analysis:
- Wire DTOs are control-plane; no packet path impact.
- Do not change serde names, defaults, skip rules, or array shapes. No layout/ABI reliance, but JSON compatibility is the invariant.
Tests + gate:
- Move wire tests by DTO family and keep the default specimen fixture gate.
- Run Rust protocol tests plus Go `pkg/dataplane/userspace/protocol_test.go`.
Why it matters:
- Field additions now require editing huge structs and the 2,334-LOC parent test file, increasing review misses on serde defaults and Go/Rust parity.
Fix direction:
1. Module-split only, no JSON shape changes.
2. Add per-family `default_specimen()` helpers so the fixture test is a registry, not a 70-entry literal.
3. Keep a final parent integration test for cross-module `ProcessStatus`.
Labels: refactor, protocol, wire-compat
Dedup note:
- The file header says protocol was split in #1325; this is not asking to undo that. It targets the remaining status DTO god structs and fixture bottleneck.

Title: `try_match_rule` is a 179-LOC hot matcher with duplicated address-family side matching
Severity: Medium. The code is cohesive but long and duplicates source/destination included/excluded logic across IPv4, IPv6, and NAT64 mixed-family arms.
Confidence: Medium
Refactor class: B requires-guardrails.
Evidence:
- userspace-dp/src/policy.rs:3786 starts `try_match_rule`; crude metric 179 LOC.
- Snippet:
  ```
  userspace-dp/src/policy.rs:3826
      let (src_ok, dst_ok) = match (src_ip, dst_ip) {
  userspace-dp/src/policy.rs:3827
          (IpAddr::V4(src), IpAddr::V4(dst)) => {
  userspace-dp/src/policy.rs:3860
          (IpAddr::V6(src), IpAddr::V6(dst)) => {
  userspace-dp/src/policy.rs:3907
          (IpAddr::V6(src), IpAddr::V4(dst)) => {
  userspace-dp/src/policy.rs:3940
          // (V4 src, V6 dst) has no inbound translation...
  ```
Proposed decomposition:
- Extract private `#[inline(always)]` helpers for `match_src_v4`, `match_dst_v4`, `match_src_v6`, `match_dst_v6`, or a generic over concrete prefix-set references if assembly proves equivalent.
- Do not move across crate boundaries; keep helpers in policy hot module or a same-crate `policy/match.rs`.
Hot-path preservation analysis:
- This is per-packet. Any split must preserve inlining, avoid heap allocation, avoid trait objects, avoid runtime family tables, and avoid extra `IpAddr` construction.
- Verify with `cargo asm`/`objdump -d` for `try_match_rule`, plus perf branch/cache counters on policy-heavy forwarding.
Tests + gate:
- Existing policy tests for excluded addresses, any-ipv4/any-ipv6, NAT64, ICMP/application terms must remain green.
- Add microbench/differential matcher test if not already present before extraction.
Why it matters:
- The current duplication makes policy address semantics easy to update in one family but miss another.
Fix direction:
1. Add helper functions for raw include/exclude side checks with direct concrete types.
2. Replace one family arm at a time, assembly-diffing after each.
3. Keep `rule.hit_counter.add(packet_len)` and result construction in the caller.
Labels: refactor, policy, hot-path, x-hpc
Dedup note:
- Not the broad policy.rs split. This is a narrow hot matcher decomposition and explicitly calls out the performance guardrails.

Title: WG cookie module mixes responder secret/load/budget logic, initiator cookie state, and 580 LOC of tests
Severity: Medium. The code is slow/control path, but it is security-sensitive cryptographic state; responder and initiator concerns now obscure each other's invariants.
Confidence: Medium
Refactor class: A mechanical / safe.
Evidence:
- userspace-dp/src/afxdp/wg/cookie.rs is 1,435 LOC.
- Production code runs through line 854; inline tests run 856-1435 (~580 LOC).
- Responsibilities fused: responder cookie checker, secret rotation, load detection, global reply budget, per-source token bucket, initiator cookie reply consume/stamp, random-source policy, tests.
- Snippet:
  ```
  userspace-dp/src/afxdp/wg/cookie.rs:296
  pub(crate) struct CookieChecker {
      secret: Mutex<SecretState>,
      load: Mutex<LoadState>,
      budget: Mutex<BudgetState>,
      per_source: Mutex<SourceTable>,
  userspace-dp/src/afxdp/wg/cookie.rs:715
  pub(crate) struct InitiatorCookie {
  userspace-dp/src/afxdp/wg/cookie.rs:855
  #[cfg(test)] mod tests {
  ```
Proposed decomposition:
- `wg/cookie/mod.rs` for constants and shared MAC helpers.
- `wg/cookie/responder.rs` for `CookieChecker`, secret rotation, build/verify.
- `wg/cookie/rate_limit.rs` for `LoadState`, `BudgetState`, `SourceTable`.
- `wg/cookie/initiator.rs` for `InitiatorCookie`.
- `wg/cookie/tests.rs` or per-submodule test files.
Hot-path preservation analysis:
- WG handshake/cookie path is slow control path, not per-transport-record encap/decap.
- Preserve Mutex granularity exactly: do not merge locks for tidiness, and do not hold a lock across AEAD if current code does not.
- Preserve zeroization and RNG fail-closed behavior; no logging of secrets/cookies.
Tests + gate:
- Move existing cookie tests with no semantic changes.
- Run WG cookie/handshake subsets and full WG tests.
Why it matters:
- Future cookie changes are high-risk security work; responder DoS gates and initiator interop should be independently reviewable.
Fix direction:
1. Move tests out first.
2. Move initiator state second; it has a clean type seam.
3. Move rate limiter structs behind the same public methods on `CookieChecker`.
Labels: refactor, wireguard, crypto
Dedup note:
- Not a repeat of the WG cookie DoS correctness findings; this assumes those fixes remain and only proposes module boundaries.

Low Confidence Findings / Negative Results

Title: Huge colocated test files should be split with their production seams, but only after preserving cross-module gates
Severity: Medium for review cost; low runtime risk.
Confidence: Low-Medium
Refactor class: A mechanical / safe.
Evidence:
- userspace-dp/src/screen/tests.rs: 5,121 LOC, about 125 tests/helper blocks by `rg`.
- userspace-dp/src/afxdp/wg/tests.rs: 3,806 LOC, about 50+ tests plus large shared handshake helpers.
- userspace-dp/src/protocol/tests.rs: 2,334 LOC, about 60+ wire tests.
- userspace-dp/src/server/tests.rs: 1,847 LOC, about 50+ dispatcher/helper tests.
- Snippet:
  ```
  userspace-dp/src/screen/tests.rs:1050  extract_screen_info_ipv4_first_fragment
  userspace-dp/src/screen/tests.rs:1912  icmp_flood_triggers
  userspace-dp/src/screen/tests.rs:2682  siphash24_matches_reference_vectors
  userspace-dp/src/screen/tests.rs:4034  port_scan_detected
  userspace-dp/src/screen/tests.rs:4970  fabric_skip_does_not_count_icmp_flood_4155
  ```
Proposed decomposition:
- `screen/tests/stateless.rs`, `screen/tests/extract.rs`, `screen/tests/rate.rs`, `screen/tests/syncookie.rs`, `screen/tests/scan.rs`, `screen/tests/fabric.rs`.
- `wg/tests/transport.rs`, `wg/tests/reconcile.rs`, `wg/tests/rekey.rs`, `wg/tests/handshake.rs`.
- `protocol/tests/status.rs`, `protocol/tests/snapshot.rs`, `protocol/tests/cos.rs`, `protocol/tests/wg.rs`, keep a small parent fixture registry.
- `server/tests/dispatch.rs`, `server/tests/snapshot.rs`, `server/tests/session_sync.rs`, `server/tests/status.rs`, `server/tests/export.rs`.
Hot-path preservation analysis:
- Tests only. The risk is losing fail-on-revert coverage, not packet performance.
- Keep shared fixtures in small `test_support` modules; do not weaken property/differential/fixture gates.
Tests + gate:
- The gate is the moved tests themselves plus full `cargo test --bin xpf-userspace-dp`.
- For protocol, keep default wire fixture and Go parity tests.
Why it matters:
- The test files now obscure which tests protect which module. A production split without a test split will still be hard to review.
Fix direction:
1. Split tests only in mechanical PRs, one directory at a time.
2. Preserve test names to keep historical failure grep useful.
3. Then land production module splits with tests already colocated.
Labels: refactor, tests, maintainability
Dedup note:
- Prior reports mention specific correctness tests and gaps; this is a structural test-layout finding across the assigned Rust scope.

Suggested issue split:
1. Policy parser cold split: extract identity/books/rule compiler helpers with no hot matcher changes.
2. Screen extractor guarded split: capture assembly baseline, extract TCP parser, then IPv4/IPv6 helpers.
3. WG engine hot/cold split: move reconcile first, then transport with codegen diff.
4. Server status refresh split: mechanical status-family helper extraction.
5. Protocol status DTO source split: no JSON changes, keep fixture gate.
6. WG cookie module split: initiator/responder/rate-limit/test modules.
7. Test-file split campaign: screen, WG, protocol, server tests, preserving names and gates.
