# userspace-dp/src/filter/

Junos-style firewall filter compiler, evaluation engine, and policer.
Mirrors the BPF firewall-filter pipeline in userspace.

## Files

- `mod.rs` — public surface: `FilterAction` (`Accept` / `Discard` /
  `Reject` only), `FilterTerm` (the matched-and-action carrier),
  `PortMatcher`, `FilterTermCounter`, and three-color policer runtime
  counters. Side-effect actions like counting, logging, policing,
  forwarding-class assignment, and DSCP rewrite are **fields on
  `FilterTerm`** (e.g. `count`, `log`, `policer_name`,
  `three_color_policer`, `forwarding_class`, `dscp_rewrite`), not enum
  variants — the engine applies them around the action verdict.
- `compiler.rs` — parses the typed config's filter terms and lowers
  them to `FilterTerm`s (prefix vectors, protocol bitmap, port
  matcher, DSCP bitmap). Three-color policer snapshots are sorted by
  name for deterministic iteration and compiled into name-derived
  stable runtime IDs before terms are linked.
- `engine.rs` — per-term evaluation, first-match-wins. It carries the
  matched `then policer ...` name in the filter result. Routing-instance
  evaluation can also return log/action/filter/term metadata so AF_XDP
  can emit PBR RT_FLOW filter-log events without re-evaluating the term
  or allocating on the packet path. No-count helper evaluation returns the
  first logged non-PBR input or lo0 match while skipping routing-instance
  terms to avoid double-emitting PBR logs. TX-selection evaluation meters
  three-color policers, carries output filter-log identity through live
  forwarding and cached flow-cache hits, and preserves terminal
  `discard`/`reject` actions so output filters cannot log deny while
  forwarding. Input/output filters with DSCP match terms force the
  flow-cache insertion path to decline caching because DSCP is not part
  of the session key. Established session hits still re-evaluate
  DSCP-sensitive input filters per packet. Forwarding rotations compare
  DSCP-sensitive input filter content by stable names, terms, and
  three-color policer runtime shape, not by compiler-positional filter
  IDs, before deciding whether existing sessions need a conservative
  packet-family purge.
- `policer.rs` — token-bucket implementation plus the #1375 RFC
  2697/2698 three-color meter core. Token math is integer-only:
  the legacy token bucket keeps its bits/sec constructor contract, and
  the three-color core uses byte/sec rates; both refill scaled `u128`
  token buckets from monotonic nanosecond timestamps.
- `tests.rs` — co-located unit tests covering matching ports, prefix
  vectors, TCP flags.

## Conventions

- Prefix matching uses linear scan over `Vec<PrefixV4>` /
  `Vec<PrefixV6>` per term (`source_v4`, `source_v6`, `dest_v4`,
  `dest_v6` on `FilterTerm`). There is no LPM trie in this package
  today — the previous README claim of an "adaptive scan above 8
  entries" was incorrect.
- Hit counters live on each `FilterTerm` (`Arc<FilterTermCounter>`)
  and are surfaced through the status JSON.
- `Filter.id` and `FilterTerm.id` are deterministic within the compiled
  snapshot order and are carried in userspace RT_FLOW filter-log records.
  Do not invent IDs beyond the compiled snapshot until the ApplyResult or
  snapshot schema exposes richer stable filter-name mapping.
- `from-interface` is matched at the binding level (caller sets the
  ingress interface; the term doesn't re-derive it).

## #1375 Three-Color Policer Runtime

Implemented here:

- srTCM (RFC 2697): committed tokens fill at CIR; overflow fills the
  excess bucket only after the committed bucket is full.
- trTCM (RFC 2698): committed and peak buckets refill independently at
  CIR and PIR.
- Color-aware classification never promotes incoming yellow or red
  packets. Color-blind classification ignores inherited color.
- Per-color treatments can carry DSCP rewrite and drop decisions in the
  meter decision.
- The Go snapshot schema, Rust wire DTO, and commit-time structural
  validation are wired for three-color policers. Commit validation
  rejects ambiguous mode declarations (`single-rate` with `two-rate`)
  and ambiguous color declarations (`color-blind` with `color-aware`)
  before they can reach the helper.
- Filter terms link to stable name-sorted runtime handles. The live
  forwarding path meters the handle at packet time, applies red drops,
  and records per-color/drop counters. Flow-cache hits carry the same
  handle in the cached TX-selection descriptor and meter before cached
  forwarding. Packets buffered for missing-neighbor retry carry their
  session key and meter at retry dispatch time before prepared TX.
- The Rust snapshot compiler also fail-closes unsupported or malformed
  three-color policer snapshots. If color-aware mode, non-`discard`
  treatment, an unknown mode, or invalid token parameters bypass Go
  admission, matching traffic still links to an explicit unsupported runtime
  that returns red/drop instead of silently forwarding unmetered.
- Rust status, Go status, CLI status formatting, and Prometheus export
  expose green/yellow/red packet and byte counters plus drop counters.
- `deriveUserspaceCapabilities()` no longer rejects the color-blind `then
  discard` `firewall three-color-policer` runtime slice.

Remaining limitations:

- Runtime token state is one `Mutex` per logical policer, not a sharded
  or packed atomic implementation. This preserves correctness and
  stable identity but is not the final high-throughput contention model.
- Equivalent snapshot replacements preserve token buckets and per-color
  counters by reusing the same runtime handle when the name-derived runtime ID
  and shape are unchanged. Shape changes intentionally create a fresh runtime
  so old tokens cannot leak across a different rate/burst contract. HA
  failover and process restart still rebuild from configured bursts until a
  broader state-sync design exists.
- Snapshot `then_action` handling currently wires red drop for
  `then discard`. Other actions, such as loss-priority propagation, stay
  fail-closed until downstream loss-priority behavior is wired. Color-aware
  mode also stays fail-closed until inherited packet color is carried through
  trusted metadata.
- Traffic-level integration, failover, and performance evidence remain
  production-hardening follow-ups for #1375, not active feature-gap blockers.

## Cache-key invariants for per-packet match fields (#1431)

PR #1430 closed the immediate filter-log enforcement gaps by treating
DSCP as cache-sensitive metadata that lives outside the 5-tuple
session/flow-cache key. #1431 codifies the contract going forward.

**The invariant.** When a filter match depends on packet fields that
are not part of the cache key, the dataplane must not reuse a
first-packet forwarding decision for later packets that can differ
on those fields.

**The cache key.** `SessionKey`
(`userspace-dp/src/session/key.rs`) is a 6-tuple:
`addr_family`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`.
For ICMP and ICMPv6 sessions, `parse_flow_ports`
(`userspace-dp/src/afxdp/frame/inspect.rs:212-232`) unconditionally
reads bytes 4-5 of the ICMP header into `src_port` (the ICMP
identifier word — meaningful for Echo Request/Reply, opaque for
other ICMP types) and stores zero in `dst_port`. ICMP **type**
and **code** are NOT in the cache key — adding an explicit
`icmp_type` or `icmp_code` filter match makes the filter
cache-sensitive unless `SessionKey` or trusted per-session
metadata is extended to carry those fields.

**Classification table.** Every match criterion (not action /
modifier) on the wire DTO `FirewallTermSnapshot`
(`userspace-dp/src/protocol/security.rs`) and the runtime
`FilterTerm` (`userspace-dp/src/filter/mod.rs`) must fall into
exactly one of these two classes:

| Match criterion | In cache key? | Notes |
|-----------------|---------------|-------|
| `source_addresses` / `source_v4` / `source_v6` | yes | `src_ip` in `SessionKey` |
| `destination_addresses` / `dest_v4` / `dest_v6` | yes | `dst_ip` |
| `protocols` / `protocol_bitmap` (+ `protocol_match_enabled`) | yes | `protocol` |
| `source_ports` | yes (TCP/UDP); ICMP-special | `src_port` carries the ICMP identifier word from bytes 4-5 of the ICMP header (meaningful for Echo Request/Reply, opaque otherwise) |
| `destination_ports` | yes (TCP/UDP); ICMP-zero | `dst_port` is 0 for ICMP |
| `dscp_values` / `dscp_bitmap` (+ `dscp_match_enabled`) | NO — cache-sensitive | see #1430 pattern below |
| (future) `tos_match` / ECN bits (non-DSCP TOS) | NO — cache-sensitive | TOS lower bits and ECN vary per packet |
| (future) `tcp_flags_match` | NO — cache-sensitive | TCP flags vary per packet |
| (future) `is_fragment` / fragment offset / MF | NO — cache-sensitive | only first fragment carries L4 |
| (future) `ihl_match` / IP options | NO — cache-sensitive | IHL varies per packet |
| (future) `icmp_type_match` / `icmp_code_match` | NO — cache-sensitive (today) | could be promoted to cache-key by adding (type, code) to `SessionKey` for ICMP |
| (future) `flex_match` | NO — cache-sensitive | byte-offset match, fully per-packet |

Fields like `action`, `count`, `log`, `policer`, `routing_instance`,
`forwarding_class`, and `dscp_rewrite` are forwarding actions and
modifiers, applied after a match has succeeded. They do not
participate in match-time key lookup and are out of scope for the
cache-key contract.

### Path (b) runbook — cache-sensitive

Adding a per-packet match field that is NOT in the cache key
requires wiring all of these hooks. DSCP is the reference
implementation (#1430); use it as the template:

1. **Aggregate flag** on `Filter` —
   `Filter.has_<X>_match_terms: bool`, computed during snapshot
   compile. See `Filter.has_dscp_match_terms` in
   `userspace-dp/src/filter/mod.rs`.
2. **Per-interface sets** on `FilterState` —
   `iface_filter_v4_has_<X>_match: FxHashSet<i32>` and the v6
   sibling, populated during snapshot compile. See the
   `iface_filter_v{4,6}_has_dscp_match` fields in
   `userspace-dp/src/filter/mod.rs`.
3. **Lookup helpers** in
   `userspace-dp/src/filter/engine/cache_sensitive.rs` —
   `interface_input_filter_has_<X>_match` and
   `interface_output_filter_has_<X>_match` (or thread the new
   flag through one general helper if the DSCP-specific
   functions are generalized in a future PR).
4. **Flow-cache insertion gate** —
   `userspace-dp/src/afxdp/flow_cache.rs:297-309` calls the
   input + output helpers and returns `None` if either fires.
5. **Established-session re-evaluation** —
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs:217-244`
   (`evaluate_dscp_sensitive_input_filter_on_session_hit`) is
   the DSCP shape; mirror it.
6. **Forwarding-rotation purge** —
   `userspace-dp/src/afxdp/worker/loop_body/mod.rs:295-330`
   uses `input_dscp_filter_families_changed` to decide whether
   to purge sessions. Extend the semantics-match comparison in
   `userspace-dp/src/filter/engine/cache_sensitive.rs:104-143`
   to cover the new match field's aggregate flag and per-term
   content. **Compare by content, never by compiler-positional
   filter/term IDs** — `Filter.id` and `FilterTerm.id` are
   stable only within a snapshot.
7. **Tests** in `userspace-dp/src/afxdp/flow_cache_tests.rs`
   following the DSCP runbook pattern in
   `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
   /`_output_filter` (DSCP-bespoke regression tests) and the
   #1431 references
   `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
   / `_output_*`. The flow-cache test home is `afxdp/` because
   `FlowCacheEntry::from_forward_decision` is
   `pub(super)`-scoped to `afxdp::flow_cache`.

Reference tests (already in the tree, cite from new field PRs):

- gate insertion: `afxdp/flow_cache_tests.rs` ::
  `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
  / `_output_filter`
- rotation purge positional-ID immunity:
  `filter/tests.rs:1806`
  (`input_dscp_filter_families_changed_ignores_positional_filter_id_change`)
- session-hit re-eval: `afxdp/tests.rs:3184`

### Path (a) — extend `SessionKey`

Promoting a per-packet match field into the cache key requires
extending `SessionKey` in `userspace-dp/src/session/key.rs` AND
proving stability across:

- HA session sync wire format (`pkg/cluster/`),
- session-table reverse / NAT-translated / forward-wire indices
  (`userspace-dp/src/session/mod.rs`),
- flow-cache key derivation (`flow_cache.rs`),
- session expiry hash bucket math,
- reverse-NAT lookup keys.

This is a significant cross-cutting refactor — file a tracker
issue against `session/key.rs` before attempting it.

### lo0 is not on the flow-cache path

Host-bound traffic resolves to
`ForwardingDisposition::LocalDelivery`, which
`is_cacheable()` returns `false` for at
`userspace-dp/src/afxdp/types/forwarding.rs:196`. Per-packet lo0
filter evaluation runs at
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:700` (session-hit
path) and `:1153` (miss path). lo0 filters therefore do NOT need
a per-interface `has_<X>_match` set — the flow-cache never holds
a lo0 decision in the first place. This is noted here so future
readers do not repeat the v1 plan investigation that mistook lo0
for a missing cache-sensitive gate.
