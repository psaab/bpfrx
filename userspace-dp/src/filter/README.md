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
  - **Protocol resolution (#2505)** uses the SHARED, normalizing
    resolver `crate::ip_proto::proto_number` (trim + lowercase + the
    full `appid.ProtocolNumber` acceptance set — tcp/udp/icmp/icmpv6/
    gre/ospf/ipip/esp/ah/sctp/vrrp/igmp/pim/egp + the specific
    `junos-*` aliases + bare numeric). It does NOT carry a local
    protocol table. A `from protocol` token reaches the snapshot
    VERBATIM (Go's `compileFilterFrom` does no alias resolution), so
    the resolver must accept exactly what the Go filter commit gate
    (`filterProtocolResolvable`) accepts or a gate-passing filter would
    lose its protocol constraint in the dataplane.
  - **Fail closed, not fail wide (#2505):** an EMPTY protocol list
    means "no constraint" (`protocol_match_enabled = false`, match-any,
    preserved). A NON-EMPTY list with any UNRESOLVABLE token raises
    `SnapshotIntegrityError::UnrepresentableFilterProtocol`, which
    propagates up through `build_forwarding_state_*` to the reconcile
    preflight (`build_reconcile_forwarding`) and aborts the reconcile
    BEFORE teardown/publish (post-#2484), keeping the prior good filter
    state live. Silently dropping the token (the pre-fix `filter_map`)
    collapsed the list to empty and disabled the match, so a `from
    protocol esp; then discard` term matched EVERY protocol — a
    fail-wide security bug. The Go gate is the primary defense; this is
    the helper-boundary backstop against version/snapshot drift.
- `engine.rs` — per-term evaluation, first-match-wins. It carries the
  matched `then policer ...` name in the filter result. Routing-instance
  evaluation can also return log/action/filter/term metadata so AF_XDP
  can emit PBR RT_FLOW filter-log events without re-evaluating the term
  or allocating on the packet path. The routing-instance result also
  carries an accumulated `log_match` (#2619) so a fall-through
  `then { log; next term; }` term ahead of the routing-instance term is
  not dropped from the PBR RT_FLOW path. The no-count log-only helper
  (`evaluate_filter_ref_log_match`) accumulates the LATEST matched logging
  term — sharing the full evaluator's semantics (#2618) instead of
  returning on the first one — while still skipping routing-instance terms
  so PBR logs are emitted only on the PBR path. TX-selection evaluation meters
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

  **Fall-through terms (`then next term` / modifier-only) (#2544).**
  "First-match-wins" applies only to TERMINATING terms. A term whose
  `then` carries NO terminating action — an explicit `then next term`
  OR a modifier-only term (only `count`/`log`/`forwarding-class`/
  `policer`/`dscp`) — must APPLY its modifiers and FALL THROUGH to the
  next term, per Junos semantics. The Go control plane records this:
  `buildFirewallFilterSnapshots` sets the wire field `next_term` true
  for a term with `NextTerm` OR an empty `Action` (a routing-instance
  PBR term is excluded — it takes its own routing decision). The Rust
  compiler maps `next_term` (or a belt-and-suspenders empty action) to
  `FilterTerm.continue_term`. Every per-term eval loop (`eval.rs`
  standard/non-routing/routing-instance/log-match, `tx_selection.rs`
  live, `cache_sensitive.rs` cached TX-selection) now: on a MATCH,
  applies the term's modifiers (count/policer side effects fire, and
  forwarding-class/dscp-rewrite/log/routing-instance accumulate into the
  running result, latest matched term winning per scalar, `log` and
  policer-drop OR'd); then, if `continue_term`, CONTINUES to the next
  term instead of returning. A matched TERMINATING term sets the result
  action and returns. If no term terminates, the accumulated modifiers
  ride the implicit default Accept. Before #2544 the empty action
  compiled to `FilterAction::Accept` and the loop returned on first
  match, so a packet matching a fall-through term was ACCEPTED there and
  a later `discard` was never reached. `continue_term` is compared in
  `filter_term_semantics_match` (it flips terminate-vs-fall-through
  without changing the parsed match vecs, so a flow-cache rebuild must
  catch a `then next term` toggle). The cached TX-selection result
  accumulates EVERY matched `then count` term in `CachedFilterCounters`
  (#2573), deduped by counter identity, so a flow whose fall-through set
  carries multiple `then count` terms increments all of them on the
  cached replay — matching the uncached full-eval path. The container is
  a `SmallVec<[_; 2]>` (built once at flow-cache install, only read on
  the per-packet replay), so the common single/dual-counter case records
  with no heap allocation. Before #2573 the result held a single
  `counter` Arc and the cached rebuild path recorded only the LAST
  matched count term (the earlier fall-through count terms were silently
  under-counted on the cached path only).

  **Fall-through log action follows the terminal verdict (#2616).** A
  matched fall-through logging term records its identity
  (`filter_id`/`term_id`) into the accumulated `log_match`, but its
  `action` field holds the Accept PLACEHOLDER the compiler assigns an
  empty/`next term` action — NOT the verdict the packet receives. Every
  evaluator entry point (`evaluate_filter_ref_counted_v4/v6`, the
  `_non_routing_` variants, the routing-instance evaluators, and the
  log-only helper) now normalizes the stored `log_match.action` to the
  FINAL terminal action before returning. A `then { log; next term; }`
  term ahead of a terminal `discard`/`reject` therefore logs DENY, not
  permit — the RT_FLOW record no longer lies about the action while the
  dataplane denies the packet. For a terminating logging term
  `term.action` already equals the final verdict, so normalization is a
  no-op there.

  **PBR session-miss counts each fall-through term exactly once (#2620).**
  When an interface input filter is route-lookup-affecting (it has a
  `then routing-instance` term), the session-miss path can run TWO
  evaluators over the same filter: the non-routing precheck
  (`evaluate_interface_filter_non_routing_counted`) for the terminal
  verdict, and — ONLY on the precheck's Accept verdict — the
  routing-instance evaluator
  (`evaluate_interface_filter_routing_instance_event_counted`, via
  `ingress_route_table_override`) for the route override. On a NON-Accept
  verdict (`discard`/`reject`) the poll path `continue`s and the routing
  evaluator NEVER runs. Both evaluators walk every matched term, so without
  care a `then { count X; next term; }` fall-through term ahead of the
  routing-instance term was counted TWICE on the Accept exit. Counter
  ownership is therefore per-EXIT, not a property of the filter:

  - **Accept / defer exit** (fall-through to default, or a matched
    routing-instance term): the routing evaluator runs and counts every
    matched term up to and including the routing-instance term. The
    precheck must NOT count.
  - **Terminal `discard`/`reject` exit** (a non-Accept term matched, with
    `then count` fall-through terms ahead of it): the routing evaluator
    never runs, so the precheck is the sole counter and records each
    matched `then count` term up to and including the terminating one.
  - **Plain non-PBR filter** (no routing-instance term): the routing
    evaluator returns early at the `affects_route_lookup` guard and counts
    nothing, so the precheck owns the count on every exit.
  - **DSCP/L4 session-HIT re-eval**
    (`evaluate_dscp_sensitive_input_filter_on_session_hit`): this never
    invokes the routing evaluator, so the precheck counts per packet on
    every exit (pre-#2620 behavior).

  The precheck takes a `count_policy: NonRoutingCountPolicy`:
  `OnlyTerminalNonAccept` (count only on the terminal discard/reject exit —
  the routing evaluator owns the Accept exit count) vs `Always` (precheck
  is the sole counter, counts on every exit).
  `evaluate_non_pbr_input_filter` derives it as `OnlyTerminalNonAccept`
  when `routing_eval_follows && interface_filter_affects_route_lookup(...)`
  else `Always`. The miss-path call site passes `routing_eval_follows =
  true` (an Accept proceeds to `ingress_route_table_override`); the
  session-hit re-eval passes `false`. This yields exactly one count per
  matched `then count` term on all four exits — neither the double-count on
  the Accept exit nor an under-count on the discard/reject or session-hit
  exits. (The earlier coarse fix gated the precheck solely on
  `affects_route_lookup`; that under-counted to zero on the discard/reject
  and session-hit exits, where the routing evaluator is never the counter.)
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
- Firewall-filter `then loss-priority <level>` (#2507) is likewise NOT wired:
  it carries no `FirewallTermSnapshot` field and there is no per-packet
  loss-priority consumer here (`apply_term_three_color_policer` always meters at
  `PacketColor::Green`). The Go control plane emits a commit WARNING that the
  action is accepted-but-inert (`validateFilterLossPriorityWarnings` in
  `pkg/config/compiler_validate_warn.go`) rather than silently committing a
  QoS no-op. Wiring a real per-packet loss-priority action onto the egress
  CoS/drop-profile path is a follow-up.
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
(`userspace-dp/src/session/key.rs`) is the standard 5-tuple
(`protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`) plus an
`addr_family` byte. The `addr_family` byte is redundant with the
`IpAddr` variant carried by `src_ip` / `dst_ip` but is materialized
on the struct for cheap branchless checks on the hot path.
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
| `tcp_flags_mask` (#2362) | NO — cache-sensitive | required-bits mask over the TCP flags byte; TCP flags vary per packet. Threaded via `TermMatchExtra` (path (b)) |
| `is_fragment` (#2362) | NO — cache-sensitive | Junos `is-fragment`: matches ANY fragment (IPv4 MF set OR offset != 0; IPv6 fragment header present). Computed by `is_any_fragment` |
| (future) `ihl_match` / IP options | NO — cache-sensitive | IHL varies per packet |
| `icmp_type` / `icmp_code` (#2362) | NO — cache-sensitive | exact match on the ICMP/ICMPv6 type/code byte; non-ICMP packets never match. Could later be promoted to cache-key by adding (type, code) to `SessionKey` |
| (future) `flex_match` | NO — cache-sensitive | byte-offset match, fully per-packet |

The `tcp_flags_mask` / `is_fragment` / `icmp_type` / `icmp_code` inputs are
carried in a small `TermMatchExtra` built once per packet at the filter-eval
call sites (`term_match_extra_from_frame` and its `ForwardPacketMeta` /
meta-only variants). The builder is fragment-safe: for a NON-FIRST fragment
(no L4 header at `l4_offset` — its bytes are payload) it sets an explicit
`l4_present = false`, and the matcher (`per_packet_l4_matches`) gates the
tcp-flags / icmp-type / icmp-code constraints on that flag — NOT on the byte
value, because 0 is a valid `icmp-type` (echo-reply) and a valid `icmp-code`, so
a zeroed byte would still match `from { icmp-type 0 }` / `from { icmp-code 0 }`.
The L4 byte fields are also zeroed (defense-in-depth) but the gate is the flag.
The L3-derived `is_fragment` bit is NOT gated by `l4_present` and stays true
(a non-first fragment IS a fragment). This applies on the
CoS / TX-selection leg too (`tx/cos_classify.rs`): the TX-selection evaluators
thread the same `TermMatchExtra`, and the deferred path snapshots it on
`PendingForwardRequest.filter_match_extra` because the UMEM frame may be
recycled before the deferred recompute runs. The flow-cache decline (output and
input legs) keeps the precomputed TX-selection descriptor from being built for a
per-packet-L4 filter, so the live per-packet evaluator always runs.

Fields like `action`, `count`, `log`, `policer`, `routing_instance`,
`forwarding_class`, and `dscp_rewrite` are forwarding actions and
modifiers, applied after a match has succeeded. They do not
participate in match-time key lookup and are out of scope for the
cache-key contract.

### All-malformed match sets fail CLOSED (#2400)

A term's `source-address` / `destination-address` / `source-port` /
`destination-port` match set restricts which traffic the term's action applies
to. The Rust compiler drops any entry that fails to parse
(`parse_address` skips an unparseable prefix; `parse_port_spec` returns `None`).
Historically an EMPTY parsed list meant "no constraint → match any", so a term
whose match set was non-empty in the config but whose entries ALL failed to
parse (every address typo'd, every port out of range) silently broadened to
match-ANY on that dimension — a `discard` term scoped to bad addresses became
discard-all (fail-OPEN filter broadening, codex 032-18 / 032-19).

`FilterTerm` now carries four derived flags —
`source_addr_constrained` / `dest_addr_constrained` /
`source_port_constrained` / `dest_port_constrained` — set at compile time when
the snapshot list held at least one REAL entry (`addr_is_real` ignores the empty
string and the literal `any`; `port_is_real` ignores the empty string). The
matcher (`engine/matching.rs` `nets_match_v4` / `nets_match_v6` / `port_match`)
then distinguishes:

- unconstrained (no real entry) → match any (unchanged unscoped behavior);
- constrained but the parsed set is empty for this packet's family (all entries
  failed to parse) → match NOTHING (fail closed);
- otherwise → the IP/port must fall in a parsed prefix/range.

This mirrors the NAT `*_constrained` fail-closed pattern (#2398 SNAT, #2394
DNAT). A bare-host address (`203.0.113.7`, no `/32`) is handled by
`parse_address`'s bare-IP fallback (`IpNet::parse` rejects a bare IP). The flags
are DERIVED from the existing snapshot lists, so there is NO new wire field
(`protocol_wire_v1.json` is unchanged). The flags are also compared in
`filter_term_semantics_match` (`engine/cache_sensitive.rs`) because the
unscoped↔all-malformed transition flips match semantics WITHOUT changing the
parsed vecs/matcher, so a flow-cache rebuild must catch it.

### Prefix-list expansion + `except` inversion (#2506)

`from source-prefix-list <name>` / `destination-prefix-list <name>` (with the
optional `except` modifier) is resolved in the GO control plane before the
snapshot is emitted, not in Rust. The Go snapshot builder
(`resolvePrefixListAddrs`, `pkg/dataplane/userspace/filters.go`) looks each
reference up in `cfg.PolicyOptions.PrefixLists` and merges the resolved CIDRs
into the term's `source_addresses` / `destination_addresses` list — so the Rust
compiler sees them exactly like literal `from source-address` entries (no
prefix-list concept exists Rust-side). Before #2506 these references were
silently dropped, leaving the term with no address scope (action-dependent
fail-open / fail-closed).

The `except` modifier ("match every address NOT in the list") is the one piece
that cannot be expressed by the address vectors alone, so it travels as two
per-direction wire flags on `FirewallTermSnapshot` — `source_except` /
`destination_except` (Go `pkg/dataplane/userspace/protocol.go`, Rust
`protocol/security.rs` with `serde(default)` for #1961 wire parity). They map to
`FilterTerm.source_except` / `dest_except`, and the matcher
(`engine/matching.rs` `nets_match_v4` / `nets_match_v6`) evaluates
`nets.iter().any(contains) ^ except`. The except flags are compared in
`filter_term_semantics_match` (`engine/cache_sensitive.rs`) — they flip the
address decision without changing the parsed vecs, so a flow-cache rebuild must
catch a toggle.

**Explicit `constrained` signal + empty-set semantics (#2506, Copilot).** A
prefix-list can resolve to ZERO prefixes — a defined-but-empty list (passes the
strict gate) or an unresolved reference on the lenient/peer-sync path. The
empty-resolution case is exactly the address-scope-loss bug #2506 fixes, so
"constrained" must NOT be derived from the resolved list length (an empty list
would collapse to match-any: fail-open for `accept`, wrong scope for
`discard`). Two explicit wire flags `source_constrained` /
`destination_constrained` (Go sets them whenever the term wrote ANY scope —
literal address or prefix-list ref) are OR'd into
`FilterTerm.source_addr_constrained` / `dest_addr_constrained` in the compiler.
The matcher's empty guard then returns `except`:

- positive (`except == false`), empty vec → `false` → match NOTHING (Junos
  `addr ∈ {}` = none; this is the #2400 all-malformed case AND the #2506
  empty-positive case);
- `except == true`, empty vec → `true` → match ALL (Junos `addr ∉ {}` = all);
- `constrained == false` (no scope at all) → match any, unchanged.

Cross-family falls out of this for free: a v4-only `... except` list leaves the
v6 vec empty, and a v6 address is trivially "not in" a v4 list, so the empty
guard's `return except` (= true for an except term) correctly matches v6 — the
v4 list does not constrain v6. (A v4-only POSITIVE list correctly fails closed
for v6 via the same guard returning `except` = false.)

Go-side scope: a plain prefix-list OR's into the positive set (with any literal
addresses); an `except` prefix-list sets the inversion flag ONLY when it is the
sole address source for the direction. The mixed literal/positive + `except`
case in one direction folds `except` away to a positive set with a warning —
there is no single boolean-inversion representation for "match A but not B". The
fold is **action-dependent in safety**: under-broadening is fail-safe for
`accept`/permit terms but fail-OPEN for a `discard`/`reject` term (traffic the
operator meant to drop via `except` is no longer dropped). Splitting into two
terms is the operator workaround, and the structured form is a documented
follow-up. An undefined prefix-list reference is rejected at commit by
`validateFirewallPrefixListReferencesStrict` (Go), so the Rust side never has to
reason about a dangling name.

### Negated port match — `source-port-except` / `destination-port-except` (#2622)

Junos `from source-port-except` / `from destination-port-except` matches every
port EXCEPT the listed ones — the port-dimension counterpart to the address
`except` above. The negated list travels as two additive wire fields on
`FirewallTermSnapshot` — `source_ports_except` / `destination_ports_except` (Go
`pkg/dataplane/userspace/protocol.go`, Rust `protocol/security.rs` with
`serde(default)` for #1961 mixed-version parity).

The Rust compiler (`compiler.rs`) selects ONE port spec list per direction: the
positive `source_ports` / `destination_ports` if it carries a real entry,
otherwise the `*_except` list. It builds the SAME `PortMatcher` from the
selected list, sets `*_port_constrained` from the selected list, and sets a
per-direction `source_port_except` / `dest_port_except` inversion flag on
`FilterTerm` when the except list is the source (positive wins if both are
present — there is no single matcher that expresses "ports in A but not B", same
fold as the address mixed case). The matcher `port_match`
(`engine/matching.rs`) evaluates `matcher.matches(port) ^ except`, mirroring
`nets_match_v4` / `nets_match_v6`:

- positive (`except == false`), `PortMatcher::Any` while constrained → match
  NOTHING (the #2400 all-malformed fail-closed case);
- `except == true`, `PortMatcher::Any` while constrained → match ALL (Junos
  "all ports except {}");
- otherwise → `(port ∈ ranges) XOR except`.

Tests: `destination_port_except_negation` / `source_port_except_negation` in
`filter/tests.rs` (port IN the except list does NOT match, port NOT in it DOES;
fail-on-revert). Scope is ports only — `packet-length` from the same review-039
finding is not implemented.

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

### `then reject` synthesizes an active reply (#2521)

`FilterAction::Reject` (`then reject`) no longer realizes as a silent
drop. It now synthesizes and transmits an active reject reply — a TCP
RST for TCP, an ICMP/ICMPv6 administratively-prohibited Destination
Unreachable otherwise — using the **same** machinery as policy
`reject`. `FilterAction::Discard` (`then discard`) is unchanged: still
a silent drop, no reply.

The synthesis is the shared `enqueue_reject_reply` in
`poll_descriptor/reject_reply.rs`; `enqueue_policy_reject_reply` and
`enqueue_filter_reject_reply` are thin wrappers over it that differ
only in the success counter (`policy_reject_sent` vs
`filter_reject_sent`). Filter reject is wired at every input/lo0
filter drop site in `poll_descriptor/mod.rs` that previously recycled
the descriptor on a terminal action: the new-flow input filter, the
DSCP/L4-sensitive session-hit re-evaluation, and both lo0 local-delivery
paths. `apply_lo0_filter_action` returns the matched `FilterAction`
(not a bare drop `bool`) so the caller can tell `Reject` from
`Discard`.

Because the generated reply runs through the SAME path as policy
reject, it inherits the #2238 output-filter / CoS / DSCP
classification (`classify_generated_reply`, keyed on the reply's OWN
egress tuple) and the SYN-cookie TX-frame budget gate — and a future
per-reason generated-reply rate limiter (#2472) covers filter reject
automatically (no parallel, un-limitable emit path). Budget exhaustion,
output-filter drops, and parse-error drops share policy reject's
counters and its fail-closed behavior (the caller still drops the
packet when synthesis returns `false`). The RT_FLOW filter-log action
maps `Reject → reject` (matching policy reject and Junos), `Discard →
deny`.

**Scope:** output-firewall-filter `then reject` realized on the
TX/CoS path (`tx/cos_classify.rs`) still collapses `Reject` to a
silent drop. That site lacks the descriptor/packet context the
reflected-reply synthesis needs, so wiring it would be a divergent
path — tracked as a follow-up, not part of #2521.
