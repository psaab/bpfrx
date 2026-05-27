# #1431 — userspace filters: preserve cache invariants for future per-packet match fields

**Status:** PLAN-READY v5 — Codex r4 + AGY r4 PLAN-READY (round 4)

**v2 verdict log (round 2):**

- Codex r2 (`task-mpnic4wn-2f38fd`): **PLAN-NEEDS-MINOR**.
  Findings (verbatim summary):
  1. `FlowCacheEntry::from_forward_decision` is `pub(super)` in
     `afxdp::flow_cache` (`flow_cache.rs:228`); a test under
     `filter/` cannot call it without visibility churn. Either
     move new tests to `afxdp/flow_cache_tests.rs` (where the
     existing DSCP tests at `643-745` already live) or make
     this PR doc-only.
  2. `dscp_rotation_does_not_fire_on_positional_id_change` is a
     duplicate of `input_dscp_filter_families_changed_ignores_positional_filter_id_change`
     at `filter/tests.rs:1806`. Drop it.
  3. Plan claims established-session re-eval test but §4.3 does
     not add one. Existing coverage already exists at
     `afxdp/tests.rs:3184`. Cite, don't duplicate.
  4. README table: reword "every field" → "every match criterion";
     include `protocol_match_enabled` / `dscp_match_enabled`
     alongside their bitmaps; add a future-TOS/ECN row since §1
     names TOS.
  5. Contract block belongs above struct, not inline on every
     field — confirmed.
  6. Keep the lo0 note, but one paragraph / one line with
     references to `is_cacheable()` and the per-packet lo0
     paths — it is useful precisely because round 1 already
     wasted review time on it.

- AGY r2 (`review-mpnicccj-1jngkm`): **PLAN-READY** with one drop
  (the duplicate positional-ID test). Confirmed:
  - All 10 r1 findings addressed.
  - In-source contract block above struct is the right surface;
    diff-visibility on PR review is the defense; optional
    one-line per-field tag like
    `pub(crate) dscp_bitmap: u64, // CACHE-INVARIANT: path (b)`
    is welcome but not required.
  - 3-test harness is right-sized; doc-only would remove the
    executable blueprint.
  - README classification table is 100% complete and accurate
    against `protocol/security.rs:60-89` and `filter/mod.rs:48-73`.
  - Keep the lo0 note — link to `types/forwarding.rs::is_cacheable`.

Both reviewers converge on dropping the positional-ID duplicate.
Codex adds a visibility issue (`pub(super)`) that v3 must address
by moving the two gate tests into `afxdp/flow_cache_tests.rs`.

**v1 verdict log (preserved verbatim):**

- Codex r1 (`task-mpni1t2r-fmeyxk`): **PLAN-KILL** with salvage path.
  Key findings (verbatim summary):
  1. Existing #1430 hooks verified.
  2. lo0 is NOT a flow-cache gap. `LocalDelivery` is non-cacheable
     in `types/forwarding.rs:181`; `FlowCacheEntry::from_forward_decision`
     refuses non-cacheable decisions at `flow_cache.rs:221`.
     lo0 is evaluated per-packet on both miss and hit paths in
     `poll_descriptor/mod.rs:700,1153`.
  3. Q3 premise was wrong. ICMP `src_port` is the echo identifier
     from `parse_flow_ports` at `inspect.rs:225`, NOT type/code. An
     explicit ICMPType/ICMPCode filter field is cache-sensitive.
  4. §4.2 was doc-by-code: Rust has no reflection; `size_of` cannot
     count `FilterTerm` fields. A manual constant list only checks
     fields already remembered by the author.
  5. The failure mode is plausible, but the harness only catches
     "field added to harness but gate forgotten" — it does NOT
     catch "field added and harness/list forgotten," the actual
     scary case.
  6. Fake-field harness arm is unsound. `from_forward_decision`
     only sees real `FilterState`/`FilterTerm`. A synthetic match
     cannot drive real filter semantics without adding test-only
     fields to production structs.
  7. Do not parameterize `dscp_sensitive_filter_semantics_match`
     today — premature with one consumer.
  8. Policers orthogonal — keep runtime-shape comparison as-is.
  9. Architectural cost net negative as written.
  10. Do not touch legacy BPF helpers; settled rule per CLAUDE.md.
  Codex salvage: "rewrite as a narrower README contract plus a
  real DSCP harness instantiation, and explicitly drop the
  fake-field proof and the 'automatic field inventory' claim."

- AGY r1 (`review-mpni22am-c41y7k`): **PLAN-NEEDS-MAJOR** with
  congruent rewrite path. Key findings:
  1. Existing #1430 hooks verified.
  2. lo0 confirmed non-cacheable; no scope shift needed.
  3. ICMP type/code confirmed NOT in cache key (`parse_flow_ports`
     stores `(ident, 0)` for ICMP); proposed mechanism's ICMP
     premise was wrong.
  4. §4.2 is compile-time theater; PLAN-KILL §4.2 specifically.
  5. §4.3's negative-case arm "structurally impossible without
     polluting `FilterTerm`."
  6. Failure mode is real but disciplined PR review is the
     defense, not the harness.
  7. Lean: paste later for `dscp_sensitive_filter_semantics_match`.
  8. Net negative maintenance.
  Action plan: delete §4.2 entirely; delete §4.3 negative-case arm;
  add an in-source contract comment block on `FilterTerm` itself;
  keep the positive-case (DSCP) harness arm.

Both reviewers converge on: keep README contract + add a real DSCP
harness as the first instantiation, drop the speculative
PER_PACKET_MATCH_FIELDS list and the fake-field test.

## 1. Issue framing (UNCHANGED FROM v1)

PR #1430 closed the immediate filter-log enforcement gaps by treating
DSCP as cache-sensitive metadata. #1431 carries the round-5 follow-up
forward: TOS (non-DSCP bits), IPv4/IPv6 fragment fields, IPv4 IHL,
IP options, TCP flags, ICMP type/code, and any other future per-packet
match are NOT currently represented in `FilterTerm`. The wire
`FirewallTermSnapshot` and the Rust `FilterTerm` never carry them.
When any of these fields lands in the userspace AST, the implementer
must either add it to the session/flow-cache key or treat it as
cache-sensitive — and the codebase must make the wrong choice loud
rather than silent.

The required invariant from the issue, verbatim:

> When a filter match depends on packet fields that are not part of
> the cache key, the dataplane must not reuse a first-packet
> forwarding decision for later packets that can differ on those
> fields.

## 2. Scope after v1 review

This v2 plan adopts the Codex / AGY salvage path:

1. **README contract section** in `userspace-dp/src/filter/README.md`
   describing the cache-key invariant, listing every match field on
   the wire DTO and `FilterTerm` with explicit "cache-key" vs
   "cache-sensitive" classification, and pointing at the existing
   #1430 hooks as the runbook for path (b) — including the
   verified fact that `LocalDelivery` is non-cacheable so lo0
   filters do not need their own cache-sensitive gate.

2. **In-source contract block** as a doc comment on `FilterTerm`
   itself in `userspace-dp/src/filter/mod.rs`. This is the loud
   reviewer-facing tripwire — anyone adding a match field to
   `FilterTerm` will read the comment in the diff. AGY's
   recommendation: "place a loud, blocking comment right next to
   the fields." Same comment block placed on
   `FirewallTermSnapshot` in `protocol/security.rs` so the wire
   DTO also carries the contract.

3. **Reference tests + citations** — NOT a new harness module.

   `FlowCacheEntry::from_forward_decision` and `FlowCacheEntry`
   itself are `pub(super)` inside `afxdp::flow_cache`
   (`flow_cache.rs:134,228`), so a test under `filter/` cannot
   reach them without visibility churn. Codex r2 flagged this;
   v3 moves test additions into `afxdp/flow_cache_tests.rs` (the
   home of the existing bespoke gate tests at lines 643-745) and
   cites — not duplicates — the existing rotation + session-hit
   regression coverage.

   What the README runbook will cite as the canonical reference
   tests for the cache-sensitive arm:

   - Flow-cache insertion gate (input + output):
     - `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
       at `userspace-dp/src/afxdp/flow_cache_tests.rs:695`
     - `from_forward_decision_skips_cache_for_dscp_matched_output_filter`
       at `userspace-dp/src/afxdp/flow_cache_tests.rs:643`
   - Established-session re-evaluation:
     - existing coverage at `userspace-dp/src/afxdp/tests.rs:3184`
       (cited per Codex r2; v3 does not add a new test here).
   - Forwarding-rotation positional-ID immunity:
     - `input_dscp_filter_families_changed_ignores_positional_filter_id_change`
       at `userspace-dp/src/filter/tests.rs:1806`
       (cited per Codex r2 + AGY r2; v3 does not add a new test).

   v3 ships **two new tests**, not three, both in
   `userspace-dp/src/afxdp/flow_cache_tests.rs`:

   - `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
     — same as the existing input-gate test but written explicitly
     in the runbook style the README cites. Acts as the "this is
     what a new-field test should look like" reference.
   - `dscp_output_gate_blocks_flow_cache_insertion_via_runbook_pattern`
     — same for output.

   If reviewers conclude even these two are redundant with the
   existing `643/695` tests, they can be dropped and the README
   simply cites the existing tests directly. **PLAN-MINOR**
   choice — both options are acceptable.

   No `PER_PACKET_MATCH_FIELDS` constant list, no `trait
   PerPacketMatchField`, no fake-field negative-case test.

4. **What is explicitly NOT in scope** (changed from v1):
   - PER_PACKET_MATCH_FIELDS constant list — DELETED. Codex r1 and
     AGY r1 both flagged it as compile-time theater. Manual list
     plus `size_of` cannot count `FilterTerm` fields; Rust has no
     reflection for this.
   - Trait `PerPacketMatchField` — DELETED. Documentation in code,
     not enforcement.
   - Fake-field negative-case harness arm
     (`cache_sensitive_harness_fake_field_uncovered_fails`) —
     DELETED. AGY r1 and Codex r1 both pointed out: cannot
     synthesize a per-packet match field without polluting
     `FilterTerm` layout; if you mock the matching engine, you're
     testing the harness, not the dataplane.
   - lo0 DSCP "gap" closure — DELETED FROM CONCERN. Verified:
     `LocalDelivery` is non-cacheable
     (`types/forwarding.rs::is_cacheable` returns false for it),
     and lo0 filter evaluation runs per-packet on both miss and
     hit paths at `poll_descriptor/mod.rs:700,1153`. The README
     contract documents this so a future reader does not chase
     the same false alarm.
   - Parameterizing `dscp_sensitive_filter_semantics_match`.
     Both reviewers said "paste later when the second cache-
     sensitive field actually lands."

## 3. What's already shipped / partially batched (UNCHANGED)

Reference call sites for the #1430 pattern:

- `FilterTerm.dscp_match_enabled` / `dscp_bitmap` —
  `userspace-dp/src/filter/mod.rs:61-62`
- `Filter.has_dscp_match_terms` aggregate —
  `userspace-dp/src/filter/mod.rs:117`
- Per-interface DSCP-match sets on `FilterState` —
  `userspace-dp/src/filter/mod.rs:423,437`
- `interface_input_filter_has_dscp_match` /
  `interface_output_filter_has_dscp_match` helpers —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:177,189`
- Flow-cache insertion gate using both helpers —
  `userspace-dp/src/afxdp/flow_cache.rs:297-309`
- Session-hit DSCP re-evaluation —
  `userspace-dp/src/afxdp/poll_descriptor/mod.rs:217-244`
- Rotation purge —
  `userspace-dp/src/afxdp/worker/loop_body/mod.rs:295-330`
- `input_dscp_filter_families_changed()` —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:167-175`
- `filter_term_semantics_match()` /
  `dscp_sensitive_filter_semantics_match()` —
  `userspace-dp/src/filter/engine/cache_sensitive.rs:104-143`
- DSCP flow-cache regression tests —
  `userspace-dp/src/afxdp/flow_cache_tests.rs:643-745`
- DSCP rotation tests —
  `userspace-dp/src/filter/tests.rs:1733-2000`

The 5-tuple session/flow-cache key —
`userspace-dp/src/session/key.rs:9-17`:

```rust
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}
```

ICMP key derivation (corrected from v1) — for `PROTO_ICMP` and
`PROTO_ICMPV6`, `parse_flow_ports` reads `frame[l4+4..l4+6]` and
stores `(identifier, 0)` (`userspace-dp/src/afxdp/frame/inspect.rs:225`).
ICMP type and code are NOT in the session key. An ICMPType /
ICMPCode filter field would be cache-sensitive unless `SessionKey`
or metadata are extended.

`LocalDelivery` cacheability (corrected from v1) —
`userspace-dp/src/afxdp/types/forwarding.rs:196` shows
`is_cacheable()` returns true only for `ForwardCandidate` and
`FabricRedirect`. `LocalDelivery`-disposition packets do not enter
the flow-cache and lo0 filter evaluation runs per-packet, so lo0
filters do not need a per-interface `has_dscp_match` set.

## 4. Concrete design (v2)

### 4.1 README contract section

Add a new section to `userspace-dp/src/filter/README.md` titled
**"Cache-key invariants for per-packet match fields"**. Required
content:

1. **The invariant** (issue's wording verbatim):
   *When a filter match depends on packet fields that are not part
   of the cache key, the dataplane must not reuse a first-packet
   forwarding decision for later packets that can differ on those
   fields.*

2. **The cache key**: cite the six fields of `SessionKey`
   (`addr_family`, `protocol`, `src_ip`, `dst_ip`, `src_port`,
   `dst_port`). For ICMP, document that `src_port` carries the
   identifier and `dst_port` is zero — ICMP type and code are NOT
   in the key.

3. **The classification table** for every match criterion on
   `FirewallTermSnapshot` and `FilterTerm` today (per Codex r2:
   reword to "every match criterion," not "every field," because
   `action`, `count`, `log`, `policer`, `routing_instance`,
   `forwarding_class`, `dscp_rewrite` are forwarding actions and
   modifiers — they do not participate in match-time key lookup
   and so are out of scope for cache-key invariants):

   | Match criterion | In cache key? | Notes |
   |-----------------|---------------|-------|
   | `source_addresses` / `source_v4` / `source_v6` | yes | `src_ip` in `SessionKey` |
   | `destination_addresses` / `dest_v4` / `dest_v6` | yes | `dst_ip` |
   | `protocols` / `protocol_bitmap` (+ `protocol_match_enabled`) | yes | `protocol` |
   | `source_ports` | yes (TCP/UDP); ICMP-special | `src_port` carries ICMP identifier |
   | `destination_ports` | yes (TCP/UDP); ICMP-zero | `dst_port` is 0 for ICMP |
   | `dscp_values` / `dscp_bitmap` (+ `dscp_match_enabled`) | NO — cache-sensitive | see #1430 pattern below |
   | (future) `tos_match` / ECN bits (non-DSCP TOS) | NO — cache-sensitive | TOS lower bits and ECN vary per packet; #1431 names this |
   | (future) `tcp_flags_match` | NO — cache-sensitive | TCP flags vary per packet |
   | (future) `is_fragment` / fragment offset / MF | NO — cache-sensitive | only first fragment carries L4 |
   | (future) `ihl_match` / IP options | NO — cache-sensitive | IHL varies per packet |
   | (future) `icmp_type_match` / `icmp_code_match` | NO — cache-sensitive (today) | could be promoted to cache-key by adding (type, code) to `SessionKey` for ICMP sessions |
   | (future) `flex_match` | NO — cache-sensitive | byte-offset match, fully per-packet |

4. **The runbook for path (b) — cache-sensitive**: list the eight
   call sites in §3 above and the four-step recipe:
   - extend the per-interface `iface_filter_v{4,6}_has_<X>_match`
     set on `FilterState`;
   - add a `Filter.has_<X>_match_terms` aggregate flag;
   - add a `interface_input_filter_has_<X>_match` /
     `_output_` helper (or thread the new flag through one
     general helper if the existing DSCP one is generalized
     later);
   - wire the gate at `flow_cache.rs:297-309`, the re-eval at
     `poll_descriptor/mod.rs:217-244`, and the rotation purge at
     `worker/loop_body/mod.rs:295-330`;
   - extend the existing gate tests in
     `userspace-dp/src/afxdp/flow_cache_tests.rs` with a new
     `<X>_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
     and `_output_gate_*` pair (Codex r2: `FlowCacheEntry` is
     `pub(super)` inside `afxdp::flow_cache`, so tests must live
     in `afxdp/`, not `filter/`).

5. **The runbook for path (a) — extend `SessionKey`**: brief
   pointer to the prerequisites — HA sync compatibility, session-
   table reverse indices, flow_cache key derivation, session
   expiry hash, key comparison cost. Path (a) requires a tracker
   issue and review against `session/key.rs`.

6. **lo0 reminder** (one paragraph per Codex r2): host-bound
   traffic resolves to `ForwardingDisposition::LocalDelivery`,
   which `is_cacheable()` returns `false` for at
   `userspace-dp/src/afxdp/types/forwarding.rs:196`. lo0 filter
   evaluation runs per-packet at
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs:700` (session-
   hit path) and `:1153` (miss path). lo0 filters therefore do
   NOT need a per-interface cache-sensitive set — flow-cache
   never holds a lo0 decision in the first place. Stated to save
   future readers the false-alarm cycle that v1 spent.

### 4.2 In-source contract block

Add a doc-comment block on `FilterTerm` in
`userspace-dp/src/filter/mod.rs` directly above the struct:

```rust
// ============================================================
// CACHE-KEY INVARIANT (#1431)
//
// Every field on FilterTerm that participates in matching MUST
// be classified:
//
//   (a) IN cache key — extend SessionKey in session/key.rs AND
//       prove key stability for HA sync, session-table reverse
//       indices, flow_cache key derivation, expiry hash, and
//       reverse-NAT lookup. File a tracker issue.
//
//   (b) NOT in cache key (cache-sensitive) — wire the #1430
//       runbook: per-interface has_<X>_match set, Filter
//       aggregate flag, flow-cache insertion gate, established-
//       session re-evaluation, and forwarding rotation purge.
//       See userspace-dp/src/filter/README.md "Cache-key
//       invariants for per-packet match fields."
//
// Skipping this classification SILENTLY breaks flow-cache: a
// first-packet decision gets reused for later packets that
// can differ on the new field. PR #1430 fixed this for DSCP;
// the same class of bug applies to any future per-packet match.
// ============================================================
```

Mirror block placed above `FirewallTermSnapshot` in
`userspace-dp/src/protocol/security.rs` so the wire DTO also
carries the contract.

### 4.3 DSCP-positive runbook tests

Add **two** new tests to
`userspace-dp/src/afxdp/flow_cache_tests.rs` (the existing home
of the bespoke DSCP gate tests at lines 643/695, and the only
module where `FlowCacheEntry::from_forward_decision`'s
`pub(super)` visibility is reachable — Codex r2 finding):

- `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern` —
  builds a realistic `FirewallFilterSnapshot` with a DSCP match
  term, binds it as v4 input filter on an interface, drives
  `FlowCacheEntry::from_forward_decision`, asserts `None`.
  Written in the explicit runbook style the new README section
  cites — acts as the canonical "this is what a new-field
  test should look like" reference.
- `dscp_output_gate_blocks_flow_cache_insertion_via_runbook_pattern`
  — same for output.

These two extend coverage of the existing bespoke tests at
`flow_cache_tests.rs:643-745`; we keep the bespoke tests and
add these as the runbook references.

Dropped from v2 (per Codex r2 + AGY r2):
- `dscp_rotation_does_not_fire_on_positional_id_change` —
  duplicate of the existing
  `input_dscp_filter_families_changed_ignores_positional_filter_id_change`
  at `filter/tests.rs:1806`. Cite in the README runbook
  instead.

Cited from existing coverage (per Codex r2; no new test added):
- session-hit DSCP re-evaluation: `afxdp/tests.rs:3184`.

Two new tests total. All positive-case. No fake field, no
constant list, no trait.

## 5. Public API preservation

- `FilterTerm` struct layout — UNCHANGED. Only a new doc-comment
  block above.
- `Filter` — UNCHANGED.
- `FilterState` — UNCHANGED.
- `interface_input_filter_has_dscp_match` /
  `interface_output_filter_has_dscp_match` /
  `input_dscp_filter_families_changed` — signatures UNCHANGED.
- `FlowCacheEntry::from_forward_decision` — body UNCHANGED.
- `FirewallTermSnapshot` (wire DTO) — UNCHANGED. New doc-comment
  block above.
- `SessionKey` — UNCHANGED.

This PR is documentation + tests. No runtime change.

## 6. Hidden invariants the change must preserve

1. Side-effect ordering on cached hits, re-eval, and rotation
   purge — already preserved by the #1430 hooks; harness only
   exercises them.
2. Allocation rules on the hot path — harness lives in
   `#[cfg(test)]`, no hot-path impact.
3. HA sync portability — out of scope; README documents path (a)
   requires HA sync review.
4. Stable-name purge comparison — exercised by the existing
   `input_dscp_filter_families_changed_ignores_positional_filter_id_change`
   test at `userspace-dp/src/filter/tests.rs:1806` (cited from
   the README runbook; no new test added).
5. Three-color policer runtime shape — already in
   `dscp_sensitive_filter_semantics_match`; not regenerated.
6. lo0 filters — documented as non-cacheable so future readers
   don't redo the v1 false-alarm investigation.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression risk | NONE | Doc + cfg(test) tests only. |
| Lifetime / borrow-checker risk | NONE | New tests use existing pub(crate) helpers; no new lifetimes. |
| Performance regression risk | NONE | No hot-path changes. |
| Architectural mismatch risk | LOW | Both reviewers explicitly endorsed this salvage path. |

## 8. Test plan

- `cargo build --release` clean.
- `cargo test --release` — full suite passes; existing DSCP
  flow-cache tests at `flow_cache_tests.rs:643-745` and DSCP
  rotation tests at `filter/tests.rs:1733-2000` still pass.
- New tests (two, both in `userspace-dp/src/afxdp/flow_cache_tests.rs`
  per Codex r2's visibility note):
  - `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
  - `dscp_output_gate_blocks_flow_cache_insertion_via_runbook_pattern`
- Cited existing tests (no duplication added):
  - rotation positional-ID immunity: `filter/tests.rs:1806`
  - session-hit re-eval: `afxdp/tests.rs:3184`
  - bespoke gate tests (already in tree): `afxdp/flow_cache_tests.rs:643,695`
- 5× flake check on the two new tests.
- `go test ./...` — no Go changes; regression coverage only.
- Smoke on `loss:xpf-userspace-fw0/1` — v4+v6, push+reverse,
  CoS-off + per-class. Pure regression — zero behavior delta is
  expected.

## 9. Out of scope (UPDATED from v1)

- Adding any new per-packet match field to `FilterTerm` or the
  wire DTO. Each such addition is a separate PR that satisfies
  the issue's acceptance criteria against the README contract.
- Extending `SessionKey`. Path (a) requires HA sync review and
  a dedicated PR.
- `PER_PACKET_MATCH_FIELDS` constant list, `PerPacketMatchField`
  trait, fake-field harness arm — explicitly removed after v1
  review.
- lo0 filter "DSCP gap" — verified non-existent.
- Parameterizing `dscp_sensitive_filter_semantics_match` —
  defer to whenever the second cache-sensitive field lands.

## 10. Validation — pre-PR

- `cargo build --release` clean.
- `cargo test --release filter::` clean.
- `cargo test --release flow_cache` clean.
- 5× flake on each new test.
- Go suite clean.
- Smoke matrix (Pass A + Pass B) per CLAUDE.md.

## 11. Round-2 resolutions

- **Q1 in-source block surface** — resolved by both reviewers:
  block doc-comment above struct is correct. Optional per-field
  tag like `// CACHE-INVARIANT: path (b)` welcome but not
  required.
- **Q2 file location** — resolved: gate tests go in
  `userspace-dp/src/afxdp/flow_cache_tests.rs` per Codex r2's
  `pub(super)` visibility note (NOT `filter/tests.rs` or a new
  `filter/cache_invariant_harness.rs`).
- **Q3 ICMP wording** — both reviewers confirmed v2's table is
  accurate against `frame/inspect.rs:225`.
- **Q4 positional-ID duplicate** — both reviewers confirmed the
  proposed test duplicates `filter/tests.rs:1806`; v3 drops it
  and cites the existing test in the README runbook.
- **Q5 theater check** — both reviewers (Codex r2 PLAN-NEEDS-MINOR,
  AGY r2 PLAN-READY) accept v2 as not-theater conditional on
  the v3 fixes.
- **Q6 lo0 note** — keep, but one paragraph with explicit
  `is_cacheable` + `poll_descriptor` line refs (v3 update
  applied to §4.1 #6).

## 12. Residual risk (AGY r2 framing)

Rust does not support compile-time structural reflection over
struct field lists. A developer adding a future match field could
still ignore the in-source block AND the README. The defense is
diff-visibility on PR review — placing the contract on both
`FilterTerm` (in-memory) and `FirewallTermSnapshot` (wire DTO)
maximizes the surface a reviewer sees in the diff.

If reviewers conclude even v3 is theater, the minimum-viable
fallback remains: ship the doc-comment block on `FilterTerm` +
`FirewallTermSnapshot` only, no test changes, and close #1431
with that as the "documents whether the new match field is in
the cache key" acceptance criterion satisfied.
