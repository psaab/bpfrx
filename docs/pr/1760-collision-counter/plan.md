# #1760 — NAT reverse-key 1:N collision telemetry counter

**Status: DRAFT v1 — pending adversarial plan review (Codex + Gemini + Claude SMR)**

## 1. Issue framing

#1760 is the correctness tracker spun out of the #1758 research: the
secondary reverse indices in the per-worker `SessionTable`
(`nat_reverse_index`, and the dual reverse entry's `key_to_handle`) are
**single-valued** — one secondary key `K` → one session handle. When two
*live* sessions derive the same `K` (reachable under interface-mode SNAT,
DNAT-to-shared-backend, NAT64, and non-bijective static NAT — all leave
`rewrite_src_port = None`), the index can only point at one of them. The
per-refresh re-assert in `index_forward_nat_key` (preserved
byte-identically by #1753, now PER-PACKET for established flows) is
last-writer-wins arbitration that does not represent the 1:N reality, and
on expiry the value-guarded removal can delete `K` while a second live
session still needs it → permanent reverse-path corruption for that flow.

The #1758 research recommended **measuring incidence before investing in
a structural fix**. This issue/PR ships ONLY that measurement: a telemetry
counter that fires when an index insert displaces a *different* handle for
the same `K`. The structural fix (multi-valued index / install-time
collision policy) is explicitly **deferred** to its own future `/research`
per the #1758 finding. **#1760 stays OPEN after this PR merges** — a
counter is observability, not a resolution.

## 2. Honest scope / value framing

The win is purely observability: it lets us decide, with production data,
whether the structural fix (a #1207/#1545/#1317-class rearchitecture
touching the conntrack reverse-lookup contract + HA sync) is worth
building, or whether the collision is rare enough to document-accept
(pool-mode SNAT is the proven-immune safe mode). At absolute scale the
runtime cost is ~0: `HashMap::insert` already returns the displaced value,
so the detection is a branch on a value we already have on the hot path —
no extra map lookup, no reintroduced per-packet cost that #1753 removed.

*If reviewers conclude the counter is not worth even this near-zero
hot-path touch (e.g. the upper-bound proxy is too noisy to be
actionable), PLAN-KILL is an acceptable verdict.*

## 3. What's already shipped / partially batched

- #1753 (Path E) made the secondary-index ADD re-assert run on every
  `update_session` refresh — established flows hit `index_forward_nat_key`
  **per packet**, so the detection site is hot. The counter MUST be
  hot-path-cheap (the cheap-proxy design below satisfies this).
- The per-worker `SessionTable` already carries plain-`u64` counters
  (`create_drops` at `session/mod.rs:157`, `delta_drops` at `:158`),
  incremented with `saturating_add` on the worker-owned table (no
  atomics). The new counter follows that exact shape. (Note: those two
  are not yet surfaced to status; this PR does not change that — it adds
  the new counter AND its full surface, the first session-table counter
  to be plumbed end-to-end.)
- `session_table_entries` / `max_sessions` are the canonical per-worker
  session-table values already plumbed end-to-end:
  `SessionTable::len()`/`max_sessions()` → `wr_counters` at
  `afxdp/worker/loop_body/mod.rs:338-339` → `WorkerRuntimeCounters`
  (`worker_runtime.rs:69-70`) → `WorkerRuntimeAtomics` publish/snapshot →
  `WorkerRuntimeStatus` (`protocol/binding.rs:50-54`) → Go
  `WorkerRuntimeStatus` (`protocol.go:870-871`) → summed into top-level
  `ProcessStatus.session_table_entries` in `server/helpers.rs:48-53` →
  Go top-level `ProcessStatus` (`protocol.go:561`) → Prometheus
  (`metrics_userspace.go:142-152`, `:533-536`) + `show system buffers`
  (`buffersfmt.go:258-265`). **This PR mirrors that path exactly for the
  new counter.**

## 4. The defect-observable site (code walk)

`index_forward_nat_key` → `index_forward_nat_key_parts`
(`session/mod.rs:1204-1234`) is the single choke point where every
forward-entry secondary index insert happens. For a non-reverse entry it
does up to three inserts into single-valued maps:

```rust
self.nat_reverse_index.insert(reverse_wire_key(key, decision.nat), handle); // :1217
// reverse_canonical (when != key)                                          // :1221
// forward_wire (when != key) -> forward_wire_index                         // :1225
```

For a reverse entry it inserts into `reverse_translated_index` (`:1214`).

The 1:N collision per #1758 §4/§4a manifests at **`nat_reverse_index`**
(the reverse_wire_key insert at `:1217` — this is THE site the four NAT
vectors collide on) and, for the dual reverse entry, at the primary
`key_to_handle` insert. Per the #1758 disposition and the "cheap proxy"
guidance, the counter targets the `nat_reverse_index` reverse_wire insert
— the canonical, NAT-mode-reachable collision site. See §11 Q2 for the
explicit reviewer decision on whether to also instrument
`reverse_canonical`, `forward_wire_index`, `reverse_translated_index`,
and/or `key_to_handle`.

## 5. Concrete design

### 5.1 Detection — cheap-proxy upper bound (default)

`HashMap::insert` returns the previously-stored value. Replace the bare
insert at `index_forward_nat_key_parts:1217` with a displaced-handle
check:

```rust
let prev = self
    .nat_reverse_index
    .insert(reverse_wire_key(key, decision.nat), handle);
if matches!(prev, Some(old) if old != handle) {
    self.nat_reverse_key_collisions =
        self.nat_reverse_key_collisions.saturating_add(1);
}
```

Zero extra lookup; the displaced value is already returned by `insert`.

**This is an UPPER BOUND on true live collisions.** It also counts benign
stale-handle overwrites — e.g. a freed-then-reused session whose old
handle still lingered in the index, or a re-assert that re-wins `K` after
a transient displacement. The counter therefore answers "how often does a
*different* handle occupy `K` at insert time" — which is a strict
superset of "two live sessions share `K`". This is documented as the
counter's semantics (§5.4) and is the right first signal: a counter that
stays at 0 in production proves the collision never fires; a nonzero
counter is the trigger to invest in the precise structural fix. (Per
#1758 Claude-SMR rec 3 and the issue's "cheap proxy preferred default".)

### 5.2 Precise variant (NOT chosen unless reviewers argue otherwise)

A TRUE live collision (displaced handle is still a live slab entry for a
*different* session) would require an extra slab lookup per re-assert on
the per-packet path #1753 just optimized — reintroducing exactly the
per-packet cost the research warned against (§11 Q4 of #1758). Default is
the cheap proxy; §11 Q1 invites Codex/Gemini to overrule on the
cost/accuracy tradeoff.

### 5.3 Field + accessor

In `SessionTable` (`session/mod.rs` near `create_drops:157`):

```rust
/// #1760: upper-bound count of NAT reverse-key (nat_reverse_index)
/// collisions — a secondary-index insert displaced a DIFFERENT handle
/// for the same reverse key K. Counts benign stale-handle overwrites
/// too (strict superset of true 1:N live collisions); see plan §5.1.
/// Worker-owned, single-threaded — plain u64, no atomics.
nat_reverse_key_collisions: u64,
```

Initialised `0` in the constructor (next to `create_drops: 0`). Accessor:

```rust
pub fn nat_reverse_key_collisions(&self) -> u64 {
    self.nat_reverse_key_collisions
}
```

### 5.4 Plumbing (mirror session_table_entries exactly)

1. **Read into worker counters** —
   `afxdp/worker/loop_body/mod.rs` at the publish tick (~:338, beside
   `session_table_entries = sessions.len()`):
   `wr_counters.nat_reverse_key_collisions = sessions.nat_reverse_key_collisions();`
2. **WorkerRuntimeCounters** (`afxdp/worker_runtime.rs:59-71`): add
   `pub nat_reverse_key_collisions: u64,`
3. **WorkerRuntimeAtomics** (`worker_runtime.rs:112+`): add
   `pub nat_reverse_key_collisions: AtomicU64,`, init `::new(0)`,
   `store(..., Relaxed)` in `publish` (~:215), `load(Relaxed)` in
   snapshot (~:284). Cumulative counter → simple Relaxed (matches
   `session_table_entries`, NOT the seqlock window tuple).
4. **WorkerRuntimeStatus (Rust)** (`protocol/binding.rs:49+`):
   `#[serde(rename = "nat_reverse_key_collisions", default)] pub nat_reverse_key_collisions: u64,`
5. **WorkerRuntimeStatus (Go)** (`protocol.go:870+`):
   `NatReverseKeyCollisions uint64 \`json:"nat_reverse_key_collisions,omitempty"\``
6. **Top-level ProcessStatus aggregation (Rust)** (`server/helpers.rs:48`):
   sum across `worker_runtime` like `session_table_entries`:
   `state.status.nat_reverse_key_collisions = worker_runtime.iter().map(|w| w.nat_reverse_key_collisions).sum();`
   Field added to `control.rs` ProcessStatus (`#[serde(rename = ...)]`)
   and to lifecycle default init (`server/lifecycle.rs:96` neighborhood).
7. **Top-level ProcessStatus (Go)** (`protocol.go:561+`):
   `NatReverseKeyCollisions uint64 \`json:"nat_reverse_key_collisions,omitempty"\``
8. **Prometheus** (`pkg/api`): add descriptor
   `xpf_userspace_session_nat_reverse_key_collisions_total`
   (CounterValue, top-level aggregate) in `metrics_descriptors.go` +
   `metrics.go` field + `Describe` + emit in
   `metrics_userspace.go`. Per-worker label variant
   `xpf_userspace_worker_session_nat_reverse_key_collisions_total`
   alongside the per-worker `workerSessionTableEntries` emit (~:533).
9. **`show system buffers`** (`buffersfmt.go`): add label
   `systemBufferLabelNatReverseKeyCollisions = "NAT reverse-key collisions"`
   and `appendCounter(systemBufferLabelNatReverseKeyCollisions, "aggregate", status.NatReverseKeyCollisions)`
   in `systemBufferCounterRows` (counter only — no capacity denominator,
   so it belongs in the Counters section, not the Utilization table).

## 6. Public API preservation

No existing public signature changes. `index_forward_nat_key` /
`index_forward_nat_key_parts` keep their signatures (body-only change).
New additive items only: one `SessionTable` field + one accessor, additive
struct fields (all `serde(default)` / `omitempty` for wire back-compat per
`feedback_wire_protocol_both_sides`), one new Prometheus desc pair, one
new buffers counter row. Older Go daemon reading new Rust → field absent →
0 (default). Older Rust daemon read by new Go → field absent → 0.

## 7. Hidden invariants the change must preserve

- **No behavior change to indexing.** The insert still happens
  identically; we only inspect its already-returned displaced value. The
  removal path, the read-side re-validation, and the load-bearing
  re-assert are untouched (removing the re-assert is explicitly NOT this
  PR — §10).
- **Hot-path allocation rule:** no allocation, no extra lookup, no atomics
  on the worker-owned table — `saturating_add` on a plain u64 (matches
  `create_drops`/`delta_drops`).
- **HA sync portability:** the counter is per-worker diagnostic only; it
  is NOT part of any synced session delta or snapshot. `upsert_synced`
  also routes through `index_forward_nat_key` — synced installs that
  displace a handle will increment the counter on the receiving node too,
  which is correct (a synced install displacing a live local handle is
  itself a collision worth counting).
- **Counter monotonicity for Prometheus `rate()`:** saturating cumulative
  u64, published with Relaxed store of the latest value (never reset,
  never decremented) — same contract as `session_table_entries`'s sibling
  cumulative counters. Emitted as CounterValue.
- **Serde back-compat both sides** (§6).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Body-only change; insert semantics identical; counter is write-only diagnostic, read by nothing in the dataplane. |
| Lifetime / borrow-checker | LOW | `insert` already takes `&mut self`; the returned `Option<u32>` is `Copy`, no borrow conflict; increment is on the same `&mut self`. |
| Performance regression | LOW | No extra lookup/alloc/atomic on the per-packet re-assert; one branch + one `saturating_add` on a value already in hand. Smoke must show ZERO throughput/retrans delta (that IS the pass criterion). |
| Architectural mismatch (#961/#946-Phase-2) | LOW | This is deliberately NOT the structural fix; it's a scoped observability primitive endorsed by all three #1758 reviewers as the right first step. The trap would be smuggling the multi-valued index in here — explicitly out of scope (§10). |

## 9. Test plan

- `cargo build` clean (release).
- `cargo test --release` full suite green.
- **New unit test** `nat_reverse_key_collision_counter_increments` in
  `session/tests.rs`: construct the #1758 interface-mode collision (two
  sessions deriving the same reverse_wire_key `K` via interface-mode SNAT
  decisions), install both, assert `nat_reverse_key_collisions() == 1`
  after the second displaces the first; a single session installing once
  leaves it at 0; a same-handle re-assert (refresh) does NOT increment
  (the `old != handle` guard). 5/5 flake loop on this named test.
- Go suite green (SHORT TMPDIR to dodge >108-char unix socket paths).
  Specifically covers `pkg/api` metrics tests, `pkg/dataplane/userspace`
  buffersfmt + protocol round-trip, `pkg/cli` + `pkg/grpcapi` `show
  system buffers` golden tests (update goldens if they assert exact
  counter-row sets).
- **Smoke matrix on loss cluster** (observability-only PR → expect ZERO
  throughput/retrans change vs baseline; that no-regression IS the pass
  criterion): Pass A CoS-off v4+v6 push+`-R` + `-P12 -R` line-rate; Pass
  B per-class 5201-5206. Confirm the counter is readable via `show system
  buffers` and Prometheus `/metrics`.
- `make test-failover` (session-path change → mandatory per CLAUDE.md).

## 10. Out of scope (explicitly)

- **The structural fix is OUT OF SCOPE.** No multi-valued / chained
  reverse index, no install-time collision-refusal/disambiguation policy.
  Deferred to its own future `/research` per #1758 — it touches the
  conntrack reverse-lookup contract + HA sync and needs differential
  tests. **#1760 stays OPEN after this PR** (counter ≠ fix).
- **Removing the re-assert is NOT done** — it is load-bearing
  last-writer-wins arbitration; removing it trades one corruption for
  another (#1758 §5). Untouched here.
- No change to the proven-immune pool-mode allocator.
- No change to #1753 (correct parity).
- The precise (live-slab-confirmed) collision counter is deferred unless
  reviewers overrule (§5.2).

## 11. Open questions for adversarial review

1. **Cheap-proxy vs precise.** Is the cheap upper-bound proxy (count any
   `old != handle` displacement) the right default, or does the
   stale-handle noise make it un-actionable enough to justify the extra
   slab lookup per re-assert (precise variant) despite the per-packet
   cost #1753 removed? Default is cheap; argue for precise only with a
   concrete noise-magnitude estimate. PLAN-KILL if you believe the proxy
   is so noisy it can never inform the fix decision.
2. **Which indices to instrument.** Plan counts only the
   `nat_reverse_index` reverse_wire insert (`:1217`) — the canonical
   site all four NAT vectors collide on (#1758 §4/§4a). Should it ALSO
   count `reverse_canonical` (`:1221`), `forward_wire_index` (`:1225`),
   `reverse_translated_index` (`:1214`), and/or the `key_to_handle`
   primary insert (the dual reverse-entry collision, #1758 §4a)? Argue
   for a separate counter per index vs one aggregate, given the operator
   only needs "does the 1:N collision fire". One counter on
   `nat_reverse_index` is the proposed minimal-sufficient signal — break
   it if reverse_translated/key_to_handle collisions are materially
   distinct phenomena an operator must disambiguate.
3. **Should the re-assert (refresh) path be excluded or distinguished?**
   The per-packet refresh re-asserts `K → same handle` for an established
   flow, which the `old != handle` guard already filters out (no
   increment). But a refresh that re-WINS `K` from a colliding peer
   (`old != handle`, displacing the peer) WILL increment — which is
   exactly the load-bearing re-arbitration #1758 describes, and arguably
   the most interesting event to count. Confirm the guard semantics are
   what we want, or argue the re-assert re-arbitration deserves its own
   distinguished counter.
4. **Wire/serde back-compat.** Are the additive `serde(default)` /
   `omitempty` fields sufficient for mixed Rust/Go daemon versions during
   rolling upgrade, per `feedback_wire_protocol_both_sides`? Any field I
   must add on BOTH protocol.rs AND protocol.go that the plan misses?
5. **Prometheus semantics.** Is a top-level aggregate CounterValue plus a
   per-worker labelled CounterValue the right surface, or is the
   per-worker variant redundant noise? Is `_total` the correct suffix for
   a saturating cumulative counter that (theoretically) could be reset by
   a worker restart replacing its atomics?
6. **Is the counter worth the touch at all?** Given pool-mode SNAT is the
   immune safe mode and the read side self-defends (miss, not
   misroute), is measuring incidence valuable enough to justify even a
   near-zero hot-path branch + the full plumbing surface, or should we
   document-accept and PLAN-KILL?
