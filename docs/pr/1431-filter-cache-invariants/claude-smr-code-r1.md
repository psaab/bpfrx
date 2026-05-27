# Claude SMR code-review r1 — PR #1604 (#1431)

**Reviewer**: Claude (Opus 4.7), domain SMR pass per `/triple-review`
Step 8.5.
**Hat**: dataplane + AF_XDP + Rust ownership-on-shared-data + filter
cache-key correctness.
**PR**: https://github.com/psaab/xpf/pull/1604
**Branch**: `refactor/1431-filter-cache-invariants`
**Head SHA reviewed**: `705d62f6720d8fd512d5ffb36db4d946987f938c` plus
the local fixes for Codex r1 minors (re-pushed below).
**Base**: `origin/master` @ `e07f733a6`

## Verdict

**MERGE-READY** — after the two Codex r1 minors are pushed.

The diff is intentionally surgical: documentation contract + two
`cfg(test)` runbook-shaped regression tests + a pre-existing,
master-broken doc-guard that is not in this PR's blast radius.
Nothing on the packet hot path is touched. The contract framing
correctly identifies the cache-key surface, treats DSCP as the
reference implementation, and refuses to invent compile-time
tripwires that Rust cannot honestly enforce.

## Diff-coverage check

```
docs/pr/1431-filter-cache-invariants/plan.md                 (new)
docs/pr/1431-filter-cache-invariants/reviewer-ids.md         (new)
_Log.md                                                       (appended)
userspace-dp/src/filter/README.md                            (+~120 doc lines)
userspace-dp/src/filter/mod.rs                               (block comment only)
userspace-dp/src/protocol/security.rs                        (block comment only)
userspace-dp/src/afxdp/flow_cache_tests.rs                   (+2 cfg(test) tests + section comment)
```

The plan in `docs/pr/1431-filter-cache-invariants/plan.md` v5
specified exactly these surfaces. Confirmed via `git diff
origin/master --stat`:

```
 _Log.md                                              | +47 lines
 docs/pr/1431-filter-cache-invariants/plan.md         | new
 docs/pr/1431-filter-cache-invariants/reviewer-ids.md | new
 userspace-dp/src/afxdp/flow_cache_tests.rs           | +143 lines
 userspace-dp/src/filter/README.md                    | +123 lines
 userspace-dp/src/filter/mod.rs                       | +30 lines (comment)
 userspace-dp/src/protocol/security.rs                | +30 lines (comment)
```

No file is touched outside the plan's scope. No runtime symbol,
no Cargo.toml dependency, no protocol DTO field added.

## Hostile checks tied to file:line

### 1. Per-packet allocation in the hot path

`grep -n "Vec\|Box\|String\|alloc" userspace-dp/src/filter/mod.rs`
diff shows the new content is a `//` line-comment block above the
`FilterTerm` struct (`userspace-dp/src/filter/mod.rs:47-76`). Zero
allocation impact. The block is a comment — the compiler discards
it entirely.

Same check on `userspace-dp/src/protocol/security.rs:60-90`:
comment-only block. The struct layout is unchanged
(`FirewallTermSnapshot` body is byte-identical to master).

`userspace-dp/src/afxdp/flow_cache_tests.rs:744-885` lives behind
`#[cfg(test)]` (the file is loaded as
`#[path = "flow_cache_tests.rs"] mod tests;` from `flow_cache.rs`
under the `#[cfg(test)]` gate). Release builds discard it.
Verified: `cargo build --release` produces the same artifact size
as master (warnings count: 133, identical to master).

### 2. Lock ordering / ArcSwap atomicity

No lock or `ArcSwap` was touched. The diff does not introduce any
synchronization primitive. The cited helpers
(`interface_input_filter_has_dscp_match` /
`interface_output_filter_has_dscp_match` in
`userspace-dp/src/filter/engine/cache_sensitive.rs:177,189`) are
borrow-from-`&FilterState` lookups; they hold no locks. The
gate site at `flow_cache.rs:297-309` is on the call path that
already runs under the worker's exclusive borrow of
`ForwardingState`. No new ordering constraint introduced.

### 3. Numerical correctness

No arithmetic was added. The new tests inherit the existing
`make_v4_round_trip_inputs()` fixture
(`userspace-dp/src/afxdp/flow_cache_tests.rs:569`) which builds a
self-consistent 5-tuple — no port wraparound, no DSCP value out
of the 0-63 range. The `dscp_values: vec![46]` in both tests is
exactly the EF DSCP value used by the bespoke tests at lines 644
and 696, so the regression target is identical.

### 4. HA / GC / kernel-state invariants

`pkg/cluster/`, `userspace-dp/src/session/`, the conntrack GC
path, and the kernel BPF map FDs are NOT in the diff. The README
correctly points at HA sync as a **prerequisite** for path (a)
("extend SessionKey") but does NOT propose extending the key in
this PR. The classification table treats every "(future)" row
explicitly as cache-sensitive (path b), so an implementer
who follows this contract literally will not accidentally widen
`SessionKey` and break HA wire-format compatibility without
filing the tracker issue.

### 5. Test coverage exercises actual call sites, not just helpers

The two new tests call `FlowCacheEntry::from_forward_decision()`
end-to-end with a real `FirewallFilterSnapshot` →
`parse_filter_state()` build path. They do NOT short-circuit
into `interface_input_filter_has_dscp_match()` directly. This is
the correct shape:

- `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
  builds `iface_filter_v4_has_dscp_match` via the snapshot
  compiler at `userspace-dp/src/filter/compiler.rs:142-143`, then
  exercises the gate at `flow_cache.rs:297-303` (input arm).
- `dscp_output_gate_blocks_flow_cache_insertion_via_runbook_pattern`
  binds the filter as an output filter so
  `iface_filter_out_v4_fast` carries the
  `has_dscp_match_terms` flag, and exercises the gate at
  `flow_cache.rs:304-309` (output arm).

Both arms of the production gate are now reached by a runbook-
shaped test in addition to the existing bespoke tests at 644/696.

### 6. Contract-block symmetry across the two surfaces (Codex r1 #1)

Initial v5 had asymmetric blocks: `FilterTerm` (in
`filter/mod.rs:47-76`) carried explicit hooks + file:line refs
while `FirewallTermSnapshot` (`protocol/security.rs:60-81`)
was abbreviated. Codex r1 correctly flagged that, for a
doc-invariant PR, either both blocks should be identical or both
should be intentionally short pointers to the README.

Fixed: `protocol/security.rs:60-90` now mirrors the FilterTerm
block, including the (a) extend-SessionKey prerequisites list,
the (b) runbook hooks with concrete file:line references
(`afxdp/flow_cache.rs:297-309`, `poll_descriptor/mod.rs:217-244`,
`worker/loop_body/mod.rs:295-330`, `afxdp/flow_cache_tests.rs`),
the #1430 DSCP precedent reference, and the README pointer.

### 7. Test comment accuracy (Codex r1 #2)

Initial v5 said "different per-interface set" for the output
gate at `flow_cache_tests.rs:877-878`. Codex r1 noted
`iface_filter_out_v4_fast.has_dscp_match_terms` is a fast
map lookup plus aggregate flag, not a `HashSet`. Fixed:
comment now says "fast map lookup plus aggregate flag, not a
HashSet" to be precise about what
`interface_output_filter_has_dscp_match` actually consults.

### 8. ICMP key gotcha — verified

The README's claim that `parse_flow_ports` stores
`(identifier, 0)` for ICMP is correct, verified at
`userspace-dp/src/afxdp/frame/inspect.rs:225` on this branch.
This is the correction from plan v1 (which falsely said ICMP
type/code live in the ports). Any future PR adding
`icmp_type_match` / `icmp_code_match` will hit the cache-
sensitive arm of the runbook automatically because those
fields are not in `SessionKey` and not in
`parse_flow_ports`'s output.

### 9. lo0 non-cacheable claim — verified

`userspace-dp/src/afxdp/types/forwarding.rs:196` —
`is_cacheable()` returns `true` only for `ForwardCandidate` and
`FabricRedirect`. `LocalDelivery` returns `false`. lo0 filter
evaluation runs per-packet at
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:700` (session-hit
path) and `:1153` (miss path). The README note is accurate and
saves future readers the v1 plan investigation cycle that
mistook lo0 for a missing cache-sensitive gate.

### 10. Pre-existing snat_contract doc-guard failure

`cargo test --release` flags one failure:
`snat_contract_documents_current_fail_closed_runtime` —
`docs/userspace-dataplane-gaps.md` must contain "fail-closed".
Verified pre-existing on `origin/master`:

```
$ git show origin/master:docs/userspace-dataplane-gaps.md | grep -c fail-closed
0
$ git diff origin/master -- userspace-dp/tests/snat_contract_doc_guard.rs docs/userspace-dataplane-gaps.md
(empty)
```

Not in this PR's blast radius. The fix belongs in a separate PR
that owns `docs/userspace-dataplane-gaps.md`.

## Verification commands run

```bash
# Repo state
git diff origin/master --stat
git diff origin/master -- userspace-dp/src/filter/mod.rs
git diff origin/master -- userspace-dp/src/protocol/security.rs
git diff origin/master -- userspace-dp/src/afxdp/flow_cache_tests.rs

# Pre-existing failure verification
git show origin/master:docs/userspace-dataplane-gaps.md | grep -c fail-closed
git diff origin/master -- docs/userspace-dataplane-gaps.md

# Build + tests
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release runbook_pattern
# 5× flake check
for i in 1 2 3 4 5; do
  TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release runbook_pattern \
    2>&1 | grep "afxdp::flow_cache.*runbook_pattern"
done
# Result: 2/2 pass × 5/5 runs.

GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...
# Result: all pkg/* clean; no failures.

# Cited file:line verification (grep against the actual branch)
grep -n "has_dscp_match_terms" userspace-dp/src/filter/mod.rs
grep -n "iface_filter_v[46]_has_dscp_match" userspace-dp/src/filter/mod.rs
grep -n "interface_input_filter_has_dscp_match\|interface_output_filter_has_dscp_match" \
  userspace-dp/src/filter/engine/cache_sensitive.rs
grep -n "evaluate_dscp_sensitive_input_filter_on_session_hit" \
  userspace-dp/src/afxdp/poll_descriptor/mod.rs
grep -n "input_dscp_filter_families_changed" \
  userspace-dp/src/afxdp/worker/loop_body/mod.rs
grep -n "is_cacheable\b" userspace-dp/src/afxdp/types/forwarding.rs
grep -n "apply_lo0_filter_action" userspace-dp/src/afxdp/poll_descriptor/mod.rs
grep -n "PROTO_ICMP\|PROTO_ICMPV6" userspace-dp/src/afxdp/frame/inspect.rs
```

All cited file:line references in the README runbook resolve to
the expected code, on this branch.

## Self-correction

What I missed in the plan review rounds that Codex and AGY
caught:

- **r1 (plan v1)**: I claimed ICMP type/code live in
  `src_port`/`dst_port` — wrong. `parse_flow_ports` stores
  `(identifier, 0)`. Codex r1 and AGY r1 both flagged this.
  Fixed in plan v2.
- **r1 (plan v1)**: I raised lo0 as a possible cache-sensitive
  gap. Both reviewers immediately showed `LocalDelivery` is
  non-cacheable. Burned a review round; plan v2 documented the
  resolution so future readers don't repeat the cycle.
- **r2 (plan v2)**: I parked the harness tests under
  `userspace-dp/src/filter/cache_invariant_harness.rs`. Codex
  caught that `FlowCacheEntry::from_forward_decision` is
  `pub(super)` in `afxdp::flow_cache` — tests under `filter/`
  cannot reach it without visibility churn. Moved to
  `afxdp/flow_cache_tests.rs` in v3.
- **r3 (plan v3)**: I left stale §4.3 and §6 sentences referring
  to "three new tests in filter/" and "the new positional-ID
  test" after the v3 decisions reduced scope to 2 tests + cite.
  Both reviewers flagged the inconsistency.

This SMR pass adds one more correction the upstream reviewers
might miss in a sub-agent run: when **Codex r1 (code review)**
flagged the asymmetric contract blocks, the fix is not just to
copy-paste the FilterTerm block into security.rs — `FilterTerm`
is `pub(crate)` to userspace-dp and lives next to the per-
interface sets, while `FirewallTermSnapshot` is the wire DTO
that is also consumed by Go-side serialization. The
`FirewallTermSnapshot` block should keep the wire-DTO framing
("its runtime twin FilterTerm in ..."), not pretend it's
authoring the runtime hooks itself. The applied fix preserves
that framing while bringing the rest into parity. Verified that
both blocks now carry: (a) extend-SessionKey prerequisites, (b)
runbook hooks with file:line refs, the #1430 precedent line,
and the README pointer.

## Net assessment

This PR ships ~250 lines of documentation + 2 cfg(test) tests +
two synchronized in-source contract blocks. It changes nothing
about the dataplane's runtime behavior. The reason it's worth
the PR cost: the next per-packet match field that lands (which
the project memory says is on the roadmap — TOS/ECN, TCP flags,
fragment match are all reachable from the current Junos config
parser surface) will hit a loud reviewer-facing tripwire in
the diff above `FilterTerm`/`FirewallTermSnapshot`, plus an
authoritative table + recipe in the filter module's README.
That is the most enforcement Rust permits without proc-macros,
and both prior plan rounds verified the alternatives
(`PER_PACKET_MATCH_FIELDS` constant list, `PerPacketMatchField`
trait, fake-field harness) are theater.

MERGE-READY after Codex r1 minors pushed.

---

## Addendum (post-rebase corrections)

After the Codex r1 + Copilot r1 fixes were pushed at `778450f74`,
two further drift items were caught and resolved:

1. **ICMP byte range (Copilot swe-agent commit `1d669302d`)** — my
   fix for Copilot's first inline finding said `parse_flow_ports`
   "reads bytes 4-6 of the ICMP header". The actual code is
   `frame.get(l4 + 4..l4 + 6)?` — a Rust half-open range covering
   exactly two bytes at offsets 4 and 5. Copilot's swe-agent
   auto-corrected the README to "bytes 4-5"; the correction is
   right and I missed it in the original SMR pass. Self-correction
   noted.

2. **5-tuple vs 6-tuple framing (Copilot r2 inline)** — my v5 plan
   described `SessionKey` as a 6-tuple because the struct literally
   has six fields. Copilot's second inline correctly noted this
   conflicts with the standard 5-tuple language used elsewhere in
   the codebase (e.g. `flow_cache.rs` comments). Both occurrences
   (README §"The cache key" and plan §3) now describe the key as
   "the standard 5-tuple plus an `addr_family` byte that is
   redundant with `IpAddr` variant but materialized for cheap
   branchless checks." This is the same information without the
   terminology collision.

Both corrections strictly tighten the doc. They do not change the
runtime behavior, the in-source contract block, or the test
shape. The verdict remains **MERGE-READY** at the post-fix SHA.

---

## Post-rebase final attestation note

Verified at SHA `9e83df3a2` (final HEAD): the SMR doc on the branch
covers the diff that ships, the comment blocks above `FilterTerm`
and `FirewallTermSnapshot` are mirrored line-for-line, and the
runbook tests still build and pass at the rebased head. No
additional findings introduced by `_Log.md` chronological merge or
the reviewer-ids.md task-ID records. Final verdict remains
**MERGE-READY**.
