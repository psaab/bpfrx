# Claude SMR code review — round 2 (PR #1610, SHA 8edb77c5b277)

**Verdict: MERGE-READY**

This round re-audits the current HEAD (`8edb77c5b277`) after the
post-r1 commits 77e72f41f / 68138b122 / 8edb77c5b landed. Codex
r3 was at SHA 77e72f41f (pre-AGY-r2-fixes); my r1 doc was also at
that SHA. This r2 doc covers the diff from 77e72f41f → 8edb77c5b277
plus a fresh sweep for any new fail-open paths.

## Diff coverage (post-r1 commits)

### Commit 68138b122 — preflight before tear_down + status mutation

Two new preflight sites added:

**1. `userspace-dp/src/server/handlers/snapshot.rs::apply`** —
runs `parse_policy_state_with_counters` with a scratch
`PolicyCounterStore::default()` AFTER the version check, BEFORE
the `guard.status.last_snapshot_generation` etc. mutations at
lines 37-41. On error: `response.ok = false` + early return.

I walked the snapshot.rs file in full. The preflight block is
at lines 33-58 (roughly). The mutations at 37-41 are AFTER the
preflight block. No `guard.*` writes happen before the preflight.
The error path returns without touching any field. ✓

**2. `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs::reconcile`** —
runs `parse_policy_state_with_counters` with a scratch counter
store at the TOP of `reconcile()` BEFORE `teardown::tear_down(self)`.
On error: returns early without tearing down workers.

Pre-existing code at line 72 `let preserved = teardown::tear_down(self);`
now runs only AFTER the preflight passes (line ~98). Workers
remain on the previous good config when integrity fails.

This was AGY r2's finding 4.2. Closed.

**3. Scratch counter store usage** confirms isolation: `PolicyCounterStore::default()` creates a fresh `Arc<Mutex<FxHashMap<…>>>` per
preflight. Rejected snapshots cannot leak `Arc<PolicyRuleCounter>`
entries into `coord.policy_counters` because the parser inserts
into whatever store is passed in. The scratch store is dropped at
function exit. ✓

### Commit 8edb77c5b — drop depth cap on book recursion

`pkg/dataplane/userspace/policies.go::expandBookNameRecursive`:

```go
func expandBookNameRecursive(ab *config.AddressBook, name string, visited map[string]bool, _depth int) []string {
    if visited[name] {
        return nil
    }
    visited[name] = true
    defer func() { delete(visited, name) }()
    if addr, ok := ab.Addresses[name]; ok {
        return []string{addr.Value}
    }
    if as, ok := ab.AddressSets[name]; ok {
        var out []string
        for _, member := range as.Addresses {
            out = append(out, expandBookNameRecursive(ab, member, visited, 0)...)
        }
        for _, nested := range as.AddressSets {
            out = append(out, expandBookNameRecursive(ab, nested, visited, 0)...)
        }
        return out
    }
    return nil
}
```

Path-based cycle detection: `visited[name]` set on entry, unset
on exit via deferred delete. Sibling AddressSets with shared
parents work because `defer` unwinds before the sibling descent.

Cycle case `A → B → A`: enters A (visited[A]=true), descends to B
(visited[B]=true), descends to A → `visited[A]` is true → returns
nil. No infinite recursion. ✓

Sibling-share case `Parent { setA { common }, setB { common } }`:
enters Parent, recurses into setA → common (visited[common]=true),
returns from common (deletes visited[common]), returns from setA
(deletes visited[setA]), recurses into setB → common (visited[common]
not set anymore, expands normally). Legacy behavior preserved. ✓

This was Copilot C2. Closed.

## Hostile re-checks at current HEAD

### Wire format Go ↔ Rust

Walked once more:
- `AddressBookSnapshot` (Go protocol.go:80-87) ↔ Rust security.rs
  `AddressBookSnapshot` — fields `id`, `name`, `prefixes_v4`,
  `prefixes_v6` match with serde rename tags.
- `PolicyRuleSnapshot.SourceBookIDs` etc. ↔ Rust
  `source_book_ids` — JSON tags identical.
- `ConfigSnapshot.AddressBooks` ↔ Rust `address_books` — match.

No drift.

### Stale-state-past-validation sweep

The fallible parse is called from three control paths in
production code:
1. `server/handlers/snapshot.rs::apply` — has preflight. ✓
2. `Coordinator::reconcile` — has preflight before tear_down. ✓
3. `Coordinator::refresh_runtime_snapshot` — has preflight (was
   the Codex r1 F2 site). ✓

The lower-level `build_forwarding_state_with_policy_counters_
and_previous` returns the Result. Its only `?` propagation point
is the `parse_policy_state_with_counters` call at
`forwarding_build/mod.rs:156`. The function does construct
`ForwardingState::default()` at the top and populates fields
through to the parse — but on parse failure the function returns
`Err(_)` and the half-built `ForwardingState` is dropped without
escaping. ✓

### HA snapshot sync

The preflight uses the same parse function as the actual build,
which is deterministic given identical inputs. Two HA peers
receiving the same ConfigSnapshot will produce the same
PolicyState (or fail validation identically). No new HA
divergence path. ✓

### Hot path Vec<BookEntry> + SmallVec<[u32; 8]>

Unchanged from r1 review. `try_match_rule` walks
`rule.source_book_idxs.iter().any(|&i| state.books[i as usize].
v4.contains(src))`. Precomputed `_match_any` flags short-circuit.
Zero Arc deref. No new findings. ✓

### Counter-leak from refresh_runtime_snapshot rejection

The Codex r1 F2 fix used a scratch counter store for the
refresh_runtime_snapshot preflight. Verified at
`coordinator/mod.rs:445` — `&preflight_counters` (a fresh
`PolicyCounterStore::default()`). The actual rebuild later in
the function uses `&self.policy_counters`. ✓

## Verification commands

```
cd userspace-dp && cargo build --release    # clean (134 warnings)
cd userspace-dp && cargo test --release --bin xpf-userspace-dp
  test result: ok. 1453 passed; 0 failed; 2 ignored
go test -count=1 ./pkg/dataplane/userspace/...
  ok  github.com/psaab/xpf/pkg/dataplane/userspace 3.072s
```

5×/5× flake check on the 10 new Rust policy tests: all green.

## Findings: none

All AGY r2 NEEDS-MAJOR findings closed. All Copilot r1 inline
findings closed. Codex r4 spot-check confirmed:
- snapshot.rs preflight order ✓
- reconcile preflight before tear_down ✓
- scratch counters on both preflights ✓
- expandBookNameRecursive path-based cycle detection terminates ✓
- no Go/Rust wire drift ✓
- no stale-state leak past validation ✓

AGY r3 verdict at current HEAD: MERGE-READY.

## Final SMR verdict on HEAD `8edb77c5b277`: MERGE-READY

The PR is structurally sound, all known fail-open paths are
closed, all reviewer findings across 4 code-review rounds are
addressed at this SHA. Smoke gate is the only remaining checkpoint.
