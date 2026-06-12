# #1896 — Compact config journal + bounded tail reads + rotation

Issue: configstore journal appends the **full compiled `*config.Config`**
per commit/config_sync/commit_confirmed/auto_rollback, and every
`show system commit` re-reads + re-unmarshals the **entire** JSONL file
before applying the limit. O(lifetime commits × config size) per history
view; no rotation; unbounded growth. Blocker #1894 (pkg/fsatomic) merged
as PR #1900.

## Verified facts (this worktree, origin/master 33b14801a)

1. `JournalEntry.Before` is dead — **no call site populates it**
   (grep: only `After:` at store.go:466/:962/:1061/:1153).
2. `JournalEntry.After` is **read by nobody**. Both `show system commit`
   renderers — `pkg/grpcapi/server_show_system.go:91` and
   `pkg/cli/cli_show_system.go:809` — print only
   `Timestamp`/`Action`/`Detail`. No other consumer of
   `ListEntries`/`ListCommitHistory` exists outside tests.
3. Full config trees already survive elsewhere with explicit retention:
   `saveRollbackFiles` (store.go:1346) writes `entry.Config.Format()`
   text to `<filePath>.N` slots (slot 1 durable, rest atomic, one
   trailing `SyncDir` — #1894 adjudication), and `loadRollbackHistory`
   reads them at boot. These rollback files are the canonical history;
   the journal payload duplicates derived data (compiled form of trees
   the rollback slots keep in source form).
4. Boot never reads the journal — only `Log()` appends and the two
   show paths read. An unparseable/old journal cannot fail boot today;
   that property must be preserved.
5. `ListCommitHistory(limit)` semantics today: take the last `limit`
   entries of ANY action, then filter to
   commit/commit_confirmed/auto_rollback (can return fewer than `limit`
   commits when persist_error/config_sync entries interleave).
   `limit<=0` means "all" (used by persist_failure_test.go:50).
6. Security note (free win): the old journal stores the full compiled
   config — including secrets — in a 0644 file with no retention.
   Compact entries remove that exposure.

## Design

### 1. New subpackage `pkg/configstore/journal`

Per the issue's suggested split. The package no longer imports
`pkg/config` (payloads dropped). `pkg/configstore` keeps
`type JournalEntry = journal.Entry` so the two renderers and tests
compile unchanged.

```go
// journal.Entry — compact v2 audit record.
type Entry struct {
    Schema     int       `json:"v,omitempty"`           // 2 for new writes; 0 = legacy
    Timestamp  time.Time `json:"timestamp"`
    Action     string    `json:"action"`
    Detail     string    `json:"detail,omitempty"`
    ConfigHash string    `json:"config_hash,omitempty"` // sha256 hex of post-action active tree Format() text
}
```

- `Before`/`After` are **deleted**. Legacy fat lines decode tolerantly:
  `json.Unmarshal` ignores unknown fields, so old entries yield
  Timestamp/Action/Detail — exactly what the renderers print. No
  migration pass, no version gate needed for reads; `Schema` is a
  forensic marker only.
- `ConfigHash` is the rollback pointer. A per-entry rollback **slot
  number** is structurally wrong: slots shift on every commit (slot 1
  becomes slot 2), so any stored slot index goes stale immediately.
  The hash of the post-action active tree's `Format()` text is stable
  and matches the rollback files byte-for-byte (saveRollbackFiles
  writes the same `Format()` text), so `sha256sum xpf.conf.N` correlates
  any retained rollback file to its journal entry. Set at the four
  config-bearing sites (commit, commit_confirmed, auto_rollback,
  config_sync); empty for persist_error/persist_recovered.

### 2. Bounded tail reads

`Journal.Tail(limit)` replaces `ListEntries(limit)`:

- Per segment, newest segment first: reverse chunked scan (64 KiB
  `ReadAt` chunks from EOF), split into lines, parse newest-first,
  skip unparseable lines (same tolerance as today), stop at `limit`.
  Result reversed to oldest-first (current output order).
- Legacy fat lines longer than a chunk are handled by accumulating
  chunks until a newline appears — cost bounded by the fat line size
  and only paid while legacy entries are still inside the tail window.
- A torn final line (no trailing `\n` / partial JSON after crash) is
  skipped by the parse-or-skip rule.
- `limit<=0`: full forward read of all segments, oldest first
  (compat path for tests; no production caller).
- The scanner takes `(io.ReaderAt, size)` so a counting wrapper can
  prove boundedness in tests.
- `ListCommitHistory` keeps its exact semantics: `Tail(limit)` then
  filter — equivalence test included.

### 3. Rotation / retention

- Size-based, checked at append time: when the current segment's size
  ≥ `maxSegmentBytes` (default 1 MiB), rotate before appending:
  delete `<path>.<maxSegments>`, shift `.i → .i+1`, rename current to
  `.1`, then `fsatomic.SyncDir`. Defaults: 1 MiB × (1 current + 2
  rotated) ≈ ≤3 MiB total, ~10–15k compact entries retained.
- Migration falls out for free: the first append after upgrade sees the
  fat legacy journal over the threshold and rotates the whole legacy
  file to `.1` intact. History stays visible (Tail merges segments);
  after `maxSegments` further rotations the fat data ages out. No
  rewrite, no boot work.
- `Tail` reads segments newest→oldest until `limit` entries found.

### 4. Append durability (adjudicated)

The journal is the commit audit trail (DurableState-adjacent), and
appends are operator-paced (commit frequency); the commit path already
pays several fsyncs (active.json durable write, rollback slot 1, dir
syncs). Policy:

- fsync the journal fd after every append;
- `fsatomic.SyncDir` when the append created the file or rotated
  segments (namespace durability);
- torn-tail self-heal: if the file is non-empty and doesn't end in
  `\n`, prefix the new record with `\n` (single write call) so a torn
  tail can never corrupt the next entry.

fsatomic's whole-file writers don't apply to appends; `SyncDir` is the
piece we reuse. Call sites continue to ignore `Log()` errors (existing
behavior — persist_error journaling on a failing disk must not recurse).

### 5. Out of scope

- `saveRollbackFiles` rewriting all ~50 slots per commit is a separate
  inefficiency (different mechanism, already adjudicated in #1894).
- Changing `ListCommitHistory` to filter-during-scan (would *improve*
  the ≤limit-commits wrinkle but breaks pre/post equivalence).
- Rollback-file encryption parity (pre-existing).

### 6. SMR round-1 deltas (Claude self-review)

- **Internal `sync.Mutex` in `Journal`** serializing `Log` and `Tail`.
  `ListCommitHistory` (store.go:1268) does not hold `Store.mu`; without
  internal locking, a reader that opens the current segment while a
  rotation renames it to `.1` re-reads the same inode under both names
  → duplicated entries in `show system commit`. Operator-paced, so a
  plain mutex is free.
- **`Tail` skips missing segments** (continue, not break): a crash
  mid-shift can leave gaps (`.1` present, `.2` missing, `.3` present);
  worst case is lost oldest retention, never corruption.
- **Append fd is `O_RDWR|O_APPEND|O_CREATE`** so the torn-tail check
  can `ReadAt` the last byte on the same fd.
- **`Log` failures get a `slog.Warn`** via a store-side helper (today
  every call site silently discards the error; with payloads gone the
  journal is the only audit record, so at least surface the failure in
  logs — still never fatal, and the persist_error path must not
  recurse into journaling its own failure).
- ConfigHash is documented as *best-effort correlation while the
  rollback slot is retained* — not a referential-integrity guarantee
  (slots shift per commit and only ~50 are kept; whether config_sync
  pushes history is irrelevant under this phrasing).

### 7. AGY plan-round-1 deltas (adversarial-review-mqb7hxhl-e7opzl, PLAN-NEEDS-CHANGES)

- **F1 reader/writer race** — same defect as SMR delta 1; resolved by
  the internal `Journal` mutex (chosen over `Store.mu.RLock` in
  `ListCommitHistory`: every `Log` site already holds the Store write
  lock, and journal-internal locking also covers any future caller).
- **F2 UTF-8 split at chunk boundaries** — the scanner operates on
  `[]byte` end-to-end (`bytes.IndexByte`/`bytes.Split`); no string
  conversion until a full line is reassembled. Adopted as an explicit
  implementation constraint + test with multi-byte Detail straddling a
  chunk boundary.
- **F3 missing intermediate segments** — same as SMR delta 2: `Tail`
  continues over `os.IsNotExist` gaps up to maxSegments.
- **F4 unbounded line accumulation** — a corrupt newline-free segment
  would otherwise buffer the whole file. Cap reverse-scan line
  assembly at 16 MiB (well above any real legacy fat entry, well below
  whole-disk): past the cap the accumulated fragment is discarded and
  the scanner resyncs at the previous newline (skip mode), dropping
  only the poisoned line. v1 read the entire file unconditionally, so
  this is strictly better.

## Tests

1. **Bounded-read proof** (issue requirement): 5,000-entry journal;
   counting `io.ReaderAt`; assert `Tail(50)` reads ≤ a small constant
   number of chunks (≪ file size). Plus `BenchmarkTail50` over a
   thousand-entry journal.
2. **Fat-legacy decode**: raw v1 lines with multi-hundred-KiB
   `before`/`after` blobs (> chunk size, forcing multi-chunk line
   assembly) parse to correct Timestamp/Action/Detail.
3. **Torn final line**: truncated JSON tail → skipped on read; next
   append self-heals; subsequent Tail returns both old and new entries.
4. **Rotation boundary**: appends across the size threshold; Tail(limit)
   spanning current+rotated segments in correct order; oldest segment
   deleted at maxSegments; legacy-fat-file first-append rotation.
5. **show-system-commit equivalence**: mixed-action journal (fat legacy
   + compact + persist_error noise); old reader logic as in-test oracle;
   assert identical ListCommitHistory output pre/post.
6. Existing suite: store_test (Detail surviving), persist_failure_test
   (`ListCommitHistory(0)`), all green unmasked.

## Live validation (lock protocol)

Deploy to loss userspace cluster via `with-cluster.sh`; several commits;
`show system commit` correct + fast; rollback 1 works; restart boots
over the legacy fat journal cleanly; re-apply CoS after deploy.

## Files

- `pkg/configstore/journal/journal.go` (+ tests) — new package.
- `pkg/configstore/journal.go` — deleted; alias + constructor wiring
  moves to store.go.
- `pkg/configstore/store.go` — four call sites gain `ConfigHash`, drop
  `After`; `ListCommitHistory` → `Tail`.
- `pkg/configstore/README.md` — journal section rewrite (format v2,
  rotation, hash correlation, durability policy).
