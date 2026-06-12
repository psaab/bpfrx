# pkg/fsatomic

The project's single source of truth for replace-a-file-on-disk writes
(#1894). Two writers, one shared core:

- `WriteFileAtomic(path, data, perm, opts...)` — create-temp-in-same-dir,
  write, fchmod, close-with-error-check, rename. **Namespace atomicity
  only**: readers never see a torn file, but after a power cut the update
  may be lost or the rename may surface not-yet-flushed data.
- `WriteFileDurable(path, data, perm, opts...)` — the same plus an fsync
  of the temp file before the rename and an fsync of the (resolved)
  parent directory after it. Survives power loss.
- `SyncDir(dir)` — one directory fsync covering previously-completed
  renames/unlinks; lets multi-file shuffles (configstore rollback slots)
  batch namespace durability into a single fsync.
- `MkdirAllDurable(dir, perm)` — `os.MkdirAll` plus an fsync of every
  newly-created level and of the deepest pre-existing ancestor. Required
  when a DurableState file lives in a directory the writer itself
  creates: `WriteFileDurable` persists the file's entry in its parent,
  not the parent's own entry in *its* parent, so on first boot a power
  cut could otherwise drop the whole just-created directory (PR #1900
  code-r1). Zero fsyncs when the path already exists.

## Persistence classes

Defined in `docs/engineering-style.md` ("Persistence classes"); the class
decides the writer:

| Class | Writer | Examples |
|---|---|---|
| DurableState | `WriteFileDurable` | active config, rollback slot 1, rescue config, `master.key`, DHCPv6 DUID, `frr.conf` |
| AtomicGeneratedConfig | `WriteFileAtomic` | swanctl conf, Kea configs, networkd `.link`/`.network`, rollback slots 2..N |
| BestEffortKernelKnob | direct `os.WriteFile` | procfs/sysfs knobs (rename impossible there) |

The AtomicGeneratedConfig class exists precisely so hot apply paths never
pay an fsync; fsync costs land only on operator-paced commit paths.

## Options

- `WithPreserveExisting()` — lift mode/ownership from an existing target
  (fchmod/fchown on the temp fd; chown only when the owner actually
  differs; a chown failure is surfaced, never silently renamed over a
  differently-owned file). Without it, the caller's `perm` is **enforced
  on every write** — unlike `os.WriteFile`, which keeps an existing
  inode's mode.
- `WithResolveSymlinks()` — write through a symlink to its resolved
  target (dangling links resolve to their destination); the durable
  dir-fsync targets the resolved parent. Without it, a symlinked target
  is replaced by a regular file.

Both options together reproduce `pkg/frr`'s `atomicWriteFile` (#1883)
semantics, which this package lifted; FRR now delegates here.

## Deliberate non-features

- **Hardlinks**: rename breaks `nlink>1` write-through (other links keep
  the old inode). No call site hardlinks these files; documented, not
  guarded.
- **Crash-leaked temps**: temp files (`.<base>.tmp-*`) are removed on
  every in-process failure path, but a crash can leak them. Owners of
  frequently-rewritten directories sweep on startup (configstore `NewDB`
  does for `.configdb`).
- **Post-rename file fsync**: redundant — the temp-fd fsync already
  flushed data+metadata; the dir fsync makes the rename durable.
- **EINTR loops**: Go's `os.File.Sync` retries EINTR internally
  (`internal/poll` `ignoringEINTR`).

## Failure semantics

The temp file is cleaned up and the target left untouched on every
failure **before** the rename. A `WriteFileDurable` error **after** the
rename (dir-fsync failure) means the new content is visible but its
durability is unknown; callers treating the write as failed must
tolerate the new content surviving — the same crash-window trade the
configstore #1799 persist-before-promote contract documents.

## Testing

`fsatomic_test.go` injects one failure per writer stage through the
package-private seams (create/write/chmod/chown/sync/close/rename/
dir-open) and asserts the three invariants: error names the stage,
target untouched (pre-rename stages), temp cleaned up.

## Callers

`pkg/configstore`, `pkg/frr`, `pkg/ipsec`, `pkg/dhcpserver`,
`pkg/networkd`, `pkg/dhcp`.

## Dependencies

Standard library only.
