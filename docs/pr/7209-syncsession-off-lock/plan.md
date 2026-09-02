# #7209 — take `sync_session` off the snapshot-wide `ServerState` mutex

> **OUTCOME: the option-(b) argument below was REFUTED by review and is kept as
> a record, not as a direction.** Read this banner before anything else in this
> file — the body argues that a session-import handle is narrow enough to
> replace the issue's standing option-(a) ruling, and that argument is dead.
> What shipped from this plan is only its PR A (`WorkerManager::records` behind
> an `ArcSwap`, PR #8290), which every design needs.
>
> Three findings killed it, all verified at `192f40502` and recorded on the
> issue (comment 5514518509). They apply to option (a) equally, so they are not
> a verdict between shapes:
>
> 1. **`synthesized_synced_reverse_entry` returns `Some` unconditionally**
>    (`afxdp/shared_ops.rs:928-937`; the tree says so at
>    `ha/session_import.rs:79`). An import running against teardown-state
>    `forwarding` therefore publishes a **wrong** reverse companion —
>    `owner_rg_id = 0`, dead resolution — not none, and nothing re-derives it.
>    The "degradation, not a hazard" claim in the § below is FALSE.
> 2. **`publish_runtime_view` DEEP CLONES `forwarding`**
>    (`coordinator/mod.rs:1312-1314`), so the published `RuntimeView` is not a
>    handle onto the owned table. The `forwarding` row of the narrowness table
>    below is false, and reading the published view instead is dead end #1
>    revived. `zone_name_to_id_ref` also returns a BORROW of Coordinator-owned
>    data, which no handle can serve.
> 3. **`refresh_reverse_prewarm_owner_rg_indexes` is asymmetric**
>    (`afxdp/shared_ops.rs:1243-1246`): the previous entry's buckets are
>    computed against the CURRENT forwarding, so insert-under-F1 /
>    remove-under-F2 leaks index entries permanently.
>
> The next prerequisite is therefore not lock work. It is making the import's
> DERIVED state (the synthesized reverse companion, the prewarm index) refuse
> or defer when its inputs are absent — #8171 did that for the entries
> themselves and not for what is computed from them.

Measured at `e0748d0c2`. Every cite below was re-anchored by SYMBOL at that
head; the issue thread's line numbers are ~1500 commits old and have rotted
twice already.

## The defect, restated

`handlers/mod.rs::handle_stream` takes one `state.lock()` and dispatches every
verb inside it, `sync_session` included. `apply_snapshot` reaches
`Coordinator::reconcile(&mut self)`, which holds that same guard across a 10 s
worker-readiness barrier (`WORKER_STARTUP_BARRIER_TIMEOUT_NS`, `bringup.rs`), a
500 ms mlx5 quiesce, an unbounded worker `join()` and BPF map-pin syscalls. The
Go side budgets 3 s per session round-trip and #5380 aborts the rest of a bulk
batch on the first transport failure, so this is dropped session mirrors — up to
255 per batch — during the failover the dedicated session socket exists to serve,
not a latency tail.

Measured today: `sync_session_is_served_while_the_state_lock_is_held_7209`
waits **1.2038 s** against its 500 ms bar.

## Option adjudicated: (b), a narrow session-import handle

The issue's standing ruling picked **(a)** — `ServerState.afxdp: Arc<Coordinator>`
plus an explicit exclusive lock for the `&mut self` methods — and rejected (b) on
this measurement:

> a handle spanning most of the Coordinator is not a narrowing, it is a rename

**That measurement is now false**, and the ruling itself says so is the condition
for switching: *"If whoever implements this finds the handle can be made narrow,
take (b) instead and say why."* Four prerequisite PRs have landed since it was
taken. Re-measured at `e0748d0c2`, the six methods `sync_session` reaches
(`synced_routing_domain`, `note_unknown_routing_domain_import`,
`zone_name_to_id_ref`, `upsert_synced_session`, `delete_synced_session`,
`routing_domains`) need exactly six things:

| needed | shape at `e0748d0c2` | work |
|---|---|---|
| `sessions.{synced,nat,forward_wire,owner_rg_indexes}` | every field already `Arc<Mutex<..>>` / shared | hold the manager as `Arc<SessionManager>` — `Deref` keeps all 65 `self.sessions.*` sites compiling |
| `bpf_maps` | `ArcSwap<BpfMaps>` (**#8179**) | `Arc<ArcSwap<BpfMaps>>` — `Deref`, 8 sites |
| `ha.rg_runtime` | `ArcSwap` | share the `Arc` |
| `neighbors.dynamic` | already `Arc<ShardedNeighborMap>` | clone |
| `forwarding` | `RuntimeViewChannel { inner: Arc<ArcSwap<RuntimeView>> }` already exists and publishes `Arc<ForwardingState>` | clone the channel |
| `workers.records` | owned `BTreeMap`, mutated under `&mut self` | **the only real work** |

Five of six are already shareable. The handle is six pointers, not a rename.

### Why (a) loses

(a) requires all **15** `&mut self` coordinator methods that reach the server —
`reconcile` among them (census comment `5474095174`) — to become `&self`, because
`Arc<Coordinator>` makes `get_mut` permanently unavailable once the session thread
holds a clone. That means interior mutability for `forwarding`, every
`workers.*` field, `tunnel_sources`, `wg_control_threads`, `validation`,
`neighbors`, and the reconcile counters. It dissolves the compiler-enforced
exclusion on the snapshot-apply transaction across a ~100-method surface and
replaces it with a convention. (b) leaves that exclusion exactly where it is:
`ServerState` keeps an **owned** `Coordinator`, all 15 methods keep `&mut self`,
and the reconcile transaction stays as exclusive as it is today.

### Why item 2 (move the blocking calls off the lock) loses

It is not merely risky, it is **structurally impossible in safe Rust** at this
ownership. You cannot drop a `MutexGuard<ServerState>` while a `&mut Coordinator`
borrow derived from it is live, and the 10 s barrier sits deep inside
`reconcile(&mut self)`. Splitting `reconcile` into resumable begin/finish phases
is the only mechanical form, and it exposes an uncommitted transaction — the
barrier `rolls back` via `stop_inner(false)` on any shortfall. That is comment
`5465999256`'s objection and it is still live.

### Why the "pump" loses (considered, rejected — a sixth dead end)

Service a session-sync inbox from *inside* the reconcile's wait loops, on the
reconcile's own thread: no lock-graph change at all, no interior mutability, no
use-after-close, and `&mut self` reborrows as `&self` for free. It is the
cheapest thing that could work and it is wrong twice:

1. **It is discipline-maintained.** `sync_session` stays queued behind any holder
   that does not pump. A future long holder that forgets reintroduces the defect
   silently — the exact design property the fan-out projection was rejected for
   (comment `5475077474`).
2. The acceptance test would stay red, and the honest repair would be to weaken
   the test to the mechanism rather than the property.

## Sequencing — two PRs

The correctness case for an off-lock import is already closed: #8171 (replay
reads the LIVE shared map), #8179 (FD lifetime held by refcount), #8175 (the
worker-set gate pinned), #8162 (the residue counted). What is left is ownership.

**PR A — make the import path's worker dependency shareable.** No behaviour
change; the same single thread still does the same things under the same mutex.

* `WorkerHandle.join` moves out of the shared record into a `WorkerManager`-owned
  `joins: BTreeMap<u32, JoinHandle<()>>`. It has exactly one producer
  (`bringup.rs`) and one consumer (`stop_and_clear`), it is lifecycle state
  rather than shared runtime state, and it is the *only* field of
  `WorkerRuntimeRecord` that needs `&mut`. With it gone the record is 100 %
  `Arc`-backed.
* `WorkerManager.records` becomes
  `Arc<ArcSwap<BTreeMap<u32, Arc<WorkerRuntimeRecord>>>>` — **one authority**,
  readable through `&self`, mutated only by `register()` / `clear_records()`.

  This is deliberately **not** the published fan-out projection rejected in
  comment `5475077474`. That design kept `records` as the authority and a second
  structure as a cache, refreshed by calling a helper at each mutation site with
  nothing enforcing it — and 17 test sites inserting directly proved the drift
  was real. Here there is no second structure: the `ArcSwap` **is** `records`, so
  a site that fails to publish cannot compile.

  `ArcSwap` rather than `RwLock` on purpose. A lock would add an ordering edge
  against `sessions.synced` inside `upsert_synced_session` — a lock-graph change,
  the category this tree has been bitten by (#7095). `ArcSwap` adds no edge and
  no `...Locked` naming hazard, and it is the tree's existing idiom (~45 uses,
  #8179's precedent). `records` is mutated at exactly two production sites, both
  reconcile-rare, so rcu-on-write is free.
* `Coordinator.sessions -> Arc<SessionManager>`,
  `bpf_maps -> Arc<ArcSwap<BpfMaps>>`. Both `Deref`, so the ~73 read sites are
  untouched.

**PR B — dispatch `sync_session` off the mutex.** `Coordinator::session_domain()
-> Arc<SyncedImportDomain>` bundling the six pointers; the six methods move onto
the domain and `Coordinator` delegates, so every existing caller and test keeps
compiling. `ServerState` gains the handle; `handle_stream` routes `sync_session`
to it BEFORE `state.lock()`.

## What changes for an import that lands mid-reconcile

It stops being blocked and starts being **served against teardown state**. That
is the intended end state, not a side effect — `session_manager.rs` already
documents it (*"`sync_session` reads the PUBLISHED forwarding view, which lags
the pending one by design — #7209"*), and #8019 added
`xpf_userspace_synced_import_zone_unresolved_total` to make the lag visible.
Two corrections to the thread on this, both measured at `e0748d0c2`:

1. **That doc comment is false today** and PR B is what makes it true. Dead end
   `5474536856` found the same thing; the comment must not be left describing
   behaviour the code does not have.
2. **`upsert_synced_session` reads `self.forwarding` at THREE sites, not one.**
   The resting-place comment says *"the import path reads it only from
   `reserve_synced_translation`, which the no-worker gate short-circuits"*. At
   head the other two — `synthesized_synced_reverse_entry` and
   `refresh_reverse_prewarm_owner_rg_indexes` — are **ungated**. They are
   degradations, not hazards (an empty table yields no synthesized reverse
   companion rather than a wrong one), but the claim as written is wrong and the
   ungated pair must be stated in the PR body rather than inherited.

Net trade, stated plainly: today a mid-reconcile burst **times out and #5380
drops the remainder of the batch**. After, every session lands, some with
narrowed zone resolution, and the narrowing is counted. Strictly better, and
observable either way.

`stop_inner`'s in-tree rationale — *"`workers.stop_and_clear(..)` above has
already joined every worker thread so this teardown has no live readers either
way"* — reasons about **workers**. An off-lock `sync_session` is a reader that
premise never covered, so PR B must annotate it rather than leave a rationale
that a later reader would build on.

## Test strategy

The existing acceptance test is necessary but **not sufficient**, and this is the
first thing to fix. `sync_session_is_served_while_the_state_lock_is_held_7209`
drives `req("sync_session")` with **no payload**, so it returns at the first
`let Some(sync_req) = session_sync else { return }`. It therefore goes green the
moment the *dispatch* is lock-free — it cannot tell that from the whole verb
being lock-free. A fix that special-cased only the empty-payload arm would pass
it.

So PR B adds a second instrument that drives a **real upsert payload and a real
delete payload** under the same lock-holder, asserting both are served within the
bar AND that the upsert actually reached the synced map. Both must be shown red
before the fix and green after; the count of collected tests is reported, not
just `ok`.

Guards for PR A:
* the published record set is the same object the reconcile mutates — a cell that
  registers a worker and reads the set back through the shared handle, with a
  paired control that two managers stay independent (so it cannot pass on a
  process-global);
* `#8175`'s `no_worker_registered_keeps_a_synced_import_off_the_reservation_path_7209`
  and `synced_import_zone_unresolved_counts_only_real_degradation_7209` must stay
  green through the refactor — they are the cells the rejected projection reddened,
  so they are the drift detector.

## Gates

`make test-rust` and `make test-go` (never a bare `cargo test` as the final
gate), plus `make test-failover` under `./test/incus/with-cluster.sh` — this is
session-sync code and the project rule is absolute. `-race` / cargo legs report
tests-collected, not exit codes: a SIGTERM'd leg is a VOID cell, not a pass.

## Docs owed in the same change

* `userspace-dp/src/afxdp/coordinator/session_manager.rs` — the false
  published-view claim, made true by PR B.
* `coordinator/mod.rs::stop_inner` — the "no live readers" rationale.
* `userspace-dp/src/server/` module docs + `docs/` — the two-socket lock story:
  which verbs take the `ServerState` mutex and which do not, and why
  `sync_session` is the one that does not.
