# Claude SMR hostile plan-review — round 91 (v10.7.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — eleventh pass
on the cut line; I authored the v10.7.0 fold of Codex r90's 2B/2H/1L, so
this review attacks my own fold first. Verdict: **PLAN YES**.

## 1. Fold verification (each Codex r90 finding, code-traced)

**r90-1 (B — owned RWoLB state can't use borrowed-replica probation
cleanup).** Verified at the base: the transient purge releases the local
reservation (`promote.rs:185-207` — BPF delete + `release_source_nat_allocation`
+ `release_nat64_allocation`), the re-entry allocates fresh P2
(`nat/source.rs:1548`), and the v10.6.0 model would have held P2 in a
no-release/no-delete probation entry — leak on reap, split-brain on
follow-up. The v10.7.0 fold RETRACTS the alive-probation-install for
RWoLB/`ReplacedSyncedLocal` provenance: a closing-flagged packet
(SYN-bearing included) rolls back the fresh allocation and skips
install/publication/Open entirely (§5.6 site-3 supplement). No entry is
created, so no owned resource is ever held by a suppressed entry. The
rollback discipline is the arm's existing one (the `ExistingResolved`
branch already guarantees an unowned `live_by_flow` allocation never
leaks). Self-attack: (i) forward-without-install is the site-2b refuse
precedent — the derived decision object exists independently of the
install; (ii) cache insertion is suppressed with the install (the
site-2b `created=false, install_failed=true` pattern) so no stale cache
entry; (iii) the next non-close packet re-enters and installs normally
with Open — master's miss semantics, no zero-producer; (iv)
`ReplacedSyncedLocal` skip means `take_synced_local` never runs — the
synced victim survives and the packet delivers uncached, the #4539
decline-delivery precedent.

**r90-2 (B — clearing no-Open probation creates unguarded delete
authority).** Verified: `takeDeleteGenV4` returns 0 for a
never-stamped key and the receiver guard falls back to unconditional
delete (`sync_conn_gen.go:176`, `:263`). The trace required a
local-origin (ForwardFlow/LocalMiss) no-Open probation entry — only the
v10.6.0 RWoLB/ReplacedSyncedLocal installs created those, and v10.7.0
creates none. Residual check: site-2c probation entries keep their
`SharedMaterialize` (peer-synced) origin even after the probation clear,
so their expiry is excluded by the `expire.rs:342-344` gate
(`!is_peer_synced`) regardless of clear state — the gen-zero Close path
is unreachable for every remaining probation class. The §7 invariant now
states this explicitly.

**r90-3 (H — key+NAT agreement ≠ decision consistency).** Verified:
`SessionDecision` carries `resolution: ForwardingResolution`
(`entry.rs:11-12`); shared publication inserts aliases without removing
prior state (`shared_ops.rs:897`); the materialize forwards with the
shared S2 (`session_glue/mod.rs:1098`). The v10.7.0 fold replaces the
skip-upsert probe with adopt-S2-preserve-deadline: the upsert installs
S2's decision/metadata wholesale; only `last_seen_ns`,
`expires_after_ns`, `probation=true`, and the alive flags carry over.
Entry and packet agree by construction. Generation-change inheritance
only shortens (≤20 s), never extends. Self-attack: the wheel re-queue
must use the preserved `expires_after_ns` — stated in the rule; the
upsert emits no Open/Close on the synced path (that is why the site-2c
zombie's silent reap holds), so adopt-S2 adds no emission.

**r90-4 (H — companion propagation is an unlisted probation refresh).**
Verified: `propagate_tcp_state_to_companion` marks the companion and
restamps `last_seen_ns`/timeout + requeues (`session/mod.rs:1254-1276` —
`entry.closing = true`, `last_seen_ns = now_ns`, timeout reselect,
`push_to_wheel`). The fold adds the wholesale skip for probation
targets (§5.6 fence paragraph + §7 invariant + §9(d) test). The mark
lost on a probation companion is no-signal-loss: the zombie reaps
local-only and emits nothing either way; the close's authoritative mark
lives on the validated live entry.

**r90-5 (L — §3.1 rows).** All six corrections re-verified at both
revisions: strict-syn `:1646` both (the plan's old range was the comment
block); `touch_if_stale` base `:301`; `build_reject_rst_frame` `:347`
both; LocalDelivery fn `:20` both; transient-purge block → master
`:1208-1223`; the #6478 consequence now states the sessionless→MISS-path
mechanics exactly (master `poll_descriptor/mod.rs:941-959`).

## 2. Full-plan consistency sweep

- Every v10.6.0 reference to the retracted alive-probation-install or
  skip-upsert shape was rewritten: §3 site-3/site-2c rows, §5.6 site-2c
  + site-3 supplement, §5.7 cross-ref, §5.8 three bullets + the
  typed-outcomes RWoLB clause, §7 invariant, §9 tests (a)/(d)/(e) + the
  new peer-synced-provenance close-skip bullet, §11 question (e). The
  retraction narratives are the only remaining mentions — grep-verified.
- The gate (§5.1–§5.4, §5.7) is untouched for the seventh consecutive
  round; Codex r90's own closing line: "The gate arithmetic, zero-trust
  absorbing-state argument, and MissingNeighbor typed-outcome dispatch
  produced no additional finding."
- The v10.7.0 shapes are strictly smaller than v10.6.0's: skip-install
  REMOVES state transitions instead of adding a lifecycle;
  adopt-preserve reuses the existing upsert; the propagation skip is a
  one-predicate guard.

## 3. Bottom line

Codex's two r90 BLOCKERs were aimed at the v10.6.0 fold's reuse of the
borrowed-replica model for an owned resource — a real category error,
now removed by retreating to the site-2b skip-install precedent, the
arc's most-reviewed refuse shape. PLAN YES for v10.7.0.
