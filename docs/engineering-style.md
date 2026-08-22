# Engineering style for xpf

This file describes the coding and review personality the project has
settled on. It is checked into the repo so new contributors — human or
agent — internalise it before touching code or reviews. It is terser and
more opinionated than `CLAUDE.md`; keep it that way.

Read this file in full before:

- writing non-trivial code in `userspace-dp/` or any hot path
- reviewing a PR
- opening a PR that claims a performance improvement

## First principles

1. **Latency is sacred.** Memory is cheap. Microseconds on the packet
   path are not. When two approaches trade bytes for branches, take the
   one that's branchless at the hot path.

2. **Correctness first, performance second, convenience last.**
   Defensive code that catches a class of bugs at build time beats tests
   that catch one instance. Favour `const _: () = assert!(...)` over
   `#[test]` pins for invariants that must not drift.

3. **One source of truth for every formula.** If two code paths compute
   the same denominator, they WILL drift. Centralise via a helper the
   first time you notice the duplication. The #704 bug was two gates
   computing "active flow count" differently.

4. **Honest framing always.** If live data doesn't support the PR's
   hypothesis, update the PR body. Don't bury it in a changelog. Don't
   hide behind "tests pass".

5. **Narrow scope.** Bug fix and behaviour choice do not ride in the
   same PR. If a reviewer flags a "maybe we should also" concern, file
   a tracking issue and cross-reference it. Don't silently expand
   scope.

6. **All code changes go through a PR.** No direct pushes to `master`
   for code — not for one-line fixes, not for hotfixes, not for revert
   commits. The PR flow is where reviewers catch what tests miss,
   where live data gets contrasted against the hypothesis, and where
   the commit message and PR body become the permanent record of why
   the change was made. Skipping it to "save time" is how regressions
   land. Docs-only maintenance skills that explicitly direct-push
   (e.g. `/sync-history`) are the only exception and must be declared
   in their `SKILL.md`.

## Workflow for every change

Every non-trivial change follows this ordering. It's the target going
forward — recent PRs have been close but not uniform, and the point of
writing it down is so the next agent can cite "step N" without having
to re-derive the pattern. Cross-references point to sections that carry
the mechanics, so this section is sequencing only.

1. **Issue first.** File a GitHub issue (or pick up an existing one)
   before writing code. Body: problem, hypothesis, acceptance criteria.
   The PR later references it by number in the title.

2. **Plan.** Read the existing code, then write a short plan under
   `docs/pr/<N>-<name>/plan.md` (the `<N>-<name>` prefix follows the
   existing convention documented in `docs/pr/README.md`) or the
   plan-mode scratch file: goal, approach, alternatives rejected, files
   touched, test strategy. No code yet.

3. **Hostile plan review with Codex (`gpt-5.5`).** Spawn via the
   `codex-rescue` agent; brief it to *critique*, not validate.
   **Terminal artifact:** Codex returns `PLAN YES` (or equivalent) AND
   every raised concern has a written disposition in the plan doc
   (applied, or rejected with reason). If Codex pushes back twice on
   the same point, assume it's right until you can show otherwise —
   "Codex stopped objecting" is not agreement. If you and Codex are
   stuck, stop and ask the user.

4. **Hostile architecture review** — same agent, same terminal rule —
   when the change touches a boundary: new BPF map, new protocol
   field, new syscall, cross-dataplane coordination, config/CLI
   surface. Skip this step for pure-local changes.

5. **Code.** Edit existing files; keep the diff scoped to the plan.
   Follow "Hot-path coding discipline" and "API shape discipline"
   below. Scope creep → separate issue + separate PR.

6. **Unit tests that reproduce the failure mode** — see the "Test
   strength" bullet under "Review discipline" below for what counts as
   a strong test.

7. **Hostile code review with Codex.** Same terminal rule: Codex
   returns `MERGE YES` (or equivalent) AND every finding has a written
   disposition. Fixes go into the same branch before push.

8. **Deploy + feature validation.** Unit tests pass ≠ firewall works.
   Run at minimum:

   | What changed | Deploy | Validation | Pass criteria |
   |---|---|---|---|
   | Any change | `make test-deploy` (standalone) | ping between zones | 0% loss |
   | Any change | `make cluster-deploy` (loss userspace cluster) + re-apply CoS (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` — deploy wipes CoS) | `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 | ≥ 23 Gbit/s, no regression vs previous run |
   | Admission / DSCP / scheduler / queueing | above + re-apply CoS (`./test/incus/apply-cos-config.sh <target>`) | `show class-of-service interface` | targeted counter (`flow_share`, `buffer`, `ecn_marked`) moves in the predicted direction — see [`cos-validation-notes.md`](cos-validation-notes.md) |
   | NAT / screens / filter / VLAN / IPsec | above | exercise that feature end-to-end from a test host | session / hit counters advance; negative case drops |
   | HA / VRRP / session sync / fabric | `make cluster-deploy` | `make test-failover` + `make test-ha-crash` | 0 / very low packet loss across failover/failback, both nodes converge |

   When a validation lane can't be run in the test env, say so
   explicitly in the PR body with the reason. Never claim success for
   a check that wasn't executed.

9. **PR open + Copilot review + Codex re-review + merge** — see
   "PR discipline" and "Merging" below for the body template and
   mechanics. Two distinct review surfaces:

   - **GitHub Copilot** auto-posts an inline review on every push to
     a PR (~30s after `git push`). It catches a different class of
     issues than Codex: stale comments, unwired fields, accidentally-
     ignored errors, missing tests. **Always fetch and triage Copilot
     comments before requesting human review** — pretend they're
     from a thoughtful but pedantic colleague. Real ones get fixed
     in the same branch; non-issues get a short reply explaining
     why.

     Standard fetch:
     ```
     gh api repos/<owner>/<repo>/pulls/<N>/comments | \
       jq -r '.[] | select(.user.login | startswith("copilot")) |
              "\(.path):\(.line // .original_line) — \(.body)"'
     ```

   - **Codex hostile code review** runs separately via the
     `codex-rescue` agent. Same terminal rule as the plan review:
     Codex returns `MERGE YES` AND every finding has a written
     disposition. Codex sees the diff with eyes that have not seen
     Copilot's findings — keep the two reviews independent so they
     can disagree productively.

   Iterate until BOTH reviewers are clean (or have explicit-with-
   reason dispositions). Squash merge once CI is green and findings
   are resolved. If the diff grows in response to review, push and
   request a re-review — both Copilot and Codex re-fire on the new
   HEAD.

## Hot-path coding discipline

### Allocations

- **Never allocate per packet.** `Vec::push` that may grow, `VecDeque`
  that returns from a function, `Box::new` inside a `while let Some`
  loop — all land on the allocator.
- **Drain into caller-provided buffers.** Prefer
  `drain_into(&mut out: VecDeque<T>)` over `drain() -> VecDeque<T>`.
  Caller reuses its buffer across polls.
- **Pre-size everything.** `VecDeque::with_capacity(expected)` at
  construction. Fixed-cap rings (`[T; N]`) where the upper bound is
  known statically.
- **Drop policy on full: drop-newest.** Dropping the head of a queue
  evicts a packet that was already close to being serviced and
  extends tail latency. Dropping the incoming packet loses a packet
  that has travelled zero further than the sender. Prefer drop-newest
  unless there's a specific reason otherwise, and document the
  rationale at the drop site.

### Atomics

- **Pick orderings deliberately.** `Relaxed` for counters. `Acquire` /
  `Release` for publish/subscribe slot patterns. `AcqRel` only when
  both sides of a CAS need ordering. If you're reaching for
  `SeqCst` — stop and re-read the algorithm.
- **No `Mutex<VecDeque>` on the hot path.** Use lock-free primitives
  (Vyukov bounded MPMC, SPSC ring, or hand-rolled MPSC). If a mutex
  is unavoidable, isolate it to a slow path.
- **Cache-pad cross-core atomics.** Producer CAS on `head` + consumer
  store on `tail` share a cache line → every op invalidates the
  other core. Split into `#[repr(align(64))] CachePadded<T>` for
  primitives whose job is cross-core coordination.

### Branches

- **Prefer branchless arithmetic.** `saturating_add`,
  `saturating_mul`, `.max()`, `.min()`, `.clamp()`, and
  `bool as u64` conversions generate predictable code.
- **Make hot-path branches predictable.** Config-time booleans
  (`flow_fair`, `exact`) that don't change at runtime give the
  branch predictor a free win. Lift them to early returns at the
  top of hot functions.
- **Don't early-return on rare errors; account for them.** Error
  paths should bump a counter and continue, not unwind. TCP doesn't
  stop because one packet didn't fit; the scheduler shouldn't
  either.

### Compile-time guards

- `const _: () = assert!(condition)` at module level is free. Use
  it for structural invariants: power-of-two sizes, fast-retransmit
  floors, maximum values that fit in a narrower type.
- A `#[test]` that asserts `CONST >= N` runs only on `cargo test`.
  A `const _: () = assert!` runs on every `cargo build`. Prefer
  the latter for values that must not drift.

## API shape discipline

- **Signatures encode contracts.** If a function must not reallocate,
  take `&mut VecDeque<T>` not `-> VecDeque<T>`. If a function expects
  the consumer to hold the "SC" half of an MPSC invariant, mark it
  `unsafe` and document the invariant at the call site.
- **Helpers over duplication, always.** The moment you write the same
  formula in two places, even if they look right today, extract it.
  This is a future-correctness guarantee, not a style choice.
- **Operator-visible units match operator config.** Tests that exercise
  admission boundaries use the same units the operator types. If the
  operator writes `buffer-size 125k` and that parses to 125000 bytes,
  the fixture is `buffer_bytes: 125_000`, not `125 * 1024`. Don't mix
  KB and KiB.

## Modularity discipline

Monolithic files and god functions silently degrade reviewability and
inlining. Treat the trend as a defect, not a style preference.

- **No monolithic files.** A `.rs` file that crosses ~2,000 LOC of
  production code (excluding `mod tests`) is a smell. By the time it
  hits ~3,000 LOC the next change to that file should split it before
  adding new logic. Apply the same rule to test files: when a single
  `mod tests` block accumulates >200 tests across unrelated subjects,
  colocate the tests next to the code they exercise (per-file `mod
  tests` blocks are the project pattern; see the `tx/` and `cos/`
  layouts for examples).
- **No god functions.** A function with >100 lines or >8 parameters
  is a refactor cue. Pull subsystems into their own helpers (state
  machine → enum + dispatch fn, repeated parameter cluster → context
  struct). The standing cautionary example is
  `poll_binding_process_descriptor` in `afxdp.rs`: #945 brought it
  down from 31 parameters to 15, but the body is still long and the
  parameter cluster is still a refactor smell — tracked as #961.
- **One responsibility per module.** A module that mixes admission
  policy with byte-mutation, or memory mapping with ring management,
  will get sliced apart eventually — do it on the way in. The
  `userspace-dp/src/afxdp/` decomposition (`tx/`, `cos/`, the planned
  `umem/` and `frame/` splits in #986/#988) is the working template.
- **Refactor with new features, not after.** When a feature would
  add ~200+ LOC to a module that's already approaching the threshold
  above, the PR splits the module first, lands the feature on the
  smaller pieces. "I'll clean it up next sprint" doesn't survive
  contact with the next on-call rotation.
- **Reviewers escalate monolith creep.** A PR that adds a new
  helper to a 2,500-line file gets a Medium+ review note pointing
  to the relevant tracking issue (or asking the author to open
  one). Don't let "but the surrounding code is already like that"
  land.
- **The gate reds the author of the growth, not the next merger**
  (#7253). `pkg/refactoraudit`'s
  `TestTouchedFileCrossedModularityThreshold` fails when a file **your
  branch touches** crosses 1500 or 2000 LOC, measured from your own diff
  against the merge base — so an unrelated file growing elsewhere can
  never red you, and regenerating `docs/refactoring-audit-current.txt`
  can never silence you. Split the file, or record the decision and its
  reason in `docs/refactoring-audit-accepted.txt`. Keeping the global
  heatmap current is `make audit-refresh`'s job; its lag fails nothing.
  See `docs/refactoring-audit.md` "The two gates".

## Overflow / failure policy

| Scenario | Policy |
|---|---|
| Bounded queue, producer push on full | Return `Err(T)` so the caller can decide. In the admission-path wrapper, drop-newest + bump overflow counter. |
| Bounded queue, consumer drain | Never fails. Loop until `pop()` returns `None`. |
| Invariant violation at config time | `panic!` with context. Not recoverable; crash-start is safer than running with a wrong invariant. |
| Invariant violation at runtime (rare, driver bug) | Bump a dedicated counter, continue. Crashing the dataplane on a single misbehaved packet punishes every other flow. |
| "Path not found" at config apply | Warn + continue if the path is a best-effort cleanup; fail hard if the path is load-bearing. Don't let `|| true` mask the load-bearing case. |

## A fail-closed exclusion owes a show-surface annotation (#6534)

When you make the snapshot builder DROP or DISARM a config object to fail
closed, you have created a second, quieter bug: the operator's `show`
output still renders that object from config, so the box now reports as
enforced something it is deliberately not enforcing. #6534 found this had
happened at ~21 sites, because each individual fail-closed fix was
reviewed on its own and every one of them looked complete.

The rule: a PR that adds an exclusion must also make the surface tell the
truth, in the same PR. Concretely:

1. Put the drop predicate in `pkg/config` as an exported
   `...ExcludedReason(...) string` (or `...Unsupported(...) bool`), not
   inline in the builder. `nat_exclusion_reason.go` and `nptv6_scope.go`
   are the worked examples.
2. Have BOTH the builder and the renderer call it. Two copies drift, and
   they drift in two directions that fail differently: a builder that
   drops what the renderer calls armed lies to the operator, and a
   renderer that annotates what the builder installs cries wolf.
3. Surface the REASON, not just the fact. "NOT INSTALLED" alone makes the
   operator guess which of five conditions fired.
4. Bind the two halves with an AGREEMENT test that names WHICH site
   diverged, and pin each fixture to ground truth first so a fixture that
   stops constructing the malformed shape fails loudly instead of passing
   vacuously (`TestNATExclusionBuilderRendererAgree_6534`).

What NOT to reach for: an applied-set readback from the helper. These
exclusions are decided by the Go builder at snapshot-build time as a
deterministic function of the committed config — the dataplane does not
decide anything at runtime, it honors a verdict already reached. There is
no runtime fact to read back, and `AppliedNATView` hands back the applied
CONFIG, not the applied SNAPSHOT, so it does not carry the drop bit
anyway. What the renderer is missing is the predicate, not a data path.

Reachability, so severity is judged correctly: every one of these
exclusions is a LENIENT-path backstop. The strict commit gate rejects the
config outright, so the lying-show state is reachable only via
`Store.Load` at boot or `Store.SyncApply` on HA peer-sync
(`opts.lenientFirewallRefs`, #1960 no-brick) — which is exactly when an
operator is reading `show` output to work out why traffic is not flowing.

## Persistence classes (#1894)

Every file write that replaces on-disk state belongs to exactly one
class, and the class picks the writer. `pkg/fsatomic` is the single
source of truth; an AST canary in that package (`TestNoDirectOsWriteFile`)
walks EVERY production `.go` file under `pkg/` (#1916, repo-wide — not a
package allowlist) and fails the suite when a direct `os.WriteFile` lands
in a function that is not on the receiver-aware allowlist.

| Class | Writer | Meaning | Examples |
|---|---|---|---|
| DurableState | `fsatomic.WriteFileDurable` | Must survive power loss: temp + fsync + rename + parent-dir fsync. | active config (`.configdb`), rollback slot 1, rescue config, `master.key`, DHCPv6 DUID, `frr.conf`, `/etc/hostname`, sudoers drop-in, user + root `authorized_keys`, TLS cert + key (`/etc/xpf/tls/*`), lifeline record, provisioned-users / -passwords / -keys markers (#5841) |
| AtomicGeneratedConfig | `fsatomic.WriteFileAtomic` | Regenerated on boot/apply; a torn file is unacceptable, a lost-on-power-cut update is fine. **No fsync — this class exists so hot apply paths never pay one.** | swanctl conf, Kea configs, networkd `.link`/`.network`, rollback slots 2..N, sshd drop-in, rsyslog drop-in, chrony drop-in, `ssh_known_hosts`, `/etc/timezone`, `/etc/resolv.conf` |
| BestEffortKernelKnob | direct `os.WriteFile` | procfs/sysfs: rename does not exist there, the atomic writers are impossible by construction. Also the `/etc/resolv.conf` bind-mount in-place fallback (rename onto a bind mount is EXDEV/EBUSY). | `rp_filter`, `accept_dad`/`addr_gen_mode`, RPS/RFS/XPS, `fib_multipath_hash_policy`, socket-buffer sysctls |

Special cases:

- **TLS cert + key are DurableState** (#1916 D6): the HTTPS API can bind a
  non-loopback `system services web-management https interface` address, so
  cert churn after a power-cut loss would break remote clients' TOFU pins.
  The pair is written with the #1916 D5 STRICT sequence — strict-remove the
  stale pair (ignore only ENOENT; any other remove/SyncDir error ABORTS the
  write, so the `{neither}` start is proven) → key (0600) → cert (0644) — so
  a crash can never leave a MISMATCHED pair. A persistence failure logs and
  serves the in-memory cert (HTTPS still installs); only a true generation
  failure returns a non-nil error.
- **`authorized_keys` uses `fsatomic.WithOwner(uid, gid)`** (#1916 D7): a
  plain durable write replaces the inode with a root-owned temp, and a crash
  before a separate post-rename chown would leave root-owned `0600` keys that
  sshd refuses (EACCES → lockout). `WithOwner` fchowns the temp fd BEFORE the
  rename so the file is correctly owned atomically at install. The owner is
  resolved cgo-free from `/etc/passwd` (`lookupUIDGID` — never `os/user`).
- **`WithOwner` vs `WithPreserveExisting` precedence**: if both are set,
  owner = `WithOwner`'s, mode = preserved-existing's (explicit owner wins).
- **`ssh_known_hosts` WRITE is AtomicGeneratedConfig, but its REMOVAL
  fsyncs the parent dir** (#5112): the write is a no-fsync
  `WriteFileAtomic` because a lost-on-power-cut rewrite just re-renders the
  SAME trust next apply. Clearing `security ssh-known-hosts` REMOVES the
  xpf-owned file (`applySSHKnownHosts` → `removeManagedSSHKnownHosts`,
  ownership-guarded on the managed header so a foreign/hand-maintained file
  is never deleted), and that removal fsyncs the parent dir
  (`fsatomic.SyncDir`): a lost unlink is the DANGEROUS direction — it would
  resurrect a revoked, now-untrusted host key on reboot. Applied durable
  trust must not outlive desired trust.

Rules of thumb:

- fsync cost lands on operator-paced commit paths only (commit,
  rollback save, rescue save, DUID persist, frr.conf reload) — never on
  per-apply, per-packet, or per-poll-tick paths.
- Multi-file shuffles batch namespace durability with one trailing
  `fsatomic.SyncDir` (renames AND unlinks) instead of per-file dir
  fsyncs — see configstore `saveRollbackFiles`.
- Temp+rename WITHOUT fsync is namespace atomicity, not durability:
  after power loss the rename can surface a zero-length file or vanish.
  Do not hand-roll it; pick a class.
- A daemon that cannot persist config must not boot pretending
  otherwise: `configstore.New` is fail-closed (#1893) — there is no
  "file-only" fallback backend.

## Review discipline

### Reviewing (adversarial by design)

- **Be antagonistic in service of quality.** Reviewers who default to
  "LGTM" let regressions land. The architect/reviewer role exists to
  hold a deliberately high bar.
- **Separate severity from style.** Correctness bugs, perf cliffs, and
  API contract issues are Medium+. Terminology drift, rustdoc rendering,
  redundant no-ops are Low. Call the severity explicitly; it tells the
  author what to do first.
- **Concrete code shape, not vague complaints.** "Consider centralising
  the formula" is less useful than a five-line snippet showing the
  exact helper signature. If you want a specific change, show it.
- **Test strength matters.** A regression test that leaves state at
  `0` before the final assertion is an arithmetic-consistency check,
  not a regression guard. Tests must recreate the failure mode.
  Counter-factual assertions that reconstruct the pre-fix formula and
  prove it *would* fail are the strongest pin.
- **Split behaviour choices out of bug fixes.** If a reviewer spots
  "while you're here, we should also clamp...", that's a separate PR
  or a follow-up issue. Don't let scope creep hide behind
  "review feedback".
- **Trust but verify.** An agent's commit summary describes what it
  intended. Read the diff. Re-run the tests on the updated head before
  approving.
- **Two independent review surfaces.** Codex (hostile, design-level)
  and Copilot (inline, mechanical-detail) catch different classes of
  bugs. Treat them as separate passes; do not skip either. Codex
  often misses the unwired-field or stale-comment bug that Copilot
  spots; Copilot often misses the architectural concern that Codex
  flags. The combined coverage is the point — losing one halves
  the review.

### Responding to review (as author)

- **Apply review items by severity, fastest first.** Cleanup-level
  items (docs, naming) land in the same push. Medium items get their
  own commit if they're substantive. Design questions get a reply
  asking for the decision before coding.
- **Don't silently defer.** If a reviewer raises a concern you don't
  act on, reply with why, and file a tracking issue. The next
  reviewer should not have to re-discover the concern.
- **Update the PR body when live data disagrees.** If the hypothesis
  turns out to be partly wrong, rewrite the summary. Keep both the
  before data and the after data visible. Future readers need the
  honest picture.

## PR discipline

### Title

- Imperative. `userspace-dp: lock-free redirect inbox eliminates cross-
  producer mutex (#706)`, not "Removed mutex".
- Issue reference in parentheses at the end. Multiple if the PR closes
  multiple.

### Body

- **Summary**: 3–6 bullets. What changed and why.
- **Hot-path shape** (for perf PRs): explicit about added instructions,
  allocations, atomics. "One `saturating_mul` + one `max` per
  admission (~2–3 ns)" is the right specificity.
- **Test plan**: checkbox list. What tests were added, what was run.
- **Live data** (for PRs that claim to move a metric): before/after
  table. If the metric doesn't move, say so.
- **Deferred**: named follow-ups with tracking issue numbers. Not
  "TODO later".
- **Refs**: every related issue.

### Commit messages

- Same shape as PR titles. Imperative, prefixed with the subsystem.
- Body paragraphs explain *why*, not *what*. The diff shows what.
- No emoji. No marketing. No "Makes the code better".

### Merging

- **Every code change lands via PR.** Even revert commits. Even
  "obviously right" one-line fixes. Even cherry-picks from someone
  else's branch. If you find yourself typing `git push origin master`
  for anything except a docs-only maintenance skill that explicitly
  does that (see first principle #6), stop — open a PR.
- Squash-merge, single commit per PR on master. Commit message is the
  PR title.
- Do not merge with failing tests. Do not `--no-verify` to skip hooks.
- Close referenced issues with a pointer to the merge commit and the
  specific follow-up issues if any part was deferred.

## Project-specific reminders

These are not "style" but are worth keeping next to the rest because
they repeatedly bite:

- **Smoke tests run ONLY on the loss userspace cluster.** The smoke
  target is `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`,
  driven by `INCUS_REMOTE=loss` + `test/incus/loss-userspace-cluster.env`.
  Invocation: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
  ./test/incus/cluster-setup.sh deploy all`. Do NOT smoke on the
  local `bpfrx-fw0/1` (legacy eBPF cluster, regression-only) or
  `bpfrx-fw` (standalone eBPF reference). `make cluster-deploy`
  without `BPFRX_CLUSTER_ENV` targets the legacy local cluster —
  that is the wrong path for any userspace-dp validation.
- **Deploy wipes CoS config.** After `cluster-setup.sh deploy`, re-run
  `./test/incus/apply-cos-config.sh <target>` before running iperf3
  for any #706 / #707 / #708 / #709 / #718 validation.
- **A `Mutex`/`RwLock` in production Rust is acquired
  poison-tolerantly, never with `.unwrap()`.** `std` poisons a lock the
  moment a thread panics under its exclusive guard, and every later
  acquisition returns `Err` — so `.unwrap()` turns one contained panic
  (the #925 worker supervisor contains it) into a panic on EVERY
  subsequent acquisition of that lock, i.e. a permanent outage of
  whatever the lock guards. Three settled forms, in order of preference:
  - `worker_queue::lock_recover` / `try_lock_recover` (#1807) for the
    worker-command queues and `shared_ops::lock_shared_recover` (#2402)
    for the shared-session / owner-RG maps. These also `clear_poison()`
    and bump a per-subsystem recovery counter. Use them **only** for
    their own subsystem: each stamps a subsystem-specific journald line,
    so borrowing one for unrelated state makes both the operator message
    and the counter lie.
  - the inline idiom `lock().unwrap_or_else(|e| e.into_inner())` — the
    tree-wide default (`nat::allocator`, `event_stream`,
    `afxdp::sharded_neighbor`, `afxdp::icmp_ratelimit`, `afxdp::wg`
    #6422). It is the only form that covers `RwLock`, which neither
    helper takes.
  - **Never** `if let Ok(g) = m.lock()` (silently skips the operation)
    or `.lock().map(..).unwrap_or_default()` (substitutes EMPTY state).
    #2402 was exactly the latter: an empty shared-session table on the
    HA promotion path silently dropped every active synced session at
    the moment of failover.

  Recovery keeps the committed prefix of everything already written,
  which is the right answer for a map. Before converting a lock that
  guards a cross-field invariant, check the critical section for panic
  sites: if there are none the recovered value is by construction
  well-formed, and if there are some, ask whether panicking forever
  actually repairs the inconsistency (it usually does not — an
  idempotent reconcile pass that can still run does).

- **Rust tests must be parallel-safe — `make test-rust` forces
  `--test-threads=1`, but a plain `cargo test --release` does not.** A
  test that silently assumed serial execution (a shared process-global
  counter, or heavy busy-spin threads) flaked or deadlocked the moment
  someone ran the suite in parallel (#6148 progress-gated liveness;
  #6157/#6294 the WG engine/frame tests wedged a full-suite run for
  >100min). Two settled patterns:
  - **A test-only global counter/state → make it `thread_local!`**, not
    a `static AtomicUsize`. Each test thread then resets/mutates/reads
    its own copy, so no parallel sibling can corrupt the assertion
    (`OUTER_ROUTE_RESOLVE_COUNT` in `afxdp/frame/wg.rs`, #6294). Strictly
    stronger than serializing every mutator behind a lock.
  - **A test that MUST touch a genuinely shared global, or that spawns
    busy-spinning worker threads → serialize it behind a poison-tolerant
    module-local guard** held for the whole body:
    `LOCK.lock().unwrap_or_else(|e| e.into_inner())`
    (`icmp_ratelimit::global_bucket_test_lock`,
    `wg::engine_tests::wg_engine_test_serial` #6157). The blocked sibling
    PARKS on the mutex (futex wait) instead of compounding scheduler
    oversubscription. Every test sharing a given global must take the
    SAME lock.
  - Prove the ISOLATION variant with a **deterministic fail-on-revert**
    (two barrier-synced threads whose per-thread counter assertion is
    mathematically impossible under a shared global). The mutex GUARD
    variant's fail-on-revert is **scheduler-dependent** (barrier + many
    iterations + a widened critical window make it effectively certain)
    and pins the guard PRIMITIVE's exclusivity, not that each heavy test
    TAKES it — verify that application by inspection, since a deterministic
    test for it reduces to the underlying flake. Back both with repeated
    parallel runs of the previously-flaky test.
- **Shared-cluster lock protocol (#1875).** The loss userspace cluster
  is shared by concurrent agents; ownership is serialized by the
  advisory flock on `/tmp/xpf-cluster.lock` with holder metadata in
  `/tmp/xpf-cluster.owner`. Who locks what:
  | Actor | Protocol |
  |---|---|
  | `cluster-setup.sh` deploy/start/stop/restart/create/destroy/init | self-locks (re-execs through `with-cluster.sh`; the build stays outside the lock) |
  | `apply-cos-config.sh` | self-locks the same way |
  | Destructive HA smoke (`test-failover`, `test-ha-crash`, `test-double-failover`, `test-stress-failover`, `test-chained-crash`, `test-active-active`, `test-restart-connectivity`, `test-private-rg`) | self-locks the same way via the `cluster-cell.sh` preamble (#4020) — a reboot / force-stop / failover QUEUES behind a held lock instead of colliding with a concurrent deploy/smoke. Read-only `test-connectivity.sh` stays lock-free |
  | Multi-command measurement cells (deploy → apply-cos → measure) | wrap the WHOLE cell: `./test/incus/with-cluster.sh "purpose" -- cmd...` |
  | `wg-interop.sh` | self-locks per command standalone; runs lock-free inside a cell (marker-aware) |
  | Ad-hoc one-liners around commands that do NOT self-lock | `flock /tmp/xpf-cluster.lock sg incus-admin -c "..."` still valid |
  Rules that keep the mutex sound:
  - **Never wrap a self-locking script in a raw outer
    `flock /tmp/xpf-cluster.lock`** — it deadlocks (the inner acquire
    cannot see a raw caller's lock). Use `with-cluster.sh`, whose
    `XPF_CLUSTER_LOCK_HELD=<lockpath>:<pid>` marker (validated by
    path + pid liveness + ancestry) makes nesting safe.
  - **Never `rm` the lock or owner files.** flock binds the inode —
    deleting the path silently splits the mutex into two "owners".
    Stuck holder recovery is `kill <holder-pid>` (kernel releases the
    lock on fd close), and only for YOUR OWN holders.
  - **Never kill another agent's holder.** The lock serializes you:
    wait (the wait loop prints who holds it, since when, and why,
    every 30s) or coordinate. `XPF_CLUSTER_LOCK_TIMEOUT=<s>` opts a
    cell into fail-fast instead of waiting forever.
  - **Never hand-roll binary deploys** (`incus file push` + restart
    loops) to the cluster — they bypass the lock AND the #1864/#1869
    verify-dataplane gate. Deploys go through `cluster-setup.sh
    deploy` / `make cluster-deploy`. The same gate now runs on the
    standalone `setup.sh deploy` path too (#6493), so `make
    test-deploy` is no longer the one binary-swap route that can put
    a verifier-rejected shim on a box and report success.
  - **Destructive HA smoke self-locks (#4020).** A `test-failover`
    that reboots a node mid-iperf is FAR more disruptive than a
    deploy, so the reboot/force-stop/failover smoke scripts share the
    `cluster-cell.sh` preamble (`xpf_enter_destructive_cluster_cell`):
    they re-exec through `with-cluster.sh` and QUEUE behind a held
    lock rather than colliding with a concurrent agent's deploy/smoke.
    Add a new destructive smoke script by sourcing `cluster-cell.sh`
    in its preamble; the `make test-cluster-lock-lib` self-test (also
    covers the `with-cluster.sh` contention matrix) asserts every
    destructive script takes the lock before it mutates a node and
    fails RED if one drops the wiring. No cluster needed — private
    lock path, mocked incus.
  - Queue diagnosis: `cat /tmp/xpf-cluster.owner` +
    `fuser -v /tmp/xpf-cluster.lock`. A dead recorded pid with the
    lock still held means a child inherited the fd (pre-#1875 raw
    holders only; `with-cluster.sh` runs cells with the lock fd
    closed, so killing a cell's tree releases instantly).
- **Raw/datagram sockets go through `pkg/linuxsock` (#2608).** A raw
  `unix.Socket(2)` is NOT close-on-exec by default (unlike Go `net`
  sockets), so a bare raw `AF_PACKET`/raw-ICMP/datagram fd leaks into
  every helper the daemon fork-execs (`frr-reload.py`, `swanctl`, DHCP
  helpers) — an fd leak and a raw-frame security boundary. Use
  `linuxsock.Socket(domain, typ, proto)` (ORs `SOCK_CLOEXEC` atomically
  into the type), never `unix.Socket` directly. `pkg/linuxsock`'s
  `TestNoDirectUnixSocket` canary scans every production `.go` under
  `pkg/` and fails the suite on a new direct call site (the one
  justified exception, `pkg/vrrp`'s pre-#2476 receiver, is allowlisted
  and pinned by its own `afpacket_cloexec_test.go`).
- **Always `source ~/.sshrc` before `git push`.** The user's SSH agent
  config lives there.
- **172.16.80.200 is the iperf3 test endpoint.** Not 172.16.50.x.
- **Use `cli`, not `xpfctl`.** The remote CLI binary is `cli`.
- **Primary is fw0 on RG0 in the loss userspace cluster.** Apply config
  changes to the primary; sync takes care of the secondary.
- **`make build` does NOT require `make generate` (#1864).** The
  git-tracked `pkg/dataplane/userspace_xdp_bpfel.o` is the deployable
  artifact; only regenerate it when `userspace-xdp/` source changes.
  Regeneration requires the PINNED toolchain
  (`userspace-xdp/rust-toolchain.toml` + the bpf-linker pin in
  `pkg/dataplane/build-userspace-xdp.sh`) and passes a kernel-verifier
  verify-then-install gate — an unpinned nightly once produced an
  object that blew the 1M-insn verifier cap and took both cluster
  dataplanes down. Never commit a regenerated `.o` unless the gate
  PASSed and `git diff --exit-code pkg/dataplane/userspace_xdp_bpfel.o`
  is clean after a pinned re-run. Recovery from a bad artifact:
  `git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build`.
- **Before claiming a CoS admission-path PR moves a metric, read the
  counters.** `show class-of-service interface` surfaces `flow_share`,
  `buffer`, and `ecn_marked` drop counts per queue since #724. See
  [`cos-validation-notes.md`](cos-validation-notes.md) for the
  methodology, the decision tree mapping counter patterns to fixes,
  and the current test-env limitation that blocks ECN end-to-end
  validation. Iterating on admission logic without reading these
  counters is how #721/#722 landed dormant on the live workload
  (#725).

## Tone signals (patterns that have worked)

- "The honest fix is..." → frame the real engineering tradeoff, not
  the easy one.
- "I would either ... or ..." → offer options in reviews, don't
  dictate.
- "I would not silently land ..." → insist on explicit agreement for
  operator-visible changes.
- "Behaviour choice, not a bug fix" → scope discipline in one phrase.
- "Does not recreate the old failure mode" → test-strength review in
  one phrase.
