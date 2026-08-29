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
   | Any change | `make cluster-deploy` (loss userspace cluster) + re-apply CoS (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` — deploy wipes CoS) | `iperf3 -P 16 -t 30 -p 5211` → 172.16.80.200 | ≥ 23 Gbit/s, no regression vs previous run |
   | Admission / DSCP / scheduler / queueing | above + re-apply CoS (`./test/incus/apply-cos-config.sh <target>`) | `show class-of-service interface` | targeted counter (`flow_share`, `buffer`, `ecn_marked`) moves in the predicted direction — see [`cos-validation-notes.md`](cos-validation-notes.md) |
   | NAT / screens / filter / VLAN / IPsec | above | exercise that feature end-to-end from a test host | session / hit counters advance; negative case drops |

   **Use 5211, not 5203, for the throughput row — and the two are not
   interchangeable (#7610).** The same row tells you to apply
   `test/incus/cos-iperf-config.set` first, and in that fixture the port IS the
   class: `bandwidth-output` term 3 maps **5203 → `iperf-3g` → `scheduler-3g`,
   `transmit-rate 3.0g exact`**, while term 11 maps **5211 → `iperf-uncapped`**.
   Measured back-to-back on a healthy fw0: **5203 → 2.86 Gbit/s, 5211 → 23.1
   Gbit/s**. This row asked for 5203 against a ≥ 23 Gbit/s bar until #7610, so a
   lane following it literally read a *correctly working shaper* as an 8x
   throughput regression — and the criterion "no regression vs previous run" made
   that reading look confirmed, because every previous run of the same wrong port
   reported the same ~3 Gbit/s. Ports 5200-5211 each select a different
   forwarding class; check `cos-iperf-config.set` before substituting one.

   5203 is the right port when you are validating the **shaper** rather than the
   dataplane: there the pass criterion is ≈ 3 Gbit/s, and a result near 23 means
   the shaper is NOT engaging.
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
- **Prefer a compile-time guard — but measure before assuming one
  exists.** A guard that cannot catch the bugs that motivated it is
  decoration, and a lint whose false positives get suppressed is worse
  than no lint: a suppressed lint reads as a checked property. Before
  proposing a `go vet` / `analysistest` rule for a recurring defect,
  pull two or three of the real historical instances out of git history
  and check the rule reds on them. A rule keyed to the vocabulary a FIX
  introduced is structurally blind to the pre-fix code — it tests the
  repair, not the property. `docs/applied-marker-invariant.md` is the
  worked example: the applied/published/converged marker rule proposed
  in #6533 missed 3 of 3 sampled historical defects and flagged the
  correct mechanisms, including its own flagship target, because
  correct markers are correct via caller contracts and readbacks that
  no intra-function dominance rule can see.

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
- **A comment is a CLAIM, not a check — verify it before you rely on
  it.** A comment that justifies a direction ("we do X because Y") is
  the most dangerous kind, because a reader takes the direction and
  never re-derives Y. Y was verified once, at authorship, and never
  again. Three landed in a single review batch, all true when written
  and false at head:

  - `daemon_apply_tail.go` asserted "every step below still RUNS (no
    early return)". A lane whose teardown sits below it checked the
    code rather than the comment, because if it *had* early-returned the
    teardown would silently stop running on exactly the commits that
    fail.
  - `netlink_lo0.go` justified per-term fail-closed with "a rejected
    table leaves NO host filter = fail-OPEN". True before #6476 added
    the cold-boot fence; false after, which is what unblocked the
    correct plan-failure direction in #6806.
  - `daemon_nft.go` justified dropping a protocol predicate as
    "mirroring the tcp-flags lowering" — and tcp-flags does not drop its
    predicate. Wrong when written.

  So: **when a comment is load-bearing for your change, read the code it
  describes.** If it is stale, annotate it as historical rather than
  deleting it — the next reader needs to know it *was* true, not merely
  that it is gone. Note the failure mode this shares with a refuted
  finding whose refutation never reached the code: in #6807 the review
  had *disproven* the repo's FRR permit-all model, and the repo's own
  comments and tests still asserted it — so a reader had not a neutral
  prior but a confidently wrong one, with every local check agreeing.
- **An agreement test cannot see a defect the two sides SHARE.** The
  #6806 lo0 parity gate compares the netlink installer against the text
  oracle. Both dropped an unresolvable token, so they agreed perfectly
  while both were fail-open, and the gate was green the whole time. When
  two implementations must match, "assert the agreement, never pin one
  to a literal" is right for drift — but drift is not the only defect.
  Add a cell asserting the PROPERTY each side owes independently (here:
  neither mirror may lose the refusal evidence at its own boundary), or
  the shared blind spot is invisible by construction.
- **A tool-gated leg that SKIPs is a green that measured nothing.** Say
  whether it ran. `nft`-dependent parity, cargo legs, cluster smoke:
  report tests-collected, not just `ok`.
- **Format the files you TOUCHED, never a directory.** `gofmt -w pkg/daemon`
  reformatted **12 pre-existing unformatted files** a lane had never
  touched, silently widening its diff. Master carries unformatted files,
  so `gofmt -w` on a directory is not idempotent with respect to your
  change in this repo specifically — and a widened diff is how an
  unrelated change rides in unreviewed. Use `gofmt -w <file>...`. If it
  has already happened, recover by filtering: for each modified `.go`,
  if its diff adds none of your change's identifiers,
  `git checkout HEAD -- <file>`.
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

### A closing keyword cannot be negated

GitHub's parser does not read negation. `Does not close #N`,
`why this does not close #N` and `merging this must not close #N` each
contain a live `close #N` token, and the issue is closed the instant the PR
merges — against the explicit written intent of the sentence it appears in.

**To scope an issue OUT of a PR, drop the verb.** Write `Refs #N`, or
`#N is out of scope, see below`. `advances #N` and `part 1 of 2 for #N` are
also safe. Never `close`/`closes`/`closed`/`fix`/`fixes`/`fixed`/
`resolve`/`resolves`/`resolved` adjacent to `#N` unless you mean it.

**One correct form does not neutralise an incorrect one elsewhere in the same
body.** A PR that ended with `Refs #7406` still closed #7406, because a
scope-explaining sentence earlier in the body said "Does not close #7406."

**Watch the heading/first-line pair.** A `## What this does NOT close` heading
followed by a paragraph beginning `` `#NNNN` `` reads to the parser as
`close #NNNN` across the blank line.

**Merge pre-flight — run it on the FLATTENED body.** These phrases wrap across
lines and carry `**` mid-token, so a line-based `grep` misses them; that is how
this got past a reviewer who was specifically looking for it:

```bash
gh pr view <n> --json body -q .body | tr '\n' ' ' | sed 's/[*_`]//g' \
  | grep -oiE '(close[sd]?|fix(e[sd])?|resolve[sd]?) +#[0-9]+'
```

Every hit must be an issue you intend to close. Also check every commit
message body — GitHub scans those on the default branch too, so a clean PR
body does not save you.

**Why this is worth a section.** The failure is invisible after the fact: the
wrongly-closed issue reads `COMPLETED`, so every subsequent sweep for open work
skips it forever, and the only contradicting evidence is a one-second gap
between the merge and the close on an issue the PR itself disclaimed. Six
issues have been recovered this way — #6683, #7406, #5192, #5084, #7033, #6979
— none by anyone noticing, all by a periodic sweep:

```bash
gh pr list --state merged --limit 400 --json number,body,mergedAt \
  -q '.[]|"===PR\(.number)|\(.mergedAt)===\(.body)"'
# flatten each body, then match:
#   \b(not|never|without)\b[^.#]{0,45}?\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b\s+#(\d+)
# a hit whose issue closed within ~2s of mergedAt is a victim
```

**Check the gap before reopening.** A real auto-close is within a second or
two. One candidate closed 4.6 hours after its merge and was a deliberate close;
reopening a legitimately-closed issue is its own kind of damage.
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

- **Never assert an exact count or an in-flight state that the SCHEDULER
  can move (#7563).** Three tests in three packages failed under a
  full-tree parallel `go test ./...` and passed on immediate re-run of
  the SAME tree, on branches that could not reach the code they failed
  in. They shared one shape: each sampled an asynchronous observable at
  a fixed point, so the value read was a reading of the machine rather
  than of the subject.
  The three mechanisms are worth recognising, because none of them is a
  data race and `-race` finds none of them:
  1. a **retry-loop test that let one attempt reach the real resource** —
     the fixture stubbed the failing attempts and let the winning one
     bind a live port, so a genuine conflict made the loop resample
     correctly and the exact-attempt-count assertion fail;
  2. a **single sample taken right after an async enqueue** — the pass
     under test hands work to a worker goroutine and returns, so "0
     applies so far" is the correct answer to the wrong question;
  3. a **counter read taken from a callback the producer fires BEFORE
     it accounts the event** — the callback is delivered first by
     construction, so observing it and then reading the counter races
     an `Add(1)` that has not happened yet.
  The fixes, in preference order: make the fixture unable to observe
  the machine at all (inject the outcome rather than sampling a real
  resource); otherwise wait on the observable that actually implies the
  property, and make the wait FAIL LOUDLY, naming what never arrived.
  Where the producer already publishes a completion watermark, wait on
  that — it is advanced by the same goroutine after the accounting, so
  a read taken once it covers the item happens-after the accounting.
  What NOT to do: add a retry or a sleep to the assertion. That hides
  the sensitivity instead of removing it, and a test that passes on the
  second attempt is indistinguishable from one that passes for the
  wrong reason. Nor is "just re-run it" free: classifying one of these
  costs a full repo-wide re-run, and — the real damage — it trains
  reviewers to re-run a red instead of reading it, which is precisely
  the habit that lets a genuine regression through.
  **Verify the population empirically rather than by pattern.** Of the
  15 counter reads in `eventstream_test.go` that matched shape 3 by
  eye, injecting a delay at the producer's accounting site red-flagged
  exactly two. Pattern-matching would have rewritten a dozen tests that
  were already sound. Reproduce a load-sensitive assertion by injecting
  the scheduling perturbation a loaded box supplies for free, and fix
  what actually reds.

- **A test that needs a kernel capability must STUB it, not skip on it
  (#6675).** `pkg/dataplane/userspace` builds every snapshot through
  `buildRouteSnapshots`, which dumps the kernel ip-rule table via
  `ruleListFn` and — correctly, per #3772 M9 — refuses to swallow a dump
  failure. In a sandbox without `CAP_NET_ADMIN` that returns EPERM,
  `buildSnapshot` returns a nil `*ConfigSnapshot`, and the ~45 test call
  sites that discard the error dereference it. A nil dereference is a
  SIGSEGV that aborts the whole test BINARY, so the first one takes every
  remaining test in the package with it: the review run shows a crash with
  no diagnostic, and reviewers chase a phantom regression in whatever PR
  happened to be under test.
  The fix is a `TestMain` that replaces the enumerator package-wide, NOT a
  `t.Skipf` on EPERM. Skipping trades a crash for silence and leaves the
  package with zero coverage in exactly the reduced-capability
  environments where reviews run; stubbing lets those tests actually run
  there. Guard the wiring with a code-pointer comparison against the real
  function (`TestPackageIsHermeticWrtKernelIPRules_6675`) — a behavioural
  check passes on any machine that HAS the capability, which is every
  laptop and most CI runners, so it would never notice the stub being
  deleted.
  **Follow-through (#7446):** hermeticity stops the ENVIRONMENT causing
  that crash; it does not stop a bad fixture causing it. The 44 call sites
  that discarded the error now go through `mustBuildSnapshot` /
  `mustBuildSnapshotWithSchedulerState`, which make the safe form the SHORT
  form — a call site gets shorter by adopting them, which is what keeps the
  population from growing back. An AST guard
  (`TestNoDiscardedSnapshotBuildErrors_7446`) fails if the discarding shape
  returns. Scope such a guard to the builders that return a POINTER: a nil
  slice or map reads back safely, so sweeping those in would flag call sites
  that cannot exhibit the defect — the guard carries a negative-control cell
  proving it does not.
  And when a package-wide default is introduced, compare the PASS SET before
  and after, not just "still green": still-green and unchanged are different
  claims, and only the second rules out a test that was passing because the
  real dependency happened to return real data.

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
  - **A worker thread whose progress the test ASSERTS must reach its
    first cycle by CONSTRUCTION, not by scheduling — write the loop as
    a do-while.** A `while !stop { work }` unbounded worker racing a
    BOUNDED one can be scheduled for the first time only after the
    bounded side finished and the main thread stored `stop`: zero
    cycles, and a `cycles >= 1` "we made progress on both sides"
    precondition trips as a scheduler artifact rather than a
    regression. `loop { work; if stop { break } }` costs one extra
    cycle and makes the precondition unfalsifiable by the scheduler
    (`#3457` in the WG snapshot-atomicity reader; `#6633`
    `reconcile_churn_until`). The do-while's contract is deterministic,
    so calling the helper with `stop` ALREADY set is an exact
    fail-on-revert
    (`reconcile_churn_completes_a_cycle_even_when_already_stopped_6633`),
    which the scheduling assertion it replaces could never be.
  - **But making a precondition guard true BY CONSTRUCTION does not make
    it MEAN anything — it can convert a false red into a vacuous
    green.** `#6633`'s do-while removed the flake in
    `install_session_serializes_with_reconcile_removal`
    (`#6989`/`#6985`/`#6945`) and, in the same move, made
    `reconcile_iters >= 1` satisfiable by a reconciler that ran its one
    cycle entirely AFTER the installer had joined. That is zero overlap:
    exactly the case the guard exists to catch, now reporting the same
    value as a healthy run. When the fix for a scheduling artifact is
    "make the number always ≥ 1", ask what the number is still able to
    distinguish. So ALSO wait on the OBSERVABLE: publish the cycle count
    live and have the bounded thread block until it advances
    (`wait_for_first_reconcile_cycle`, `#6989`). The do-while stays — it
    is what makes the count non-zero; the counter is what makes it
    visible while the loop is still running.
  - **A rendezvous between test threads is safe when it cannot cycle and
    cannot wedge — check both, don't assume either.** `#6633` rejected
    one on the grounds that it adds a blocking edge and turns a false red
    into a hang, which is the right default. It is admissible when (a)
    there is no cycle in the wait-for graph — the awaited thread is
    unbounded, takes no lock the waiter holds, and its `stop` is set by a
    third thread only after the waiter is joined — and (b) the wait is
    not a block but a bounded poll that PANICS BY NAME, so a stall is a
    named assertion failure and never an rc=124 wedge. Record the
    disposition at the call site: a later reader will find the older
    "prefer the do-while to a rendezvous" rule and needs to know which
    conditions changed.
  - **A liveness backstop is not a timing assertion, and a red there is
    never fixed by raising it.** Size it orders of magnitude above the
    healthy path (60s against a microsecond publish; 30s against a
    microsecond sweep) and say so IN THE FAILURE TEXT, because the next
    person to see it red will be deciding whether the machine was merely
    loaded. Tightening a bound to "make the wait meaningful" just moves
    the wall-clock sample — a 5s bound reddened master twice.
  - **`thread_local!` is only for a TEST-ONLY global. A PRODUCTION global
    takes the guard, whatever its shape.** `DETERMINISTIC_V6_DOWNGRADE_COUNT`
    (`nat64.rs`) is an `AtomicU64` two tests assert deltas on, which looks like
    the counter case above — but it is bumped on the real downgrade path and
    read by the operator warning, so making it thread-local would break the
    product: the increment happens on whichever thread compiles the snapshot
    and a reader on another thread would see zero. Check where the global is
    WRITTEN before choosing the pattern (#7413).
  - **Enumerate the affected population by RUNNING every test alone, not by
    reading call sites.** For #7413 the two shared observables were a
    production counter and the process-wide count of threads named
    `neigh-monitor`. Reading call sites suggested ~28 candidate coordinator
    tests; running all 4549 tests individually and watching for each
    observable's own log line found **exactly 2** counter bumpers and
    **exactly 10** monitor spawners — and showed that every one of the ten
    STOPS its monitor, which ruled out a leak and left concurrent overlap as
    the only mechanism. It also found the one spawner in a different module,
    which is what forced the guard to be `pub(crate)` rather than
    module-scoped. A guard over the population you guessed is a guard over
    part of it.
  - **Be explicit about which guards are BOUND and which are precautionary.**
    In #7413 the guard on the two asserting gates reds 5/8 when removed; the
    guard on the other eight spawners does NOT red even when paired one-to-one
    with an asserter at `--test-threads=2`, because their monitor windows are
    too short to overlap the assertion window today. They are kept as defence
    in depth over an enumerated population — not claimed as tested — and the
    two gates carry a `before == 0` precondition so a future spawner that does
    collide fails by NAMING the missing lock instead of as an off-by-one delta
    that reads like a real leak.
  - Prove the ISOLATION variant with a **deterministic fail-on-revert**
    (two barrier-synced threads whose per-thread counter assertion is
    mathematically impossible under a shared global). The mutex GUARD
    variant's fail-on-revert is **scheduler-dependent** (barrier + many
    iterations + a widened critical window make it effectively certain)
    and pins the guard PRIMITIVE's exclusivity, not that each heavy test
    TAKES it — verify that application by inspection, since a deterministic
    test for it reduces to the underlying flake. Back both with repeated
    parallel runs of the previously-flaky test.
  - **Not every parallel-only wedge is a scheduling problem. MEASURE the
    wedged process before theorising: sample `utime+stime` from
    `/proc/<pid>/stat` over 5s. Non-zero => spinning (oversubscription,
    starvation). ZERO => every thread is parked, and it is a real deadlock
    that no amount of serialization fixes.** #6952 was the residual wedge
    left after the #6157 guard, and it measured ZERO ticks: three tests
    appeared hung, but two were innocents parked on `wg_engine_test_serial`
    and the third — `install_session_serializes_with_reconcile_removal` — sat
    in `RwLock::write_contended` inside `reconcile_peers`, on its OWN read
    guard. The cause was a **shadowed lock-guard rebind**:

        let by_index = engine.sessions_by_local_index.read().unwrap();
        ... asserts ...
        engine.reconcile_peers(&[]);   // takes .write() on the SAME RwLock
        let by_index = engine.sessions_by_local_index.read().unwrap();

    The second `let` shadows the name but does NOT drop the first guard — a
    shadowed value lives to the end of the enclosing BLOCK, not to its last
    use — so the read guard was still held across the reconcile, and
    `std::sync::RwLock` is not reentrant. Scope the guard (`{ ... }` or an
    explicit `drop`); do not rely on rebinding to release it. The sweep for
    this class is cheap: within one function, a lock guard binding that is
    still in scope when the same lock is taken again.
  - **A conditional write is what makes such a self-deadlock INTERMITTENT.**
    `reconcile_peers` takes the demux write lock only when
    `dropped_indices` is non-empty, i.e. only when the peer it removes still
    owns a live session. In a test that races an installer against a
    reconciler, whether it does is decided by the interleaving — so the
    deadlock fired on roughly one schedule in six and every other run passed
    with the bug fully present. When a hazard is gated on a conditional, a
    regression test must ARRANGE the deciding condition deterministically
    (`orphan_demux_sweep_does_not_self_deadlock_6952` installs a session and
    asserts the demux map is non-empty BEFORE running the sweep) rather than
    inherit it from the racing caller, which reds one run in six.
  - **`--test-threads=1` does not make a test's OWN threads safe.** It
    serializes libtest's test slots, not threads a test body spawns. #6952
    self-deadlocks a single thread; serial mode only shifts CPU availability
    and therefore the odds. Treat the flag as a rate reducer, never as a
    correctness guarantee — and never as evidence that a wedge is a
    parallelism artifact.
  - **Wrap a body that can self-deadlock in a bounded runner so a revert
    fails BY NAME.** A wedge exits 124: neither "the guard fired" nor "the
    guard failed to fire", so any mutation cell that lands on it is
    uninterpretable and scoring it as either polarity manufactures evidence.
    `engine_tests::run_bounded` runs the body on a worker thread and asserts
    completion against a deliberately loose 30s backstop (the healthy path is
    microseconds, so a loaded machine cannot flake it). The parked worker is
    left detached on the deadlock path; libtest exits the process rather than
    joining it.
  - **Such a runner must distinguish a body that PANICKED from a body that
    PARKED.** Deciding "done" from a flag the worker sets AFTER calling the
    body reports a panicking body as a deadlock: the flag stays false, the
    caller burns the whole backstop, and the named failure claims the wrong
    defect. `run_bounded` polls the join handle alongside the flag and
    `resume_unwind`s the body's payload, so the failure names the assertion
    that actually fired (#6989 — found when a mutation cell removing
    `reconcile_lock` produced "found 126 … install/reconcile race left
    orphans" and it was buried 30s later under a #6952 self-deadlock claim).
    A body that genuinely parks never finishes, so the deadlock path is
    untouched.
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
