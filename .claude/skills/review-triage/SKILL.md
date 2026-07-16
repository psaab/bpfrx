# review-triage — triage a model review + write a reasoned result file

Codifies the standing review-watcher discipline: triage every finding in a
`/tmp/*-review*.md` file against CURRENT `origin/master`, file every genuine
one as a GitHub issue, and write a **result file with explicit reasoning** to
`/tmp/result-<basename>.md`.

This skill exists because the result files were too terse — "NOT-MATERIAL",
"LOW", "already fixed" with no *why*. The user's directive (2026-07-07): **every
disposition must justify itself** — why refuted, why that severity, why fixed.
A disposition without its reasoning is not reviewable and is indistinguishable
from a guess.

## When it runs

The standing cron fires ~every 10 min. For each `/tmp/*-review*.md` NOT matching
`result-*` and NOT yet marked (`/tmp/.researched-<basename>`):

1. `git -C /home/ps/git/bpfrx fetch origin master`; note the review's base commit
   and whether it is STALE (older than current master) or FRESH (≈ current).
2. Triage EACH finding vs CURRENT `origin/master` source (never the review's own
   "confirmed", never the local checkout — it is often 100s-1000s of commits
   behind; use `git show origin/master:<path>`).
3. File every GENUINE, novel, not-already-fixed finding as a GitHub issue
   (RFC/spec basis + concrete fix + file:line provenance), then drive it.
4. Write `/tmp/result-<basename>.md` (see format below).
5. `touch /tmp/.researched-<basename>`.

If no unprocessed review files exist, do nothing.

## The three verification gates (in order)

**Gate 1 — does the cited symbol EXIST in bpfrx?** Some reviews (the
`/home/ps/git/avacado-xpf` fork tell) cite code that does not exist in bpfrx
(e.g. an nftables host-inbound subsystem; ours is the Rust zone-keyed
classifier). Confirm every cited symbol/file/line via `git show
origin/master:<path>` + grep. If absent → **CONFABULATED** (do not file). Record
WHICH symbol is missing and why (the wrong-fork evidence).

**Gate 2 — is it already fixed?** On an active branch, fixes merge within hours;
a month-stale base predates entire hardening waves. Grep the FIX symbol on
current master. If fixed → **ALREADY-FIXED** — cite the fixing PR **and the
symbol/file:line that proves the case is now closed**, not just "fixed by #X".

**Gate 3 — is the flaw real + material on current master?** Trace the failure
scenario (input → wrong output) against the actual code. Weight-verify HARD:
Codex ~90% genuine, AGY/avacado ~98% stale/false. A claimed fail-open is often a
misread of a hardened path — find the disproving code path.

## The result file — MANDATORY reasoning (the point of this skill)

Path: `/tmp/result-<basename>.md`. Every line must carry its *why*.

### Header
- Review title/cohort; base commit + STALE-or-FRESH vs current master; the
  master SHA triaged against; whether it cites real bpfrx code or the avacado
  fork; one-line outcome counts.

### Per-finding table + a reasoning line for each

For EACH finding, state the disposition AND justify it:

- **GENUINE → #issue.** Give the current-master file:line, the concrete failure
  scenario (specific input → wrong output/bypass/crash), and the fix. Then the
  **severity justification** (below) — the single most-skipped part.
- **ALREADY-FIXED → PR#.** Not just "fixed by #X" — cite the SYMBOL/file:line on
  current master that closes THIS finding's specific case, and one clause on why
  it covers it (e.g. "`is_drop` returns `RouteOverride::Drop` on Reject|Discard,
  so the steer never builds").
- **NOT-MATERIAL / refuted.** The **disproving mechanism** — the exact code path,
  file:line, that makes the claim FALSE, and the one-sentence trace. Not "not
  exploitable" but *why*: "the `addrs_known` guard at mod.rs:NNN gates
  `check_land`, so the UNSPEC==UNSPEC case never reaches it." If the review's own
  trace is wrong, say which step is refuted and by what (e.g. "the flat-set trace
  is refuted: `SetPath` reuses the same-key container so two set-lines MERGE; only
  `load override` of a hand-authored dup loses").
- **DELIBERATE.** The doc/comment reference that records the intentional tradeoff
  (e.g. "#1960 no-brick: warn-not-reject so a persisted config doesn't brick").
- **CONFABULATED.** WHICH cited symbol is absent from bpfrx + the fork evidence.
- **NEGATIVE.** What was verified correct + the guarding mechanism.

### Severity justification — REQUIRED for every GENUINE and every downgrade

Never write a bare "HIGH"/"MEDIUM"/"LOW". State the reasoning across these axes:

- **Exploitability / trigger** — who can trigger it, from where, and what
  precondition is needed (unauthenticated remote? on-path? a hand-authored
  config? a crafted packet?). A finding needing a contradictory config that
  survives a lenient load is narrower than one a remote attacker triggers.
- **Blast radius** — what it compromises (whole dataplane? one flow? one
  counter? a display line?) and whether it fails OPEN (traffic that should drop
  passes — high) or CLOSED (over-restrictive — usually low).
- **Bounding factors** — what LIMITS the impact (a downstream gate that still
  catches it; a table cap; the AF_XDP forwarder not honoring the abused feature;
  the exploit packet being itself malformed).
- **Why not higher / not lower** — explicitly reconcile with the review's rating.
  If you downgrade a review's MEDIUM to LOW, name the bounding factor the review
  missed. If you raise it, name the amplifier.

Worked examples of the required depth:
- *"HIGH — a PermControl (non-super-user) operator escalates to root file-write /
  command-exec via `matching -w /path` (getopt permutation parses it as an
  option). Unbounded: no downstream gate; the RBAC boundary the config sets
  (control ≠ super-user) is defeated. Not just 'command injection' — a real
  privilege-boundary break."*
- *"LOW (review said MEDIUM) — the malformed-option break lets an LSRR-after-a-
  bad-option bypass the source-route screen, but bounded: the exploit packet is
  itself malformed AND xpf's AF_XDP forwarder doesn't honor source-routing, so
  the leaked option transits inert. Real fail-open in the screen contract, not a
  live routing bypass — hence LOW not MEDIUM."*

### Method note
Fresh-vs-stale base, weight-verify caveats, any file instability (e.g. a rotating
multi-cohort clobber writing several cohorts to one filename), and whether the
review over/under-scoped its own severities.

## Standing rules (carry over from the cron)

- No-dismissal: the TRIAGE never drops a finding — every one gets a tracked
  disposition (issue for genuine/low/refactor/test-cov; close-with-evidence for
  already-fixed/not-material/deliberate). Only the multi-stage /research or
  /engineer pipeline may dismiss, and only with recorded evidence.
- **One NEW issue per finding — NEVER a comment on an existing tracker.** When
  triaging, file a SEPARATE new `gh issue create` for each genuine finding. Do
  NOT append findings as comments to an existing umbrella/tracker issue
  (e.g. "folded onto #4421") — a comment is invisible to `gh issue list`, is not
  individually assignable / closeable / driveable, and buries the work so it
  never gets scheduled. Even a 21-finding refactor audit → 21 individual issues
  (labeled `refactor`), not one comment. Group into ONE new issue only a *tight
  cohort of near-identical* LOW items, and even then it is a NEW issue, not a
  comment. Anti-work guidance (a "do-NOT-split" guardrail) is the sole exception
  — that goes in a docs guardrail note, since it is not a driveable unit. This
  rule exists because grouping-into-a-comment was caught (2026-07-08 user: "why
  are you adding them to existing issues and not creating new issues for
  everything when you triage?").
- Result file complements the issues: the GitHub issues are the driveable
  backlog; `/tmp/result-*.md` is the human-readable audit trail of EVERY
  finding's disposition + reasoning.
- Cap 3 background agents, ≤1 concurrent cargo; parent reviews+merges every PR;
  worktrees only; heredoc commits (no backticks); FULL cargo before a dataplane
  merge; test-failover for session-sync/HA changes.
