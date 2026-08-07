---
name: deep-review
description: Run a full-coverage defensive security review with worktree-isolated subagents — Rust dataplane + Go control plane — single final file at /tmp/<model>-review-NNN.md, generic work-dirs, freshness gate against origin/master.
user-invocable: true
---

# Deep Review Skill — Paladin Coverage Campaign

Run this as a COVERAGE CAMPAIGN, not a best-findings pass. You are the COORDINATOR. Fan the review out across the whole codebase using metacode subagents — one subagent per (expertise-area, file-batch) — so that each subagent works with a SMALL context and DEEP domain focus, then merge into one report.

This skill is the successor to `paladin-review.txt` — it keeps the worktree-isolated, single-final-file contract (repo-agnostic) and adds argument support for extra context.

## Arguments

- `/deep-review` — full coverage, default focus (core firewall behavior: zone policies, global policies, host-inbound, application matching, default deny/permit + VRRP/HA cold-boot, dataplane int-truncation, DDNS/observability resource safety)
- `/deep-review focus on zone policies only` — extra focus context is appended as a bias line, does NOT reduce coverage — all areas still reviewed
- `/deep-review --area A3 --focus "config compiler integer truncation"` — area filter (optional) + focus string
- `/deep-review --batch-size 100` — override batch size (default 150)
- Any free-form text after `/deep-review` is treated as extra context / focus and is passed to every subagent as bias.

**How extra context is handled:** The coordinator takes `$ARGUMENTS` (everything after `/deep-review`), sanitizes it (no shell), and appends as:

> Focus this run: <extra context>

This line is added to every subagent prompt AND to the final report header as "Extra context: <...>" — it biases persona emphasis but does NOT reduce coverage (all areas still reviewed per contract). Use it to drive depth on a subsystem without losing breadth.

## Authorization

I am the owner and maintainer of this repository. This is an authorized internal defensive review of my own code, performed to find and FIX weaknesses before they ship. The output is a private triage report that feeds bug-fix issues in the normal fix/PR workflow. No third-party systems are targeted; no code is exploited, weaponized, or exfiltrated. The review exists to strengthen enforcement, not catalogue bypasses.

## Context

Internal code-health and hardening review of our own repository, run by the maintainer as routine quality work. The codebase is a firewall/router platform (Go control plane + Rust AF_XDP userspace dataplane), so the review looks for defects that could degrade its protections in production — input-validation gaps, policy-enforcement errors, resource-exhaustion risks, correctness bugs, memory-safety and concurrency bugs — triaged and patched. Do not modify any repository source files in this pass; findings are handed to normal fix/PR workflow, written report is deliverable.

## Setup (only permitted repo mutation)

First, update the checkout with `git pull --rebase` (only permitted repo mutation). If it fails (e.g. proxy blocks github), audit existing checkout and record commit reviewed.

Record base commit SHA (`git rev-parse HEAD`) after rebase — immutable review target. Immediately after, fetch origin/master and record origin/master SHA: `git fetch origin master && git rev-parse origin/master`. All subagents MUST work from base SHA via detached git worktree, NOT mutable working tree. Discover repo root via `git rev-parse --show-toplevel`; never hardcode a repo path. Save base SHA + repo root + origin/master SHA + fetch timestamp for entire campaign.

Freshness gate (hard):
- If base SHA is >20 commits behind origin/master, rebase again or abort and document staleness. Stale base causes already-fixed findings to be re-reported.
- At COORDINATOR MERGE time, MUST re-fetch and re-verify every High/Critical (and any MATERIAL) against origin/master tip file content. If fixed on tip, mark FIXED and drop — do NOT file.
- Also refresh `gh issue list --state open` at merge time. Open issues grow; dedup index at start can be stale.

Retired path exclusion (hard): eBPF dataplane retired (#1373, deleted #1476). DO NOT report findings in retired/dead code as material individually-fileable issues (bpf/ except headers, pkg/dataplane top-level legacy Manager, dpdk_worker/, etc.). If file contains RETIRED-eBPF comment or lives outside live paths (userspace-dp/, userspace-xdp/, pkg/dataplane/userspace/, pkg/config/, pkg/cluster/, pkg/vrrp/, etc.), treat as STALE unless proven still wired into live userspace-dp enforcement path. Any finding in retired path MUST be labeled Gate verdict: STALE (retired eBPF path, live caps at 32 pools) and MUST NOT count toward material individually-fileable count.

Include any extra context from $ARGUMENTS in final header as Extra context: <args>.

## Phase 0 — Coordinator Setup (top-level context)

### Scratch work location rule (mandatory, repo-agnostic) — to avoid /tmp pollution:
- Determine `<whoami>` DYNAMICALLY at runtime from environment — do NOT hardcode a model name, do NOT use Unix username `ps`. Must work across model changes (fable -> claude-spark -> muse-spark -> opus -> sonnet etc.) and across host families (Claude vs Muse):
  ```bash
  # Dynamic model detection — handles changing models across runs AND across host families (Muse vs Claude)
  # Sources checked in priority order: explicit host envs (ANTHROPIC_MODEL, MUSE_MODEL, CLAUDE_CODE_SUBAGENT_MODEL), then settings.json
  # Do NOT blindly normalize muse- -> claude- — keep Muse family distinct (muse-spark) while still accepting legacy claude- alias
  MODEL_RAW="${MUSE_MODEL:-${ANTHROPIC_MODEL:-${CLAUDE_CODE_SUBAGENT_MODEL:-${ANTHROPIC_DEFAULT_OPUS_MODEL:-${ANTHROPIC_DEFAULT_SONNET_MODEL:-}}}}}"
  [ -z "$MODEL_RAW" ] && MODEL_RAW=$(jq -r '.model // empty' ~/.claude/settings.json 2>/dev/null || echo "")
  # Muse Spark identity: when running under Muse (check for muse marker), prefer muse-spark family even if settings.json says opus[1m]
  # Detect Muse host via env or by checking if original MODEL_RAW was empty and settings.json is generic opus
  if [ -z "${ANTHROPIC_MODEL:-}" ] && [ -z "${MUSE_MODEL:-}" ] && [ -z "${CLAUDE_CODE_SUBAGENT_MODEL:-}" ]; then
    # No explicit env — check if we are on Muse host via available marker (Muse CLI leaves MUSE_* or the binary reports muse)
    if command -v muse >/dev/null 2>&1 || [ -n "${MUSE_CLI:-}" ] || grep -qi muse ~/.claude/settings.json 2>/dev/null; then
      # Heuristic: generic opus[1m] in settings.json on a Muse host likely means Muse Spark, not Claude Opus
      if echo "$MODEL_RAW" | grep -qiE '^opus(\[.*\])?$'; then
        MODEL_RAW="muse-spark-1.1"
      fi
    fi
  fi
  MODEL_LC=$(echo "$MODEL_RAW" | tr '[:upper:]' '[:lower:]')
  # Extract family: muse-spark, claude-spark, claude-opus, claude-sonnet, claude-fable, claude-haiku, codex, gemini, fable, opus, etc.
  # Keep muse- and claude- distinct — do NOT rewrite muse- -> claude-
  # Handle bracket version like opus[1m] -> opus
  MODEL_LC=$(echo "$MODEL_LC" | sed -E 's/\[.*\]$//')
  if [[ "$MODEL_LC" == muse-* ]]; then
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1-2)
  elif [[ "$MODEL_LC" == claude-* ]]; then
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1-2)
  else
    # For non-prefixed (fable, codex, gemini, opus, agy), first part is family
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1)
  fi
  # Strip any remaining version suffix that survived cut (e.g. claude-spark-1.1 -> cut gives claude-spark, good; but claude-3.5 -> claude)
  WHOAMI=$(echo "$WHOAMI" | sed -E 's/-[0-9]+(\.[0-9]+)*$//; s/-[0-9]{8,}$//; s/-[0-9]+$//' | sed -E 's/\[.*\]$//')
  [ -z "$WHOAMI" ] && WHOAMI="claude"
  # Final normalization: ensure spark/opus/sonnet keep family prefix (handle bare spark/opus)
  if [[ "$MODEL_LC" == *"muse"* && "$MODEL_LC" == *"spark"* && "$WHOAMI" == "spark" ]]; then WHOAMI="muse-spark"; fi
  if [[ "$MODEL_LC" == *"spark"* && "$WHOAMI" == "spark" ]]; then WHOAMI="muse-spark"; fi
  if [[ "$MODEL_LC" == *"opus"* && "$WHOAMI" == "opus" ]]; then
    # Distinguish muse-spark host vs real opus
    if [[ "$MODEL_LC" == muse-* ]]; then WHOAMI="muse-spark"; else WHOAMI="claude-opus"; fi
  fi
  if [[ "$MODEL_LC" == *"sonnet"* && "$WHOAMI" == "sonnet" ]]; then WHOAMI="claude-sonnet"; fi
  echo "Detected model: $MODEL_RAW -> family $WHOAMI (normalized from $MODEL_LC)"
  ```
  This handles dynamic changing models across runs (you may be `muse-spark` now per MUSE_MODEL=muse-spark-1.1 which sometimes displays as `claude-spark-1.1` on Claude hosts, previously `fable` per fable-173.md, etc.). Prior `fable-173.md` etc were from older model run — new runs will be `muse-spark-review-NNN.md` if you are on Muse Spark, `claude-spark-review-NNN.md` if on Claude Spark, `claude-opus-review-NNN.md` if on opus, etc. Final file MUST use this detected family name: `/tmp/<whoami>-review-NNN.md` (e.g. `/tmp/muse-spark-review-042.md`, `/tmp/claude-spark-review-001.md`, `/tmp/fable-review-173.md`). The `muse-` and `claude-` families are now distinct — do NOT normalize `muse-`→`claude-`.
  ```bash
  # Prefer MUSE_MODEL / ANTHROPIC_MODEL (e.g. muse-spark-1.1, claude-spark-1.1, claude-opus-4-8, fable), fallback to CLAUDE_CODE_SUBAGENT_MODEL
  # Keep muse- and claude- distinct — muse-spark stays muse-spark
  MODEL_RAW="${MUSE_MODEL:-${ANTHROPIC_MODEL:-${CLAUDE_CODE_SUBAGENT_MODEL:-${ANTHROPIC_DEFAULT_OPUS_MODEL:-}}}}"
  MODEL_LC=$(echo "$MODEL_RAW" | tr '[:upper:]' '[:lower:]' | sed -E 's/\[.*\]$//')
  if [[ "$MODEL_LC" == muse-* ]]; then
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1-2)
  elif [[ "$MODEL_LC" == claude-* ]]; then
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1-2)
  else
    WHOAMI=$(echo "$MODEL_LC" | cut -d'-' -f1)
  fi
  WHOAMI=$(echo "$WHOAMI" | sed -E 's/-[0-9]+(\.[0-9]+)*$//; s/-[0-9]{8,}$//; s/\[.*\]$//')
  [ -z "$WHOAMI" ] && WHOAMI="muse-spark"
  ```
  This handles dynamic changing models across runs (you are currently `muse-spark` per MUSE_MODEL=muse-spark-1.1 -> family `muse-spark`, not `fable`). Prior `fable-173.md`/`claude-spark` etc were from older model runs — new runs will be `muse-spark-review-NNN.md` on Muse Spark. Final file MUST use this detected family name: `/tmp/<whoami>-review-NNN.md` (e.g. `/tmp/muse-spark-review-042.md`, `/tmp/claude-spark-review-001.md`, `/tmp/fable-review-173.md`).
- NEVER write any .md file directly under /tmp/ during campaign. Not /tmp/<whoami>-review-NNN.md, not /tmp/<whoami>-review-NNN-<area>-b<batch>.md, not any other *.md directly under /tmp/. ALL scratch work MUST go under a subdirectory of /tmp/.
- Create dedicated work directory (repo-agnostic, no repo name in path):
    /tmp/review-work-<whoami>-<NNN>/
  (e.g. /tmp/review-work-claude-spark-039/ — NNN from "choose output file number", <whoami> full model name. No repo name. mkdir -p). All per-(area,batch) intermediate findings go there AND draft final goes there. No file matching /tmp/<whoami>-review-NNN*.md exists directly under /tmp/ during work — only prior campaign finals. `ls /tmp/<whoami>-review-NNN*.md` during work should show only old finals for other NNNs, never current NNN. `ls /tmp/review-work-<whoami>-<NNN>/*.md` shows intermediates.
- Each subagent will create its OWN detached git worktree at:
    /tmp/review-wt-<whoami>-<NNN>-<area>-b<batch>/
  via: `git worktree add --detach <wt-path> <base-SHA>`
  All source file reads happen from inside that worktree path (discover repo root via `git rev-parse --show-toplevel`).
- Coordinator ensures /tmp/review-work-<whoami>-<NNN>/ exists before launching. Coordinator reads ONLY final files at /tmp/*-review-*.md directly under /tmp/ for dedup — it MUST NOT include /tmp/review-work-*/ or /tmp/review-wt-*/.
- Subagents create/clean own worktrees; coordinator sweeps leftovers after merge.

### Duplicate suppression:
Read all prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `/tmp/fable-review*.md`, `/tmp/opus-review*.md`, `/tmp/ps-review*.md`, `/tmp/avo-review*.md` files (ONLY final NNN files directly under /tmp/, NOT files under /tmp/review-work-*/ or /tmp/review-wt-*/). Build compact dedup index (title + file + root cause) and pass to EVERY subagent so none re-reports known issue. At merge time, refresh `gh issue list --state open --limit 200 --json number,title` — fresh issues can make finding DUP.

Read orientation docs so subagents inherit context, not just code: CLAUDE.md, docs/engineering-style.md, docs/* design/state/feature-gap docs, and any issue/backlog docs. Extract one-paragraph orientation blurb + dedup index to hand to subagents. Pass also: base-SHA, origin/master SHA, NNN, <whoami>, work-dir path (/tmp/review-work-<whoami>-<NNN>/), worktree naming convention (generic review-wt-...), and any extra context from $ARGUMENTS.

Build authoritative file list (repo-agnostic):
  git ls-files | grep -iE '\.(go|rs|c|h|hpp|cpp|cc|cxx|py)$'  (INCLUDE .go and .rs — ~95% of repo)
Assign every file to exactly one EXPERTISE AREA using map below. Any file whose path not covered goes to nearest area by directory; log assignment so coverage provably complete.

Batch within each area: if area >150 source files, split into consecutive batches <=150 files (keep package/subdir together where possible). Small areas single batch.

For each (area, batch), launch ONE metacode subagent. Run areas in parallel; within area batches may run in parallel up to concurrency limit. Each subagent gets ONLY batch file list — keeps context small. Coordinator ensures /tmp/review-work-<whoami>-<NNN>/ exists before launching. Subagents create/clean own worktrees; coordinator sweeps leftover worktrees/work-dir after PHASE 2.

### Expertise areas (area -> paths -> persona) — verify counts against git ls-files; batch any area >150

A1. Rust dataplane — packet path & memory safety
Paths: userspace-dp/src/{afxdp,frame,parser,checksum,ethernet,session,screen,cos,wg,io_uring,mpsc*,worker,coordinator,tx,umem,...} ; userspace-xdp/
Persona: senior Rust systems engineer — memory safety in unsafe, packet parse/rewrite bounds, checksum correctness, integer overflow/truncation (as casts), byte-order, lock-free/atomic ordering, cache-line/HPC invariants, fail-closed parsing. (~360 files ~3 batches)

A2. Rust dataplane — NAT / NAT64 / translation
Paths: userspace-dp/src/{nat,nat64,nptv6,...}
Persona: NAT/CGNAT specialist — port allocation lifecycle & exhaustion, twice-NAT ordering, translation correctness, embedded-ICMP reversal, HA port-reservation on synced sessions, fragment handling.

A3. Go config compiler, schema & CLI grammar
Paths: pkg/config/ ; pkg/cmdtree/ ; pkg/appid/
Persona: parser/compiler engineer — Junos AST dual-shape (#2419 bracket lists), strict-vs-lenient gates, typed-leaf schema validators, integer truncation on Atoi/len()->uint16/uint32, fail-closed on malformed config, recursion/DoS caps. (~400 files ~3 batches)

A4. Go configstore, persistence & crypto-at-rest
Paths: pkg/configstore/
Persona: storage/crypto engineer — durable temp+fsync+rename ordering, AES-GCM/HKDF/nonce handling, commit/rollback + commit-confirmed timers, journal torn-tail recovery, envelope compatibility, secret redaction.

A5. HA — cluster, VRRP, RA, conntrack sync
Paths: pkg/cluster/ ; pkg/vrrp/ ; pkg/ra/ ; pkg/conntrack/
Persona: distributed-systems/HA engineer — failover timing, split-brain & dual-primary, VRID/priority math and uint8 wraps, session-sync wire codec & anti-replay, cold-boot ordering, lock discipline & data races, dual-stack tie-break.

A6. Dataplane Go manager & control-plane->dataplane compilation
Paths: pkg/dataplane/ ; pkg/dataplane/userspace/
Persona: control-plane engineer — compilation of typed config into dataplane control messages/map writes, pool/binding index math & caps, eventstream framing & write serialization, HA glue, partial-apply safety. (~216 files ~2 batches)

A7. Daemon lifecycle & host integration
Paths: pkg/daemon/ ; pkg/networkd/ ; pkg/routing/ ; pkg/frr/ ; pkg/ipsec/
Persona: Linux systems engineer — systemd/interface management, netlink, FRR/strongSwan config generation and command-execution surfaces (shell/vtysh -c/exec injection), IPsec apply/teardown ordering, route-leak correctness. (~220 files ~2 batches)

A8. APIs (gRPC / REST) & surfaces
Paths: pkg/grpcapi/ ; pkg/api/
Persona: API-engineer — untrusted-input validation on every RPC/HTTP field, injection, authz/allowlist enforcement, integer/format handling, resource leaks, DoS amplification (unbounded scans/streams), graceful-shutdown correctness. (~230 files ~2 batches)

A9. Observability & telemetry
Paths: pkg/flowexport/ ; pkg/snmp/ ; pkg/logging/ ; pkg/rpm/ ; pkg/feeds/ ; pkg/eventengine/
Persona: telemetry engineer — NetFlow/IPFIX/SNMP wire encoders & length fields, SNMPv3 crypto (IV/salt/RNG-error handling), goroutine/fd leaks, log-record field correctness, backoff/retry overflow.

A10. Services (DHCP / DDNS / policy simulator) + CLI/show + build/deploy tooling
Paths: pkg/dhcp/ ; pkg/dhcprelay/ ; pkg/dhcpserver/ ; pkg/ddns/ ; pkg/policymatch/ ; pkg/cli/ ; pkg/natshow/ ; cmd/ ; scripts/ ; bpf/
Persona: protocol + tooling generalist — DHCPv4/v6 & relay correctness, DDNS backend ownership semantics (PrevAddr/foreign-record safety), simulator<->dataplane verdict parity, CLI dispatch & show-output correctness, Python signing/deploy/image TOCTOU & scheme enforcement. (~170 files ~2 batches; keep pkg/cli in own batch)

## Phase 1 — Per-subagent contract

You are a <persona for this area>. Review ONLY files in attached batch list (do not wander outside them, except to read a called function's contract to confirm/refute). You have been given: repo orientation blurb, dedup index, batch file list, base SHA, origin/master SHA, extra context from $ARGUMENTS (if any).

Extra context handling: If coordinator passes extra context (e.g. "focus on zone policies only"), treat it as focus bias: prioritize that subsystem in evidence search and confidence, but still cover ALL files in batch and report module-by-module log incl. negatives for full coverage. Do NOT drop coverage of other files because focus says otherwise. Mention in report header: Extra context: <text> and per-finding if focus-driven.

Worktree isolation (mandatory, repo-agnostic):
Before reading any source file, create a detached worktree for this exact review SHA:
  git worktree add --detach /tmp/review-wt-<whoami>-<NNN>-<area>-b<batch> <base-SHA>
All source file reads in your batch MUST use paths under that worktree:
  /tmp/review-wt-<whoami>-<NNN>-<area>-b<batch>/pkg/config/foo.go
  .../userspace-dp/src/...
NOT the main working tree (discover via git rev-parse --show-toplevel; never hardcode repo path like /home/ps/git/avacado-xpf). This gives immutable isolated view and avoids races. If git worktree add fails (path exists), remove stale path with git worktree remove --force <wt-path>; rm -rf <wt-path> then retry. Batch file list is relative (pkg/..., userspace-dp/...); prepend wt-path to open.
When your review fully written, clean up own worktree:
  git worktree remove --force /tmp/review-wt-<whoami>-<NNN>-<area>-b<batch>
  rm -rf /tmp/review-wt-<whoami>-<NNN>-<area>-b<batch>

Module-by-module sweep: For each file/module explicitly cover:
- correctness & bugs (policy-enforcement, input validation, fail-open/fail-closed)
- memory safety / concurrency / integer truncation / resource leaks
- feature-completeness gaps vs vSRX (where in scope)
- performance/latency issues
- test-coverage gaps
If module has no finding, WRITE NEGATIVE RESULT and one line why (what invariant checked and found sound). Negative results required — prove coverage. Do NOT collapse to high-impact only — report EVERY credible candidate at ALL confidence tiers (High/Medium/Low). Including medium- and low-confidence findings is mandatory. Honesty: never fabricate, pad, or inflate.

Evidence bar — every finding must include, using EXACTLY these field labels:

Title
Severity
Confidence
Gate verdict (FIXED / STALE / DUP / COHORT / NEG / MATERIAL — assign one; only MATERIAL counts as individually fileable)
  - FIXED = already fixed on origin/master tip (cite origin/master line numbers)
  - STALE = retired path, symbol gone, or eBPF legacy (cite retirement PR #1476 and live cap e.g. userspaceShimMaxNATPools=32)
  - DUP = covered by open GH issue (cite issue number)
  - COHORT = real but low-materiality / defense-in-depth / test-coverage / observability / lenient-HA-sync / display-only / client-DoS-only — aggregates to cohort issue
  - NEG = you proved it sound — MUST NOT appear in findings table, only in inspection log
  - MATERIAL = survives all gates, live enforcement, verified on origin/master, not dup, not cohort
Evidence (file:line refs + quoted 5-10 line code snippet you actually read — from YOUR worktree path at base SHA, but you must also have checked origin/master tip for same lines if you claim MATERIAL)
Trace (step-by-step runtime execution trace; REQUIRED for High/Medium MATERIAL only — do not waste lines on COHORT)
Refutation attempt (REQUIRED for High/Critical MATERIAL: describe how you TRIED to prove false positive — read validators/guards/callers/type defs that would make safe — and state why finding survived. If not survive, mark NEG and move to log. Do NOT report High/Critical you did not try to refute.)
HPC/invariant check (where relevant: atomic wrapping, lock contention, cache-line alignment, endianness)
Why it matters (if MATERIAL, must cite concrete production impact)
Fix direction (concrete — remediation work-list)
Labels (include vsrx-parity for parity issues)
Dedup note (why not restatement of any entry in dedup index — cite specific issue numbers checked)
Verified against origin/master (for MATERIAL: exact file:line on origin/master tip you checked, and result: still present / fixed)

Write results to: /tmp/review-work-<whoami>-<NNN>/<whoami>-<area>-b<batch>.md (coordinator gives NNN, <whoami>, <area>, <batch> and ensures work dir exists), starting with: base commit, your worktree path, your batch file list, and your module-by-module log, then findings.
IMPORTANT: Do NOT write ANY file directly under /tmp/ — not /tmp/<whoami>-review-NNN*.md, not /tmp/<whoami>-review-NNN-*.md, not any *.md. All intermediates MUST go under /tmp/review-work-<whoami>-<NNN>/. During work, `ls /tmp/*-review-*.md` should show only prior campaign finals, never this NNN. ONLY file that may ever appear directly under /tmp/ matching /tmp/<whoami>-review-NNN.md will be created by coordinator as VERY LAST STEP after verification, by copying verified draft final from work dir to /tmp/.

## Phase 2 — Coordinator Merge, Verify & Report

Collect all per-subagent files from /tmp/review-work-<whoami>-<NNN>/ (NOT from /tmp/<whoami>-review-NNN*.md — no such file should exist yet; during work no file matching /tmp/*-review-*.md for this NNN exists directly under /tmp/). Merge findings; dedup across areas and against prior-campaign dedup index (deeper restatement still duplicate unless changes root cause or severity — say explicitly).

Verify against origin/master tip and FRESH GH issues (hard):

1. Re-fetch origin/master: `git fetch origin master && git rev-parse origin/master` Record origin/master SHA in report header alongside base SHA.
2. Fresh GH issues: `gh issue list --state open --limit 200 --json number,title` This refreshes open issues at triage time.
3. For every Critical and High (and any finding subagent marked MATERIAL) that survives merge, you MUST:
   a. Open cited file on origin/master tip (NOT just base worktree): `git show origin/master:<path>` or `git -C <repo> show origin/master:<path> | grep -n ...` Confirm lines still exist and still vulnerable.
   b. If file gone or fixed, mark FIXED and drop. Document origin/master line numbers that prove fix.
   c. If file lives in retired path, mark STALE. Check live cap.
   d. If DUP, cite issue number.
   e. If low-materiality, mark COHORT.
4. After steps 2-3, produce triage sections:
   - Verified-against-origin/master highlights: 2-5 bullets explaining most interesting FIXED/STALE/DUP decisions, with origin/master file:line evidence.
   - Per-finding table with columns: | Finding | Area | Gate verdict (MATERIAL/FIXED/STALE/DUP/COHORT/NEG) | Reasoning | — this table is an INDEX ONLY, not a substitute for evidence.
   - Full findings section (MANDATORY, self-contained): inline the COMPLETE 13-label evidence bar for EVERY individually-fileable MATERIAL (and the grouped COHORT issue, if any) directly in the published final — Title, Severity, Confidence, Gate verdict, Evidence (file:line + 5-10 line quote read from worktree at base SHA), Trace (required for High/Medium MATERIAL), Refutation attempt (required for High/Critical MATERIAL), HPC/invariant check, Why it matters (concrete production impact — why it is load-bearing major and needs deeper investigation), Fix direction (concrete remediation), Labels, Dedup note, Verified against origin/master (exact origin/master file:line and result). The published final MUST NOT require the reader to open per-batch intermediates under /tmp/review-work-*/ or /tmp/review-wt-*/ to get the rationale — those are retained only for audit. If the per-finding table and the full findings section disagree, the full findings section is authoritative.
   - Count summary: total parsed, dropped-dup count, dropped-stale-or-fixed count, pure NEG count, cohort'd low-materiality count, filed individually count.

Produce DRAFT final report at: /tmp/review-work-<whoami>-<NNN>/<whoami>-review-NNN.md (still inside work dir, NOT directly under /tmp/). Verify completeness, then as VERY LAST STEP, copy it to: /tmp/<whoami>-review-NNN.md This copy is ONLY file that may ever exist directly under /tmp/ matching /tmp/<whoami>-review-NNN*.md for this NNN. During work, no file matching /tmp/*-review-*.md for this NNN exists directly under /tmp/ — only prior campaign finals. After copy, verify `ls /tmp/<whoami>-review-NNN*.md` shows exactly ONE file (final) and `ls /tmp/<whoami>-review-NNN-*.md` shows none.

Cleanup (mandatory) AFTER final copy verified: remove ALL worktrees created for this NNN: git worktree list | grep "review-wt-<whoami>-<NNN>-" -> git worktree remove --force; rm -rf /tmp/review-wt-<whoami>-<NNN>-* (Optionally keep /tmp/review-work-<whoami>-<NNN>/ for post-verification inspection, but per strictest interpretation: rm -rf /tmp/review-work-<whoami>-<NNN>/ after final exists in /tmp/. Draft final inside work dir is NOT published final — published final is copy in /tmp/.)

Produce ONE final report at /tmp/<whoami>-review-NNN.md (via copy from work-dir draft) with: Base commit reviewed + origin/master SHA (both, with fetch timestamp). Output path. Duplicate suppression summary (including fresh GH open count at triage time). Triage result — MANDATORY top section (Review base SHA + verified-against origin/master SHA, Open GH issues at triage fresh count, Outcome: X individually-filed material issues, Y cohort issue (Z survivors), Why zero if zero). Verified-against-origin/master highlights. Per-finding table with Gate verdict (INDEX ONLY — see Full findings section for authoritative evidence). Explicit expertise-area + module checklist with per-area file counts and batch counts (proving full-tree coverage). Module-by-module inspection log (aggregated, incl. negatives — NEG belongs ONLY here). Full findings section (MANDATORY, self-contained) — inline COMPLETE 13-label evidence bar for every MATERIAL (and grouped COHORT) directly in the published final: Title, Severity, Confidence, Gate verdict, Evidence (file:line + 5-10 line quote), Trace (High/Medium MATERIAL), Refutation attempt (High/Critical MATERIAL), HPC/invariant check, Why it matters (concrete production impact — why load-bearing major needs deeper investigation), Fix direction, Labels, Dedup note, Verified against origin/master — with exact origin/master file:line. This section is authoritative and MUST NOT require opening /tmp/review-work-*/ intermediates. Then Coverage & verification summary: files reviewed/total, findings per area, how many Critical/High coordinator-verified vs dropped as FIXED/STALE/DUP/COHORT/NEG. Suggested issue split (with mapping to Gate verdicts). TARGET: aggregate across all areas, report material findings that survive freshness + retired-path + dedup + materiality gates. At least 20 is aspirational, NOT mandatory. If provably-complete sweep after origin/master verification yields 0 individually-fileable material issues and 1 cohort issue of 41 low-materiality survivors (as in claude-003), that IS correct outcome — report 0+cohort and let coverage log stand. Do NOT pad with NEG.

Focus line to append per run (biases persona emphasis, does NOT reduce coverage — all areas still reviewed):
Focus this round on core firewall behavior: zone policies, global policies, host-inbound, application matching, default deny/permit — ensure packets that should be denied are denied and allowed packets are allowed — AND on areas prior campaigns under-covered: VRRP/HA failover & cold-boot, dataplane integer-truncation on config casts, and DDNS/observability resource safety.

If extra context is passed via /deep-review <context>, append that as second focus line: Focus this run (extra): <extra context> — and ensure every subagent prompt includes it. It is a bias, not a scope reduction — all areas still reviewed.

Use exact field labels so report parses programmatically. The extra context MUST NOT break the worktree isolation or single-final-file rules.

