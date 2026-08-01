# Claude SMR hostile plan-review — round 47 (plan v47 @ `b677e3a74`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r46's SMR
raised the epoch-lifetime pin (folded in v47 — IS Codex M1); r47
re-verifies the v47 folds of Codex's 3M/3m against the real code,
rules on my own earlier fold's correctness (the capture surface), and
attacks the capture ordering and the file-restore fallback. All line
numbers re-verified against the worktree.

## A. Fold verification (r46 findings → v47)

### 1. Codex M1 (node-lifetime dispatch epoch) — FOLDED

The provider-scoped candidates fail exactly as Codex stated:
`lastAppliedConfigGen` skips gen-0 and failed applies
(`sync_conn_config.go:280-288,345-360`) and `resetRecvGen` fires on
bulk re-prime (`sync_conn_gen.go:340-367`); `ConfigsReceived`
increments at receipt before disposition (`sync_conn_read.go:298-330`)
and both live on the replaceable `SessionSync` — the
`daemon_apply_tail.go:238-255` mid-callback swap ABA-erases a pulse.
The v47 epoch — incremented in the critical section on each
SUCCESSFUL reservation, node-lifetime, preserved across replacements,
exposed beside the counter — closes the ABA by construction (it never
resets within the node's lifetime). counter==0 AND epoch-unchanged is
a complete quiescence predicate over dispatched frames; the
verified-undispatched residual stays with the composition. FOLDED.

### 2. Codex M2 (done predicate observable + closed) — FOLDED

The exposure lands in pkg/cluster's rendering and relays through the
code-untouched grpcapi/cli (`server_show_cluster_text.go:66-74` —
verified it relays `s.cluster.FormatStatus()` verbatim);
`IsConfirmPending` (`store_commit.go:796-800`) and `IsDirty`
(`store_lock.go:334-338`) are independent exposed state and the
`LoadOverride`-sets-dirty path (`store_command.go:304-334`) is exactly
why the Dirty term belongs. The M2c rebuttal stands on the evidence:
`ActiveApplied()` compares `appliedDigest == digest(active.Format())`
(`store.go:797-809`), so a failed DIFFERENT-text apply reads false
(the new text's digest was never stamped —
`daemon_apply.go:49-70` stamps only on success), a failed SAME-TEXT
reapply leaves the same text's prior converged enforcement (correctly
true), and a fresh boot's empty `appliedDigest` makes a failed
bringup read false. FOLDED.

### 3. Codex M3 (capture surface) — FOLDED, with nit m1

My own first v47 fold here was WRONG and was corrected in the amend
before dispatch: `.configdb/active.json` is a JSON envelope
(`writeTreeMarked`, `db.go:105-130`), not Junos text — it cannot feed
`LoadOverride` (`store_command.go:306-309` takes Junos text) — and its
body is KEY-ENCRYPTED when the config carries a master password
(`maybeEncryptTreeJSON`, `crypto.go:262-285` — cleartext only when
`masterPasswordPRF(tree) == ""`). The amended two-part capture
(digest from the status surface; the operator's own committed text as
the re-convergence artifact; the on-disk file as a byte-exact
stopped-daemon restore fallback with the caveats named) is honest.
FOLDED — but see m1: the file-restore fallback's encryption scope is
not pinned tightly enough.

### 4. Codex m1 (teardown legs) — FOLDED

(g1) READER-WINS and (g2) STOP-WINS cover the two orderings the
exclusion permits; the impossible freeze-inside-the-section seam is
gone. FOLDED.

### 5. Codex m2 (load replace) — FOLDED

Only `load override` remains; the modes are override/merge/set
(`cmd/cli/main.go:549-590`; `cli_config.go:160-170` shows override +
merge). FOLDED.

### 6. Codex m3 (scoping + §5.1 coherence) — FOLDED

Grep-verified: the live GAP-FREE heading, the ALL-INGRESS JOIN
phrasing, and the witness's reader scope are all qualified; the two
surviving unscoped hits are v43/v44 revision-HISTORY records,
correctly preserved. The touched set (configstore + daemon + cluster;
grpcapi/cli code-untouched relays) is internally consistent. FOLDED.

## B. Fresh attacks on the v47 delta

**Attack 1 (SUCCEEDED as nit m1) — the file-restore fallback is
undecryptable cross-box when the body is encrypted.** The v47 text
names the encryption caveat but does not pin the consequence: an
encrypted `active.json` is keyed by the SOURCE node's
`.configdb/master.key` (`crypto.go:262-285`), so a byte-exact restore
onto the AUTHORITY cannot be decrypted by the authority's own key —
the authority's Load would fail on an unreadable active. The fallback
must be pinned: the file-level restore applies ONLY when the captured
body is cleartext (no master password); with a master password, the
operator's config TEXT is the only re-convergence artifact. One
clause. MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the capture is not ordered against
the commit freeze.** The v47 text captures "BEFORE the fence" but
never orders the capture against the refrain-from-commits discipline:
a commit landing between the capture and the fence's start leaves the
captured digest describing the PRE-commit config, and the
post-restart comparison then fails falsely (or worse, the operator
"verifies" against a stale intent). One clause: the capture is the
fence's FIRST action, taken AFTER the commit freeze is declared (and
any commit that lands anyway forces a re-capture). MINOR.

**Attack 3 (FAILED) — the (2a) preflight needs the peer's epoch.**
The preflight is a cleanliness gate, not a join; a peer-side late
dispatch between (2a) and (2b) is residual (iii)'s admitted window.
The epoch adds nothing to a point check. FAILED.

**Attack 4 (FAILED) — a transport-changing apply mid-fence resets the
witness.** The witness re-points to the fresh provider, which has no
connection to the stopped peer and reads Down — consistent; the
counter and epoch are node-lifetime and survive. FAILED.

**Attack 5 (FAILED) — the rebaseline rule never terminates.** The
peer is stopped; no new frames arrive; the epoch settles after the
last in-flight dispatch; the repeat pass converges. FAILED.

## C. Findings

### MAJOR (0)

None. All six r46 findings fold on independent verification — one
after I caught my own fold's format error and corrected it in the
amend (the on-disk file is a possibly-encrypted JSON envelope, not
Junos text).

### MINOR (2)

**m1.** Pin the file-restore fallback to the cleartext-body case: an
encrypted `active.json` is keyed by the source's master.key and is
undecryptable on the authority (`crypto.go:262-285`); with a master
password present, the operator's config TEXT is the only
re-convergence artifact.

**m2.** Order the capture against the commit freeze: the capture is
the fence's FIRST action, taken AFTER the refrain-from-commits
discipline is declared; any commit that lands anyway forces a
re-capture.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the file-restore
encryption scope and the capture/freeze ordering). A v48 containing
only these two pins is PLAN-READY by inspection from me.
