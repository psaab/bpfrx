# #1944 implementation reviewer IDs + verdicts

PR: #1949 (engineer/1944-login-user-password)

Plan converged at r5 (PLAN-READY: Claude SMR + Codex + AGY). This is the
implementation 4-way review (Codex + AGY + Claude SMR + Copilot).

| Reviewer | Task / ID | Round | Verdict |
|----------|-----------|-------|---------|
| Codex    | foreground codex exec (/tmp/codex-1944-out.txt) | r1 | CHANGES-REQUIRED |
| AGY      | adversarial-review-mqhuid2o-edharg (timed out, full-explore); adversarial-review-mqhuwq5g-zivv2m | r1 | MERGE-READY |
| Claude SMR | in-conversation | r1 | CHANGES-REQUIRED (concur Codex High #2) |
| Copilot  | PR #1949 | r1 | requested |

## Round 1 findings + dispositions

Codex r1 (CHANGES-REQUIRED):
- **High #1 — inline hierarchical `authentication encrypted-password "x";`
  (no braces) bypasses the typed-leaf validator.** Verified PARTIALLY: in
  that AST shape SchemaValidate returns nil BUT the compiler also reads
  `encrypted-password` only as a CHILD of `authentication`, so the value
  compiles to "" (empty) — plaintext is NOT stored or applied. Same
  pre-existing shape behavior as `root-authentication`. The
  plaintext-rejection SECURITY invariant holds (no plaintext reaches
  /etc/shadow). The real residue is that a VALID hash written in that
  unusual inline form is silently dropped — a config-silently-ignored
  paper-cut, not a security break. Disposition: ACCEPT as a known
  parser-shape limitation shared with root-auth; flat-set (the `set`
  output) and braced hierarchical both work and are tested. Documented.
- **High #2 — lenient Load/SyncApply path carries plaintext/DES into
  `chpasswd -e`.** Verified TRUE: `CompileConfigLenient` keeps
  `EncryptedPassword="password12345"` (the #1319 boot/peer-sync downgrade),
  and `reconcileUserPassword` would write it to /etc/shadow literally.
  This breaks "plaintext never reaches /etc/shadow" on the non-operator
  ingress. Disposition: FIX — re-validate `ValidateCryptHash(desired)` at
  the apply boundary in `reconcileUserPassword`; skip+warn on failure
  (defense-in-depth credential gate). A persisted/synced bad value can no
  longer be applied; boot still does not brick.
- **High #3 — D2 lock `chpasswd` failure leaves the live hash.** Verified
  TRUE but irreducible: if the OS `chpasswd` tool itself fails we cannot
  edit /etc/shadow. Disposition: keep the loud warning (already present);
  no silent orphan — operator sees the failure. Acceptable.
- **Low — no-auth warning treats `!$6$…` (locked-but-restorable) as
  usable.** Verified TRUE. Disposition: FIX — strip a leading `!`/`!!`
  before the usable-password check so a locked-restorable hash with no ssh
  keys still warns.

AGY r1 (MERGE-READY): independently verified all three invariants on the
strict path; did not exercise the lenient ingress (Codex High #2 gap).

## Round 2 (head 510523739 → 8f-fix)

| Reviewer | Task / ID | Round | Verdict |
|----------|-----------|-------|---------|
| Codex    | foreground (/tmp/codex-1944-r2-out.txt) | r2 | CHANGES-REQUIRED → fixed |
| AGY      | adversarial-review-mqhvi9y9-hvahz1 | r2 | (see below) |
| Claude SMR | in-conversation | r2 | concur Codex r2 High |
| Copilot  | PR #1949 | r2 | re-requested |

Codex r2: confirmed the per-user apply-boundary guard + no-auth warning
fixes are correct and complete, then found the SYMMETRIC **High**:
`applyRootAuth` (root-authentication) had the same lenient-ingress hole —
it sent `root:<value>` to `chpasswd -e` checking only non-empty, so a
persisted/synced plaintext root password would be applied. Since #1944
explicitly shares `ValidateCryptHash` with root-auth (E1), the
apply-boundary guard belongs there too. FIXED: `applyRootAuth` now
re-runs `config.ValidateCryptHash` before the root `chpasswd -e` and
skips+warns on failure (SSH keys still applied). New test
`TestRootAuthApplyBoundaryRevalidatesHash`. No-regression: per-user path,
inline-form-compiles-to-"", and the no-auth warning all still verified by
Codex r2.

## Round 3 — FINAL (head 8cfdacf68 → +copilot-fix)

| Reviewer | Task / ID | Round | Verdict |
|----------|-----------|-------|---------|
| Codex    | foreground (/tmp/codex-1944-r3-out.txt) | r3 | **MERGE-READY** |
| AGY      | adversarial-review-mqhvqwzm-ubulh5 | r3 | **MERGE-READY** |
| Claude SMR | in-conversation | r3 | **MERGE-READY** |
| Copilot  | PR #1949 (reviews @ 09:37) | r2 | findings fixed → re-requested |

Codex r3: no findings — r2 root-auth High closed; confirmed NO unvalidated
value reaches `chpasswd -e` on any production path (per-user apply
validates `desired`; per-user lock sends constant `!`; root apply
validates `ra.EncryptedPassword`; no other chpasswd sites). All three
invariants reconfirmed.

AGY r3: MERGE-READY — independently reconfirmed lock-on-removal (locks /
never-orphans / never-on-read-error / UID-keyed), the apply-boundary guard
on all three chpasswd inputs, and empty-passwordless-shadow → D2 lock.

Copilot (formal, 2 comments on the head): `ValidateCryptHash` accepted an
empty INTERMEDIATE `$`-field (`$6$salt$$hash`, doubled `$`) — passes the
alphabet-only check (no chars) but is malformed and fails at PAM. FIXED:
reject any empty field in `fields[2:]`; added `$6$salt$$hash` and
`$6$$$hash` to the TestValidateCryptHash reject table.

All four reviewers clean / addressed on the final revision.
