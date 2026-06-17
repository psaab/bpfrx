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
