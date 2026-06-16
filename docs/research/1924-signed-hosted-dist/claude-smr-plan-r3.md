# Claude SMR hostile plan-review — #1924 r3

Reviewer: Claude (domain SMR). Posture: HOSTILE final consistency sweep.

## r2 findings — verified resolved in r3
- **N1** (deploy can't bind bytes): §5.2 now scopes image-verify to validate.py
  (which imports) + a new `xpf-deploy.py fetch`/`--image-url`; the alias-launch
  path explicitly no longer claims to verify. Matches the actual xpf-deploy.py
  `incus init <alias>` flow. RESOLVED.
- **N2** (publish gate omits latest.json): §5.5 clause (d) added — latest.json
  must verify AND name a version in the publish set. RESOLVED.
- **N3** (apt backend contradiction): §8 R3 + §11 + Inc-2 all now say
  flat-signed-repo default / `apt-ftparchive` (reprepro opt-in). No surviving
  "use reprepro" prescription. RESOLVED.
- **N4** (GitHub Releases / pool tree): §3 splits `XPF_IMAGE_BASE_URL` (GH
  Releases OK) vs `XPF_APT_BASE_URL` (directory host); §9 OQ-1 + all functional
  refs + summary split; descriptive refs annotated. RESOLVED.
- **N5** (fresh-host overpromise): §3 + §5.4 install.sh PREFLIGHT refuses kernel
  <6.18 / non-amd64 / no-networkd. RESOLVED.
- **NIT-2** (rotation lockout): §5.4 + §2 + §11 ship the keyring in the package
  payload so `apt upgrade` delivers rotated keys. The standard pattern.
  RESOLVED (and correctly scoped: one debian/install line, no postinst logic).
- **NIT-1** (Valid-Until deadlock): §5.6 long default (1y, `XPF_APT_VALID_DAYS`).
  RESOLVED.
- **NIT-3** (watermark storage): §5.6 `${XDG_STATE_HOME}/xpf/…` + best-effort.
  RESOLVED.
- Nits: §6 reworded to parsed-hash; stray fence removed (fence count even).

## New-issue hunt on r3
- The two-URL split is internally consistent: install.sh URI uses
  `XPF_APT_BASE_URL`; install.sh + images use `XPF_IMAGE_BASE_URL`; publish
  feeds each per URL. No dangling single-URL functional reference remains
  (descriptive ones are annotated at §1).
- NIT-2's debian/ touch is honestly disclosed in the blast-radius table (§2)
  and §11; it does not contradict the "zero pkg/** and no postinst" claim
  (it is a packaged file + one install line, no maintainer-script logic).
- The verify helper name is consistent (`verify_image_artifact`, §5.2/§6).
- Scope discipline holds: AGY-HIGH-2 (postinst cut-over) remains documentation
  only; no forwarding-path change; no smoke needed.

## Verdict
**PLAN-READY.**

Every r1 and r2 finding from all three reviewers is resolved; the r3 fixes
introduced no new contradiction. The trust model is sound and now precise
(out-of-band git pubkey root; honest curl|sh tier; per-file verify of the exact
imported bytes; fail-closed publish covering images+apt+install.sh+latest.json;
keyring-in-package for rotation; long Valid-Until for manual signing). Path
options are correctly adjudicated (minisign image + PGP apt; flat-repo default
stateless-safe; reprepro opt-in). The two OPEN QUESTIONS (hosting URLs, signing
identity) are genuine engineer-time inputs — every §5 mechanism runs with a
placeholder key + parametrised URLs — not PLAN-READY blockers. Ready for
implementation on the user's `/engineer 1924` with the two inputs supplied at
release time.
