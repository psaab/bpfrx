# Claude SMR hostile code review — PR #1938 (#1924 mechanism) r1

Reviewer: Claude (security/build-release SMR). Posture: HOSTILE.

## Verification correctness (the core)
- `verify_image_artifact` (sign.py): order is correct — `verify_signature`
  (minisign over the manifest) runs BEFORE `parse_manifest`, so a tampered
  manifest is rejected before its contents are trusted. Per-file: hashes the
  EXACT `path` arg, compares to `manifest[basename(path)]`. A basename absent
  from the manifest raises; a hash mismatch raises. This binds the consumed
  bytes — not a cwd `sha256sum -c`. GOOD.
- `parse_manifest`: rejects pathful names (`/` in name), `.`/`..`/empty,
  non-64-hex digests, duplicate basenames, and an empty manifest. GOOD.
- `write_manifest`: basename-only, rejects duplicate basenames at write. GOOD.
- Selftest proves all four tamper vectors fail (modified artifact, tampered
  manifest, tampered sig, wrong pubkey) + per-file qcow2-only verify. 13/13.

## Fail-closed publish (publish.py)
- `gate_images`: requires ≥1 signed manifest; verifies signature; requires
  every listed file present + hash-matching (no partial set). GOOD.
- `gate_latest`: requires latest.json + .minisig, verifies signature, requires
  the named version be in the publish set. GOOD (resolves N2).
- `gate_apt`: requires InRelease, REFUSES the placeholder archive key, verifies
  against an EPHEMERAL gnupg keyring built only from the pinned pubkey (does
  not trust the publisher's global keyring). GOOD.
- install.sh.minisig required when install.sh is in the set. GOOD.

## install.sh
- Placeholder keyring: `install_keyring` DIES on a real run (only warns under
  dry-run). So a real install can never wire a non-verifying keyring. GOOD.
- kernel preflight: `case "$kmaj$kmin" in *[!0-9]*) die` guards before the
  numeric `-lt` comparisons; `6.8` parses as maj=6 min=8 -> 8<18 -> refused
  correctly; `6.18` -> 18 -> ok; `6.18-rc1` -> non-numeric -> dies "cannot
  parse" (acceptable refuse). No 6.8-vs-6.18 misparse. GOOD.
- All expansions in `run`/`write_source` are quoted; the deb822 body is a
  heredoc with only `$XPF_APT_BASE_URL`/`$CHANNEL`/`$KEYRING` interpolated —
  these come from env/constants, not untrusted input. `run` uses `eval "$*"`
  on caller-controlled command strings (not network input). Acceptable.

## sign.py minisign
- `sign_manifest` passes the secret key by PATH; `input="\n"` feeds an empty
  passphrase so a passwordless key signs unattended and a password-protected
  key fails loudly. Secret bytes never enter the process. No `shell=True`
  anywhere — all subprocess calls are arg lists. GOOD.

## build-apt-repo.sh
- Flat path uses `apt-ftparchive packages/release`; signs InRelease
  (clearsign) + Release.gpg (detached). Unsigned path warns + (publish.py
  refuses). `Valid-Until` set explicitly via `-o ...::ValidUntil`. reprepro
  path requires XPF_GPG_KEY. Args are quoted. GOOD.
- Minor: the `--debs` arg loop `while ... [ "${1#--}" = "$1" ]` consumes tokens
  until the next `--flag`; a deb path literally starting with `--` would be
  skipped, but deb paths never start with `--`. Acceptable.

## debian/rules keyring
- Installs the keyring under `debian/xpf/etc/apt/keyrings/` — dh auto-registers
  `/etc/*` as conffiles, so an operator/rotation edit is preserved and the
  rotated key ships on upgrade. Prefers the real key, else placeholder. GOOD.

## Findings
- **S1 (LOW / hardening):** `gate_apt` builds an ephemeral GNUPGHOME but does
  not set `--trust-model always` or check the key is the EXPECTED one beyond
  "import this pubkey, verify against it." Since the keyring contains ONLY the
  pinned pubkey, a valid signature necessarily came from that key — so this is
  sufficient. No change required; noting for the reviewers.
- **S2 (NIT):** `install.sh` `is_placeholder_key` greps the heredoc-captured
  `$ARCHIVE_KEY`; correct, but if a real key happens to contain the literal
  string it would false-positive. The marker is specific enough
  (`PLACEHOLDER-xpf-archive-keyring`) that this is not a real risk.
- **S3 (NIT):** selftest exits 77 (skip) if minisign/gpg/apt-ftparchive absent.
  CI must install them or the gate silently skips. The PR text + Makefile note
  the apt deps; acceptable, but the CI workflow (future Inc 4) must install
  them.

## Verdict
**APPROVE-WITH-NITS.** The security-critical paths are correct: signature-then-
parse ordering, per-file byte binding, fail-closed publish covering all four
artifact classes, placeholder refusal on real installs, no secret-key leakage,
no shell=True. S1–S3 are hardening/CI notes, not blockers. Pending Codex + AGY
+ Copilot.

---

## r2 — fixes applied after Codex + AGY REQUEST-CHANGES (both)

Codex (6) + AGY (5) converged REQUEST-CHANGES. All resolved:

| Finding | Sev | Fix |
|---|---|---|
| publish uploads unsigned files (whole dist tree) | Codex-H1 / AGY-A2 | publish.py `list_versions` now DIES on any xpf-*.SHA256SUMS without a .minisig (fail-closed); selftest 5b. |
| keyring in /etc = conffile prompt + force-confnew clobber | AGY-A1 | moved keyring to /usr/share/keyrings (non-conffile) in debian/rules + install.sh + Signed-By + docs. |
| stale signed InRelease green-lights unsigned rebuild | Codex-H2 | build-apt-repo.sh rm's Release/InRelease/Release.gpg before each flat build. |
| Valid-Until not emitted (ValidUntil vs ValidTime) | Codex-M3 | use APT::FTPArchive::Release::ValidTime (seconds) + grep-assert the field landed; selftest checks it. |
| image placeholder pubkey not fail-closed | Codex-M4 | sign.require_real_pubkey() rejects *.placeholder in verify_image_artifact; publish.py explicit guard. |
| validate.py cross-manifest mismatch | AGY-A3 | bind BOTH artifacts to the SAME manifest (single chosen manifest, else fail). |
| TOCTOU manifest swap between verify and parse | Codex-M5 / AGY-A4 | copy manifest+sig into a 0700 temp dir; verify+parse the copy. |
| publish parses manifest before verifying signature | Codex-L6 | gate_images verifies signature THEN parses. |
| $DEBS unquoted word-split/glob | AGY-A5 | set -f around the loop + reject paths with unsupported chars. |

Gate after fixes: shellcheck clean, py compile clean, **selftest 15/15** (added
Valid-Until + publish-fail-closed regression cases). Verdict: **APPROVE**
(pending Codex + AGY re-review + Copilot).

---

## r3–r7 — iterated hardening (Codex + AGY + Copilot)

Both Codex and AGY drove multiple REQUEST-CHANGES rounds; every finding fixed:

- r3 (Codex): orphan sweep must walk recursively (publish uploads the tree);
  gate_apt must fail-closed on dpkg-deb extraction failure. FIXED.
- r3 (AGY): gate_latest + gate_images manifest-parse TOCTOU → new
  verify_and_read/verify_manifest_map (copy→0700→verify→return bytes);
  multi-suite apt gate (every suite under dists/ must verify); reject `\` in
  basenames. FIXED. AGY APPROVE at r3-followup.
- r4 (Codex): --no-apt would upload dist/apt ungated → refuse --no-apt when
  dist/apt exists; reject symlinks under the image publish root. FIXED. AGY
  APPROVE at r4.
- r5 (Codex): symlinks under dist/apt also dereferenceable → gate_apt rejects
  them too. FIXED. AGY APPROVE at r5.
- Copilot: docs claimed a fetch watermark that wasn't implemented → implemented
  the monotonic anti-rollback watermark in cmd_fetch (refuse older,
  --allow-rollback override, advance-after-verify, best-effort). FIXED + tested
  live.

Final gate: go build clean, shellcheck clean, py compile clean, selftest 17/17
(sign/verify, 4 tamper vectors, per-file, flat signed repo + InRelease verify +
tamper-fail + Valid-Until, publish fail-closed on unsigned/orphan/symlink,
install.sh dry-run). SMR verdict: APPROVE.
