# Plan of action — #1924: signed, hosted appliance distribution

> Revision: r1 (2026-06-16)
> Status: DRAFTING — pre-review
> Branch: research/1924-signed-hosted-dist
> Mode: `/research` — STOPS at PLAN-READY. No implementation, no PR, no
> production source touched until `/engineer 1924`.

## 1. Problem statement

Follow-up from #1879 / PR #1906 (appliance images, Path C) and #1917/#1923
(the `xpf` / `xpf-appliance` `.deb` + `make deb` + bake-installs-the-deb).
Today the distribution story stops at "build the artifacts locally":

- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
  (plain sha256 of the qcow2 + incus metadata) and a `dist/xpf-<ver>.manifest`
  (provenance text). Neither is signed. An operator who downloads the image
  has no cryptographic proof of origin — `sha256sum -c` only proves the file
  matches a checksum file that itself is unauthenticated. A MITM or a
  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
- **No published distribution channel.** `make deb` writes to `dist/deb/`;
  `make image` writes to `dist/`. There is no hosted location, no retention
  policy, no stable/edge channel layout. The CLAUDE.md "Quick Start" and
  `docs/install-images.md` assume the operator builds locally or copies
  files by hand.
- **No `apt` path.** The `xpf-appliance` metapackage (debian/control) is
  explicitly designed as "the operator-facing entry point: `apt install
  xpf-appliance` … e.g. from a hosted apt repo" — but no such repo exists.
  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
- **No verification on the consumer side.** `scripts/deploy/xpf-deploy.py`
  and `scripts/image/validate.py` consume `--qcow2 … --metadata …` paths
  directly with no signature import or check; `build_config_drive` in
  xpf-deploy.py validates the day-0 *config*, not the *image*.

Goal (issue): an operator fetches + verifies the appliance image and the
packages from a trusted, signed source instead of copying files by hand.

### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)

This plan deliberately does NOT invent answers to two inputs that are
operator/infra/security decisions. The mechanism is designed so both are
**config inputs**, not hardcoded constants, so the plan converges PLAN-READY
pending only these two engineer-time values:

- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
  repo host), the retention policy, and the channel layout (stable / edge).
- **OQ-2 — Signing identity.** WHICH signing key, and key management: who
  holds the secret key, rotation cadence, and where the public key is pinned.

These are surfaced as `XPF_DIST_BASE_URL` (or equivalent) and a checked-in
public key file + `XPF_SIGN_SECKEY` (path, never the key itself). See §9.

## 2. Blast radius / affected surface

New work is almost entirely ADDITIVE — no production dataplane / control-plane
source is touched. Surface:

| Area | Change class | Files |
|---|---|---|
| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
| `.deb` repo build tooling | NEW | `scripts/dist/` (repo builder + signer) |
| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-archive-keyring.asc` / `xpf.pub` |
| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
| Docs | extend / NEW | `docs/install-images.md`, NEW `docs/distribution.md` |
| CI/release (optional) | NEW (deferrable) | `.github/workflows/release.yml` |

Zero changes to: `pkg/**` (Go control plane), `userspace-dp/**` (Rust
dataplane), `bpf/**`, the daemon, CLI, or the wire protocol. No smoke-test
exposure on the loss cluster (no forwarding-path change). This is build/release
plumbing.

## 3. Design overview

Three independent-but-coordinated mechanisms, each gated by a config input:

1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
   checksum manifest), so one signature transitively authenticates the qcow2 +
   incus metadata. Verify on import in `validate.py` / `xpf-deploy.py`.
2. **Build + sign an apt repo** for the `xpf` / `xpf-appliance` `.deb`s, so
   `apt install xpf-appliance` works from a hosted, authenticated index.
3. **`install.sh`** (Tailscale-style) that bootstraps trust (installs the
   pinned archive keyring), adds the apt source, and runs `apt install
   xpf-appliance` — one command on a fresh Debian/Ubuntu host.

Publishing (where bytes land) is a thin `dist-publish` target parametrised by
`XPF_DIST_BASE_URL` (OQ-1). The mechanism is host-agnostic: a static file
server, an S3/GCS bucket fronted by HTTPS, or GitHub Releases all satisfy the
contract "serve these files under a base URL over TLS".

### Trust model (the spine of the design)

There are TWO distinct trust roots, and the plan keeps them clean:

- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
  PUBLIC key out-of-band ONCE (checked into the repo + published at a
  well-known URL) and pins it. Every image download is verified against it.
- **Apt trust** — the apt archive signing key. `apt` itself enforces this via
  signed `Release`/`InRelease` once the archive keyring is installed under
  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).

The `install.sh` bootstrap is the ONLY moment trust is established over the
network, so it is the highest-risk step and gets the most scrutiny (§5, §8).
We **pin the keyring fingerprint inside install.sh** (and verify the fetched
keyring against it) so a compromised host serving a bad keyring is caught —
install.sh's own integrity is the remaining root (mitigations in §8).

## 4. Multiple Path Options

### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)

| Option | Pros | Cons |
|---|---|---|
| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
| **cosign / sigstore** | keyless OIDC option, transparency log | requires Fulcio/Rekor infra or a static key; new dep; apt still needs PGP; over-engineered for a single-publisher appliance |

**Recommendation (mechanism, value deferred to OQ-2):**
- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
  exactly the issue's lead, one pinned Ed25519 pubkey. The image consumer
  (validate.py / xpf-deploy.py / operator) is a script we control, so it can
  call `minisign -V` directly — we are not constrained to apt's PGP.
- **Apt repo → OpenPGP** (`gpg`/`sequoia`) over `Release`, because apt
  mandates it. This is unavoidable: apt will not trust a minisign signature.

This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
the apt archive. It is NOT redundancy — they authenticate different artifacts
to different consumers (our scripts vs apt). Both public keys are checked into
the repo and published. (An ALTERNATIVE single-tool variant — PGP for both,
dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
the recommendation is the two-tool split because minisign's single-pubkey pin
is dramatically simpler to verify in install.sh and in our Python consumers.)

#### 4A-alt. Single-tool (PGP-only) variant
Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
Pros: one key to manage (one OQ-2 answer), apt-native. Cons: image consumers
(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
with a keyring, which is heavier and more error-prone to pin than `minisign
-V -p key.pub`; PGP's web-of-trust/expiry semantics add footguns for a
single-publisher appliance. Kept as a fallback if the user prefers exactly one
signing identity.

### 4B. Apt repository tooling

| Option | Pros | Cons |
|---|---|---|
| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
| **aptly** | snapshots, multi-version, mirroring, publish to S3 natively, channels (stable/edge) map to "distributions" cleanly | larger, its own DB, more moving parts than we need for one package |
| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |

**Recommendation:** **reprepro** for the pool repo. It is the smallest mature
tool that produces a correct signed `Release`/`InRelease` with channels via
distinct distributions (`stable`, `edge`), and its `conf/distributions` is one
readable file. `aptly` is the upgrade path IF OQ-1 picks S3 + we later need
snapshots/mirroring. The flat-repo path is the zero-dependency fallback
(documented) if reprepro is unwanted on the build host.

Channel layout (deb822, the contract install.sh writes):
```
/etc/apt/sources.list.d/xpf.sources:
  Types: deb
  URIs: <XPF_DIST_BASE_URL>/apt        # OQ-1
  Suites: stable                       # or edge
  Components: main
  Architectures: amd64
  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
```

### 4C. install.sh trust-bootstrap (the security-critical step)

| Option | Pros | Cons |
|---|---|---|
| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
| **TOFU (trust on first use)** — just `apt-key add` whatever is served | trivial | INSECURE — rejected; defeats the entire point of the issue |

**Recommendation:** **embed the ASCII-armored archive pubkey inline** in
install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
through apt's own signed `Release`. The keyring-in-install.sh means there is
exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
and we publish install.sh over HTTPS at a stable URL + document a
`curl … | sha256sum` / signature check for the paranoid (§8). Inline-embed is
strictly simpler to reason about than fetch+pin-fingerprint (which still
reduces to "trust the fingerprint hash in install.sh"). TOFU is rejected.

### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)

| Option | Pros | Cons |
|---|---|---|
| **GitHub Releases** (per-tag assets) | free, TLS, no infra, matches `gh release`; the repo is already on GitHub | not an apt repo by itself (need GitHub Pages or a bucket for the apt pool); release assets are per-tag not channel-stable URLs |
| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
| **Self-hosted static file server** | full control | the user runs+secures it |

**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
release upload`s the `dist/` tree (images + sigs) and the reprepro `apt/` pool
to `XPF_DIST_BASE_URL`. The plan provides a pluggable `XPF_PUBLISH_CMD` so the
user wires their chosen backend without the mechanism caring. Retention +
channel layout are documented defaults (keep last N images per channel) the
user tunes. **No backend is hardcoded.**

## 5. Detailed mechanism (recommended path)

### 5.1 Image signing (bake.py, additive)
After step 6 writes `dist/SHA256SUMS`, add step 6b:
```
minisign -S -s "$XPF_SIGN_SECKEY" -m dist/SHA256SUMS \
         -t "xpf image $ver" -x dist/SHA256SUMS.minisig
```
- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
  If unset, bake prints a clear WARNING and skips signing (so a dev bake still
  works), exactly like `--skip-validate` today warns "do not publish".
- The pinned PUBLIC key ships in-repo as `scripts/dist/xpf-image.pub` and is
  ALSO copied into `dist/` so the published tree is self-describing.
- One signature over `SHA256SUMS` transitively covers both image artifacts
  (the checksums inside are verified after the signature checks out).

### 5.2 Image verify (validate.py + xpf-deploy.py, optional gate)
Add a `verify_artifacts(qcow2, metadata, sigdir)` helper:
1. `minisign -V -p <pinned pub> -m SHA256SUMS -x SHA256SUMS.minisig`
2. then `sha256sum -c SHA256SUMS` for the two files.
Wire it as:
- `validate.py`: a new `--verify-sig` flag (default ON when a `.minisig` is
  present next to the artifacts; a `--no-verify-sig` escape hatch for local
  dev bakes that skipped signing).
- `xpf-deploy.py`: verify the image at `import_image`-equivalent time before
  `incus image import` / `virt-install --import`. If the operator points at a
  hosted URL (future `--image-url`), fetch then verify then import.
- The pinned pubkey path is a constant in the script (checked-in pub) with an
  `XPF_IMAGE_PUBKEY` override for rotation/testing.

### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh + reprepro)
- `conf/distributions` with `stable` and `edge` suites, `Components: main`,
  `Architectures: amd64`, `SignWith: <KEYID>` (OQ-2 PGP key).
- `make dist-repo` runs `make deb` then `reprepro -b <repo> includedeb
  <suite> dist/deb/xpf_*.deb dist/deb/xpf-appliance_*.deb`.
- Output is the standard pool/dists tree under `dist/apt/`, ready to publish.
- Flat-repo fallback script documented for no-reprepro hosts.

### 5.4 install.sh (NEW)
Tailscale-shaped, POSIX sh, idempotent:
1. Detect distro/arch; refuse non-amd64 / non-Debian-family with a clear msg.
2. Install the pinned archive keyring to `/etc/apt/keyrings/
   xpf-archive-keyring.asc` (embedded inline, `0644`).
3. Write `/etc/apt/sources.list.d/xpf.sources` (deb822, `Signed-By`,
   `XPF_DIST_BASE_URL` substituted; default channel `stable`,
   `XPF_CHANNEL=edge` override).
4. `apt-get update && apt-get install -y xpf-appliance`.
5. Print next steps (day-0 config, `cli`, mgmt reachability caveat — the
   interface-takeover warning from #1879 is RESTATED here because a bare-metal
   `apt install` on a remote box can cut mgmt if fxp0 mapping is wrong).
- `install.sh` is itself published at `XPF_DIST_BASE_URL/install.sh` and the
  doc gives the `curl -fsSL … | sh` one-liner PLUS the paranoid
  "download, read, verify, run" variant.

### 5.5 Makefile + docs
- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
  channel policy, retention, publish backends) + the operator runbook (the
  install.sh one-liner, the manual apt steps, the image verify steps).
- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
  verify from `XPF_DIST_BASE_URL`"; document `SHA256SUMS.minisig`.

## 6. Test / validation strategy (research scope = how /engineer will prove it)

No loss-cluster smoke (no forwarding change). Validation is local + CI-shaped:

1. **Sign/verify round-trip (image):** bake (or a stub SHA256SUMS) → sign with
   a throwaway minisign key → `verify_artifacts` PASSES; flip one byte of the
   qcow2 → verify FAILS at `sha256sum -c`; flip the `.minisig` → verify FAILS
   at `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
   verify that can't fail is theater.)
2. **Apt repo:** build the signed repo into a temp dir → spin a Debian
   container (or the local incus image flow) → run install.sh pointed at a
   `file://` or `http://localhost` serving of the temp repo → `apt install
   xpf-appliance` succeeds → `apt-get update` against a TAMPERED `Release`
   FAILS with apt's signature error (negative test).
3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
   wrong arch; the keyring fingerprint embedded matches the published keyring.
4. **bake.py unchanged paths:** the existing image-validation matrix
   (`scripts/image/validate.py a|b|c`) still passes; signing is additive and
   does not perturb the boot/day-0 contract.
5. **Doc accuracy:** the `curl | sh` one-liner and the manual steps are
   copy-pasteable against a local test publish.

The signing key used in tests is a generated throwaway, NEVER OQ-2's real key.

## 7. Rollout / sequencing

`/engineer` should land this as small, independently-reviewable increments
(each its own commit, true-merge per project policy):

- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
  negative tests; docs). Shippable alone; gives signed images immediately.
- **Inc 2 — apt repo build tooling** (`scripts/dist/build-apt-repo.sh`,
  reprepro `conf/distributions`, `make dist-repo`, PGP archive pubkey
  placeholder; container repo test). Shippable alone.
- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
- **Inc 4 (optional, deferrable) — CI release workflow** (`.github/workflows/
  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
  OQ-2 being real, and on the user wanting CI to hold the secret key (a
  security decision — may prefer manual signing on an air-gapped host).

The two OPEN QUESTIONS are NOT blockers to Inc 1–3 landing as MECHANISM with
placeholder keys + parametrised URLs; they ARE blockers to a real public
release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
the values are dropped in at engineer/release time.

## 8. Risks & mitigations

- **R1 — install.sh is the trust root over the network.** A compromised host
  serving a bad install.sh defeats everything. Mitigation: publish install.sh
  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
  self-authenticating once install.sh runs); document a verify-before-run
  variant (publish `install.sh.minisig` too, signed by the image key, so the
  paranoid operator verifies install.sh with the SAME pinned pubkey they used
  for the image). This closes the loop: ONE pinned pubkey authenticates both
  the image and install.sh.
- **R2 — key compromise / rotation.** OQ-2 owns the policy, but the mechanism
  must not hardcode a single key. Mitigation: pubkey paths are overridable
  (`XPF_IMAGE_PUBKEY`, apt `Signed-By` is a file), and the plan documents a
  rotation runbook (publish new pubkey, dual-sign during overlap, retire old).
- **R3 — apt repo correctness (stale Packages index, missing arch).** Use
  reprepro (it owns index generation) rather than hand-rolled scanning;
  negative test (tampered Release must fail apt).
- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
  may not be installed. Mitigation: `require()`-style preflight in the new
  scripts with an apt-install hint (matches bake.py's existing `require`
  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
  warning, same posture as `--skip-validate`).
- **R5 — mgmt cut-off on bare-metal apt install.** #1879's interface-takeover
  hazard applies harder to `apt install xpf-appliance` on a remote box than to
  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
  a config that takes over interfaces; the package's first-boot/day-0 contract
  (already built in #1879/#1917) governs safe bootstrap. (This is a
  documentation + sequencing mitigation; no new safe-bootstrap code is in
  scope for #1924 — it was #1879's deliverable.)
- **R6 — two keys confuse operators.** Mitigation: docs/distribution.md has a
  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
  archive, PGP), each with its fingerprint and pin location. The single-tool
  §4A-alt remains the fallback if the user wants exactly one identity.

## 9. Open questions (engineer-time inputs — NOT blockers to PLAN-READY)

- **OQ-1 (hosting target):** the value of `XPF_DIST_BASE_URL`, the channel
  layout (which suites exist), and the retention policy. Mechanism treats it as
  a parameter; the user supplies the URL + picks GitHub Releases / bucket /
  self-host at `/engineer`/release time.
- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
  archive key (apt), who holds the secret keys, rotation cadence, and where the
  public keys are pinned/published. Mechanism ships placeholder pubkeys + reads
  the secret-key PATH from env; the user supplies real keys at release time.
- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
  is the PGP-only single-identity fallback. The user MAY collapse to one PGP
  identity if they prefer one key to manage — flag for the user, default is the
  two-tool split.
- **OQ-4 (CI signing):** does the secret key live in CI (automated release) or
  on an air-gapped host (manual sign+publish)? Drives whether Inc 4 ships. A
  security posture choice; default assumption is manual until the user opts in.

## 10. Why not just keep SHA256SUMS?

A plain checksum file proves integrity against accidental corruption, not
authenticity against an adversary. The issue's explicit goal is "a TRUSTED,
SIGNED source." Without a signature, any party who can serve the file can serve
a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
is the usability bar (the issue's "rather than copying files by hand").

## 11. Recommendation summary

- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
  in validate.py + xpf-deploy.py. Additive to bake.py.
- Apt: **reprepro**-built signed repo (PGP `Release`), `stable`/`edge` suites,
  deb822 `Signed-By`.
- Bootstrap: **install.sh** with the archive keyring embedded inline +
  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
  `XPF_DIST_BASE_URL`. No backend hardcoded.
- Ship as Inc 1–3 (each independently reviewable); Inc 4 (CI release) is
  optional + gated on OQ-1/OQ-2/OQ-4.
- The two OPEN QUESTIONS (hosting target, signing identity) are engineer-time
  inputs, not PLAN-READY blockers; the mechanism is complete pending only their
  values.
```
