# Plan of action — #1924: signed, hosted appliance distribution

> Revision: r2 (2026-06-16)
> Status: REVISED after r1 3-way hostile review (Codex + AGY + Claude SMR all
> PLAN-NEEDS-MAJOR). r2 changes log at the bottom (§12).
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
| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
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
network, so it is the highest-risk step and gets the most scrutiny (§4C, §8).
**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
pin a fingerprint — those were mutually exclusive in r1; we picked inline).
install.sh's own integrity is therefore the bootstrap root. The minisign
**image** pubkey (`xpf-image.pub`) used for Tier-B verify-before-run has its
root of trust in the **in-repo checked-in copy obtained via `git clone` /
GitHub — independent of `XPF_DIST_BASE_URL`**; the copy served from the dist
host is a convenience, NEVER the trust root (else verification is circular).
Mitigations and the honest trust tiers are in §4C + §8.

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

**Recommendation (r2 REVISED — resolves AGY-MEDIUM-2):** the choice now
DEPENDS on the publish model (OQ-1), and the plan says so instead of
prescribing reprepro unconditionally:
- **Stateful publisher (a persistent host/bucket that survives between
  releases): reprepro.** Smallest mature tool, signed `Release`/`InRelease`,
  `stable`/`edge` as distinct distributions, one readable `conf/distributions`.
  Its Berkeley-DB under `db/` is fine when that state persists.
- **Stateless CI publisher (e.g. a fresh GitHub Actions runner each release):
  flat signed repo** generated from scratch via `apt-ftparchive` /
  `dpkg-scanpackages` + `gpg --clearsign` over `Release`/`InRelease`. No DB to
  carry between runs; the existing pool is `aws s3 sync`'d down (or `gh release
  download`'d), the new `.deb` added, the indices regenerated, re-signed,
  re-uploaded. This is the model that does NOT break when the runner's local
  `db/` is destroyed (AGY-MEDIUM-2).
- **aptly** remains the option if S3-native publish + snapshots/mirroring are
  wanted (it manages its own state + publishes to S3 directly).

**Default recommendation: the flat signed repo**, because it is robust to BOTH
stateful and stateless publishers and has zero non-dpkg/gpg dependencies; pick
reprepro only if the publisher is known-persistent and the operator prefers its
ergonomics. Either way the on-disk contract is identical (deb822 `Signed-By`,
signed `InRelease`), so the install.sh side is unaffected by the choice.

**r2 retention (resolves Codex-3 for the apt side):** apt suites keep the
latest `.deb` per arch; apt-level rollback to an older `.deb` is NOT a goal —
rollback is `xpfd upgrade`'s job (#1917). If apt-pin-to-old IS wanted, that is
the aptly/multi-version path (a user OQ, flagged in §9).

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
and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
the inline-embed and the "fetch keyring + pin fingerprint" options are mutually
exclusive — the plan picks inline-embed and drops the fingerprint-pin language
from §3. The trust model is therefore precisely: *"an authentic install.sh
CONTAINS the apt archive key."* TOFU is rejected.

**r2 honest trust tiers (resolves SMR-F2 + Codex-6):** there are two clearly
separated UX tiers, labeled as such in the docs:
- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
  Docker / rustup accept. The `.minisig` does NOT retroactively protect this
  user (they ran the script before verifying). State this honestly.
- **Tier B — verify-before-run.** The operator obtains `xpf-image.pub` **via
  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
  The loop closes ONLY because the pubkey came from the repo, not the dist host
  (SMR-F1). Docs MUST say: "get the pubkey/fingerprint from the source repo or
  release notes, NEVER from `XPF_DIST_BASE_URL`."

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

### 5.1 Image signing (bake.py, additive) — PER-VERSION, not a global SHA256SUMS

**r2 change (resolves Codex-3 retention + AGY-HIGH-1 partial-download +
SMR-F3/Codex-1 path-binding):** the bake stops emitting a single global
`dist/SHA256SUMS`. Instead each bake writes a **per-version, version-named**
checksum manifest and signs THAT:
```
dist/xpf-<ver>.SHA256SUMS          # lists exactly this version's qcow2 + metadata
dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
```
Signing step (after step 6):
```
minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
```
- **Why per-version:** retaining v1 alongside v2 (Codex-3) no longer orphans
  v1's checksums — each version owns its signed manifest. A `latest` symlink/
  pointer (`dist/<channel>/latest -> xpf-<ver>.*`) is a convenience, never the
  trust root.
- The manifest lists BOTH the qcow2 and the incus metadata, BUT verification
  (§5.2) is **per-file**, so the libvirt operator who only fetched the qcow2
  can verify it without the metadata present (AGY-HIGH-1).
- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
  If unset, bake prints a loud WARNING and skips signing (dev ergonomics);
  the publish-time guard (§5.5) then REFUSES to publish unsigned artifacts —
  signing is fail-OPEN at bake but fail-CLOSED at publish.
- The pinned PUBLIC key ships in-repo as `scripts/dist/xpf-image.pub` and is
  copied into `dist/` so the published tree is self-describing. **Its root of
  trust is the in-repo checked-in copy obtained via `git clone`/GitHub —
  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
  NEVER the root** (SMR-F1, Codex-6, AGY-MEDIUM-1).

### 5.2 Image verify (validate.py + xpf-deploy.py) — verify the EXACT imported file

**r2 change (resolves SMR-F3 + Codex-1 + AGY-HIGH-1):** the verifier does NOT
run a cwd-relative `sha256sum -c`. It:
1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
   the manifest is authentic.
2. **Parses** the manifest, rejecting pathful entries and duplicate basenames,
   into `{basename: hash}`.
3. For EACH file actually being imported (the concrete `--qcow2` / `--metadata`
   argument paths), computes its SHA256 and compares against the manifest entry
   for that file's basename. A file not listed, or a hash mismatch, FAILS.
   Files in the manifest that the operator did NOT fetch are simply not checked
   (per-file, so qcow2-only libvirt verifies fine).
Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
reused by both consumers.
Wire it as:
- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
  to the artifacts; `--no-verify-sig` escape hatch for local dev bakes).
- `xpf-deploy.py`: verify each image file before `incus image import` /
  `virt-install --import`. Future `--image-url` fetches then verifies then
  imports the EXACT downloaded file.
- Pinned pubkey path is a checked-in constant; `XPF_IMAGE_PUBKEY` overrides for
  rotation/testing.

### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh)
Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
- Inputs: the existing pool (synced down from `XPF_DIST_BASE_URL` if present),
  the freshly built `dist/deb/xpf_*.deb` + `xpf-appliance_*.deb`, the channel
  (`stable`/`edge`), the PGP key (OQ-2).
- Flat path: lay out `pool/main/x/xpf/*.deb`; `apt-ftparchive packages` →
  `dists/<suite>/main/binary-amd64/Packages{,.gz}`; `apt-ftparchive release` →
  `dists/<suite>/Release`; `gpg --clearsign -o InRelease` + `gpg -abs -o
  Release.gpg`; include `Valid-Until` (§5.6 freshness).
- reprepro path (opt-in `XPF_APT_TOOL=reprepro`): `conf/distributions` with
  `stable`/`edge`, `Components: main`, `Architectures: amd64`,
  `SignWith: <KEYID>`; `reprepro includedeb <suite> …`.
- Output: standard `dists/` + `pool/` tree under `dist/apt/`, ready to publish.
- **r2 GitHub-Releases caveat (AGY-MEDIUM-3):** if OQ-1 = GitHub Releases, a
  per-tag flat-asset layout CANNOT serve a `dists/`+`pool/` directory tree;
  GitHub Pages or a bucket is required for the APT pool even when the IMAGES
  use Release assets. The plan flags this as an OQ-1 constraint, not a blocker
  to the mechanism (the flat tree is identical wherever it is served from).

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
  doc gives both Tier A (one-liner) and Tier B (verify-before-run) per §4C.

**r2 (resolves AGY-HIGH-2) — apt UPGRADE inherits #1917's postinst cut-over.**
install.sh's FIRST install is safe (no running daemon to cut). But a later
`apt upgrade xpf-appliance` (the whole point of the repo) runs the `xpf`
package's postinst, which on a STANDALONE node invokes `xpfd upgrade` — a
verified STOP→FLIP→START with a bounded MEASURED multi-second DATAPLANE gap
(it does not cut the mgmt path; fxp0/SSH is not forward-switched, and the
postinst has a safety-net `systemctl is-active` restart). This is #1917's
existing, reviewed mechanism — **#1924 does NOT change it**. The plan's only
obligations here are DOCUMENTATION:
- `docs/distribution.md` states that `apt upgrade` triggers a dataplane blip on
  standalone nodes, and documents `XPF_NO_POSTINST_CUT=1 apt-get upgrade` (the
  existing postinst escape hatch) for operators who want stage-only + manual
  `xpfd upgrade` at a chosen time.
- For HA nodes (`/etc/xpf/node-id` present) the postinst is already STAGE-ONLY;
  the repo upgrade does NOT cut — `xpfd upgrade --rolling` does. Doc restates
  this so an operator does not `apt upgrade` both nodes expecting auto-rolling.
- No `postinst` / `pkg/upgrade` code is in scope for #1924.

### 5.5 Makefile + docs + fail-closed publish

- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
- **r2 fail-closed publish (resolves Codex-2 + SMR-F6):** `make dist-publish`
  runs a PRECONDITION gate before invoking `XPF_PUBLISH_CMD`. It REFUSES (exit
  non-zero, nothing uploaded) unless, for every artifact in the publish set:
  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
  pinned pubkey; (b) the apt `InRelease` verifies against the archive pubkey;
  (c) `install.sh.minisig` verifies (if install.sh is in the set). Bake may be
  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
  can never reach the channel.
- **r2 `XPF_PUBLISH_CMD` contract (resolves SMR-F5):** invoked exactly as
  `$XPF_PUBLISH_CMD <local-dist-dir> <XPF_DIST_BASE_URL>`; must be idempotent
  and exit non-zero on failure. The plan documents this signature so the
  backend (rsync / `aws s3 sync` / `gh release upload` wrapper) is a thin shim.
- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
  channel policy, retention, publish backends, the `apt upgrade` blip note from
  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
  image verify steps, the out-of-band pubkey source).
- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
  verify from `XPF_DIST_BASE_URL`"; document the per-version
  `xpf-<ver>.SHA256SUMS.minisig`.

### 5.6 Freshness / anti-rollback (r2 — resolves Codex-4)

Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
Mitigations, scaled to a single-publisher appliance (not full TUF):
- **Apt:** the signed `Release`/`InRelease` carries `Valid-Until` (flat path
  sets it explicitly; reprepro via `conf/distributions` `ValidFor`). apt warns/
  refuses a stale `Release` — built-in replay protection for the package path,
  re-signed each publish.
- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
  bake date + the per-version manifest name) signed with the image key. The
  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
  older than a locally-remembered version (simple monotonic check), then
  fetches the named version. This is a LIGHTWEIGHT anti-rollback signal, not a
  guarantee against a sophisticated freeze attack — documented honestly as
  "detects stale mirrors / accidental rollback," with TUF-grade freshness
  called out as a future option (not in #1924 scope). Flagged so reviewers do
  not read it as a strong guarantee.

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
   wrong arch; the inline-embedded keyring matches the archive signing key used
   to sign the test repo's `InRelease` (so apt accepts it). `--dry-run` mode
   prints the actions without mutating the host (for CI).
3b. **Fail-closed publish (r2):** `make dist-publish` with an UNSIGNED image in
   the set EXITS non-zero and uploads NOTHING (assert the publish shim is never
   invoked). With everything signed it proceeds. (The single most likely
   production mistake — publishing an unsigned dev bake — is blocked here.)
3c. **Freshness (r2):** an apt `Release` past `Valid-Until` makes `apt-get
   update` fail; `latest.json` older than the remembered version is rejected by
   the image fetch path.
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

## 12. r1 → r2 change log (response to 3-way hostile review)

All three r1 reviewers returned **PLAN-NEEDS-MAJOR** (Codex, AGY, Claude SMR).
The convergent + unique findings and their resolutions:

| Finding | Source(s) | Resolution in r2 |
|---|---|---|
| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
| Partial download (libvirt fetches only qcow2) crashes `sha256sum -c` on missing metadata | AGY-HIGH-1 | §5.1/§5.2: per-file verification; missing-but-unfetched files are not checked. |
| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
| `curl \| sh` honest trust level | SMR-F2 | §4C: Tier A = TLS + first-fetch trust (same as Tailscale/Docker/rustup), stated plainly. |
| Publish not fail-closed (unsigned dev bake can ship) | Codex-2, SMR-F6 | §5.5: `make dist-publish` precondition gate refuses unsigned artifacts. |
| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
| GitHub Releases can't host a `dists/`+`pool/` tree | AGY-MEDIUM-3 | §5.3: flagged as an OQ-1 constraint (Pages/bucket needed for the pool). |
| OQ coupling = hidden blockers? | AGY-MEDIUM-3 | §9: confirmed engineer-time inputs; every §5 mechanism runs with placeholder key + parametrised URL. |
| `XPF_PUBLISH_CMD` under-specified | SMR-F5 | §5.5: exact contract `$CMD <dist-dir> <base-url>`, idempotent. |
| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |

Two findings examined and held as documentation-only (not #1924 code scope):
AGY-HIGH-2 (postinst cut-over is #1917's reviewed mechanism) and the
single-tool §4A-alt (kept as the user's OQ-3 fallback). The minisign(image) +
PGP(apt) split, deb822 `Signed-By`, and TOFU-rejection were affirmed by all
three reviewers as correct and are unchanged.
