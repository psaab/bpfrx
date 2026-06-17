# xpf signed, hosted distribution (#1924)

Signed appliance images + a signed apt repo + a one-command installer, so an
operator fetches and verifies from a trusted, signed source instead of copying
files by hand. Spec: `docs/research/1924-signed-hosted-dist/plan.md`. Tooling:
`scripts/dist/`.

This document is the contract for the distribution mechanism. It is complete
as a MECHANISM; two operator decisions (below) are supplied at release time as
config inputs and are NOT hardcoded.

## Trust model (read this first)

Two independent trust roots, by design:

| Artifact | Tool | Public key (pinned) | Consumer |
|---|---|---|---|
| Appliance image (qcow2 + incus metadata) + `install.sh` + `latest.json` | **minisign** (Ed25519) | `scripts/dist/xpf-image.pub` | our scripts (`validate.py`, `xpf-deploy.py fetch`) + the operator |
| Apt repository (`Release`/`InRelease`) | **OpenPGP** | `scripts/dist/xpf-archive-keyring.asc` | `apt` itself |

minisign and OpenPGP are NOT redundant — they authenticate different artifacts
to different consumers. apt mandates OpenPGP for `Release`; the image consumers
are scripts we control, so minisign's single pinned pubkey is the smaller trust
surface there.

**Root of trust for the image pubkey:** the in-repo checked-in copy obtained
via `git clone` / GitHub — **independent of any hosting URL**. The copy served
from the dist host is a convenience, never the root. To verify `install.sh`
before running it (Tier B), get `xpf-image.pub` from the source repo, NOT from
`XPF_IMAGE_BASE_URL`.

## The two operator inputs (decide at release time)

1. **Hosting target.**
   - `XPF_IMAGE_BASE_URL` — serves the image artifacts, their `.minisig`
     signatures, `install.sh`, and `latest.json`. Any static HTTPS host works,
     **including GitHub Releases** (flat assets are fine for images).
   - `XPF_APT_BASE_URL` — serves the `dists/`+`pool/` apt tree. Requires a
     directory-serving host (static bucket / GitHub Pages / file server).
     **GitHub Releases CANNOT serve this** (flat assets only).
   - Plus the retention policy (keep last N versions per channel) and the
     channel layout (`stable`, `edge`).

2. **Signing identity.**
   - The minisign image keypair and the OpenPGP archive key: who holds the
     secret keys, the rotation cadence, and where the public keys are pinned.
   - `XPF_SIGN_SECKEY` is a PATH to the minisign secret key (never the bytes).
   - `XPF_GPG_KEY` is the OpenPGP key id/fingerprint that signs `Release`.

Until these are decided, `scripts/dist/*.placeholder` ship as placeholders
whose secret keys were shredded at generation (held by no one). With a
placeholder in place, verification FAILS — the correct fail-safe. See
`scripts/dist/README.md` for the go-live steps.

## Publisher runbook

```bash
# 1. Build a signed image (signs inline when XPF_SIGN_SECKEY is set).
XPF_SIGN_SECKEY=/secure/xpf-image.sec make image
#    -> dist/xpf-<ver>.qcow2, .incus-metadata.tar.gz,
#       .SHA256SUMS, .SHA256SUMS.minisig, xpf-image.pub

# 2. Build the signed apt repo (flat default; reprepro opt-in).
XPF_GPG_KEY=<keyid> make dist-repo
#    or: XPF_APT_TOOL=reprepro XPF_GPG_KEY=<keyid> make dist-repo

# 3. Write + sign the per-channel freshness pointer.
XPF_SIGN_SECKEY=/secure/xpf-image.sec \
  python3 scripts/dist/publish.py make-latest --channel stable --version <ver>

# 4. (optional) sign install.sh so Tier-B verify-before-run works.
minisign -S -s /secure/xpf-image.sec -m scripts/dist/install.sh \
         -x dist/install.sh.minisig
cp scripts/dist/install.sh dist/install.sh

# 5. Fail-closed publish (refuses unsigned artifacts; uploads per URL).
XPF_IMAGE_BASE_URL=https://dl.example.com/xpf \
XPF_APT_BASE_URL=https://dl.example.com/xpf/apt \
XPF_PUBLISH_CMD=/path/to/publish-shim \
  make dist-publish
```

`XPF_PUBLISH_CMD` is a thin backend shim invoked exactly as
`$XPF_PUBLISH_CMD <local-dir> <dest-base-url>`, once per URL (image tree →
`XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`). It must be idempotent and
exit non-zero on failure. Example shims: `rsync -a "$1/" "$2/"`,
`aws s3 sync "$1" "$2"`, a `gh release upload` wrapper. No backend is
hardcoded.

### Channel + retention

`stable` and `edge` are distinct apt suites and distinct `dist/<channel>/`
image pointers. Retention is a publisher policy (keep last N per channel);
per-version manifests mean retaining old versions never orphans their signed
checksums.

### Freshness / anti-rollback

- Apt `Release`/`InRelease` carries `Valid-Until` (default 1 year,
  `XPF_APT_VALID_DAYS`). A SHORT window with manual/air-gap signing would
  expire the repo between releases — keep it long for a manual cadence, or run
  an automated re-sign job.
- Images: `latest.json` (signed) names the current version per channel.
  `xpf-deploy.py fetch` records a best-effort monotonic watermark at
  `${XDG_STATE_HOME:-~/.local/state}/xpf/image-watermark.json` (per
  `--channel`, default `stable`) and REFUSES a version older than the recorded
  one — `--allow-rollback` permits a deliberate downgrade. This detects stale
  mirrors / accidental rollback; it is not TUF-grade freeze protection, and a
  fresh workstation with no watermark trusts the artifact's own signature.

### Key rotation

The archive keyring ships BOTH inline in `install.sh` (new installs) AND in the
`xpf` package payload at `/usr/share/keyrings/xpf-archive-keyring.asc` (via
`debian/rules`). During a dual-sign window, a normal `apt upgrade`
delivers the rotated key to EXISTING hosts before the old key retires — so
rotation is not a fleet lockout. Image-pubkey rotation: publish the new
`xpf-image.pub`, dual-sign during overlap, retire the old.

## Operator runbook

### Install (Tier A — one-liner)

```bash
curl -fsSL https://dl.example.com/xpf/install.sh | sh
```

Trust level: TLS + first-fetch trust of `install.sh` (the same level
Tailscale/Docker/rustup accept). `install.sh` preflights arch/distro/kernel
(refuses kernel < 6.18 — use the appliance image on older hosts), installs the
pinned archive keyring, writes the deb822 apt source, and `apt install
xpf-appliance`.

### Install (Tier B — verify before run)

```bash
# get the image pubkey from the SOURCE REPO, not the dist host
git clone https://github.com/psaab/xpf && cp xpf/scripts/dist/xpf-image.pub .
curl -fsSLO https://dl.example.com/xpf/install.sh
curl -fsSLO https://dl.example.com/xpf/install.sh.minisig
minisign -V -p xpf-image.pub -m install.sh -x install.sh.minisig
# read install.sh, then:
sh install.sh
```

### Verify + import an image

```bash
# downloads + verifies the EXACT bytes against the signed manifest, then
# imports to a local incus alias
xpf-deploy.py fetch --version <ver> --image-url https://dl.example.com/xpf
# libvirt/KVM (qcow2 only):
xpf-deploy.py fetch --version <ver> --image-url ... --qcow2-only
```

### CAUTION — interface takeover (#1879)

`xpfd` owns and renames every interface on the host. A bare-metal `apt install
xpf-appliance` on a remote box can cut your management path if the fxp0 mapping
is wrong. Seed a safe day-0 config (fxp0 = mgmt DHCP) before relying on remote
access, or use console.

### Upgrades

`apt upgrade xpf-appliance` triggers the #1917 postinst cut-over:
- **Standalone node:** a verified STOP→FLIP→START with a bounded, measured
  DATAPLANE blip (mgmt/SSH is not forward-switched). Use
  `XPF_NO_POSTINST_CUT=1 apt-get upgrade` to stage only and run `xpfd upgrade`
  at a chosen time.
- **HA node** (`/etc/xpf/node-id` present): stage only — `apt upgrade` does NOT
  cut. Cut with `xpfd upgrade --rolling` so the cluster keeps forwarding. Do
  not `apt upgrade` both nodes expecting auto-rolling.

This is #1917's existing, reviewed mechanism — #1924 does not change it.

## Self-test (no real key, no host)

```bash
make dist-selftest      # = scripts/dist/selftest.sh
```

Generates a throwaway keypair, signs, verifies, proves tamper-detection (4
ways), builds a flat signed apt repo + verifies `InRelease` (and that a
tampered `InRelease` fails), and dry-runs `install.sh`. Exits non-zero if any
positive check fails or any tamper check passes.
