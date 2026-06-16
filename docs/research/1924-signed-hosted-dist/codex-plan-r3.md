Reading additional input from stdin...
2026-06-16T22:55:43.009011Z ERROR codex_models_manager::manager: failed to refresh available models: timeout waiting for child process to exit
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed2a5-d1a2-71f3-b398-5afcd5d79a5c
--------
user
HOSTILE plan reviewer, ROUND 3 (research, NO code). xpf issue #1924 signed/
hosted appliance distribution. You PLAN-NEEDS-MAJOR'd r2 with 5 findings (N1
deploy can't bind bytes; N2 publish gate omits latest.json; N3 apt backend
self-contradiction flat-vs-reprepro; N4 GitHub Releases can't host pool tree;
N5 fresh-host overpromise vs kernel floor) + 2 nits (§6 sha256sum-c wording;
stray code fence).

Read docs/research/1924-signed-hosted-dist/plan.md (now r3; §12b maps each r2
finding to its fix). VERIFY each N1-N5 + the 2 nits + AGY's NIT-1/2/3 are
resolved, and hunt any NEW contradiction r3 introduced (especially the
two-URL split XPF_IMAGE_BASE_URL/XPF_APT_BASE_URL, the packaged-keyring
NIT-2 fix touching debian/, and the install.sh PREFLIGHT). Re-ground in
scripts/deploy/xpf-deploy.py, scripts/image/validate.py, debian/control.

Be hostile, quote exact r3 lines, no KILL without a counter-example. If
everything is resolved with no new blocker, PLAN-READY. End with EXACTLY one
verdict: PLAN-READY / PLAN-READY-WITH-NITS / PLAN-NEEDS-MAJOR / PLAN-KILL +
one-paragraph rationale.
2026-06-16T22:55:48.122108Z ERROR rmcp::transport::worker: worker quit with fatal: Transport channel closed, when Client(HttpRequest(HttpRequest("http/request failed: error sending request for url (https://chatgpt.com/backend-api/wham/apps)")))
2026-06-16T22:55:49.155374Z ERROR codex_api::endpoint::responses_websocket: failed to connect to websocket: IO error: failed to lookup address information: Try again, url: wss://chatgpt.com/backend-api/codex/responses
codex
I’ll review this as a hostile plan check only: first re-ground in the r3 plan and the named source files, then verify each prior finding and look for new contradictions around the URL split, packaged keyring, and preflight.
exec
/bin/bash -lc "sed -n '1,260p' docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
# Plan of action — #1924: signed, hosted appliance distribution

> Revision: r3 (2026-06-16)
> Status: REVISED after r2 review (Codex PLAN-NEEDS-MAJOR + Claude SMR
> PLAN-NEEDS-MAJOR + AGY PLAN-READY-WITH-NITS). r3 resolves the r2-introduced
> contradictions (N1–N5) + the key-rotation lockout (NIT-2). Change logs §12.
> Branch: research/1924-signed-hosted-dist
> Mode: `/research` convergence; implementation begins only on the user's own
> `/engineer 1924`. No production source touched in this doc.

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

These are surfaced as config inputs — `XPF_IMAGE_BASE_URL` + `XPF_APT_BASE_URL`
(§3 N4 two-URL split) and a checked-in public key file + `XPF_SIGN_SECKEY`
(path, never the key itself). See §9. (References below to "the dist host" /
"XPF_DIST_BASE_URL" mean whichever of the two URLs serves the artifact in
question — the trust-model point is identical for both.)

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
| Packaged archive keyring (r3 NIT-2) | NEW (one `debian/install` line, no postinst logic) | ships `xpf-archive-keyring.asc` to `/etc/apt/keyrings/` so existing hosts get rotated keys via `apt upgrade` |
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
3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
   ≥6.18 + systemd-networkd present), bootstraps trust (installs the archive
   keyring), adds the apt source, and runs `apt install xpf-appliance` — one
   command on a Debian/Ubuntu host **that already meets the kernel floor**.

**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
floor; it does NOT install a kernel.** The appliance's verifier floor is kernel
≥6.18 + the mlx5/i40e driver set (the IMAGE owns that closure; `debian/control`
states kernel handling is out of scope). A bare-metal `apt install
xpf-appliance` on Debian 12 / Ubuntu 24.04 would install the packages but
`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
and REFUSES with a clear message ("xpf requires kernel ≥6.18 + native-XDP NIC;
use the appliance image, or upgrade the host kernel") rather than leaving a
broken install. The image (bake.py) remains the turnkey path for hosts that do
not meet the floor.

**r3 (resolves N4) — TWO base URLs, not one.** Images and the apt pool have
different hosting shapes, so the mechanism takes two parameters:
- `XPF_IMAGE_BASE_URL` (OQ-1a): serves the image artifacts + sigs +
  `latest.json` + `install.sh`. Satisfiable by ANY static host INCLUDING
  GitHub Releases (flat assets are fine for images).
- `XPF_APT_BASE_URL` (OQ-1b): serves the `dists/`+`pool/` tree. Requires a
  real directory-serving host (static bucket / Pages / file server) — **GitHub
  Releases CANNOT serve this** (flat assets only). install.sh writes
  `URIs: <XPF_APT_BASE_URL>`.
They MAY be the same host (a bucket serves both); they need not be. Publishing
is a thin `dist-publish` target parametrised by both (each fed to
`XPF_PUBLISH_CMD`). The mechanism is host-agnostic per URL.

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
  URIs: <XPF_APT_BASE_URL>             # OQ-1b (dists/+pool/ tree)
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

exec
/bin/bash -lc "sed -n '1,260p' scripts/deploy/xpf-deploy.py" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc "sed -n '1,260p' scripts/image/validate.py" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
#!/usr/bin/env python3
"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.

Subcommands:
  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
                                  is two files. (Default if args are *.yaml.)
  launch --name … --nic …         imperative launch without a YAML file.
  inventory                       list host NICs, SR-IOV VFs, bridges → the
                                  values you drop into a definition.

Interface naming is POSITIONAL (matches pkg/daemon/linksetup.go assignName):

  standalone:      pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
  cluster node 0:  pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
  cluster node 1:  pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)

A NIC's backing (virtio bridge / SR-IOV VF / PCI passthrough) is declared
explicitly per interface — `backing:` in YAML, or the `<backing>:<source>`
spec for --nic. The tool translates each to the right incus device / libvirt
virt-install argument. The day-0 config drive is built and check-config
validated in-process (no shell helpers).

Global options: --dry-run  --hypervisor incus|libvirt  --no-start  --image X

Examples:
  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
  xpf-deploy.py launch --name fw1 --config standalone.conf \\
      --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0
  xpf-deploy.py inventory
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    yaml = None

VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}
SYS_NET = "/sys/class/net"


def die(msg):
    sys.exit(f"ERROR: {msg}")


# ── naming contract ───────────────────────────────────────────────────
def expected_name(idx, mode, node_id):
    """vSRX name the guest assigns to the NIC at position idx (0-based);
    mirrors assignName() in pkg/daemon/linksetup.go."""
    if idx == 0:
        return "fxp0"
    if mode == "cluster":
        if idx == 1:
            return "em0"
        fpc = 7 if node_id == 1 else 0
        return f"ge-{fpc}/0/{idx - 2}"
    return f"ge-0/0/{idx - 1}"


def norm_role(role):
    r = role.strip()
    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    return f"ge-{m.group(1)}/0/{m.group(2)}" if m else r


# ── host introspection ────────────────────────────────────────────────
def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def is_physical_nic(dev):
    if dev == "lo" or not os.path.isdir(os.path.join(SYS_NET, dev, "device")):
        return False
    return not re.match(r"(veth|tap|br-|virbr|docker|incusbr)", dev)


def driver_of(dev):
    link = os.path.join(SYS_NET, dev, "device", "driver")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def pci_of(dev):
    link = os.path.join(SYS_NET, dev, "device")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def native_xdp_hint(driver):
    if driver in ("mlx5_core", "i40e", "ice", "ixgbe", "bnxt_en", "nfp"):
        return "native"
    if driver in ("iavf", "ixgbevf", "virtio_net"):
        return "no (generic)"
    return "unknown"


def vf_parent(addr):
    """(PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
    if not os.path.isdir(SYS_NET):
        return None
    for pf in os.listdir(SYS_NET):
        devdir = os.path.join(SYS_NET, pf, "device")
        if not os.path.isdir(devdir):
            continue
        for entry in os.listdir(devdir):
            if entry.startswith("virtfn") and \
               os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
                return pf, entry[len("virtfn"):]
    return None


def cmd_inventory(_args):
    print(f"=== Physical NICs ===")
    print(f"{'NETDEV':<14} {'DRIVER':<10} {'PCI':<14} {'MAC':<18} {'LINK':<6} NATIVE-XDP")
    for dev in sorted(os.listdir(SYS_NET)):
        if not is_physical_nic(dev):
            continue
        drv = driver_of(dev)
        print(f"{dev:<14} {drv:<10} {pci_of(dev):<14} "
              f"{_read(os.path.join(SYS_NET, dev, 'address')):<18} "
              f"{_read(os.path.join(SYS_NET, dev, 'operstate')):<6} {native_xdp_hint(drv)}")
        devdir = os.path.join(SYS_NET, dev, "device")
        total = _read(os.path.join(devdir, "sriov_totalvfs"))
        if total and total != "0":
            num = _read(os.path.join(devdir, "sriov_numvfs")) or "0"
            print(f"    SR-IOV: {num}/{total} VFs. Create N:  "
                  f"echo N | sudo tee {devdir}/sriov_numvfs")
            for entry in sorted(os.listdir(devdir)):
                if entry.startswith("virtfn"):
                    vfpci = os.path.basename(os.path.realpath(os.path.join(devdir, entry)))
                    print(f"      vf{entry[len('virtfn'):]:<3} pci:{vfpci}   "
                          f"(sriov:{dev}  |  pci:{vfpci},mac=02:..)")
    print("\n=== Host bridges (bridge:<name>) ===")
    found = False
    for dev in sorted(os.listdir(SYS_NET)):
        if os.path.isdir(os.path.join(SYS_NET, dev, "bridge")):
            print(f"  bridge:{dev}")
            found = True
    if not found:
        print("  (none — create: sudo ip link add br-lan type bridge; ip link set br-lan up)")
    return 0


# ── appliance model ───────────────────────────────────────────────────
def validate_appliance(ap, where):
    if not ap.get("name"):
        die(f"{where}: name is required")
    if ap["mode"] not in ("standalone", "cluster"):
        die(f"{where}: mode must be standalone|cluster")
    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
        die(f"{where}: cluster needs node_id 0|1")
    if not ap["interfaces"]:
        die(f"{where}: at least one interface (position 1 = fxp0)")
    for i, ic in enumerate(ap["interfaces"]):
        if ic.get("backing") not in VALID_BACKINGS:
            die(f"{where}: interface {i + 1} backing must be one of {sorted(VALID_BACKINGS)}")
        if not ic.get("source"):
            die(f"{where}: interface {i + 1} needs a source")
        want = expected_name(i, ap["mode"], ap.get("node_id"))
        if ic.get("role") and norm_role(ic["role"]) != want:
            die(f"{where}: interface {i + 1} declares role '{ic['role']}' but position {i + 1} "
                f"is '{want}' — reorder or fix; position is the contract.")
        ic["_name"] = want


def load_yaml_appliance(path):
    if yaml is None:
        die("PyYAML required for YAML deploy (apt install python3-yaml). "
            "Use the 'launch' subcommand for a no-YAML, no-dependency path.")
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        die(f"{path}: top level must be a mapping")
    a = doc.get("appliance") or {}
    ap = {
        "name": a.get("name"), "mode": a.get("mode", "standalone"),
        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
        "cpu": a.get("cpu", 4), "memory": a.get("memory", "4GiB"),
        "config": a.get("config"), "interfaces": doc.get("interfaces") or [],
        "pool": a.get("pool", "default"),
        "base_dir": os.path.dirname(os.path.abspath(path)),
    }
    validate_appliance(ap, path)
    return ap


# ── day-0 config drive (pure Python; xorriso/genisoimage for the ISO) ──
def find_xpfd():
    for c in (os.environ.get("XPFD"), os.path.join(os.getcwd(), "xpfd"),
              shutil.which("xpfd")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def build_config_drive(ap, runner):
    cfg = ap.get("config")
    if not cfg:
        return None
    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["base_dir"], cfg)
    iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")
    if runner.dry:
        print(f"==> (dry-run) would build day-0 drive {iso} from {cfg_path} "
              f"(label xpf-config, check-config validated)")
        return iso
    if not os.path.isfile(cfg_path):
        die(f"config not found: {cfg_path}")
    xpfd = find_xpfd()
    if xpfd:
        nodearg = ["-node-id", str(ap["node_id"])] if ap["mode"] == "cluster" else []
        r = subprocess.run([xpfd, "check-config"] + nodearg + [cfg_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(f"day-0 config REJECTED by check-config:\n{r.stdout}{r.stderr}")
        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
    else:
        print("WARNING: no xpfd binary found — skipping build-host validation "
              "(the appliance still validates at first boot).")
    mkiso = next((t for t in ("xorriso", "genisoimage", "mkisofs") if shutil.which(t)), None)
    if not mkiso:
        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
        if ap["mode"] == "cluster":
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{ap['node_id']}\n")
        if mkiso == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", iso, stage]
        else:
            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
        subprocess.run(argv, check=True, capture_output=True, text=True)
        print(f"==> built day-0 drive {iso} (label xpf-config)")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return iso


# ── memory / pci helpers ──────────────────────────────────────────────
def memory_mb(val):
    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", str(val).strip())
    if not m:
        die(f"unparseable memory '{val}'")
    return int(m.group(1)) * 1024 if (m.group(2) or "M").upper().startswith("G") else int(m.group(1))


def pci_parts(addr):

 succeeded in 0ms:
#!/usr/bin/env python3
"""xpf appliance image validation (#1879 Path C), in Python.

Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
never the shared loss cluster) and proves the first-boot contract:

  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
     the image's own kernel (the bake gate).
  b  valid day-0 drive -> config validated + installed + committed at first
     boot (hostname applied); a reboot does NOT re-apply (stamp).
  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
     boot survives, factory bootstrap still reachable.

Usage:
  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
"""

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import make_config_drive  # noqa: E402

ALIAS = "xpf-image-validate"


def info(m):
    print(f"==> {m}")


def fail(m):
    print(f"FAIL: {m}", file=sys.stderr)
    sys.exit(1)


def incus(*args, check=True, capture=False):
    return subprocess.run(["incus", *args], check=check,
                          capture_output=capture, text=True)


def guest(inst, *cmd, check=True, capture=False):
    return subprocess.run(["incus", "exec", inst, "--", *cmd],
                          check=check, capture_output=capture, text=True)


def guest_sh(inst, script):
    """Run a shell snippet in the guest; return True on exit 0."""
    return subprocess.run(["incus", "exec", inst, "--", "sh", "-c", script],
                          capture_output=True, text=True).returncode == 0


class Harness:
    def __init__(self, qcow2, metadata, net, keep):
        self.qcow2, self.metadata, self.net, self.keep = qcow2, metadata, net, keep
        self.created_net = False
        self.instances = []
        self.work = tempfile.mkdtemp(prefix="xpf-validate-")

    # ── lifecycle ──
    def ensure_network(self):
        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
            info(f"creating validation network {self.net} (NAT + DHCP)")
            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
                  "ipv4.nat=true", "ipv6.address=none")
            self.created_net = True

    def import_image(self):
        incus("image", "delete", ALIAS, check=False, capture=True)
        info(f"importing image into local incus as {ALIAS}")
        incus("image", "import", self.metadata, self.qcow2, "--alias", ALIAS)

    def launch(self, name, iso=None):
        incus("delete", "-f", name, check=False, capture=True)
        incus("init", ALIAS, name, "--vm", "--network", self.net,
              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB", capture=True)
        if iso:
            incus("config", "device", "add", name, "day0", "disk",
                  f"source={os.path.realpath(iso)}", capture=True)
        self.instances.append(name)
        incus("start", name)
        self.wait_agent(name)

    def drop(self, name):
        if not self.keep:
            incus("delete", "-f", name, check=False, capture=True)
            if name in self.instances:
                self.instances.remove(name)

    def cleanup(self):
        if self.keep:
            print(f"keeping instances {self.instances}, alias {ALIAS}, network {self.net}")
        else:
            for i in self.instances:
                incus("delete", "-f", i, check=False, capture=True)
            incus("image", "delete", ALIAS, check=False, capture=True)
            if self.created_net:
                incus("network", "delete", self.net, check=False, capture=True)
        subprocess.run(["rm", "-rf", self.work], check=False)

    # ── waiters ──
    def _wait(self, name, pred, tries, secs, what):
        for _ in range(tries):
            if pred():
                return
            time.sleep(secs)
        fail(f"{name}: {what}")

    def wait_agent(self, name):
        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
                   80, 3, "incus agent not ready after 240s")

    def wait_xpfd(self, name):
        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
                                       check=False, capture=True).returncode == 0,
                   40, 3, "xpfd not active after 120s")

    def wait_fxp0_dhcp(self, name):
        self._wait(name, lambda: guest_sh(name, 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'),
                   30, 3, "fxp0 has no IPv4 DHCP address after 90s")

    # ── scenarios ──
    def scenario_a(self):
        info("── Scenario A: first boot, NO config drive ──")
        self.launch("xpf-image-a")
        self.wait_xpfd("xpf-image-a")
        kver = guest("xpf-image-a", "uname", "-r", capture=True).stdout.strip()
        info(f"guest kernel: {kver}")
        rel = kver.split("-")[0]
        if not _kver_ge(rel, (6, 18)):
            fail(f"guest kernel {kver} < 6.18")
        if not guest_sh("xpf-image-a", 'uname -r | grep -q -- -generic'):
            fail("running kernel is not the -generic flavor")
        if not guest_sh("xpf-image-a", 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
            fail("linux-modules-extra (mlx5/i40e driver set) missing")
        if not guest_sh("xpf-image-a", '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
        if not guest_sh("xpf-image-a", 'grep -qw init_on_alloc=0 /proc/cmdline'):
            fail("init_on_alloc=0 missing from the booted kernel cmdline")
        info("in-guest verify-dataplane (the bake gate, image kernel)...")
        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
                 check=False).returncode != 0:
            fail("in-guest verify-dataplane REJECTED — image must not ship")
        self.wait_fxp0_dhcp("xpf-image-a")
        if not guest_sh("xpf-image-a", 'ss -tln | grep -q ":22 "'):
            fail("sshd not listening")
        if not guest_sh("xpf-image-a",
                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
            fail("sshd effective config does not refuse root password auth")
        if not guest_sh("xpf-image-a", '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
            fail("sshd effective config does not pin PermitEmptyPasswords no")
        if guest("xpf-image-a", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("unexpected /etc/xpf/xpf.conf")
        if guest("xpf-image-a", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("unexpected day-0 stamp")
        if not guest_sh("xpf-image-a",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
            fail("day-0 loader did not log the no-medium fallback")
        info("Scenario A PASS")
        self.drop("xpf-image-a")

    def scenario_b(self):
        info("── Scenario B: first boot WITH valid day-0 config drive ──")
        conf = os.path.join(self.work, "day0-valid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-b;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
                                                   validate=False)
        self.launch("xpf-image-b", iso)
        self.wait_xpfd("xpf-image-b")
        if guest("xpf-image-b", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
            fail("day-0 stamp missing")
        if guest("xpf-image-b", "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
            fail("/etc/xpf/xpf.conf missing")
        if not guest_sh("xpf-image-b",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("day-0 loader did not log the install")
        self._wait("xpf-image-b",
                   lambda: guest_sh("xpf-image-b",
                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
                                    '| grep -q "host-name xpf-day0-b"'),
                   20, 3, "committed config does not show host-name xpf-day0-b")
        if not guest_sh("xpf-image-b", '[ "$(hostname)" = xpf-day0-b ]'):
            fail("hostname not applied")
        info("rebooting xpf-image-b — second boot must NOT re-apply...")
        incus("restart", "xpf-image-b")
        self.wait_agent("xpf-image-b")
        self.wait_xpfd("xpf-image-b")
        if not guest_sh("xpf-image-b",
                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("second boot re-applied the day-0 config")
        if not guest_sh("xpf-image-b",
                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
        info("Scenario B PASS")
        self.drop("xpf-image-b")

    def scenario_c(self):
        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
        conf = os.path.join(self.work, "day0-invalid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
                                                   validate=False)
        self.launch("xpf-image-c", iso)
        self.wait_xpfd("xpf-image-c")
        if not guest_sh("xpf-image-c",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
            fail("day-0 loader did not log the commit-check REJECT")
        if guest("xpf-image-c", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("invalid config was installed")
        if guest("xpf-image-c", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("stamp written on REJECT")
        self.wait_fxp0_dhcp("xpf-image-c")
        if not guest_sh("xpf-image-c", '[ "$(hostname)" != xpf-day0-c ]'):
            fail("invalid config changed the hostname")
        info("Scenario C PASS (fallback reachable, boot survived)")
        self.drop("xpf-image-c")


def _kver_ge(ver, floor):
    try:
        parts = tuple(int(x) for x in ver.split(".")[:2])
    except ValueError:
        return False
    return parts >= floor


def maybe_reexec_incus_admin():
    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
        return
    import grp
    try:
        in_grp = "incus-admin" in [g.gr_name for g in grp.getgrall()
                                   if os.getlogin() in g.gr_mem]
    except Exception:
        in_grp = False
    if in_grp:
        # Quote every token — a qcow2/metadata path with spaces or shell
        # metacharacters must not break (or inject into) the `sg -c` shell.
        cmd = " ".join(shlex.quote(a) for a in [sys.executable] + sys.argv)
        os.execvp("sg", ["sg", "incus-admin", "-c", cmd])


def main():
    maybe_reexec_incus_admin()
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--qcow2", required=True)
    p.add_argument("--metadata", required=True)

exec
/bin/bash -lc "sed -n '1,220p' debian/control" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc 'pwd && git rev-parse HEAD && git status --short && rg -n "''^(#+|##|###)|N1|N2|N3|N4|N5|NIT|AGY|XPF_IMAGE_BASE_URL|XPF_APT_BASE_URL|PREFLIGHT|latest'"\\.json|reprepro|flat|sha256sum|"'```" docs/research/1924-signed-hosted-dist/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
Source: xpf
Section: net
Priority: optional
Maintainer: xpf maintainers <noreply@anthropic.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://github.com/psaab/xpf
Rules-Requires-Root: no

Package: xpf
Architecture: amd64
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: Junos-style firewall with AF_XDP userspace dataplane
 xpf is a Junos-style stateful firewall that clones Juniper vSRX
 capabilities using native Junos configuration syntax. The runtime
 forwarding path is a Rust AF_XDP userspace dataplane driven by the
 Go control plane (xpfd).
 .
 This package ships the binary set (xpfd, xpf-userspace-dp, cli),
 the day-0 config-drive loader, and the systemd units. Binaries are
 installed to a dpkg-static staging path; the live /usr/local/sbin
 symlinks are created on first install (the in-place upgrade cut-over
 mechanism that flips them after a verify gate is a separate increment
 and is intentionally not part of this package's postinst).
 .
 The AF_XDP shim is embedded into the xpfd binary (go:embed), so no
 separate shim object is shipped.

Package: xpf-appliance
Architecture: amd64
Depends: ${misc:Depends},
 xpf (= ${binary:Version}),
 frr,
 strongswan,
 strongswan-swanctl,
 kea-dhcp4-server,
 kea-dhcp6-server,
 chrony,
 iproute2,
 nftables,
 ethtool,
 tcpdump,
 pciutils,
 iputils-ping,
 traceroute,
 openssh-server,
 openssh-client,
 systemd-resolved,
 rsyslog,
 curl,
 ca-certificates
Description: xpf firewall appliance metapackage
 Pulls in the xpf firewall binary package plus the full runtime
 dependency set (routing, IPsec, DHCP server, time sync, networking
 tooling). This is the operator-facing entry point: `apt install
 xpf-appliance` provisions a complete firewall in one step (e.g. from a
 hosted apt repo).
 .
 NOTE: the appliance image bake (scripts/image/bake.py) installs the
 runtime dependency set explicitly plus the xpf binary package, rather
 than this metapackage, so apt does not have to resolve the full
 dependency closure against a single local .deb during the offline bake.
 The dependency set here MUST stay in sync with bake.py's
 RUNTIME_PACKAGES.
 .
 The held/pinned kernel channel and the in-place kernel-upgrade
 mechanism are out of scope for this package and tracked separately.

 exited 2 in 0ms:
/bin/bash: -c: line 1: unexpected EOF while looking for matching ``'

codex
The first search command failed because the shell interpreted backticks inside the pattern; the direct file reads succeeded. I’ve got the core r3 language and am pulling the remaining plan sections with line numbers now so findings can cite exact text.
exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '261,560p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   261	
   262	**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
   263	release upload`s the image tree (images + sigs + `latest.json` + install.sh) to
   264	`XPF_IMAGE_BASE_URL` and the flat `apt/` pool tree to `XPF_APT_BASE_URL` (§3 N4
   265	two-URL split). The plan provides a pluggable `XPF_PUBLISH_CMD` so the user
   266	wires their chosen backend without the mechanism caring. Retention +
   267	channel layout are documented defaults (keep last N images per channel) the
   268	user tunes. **No backend is hardcoded.**
   269	
   270	## 5. Detailed mechanism (recommended path)
   271	
   272	### 5.1 Image signing (bake.py, additive) — PER-VERSION, not a global SHA256SUMS
   273	
   274	**r2 change (resolves Codex-3 retention + AGY-HIGH-1 partial-download +
   275	SMR-F3/Codex-1 path-binding):** the bake stops emitting a single global
   276	`dist/SHA256SUMS`. Instead each bake writes a **per-version, version-named**
   277	checksum manifest and signs THAT:
   278	```
   279	dist/xpf-<ver>.SHA256SUMS          # lists exactly this version's qcow2 + metadata
   280	dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
   281	```
   282	Signing step (after step 6):
   283	```
   284	minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
   285	         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
   286	```
   287	- **Why per-version:** retaining v1 alongside v2 (Codex-3) no longer orphans
   288	  v1's checksums — each version owns its signed manifest. A `latest` symlink/
   289	  pointer (`dist/<channel>/latest -> xpf-<ver>.*`) is a convenience, never the
   290	  trust root.
   291	- The manifest lists BOTH the qcow2 and the incus metadata, BUT verification
   292	  (§5.2) is **per-file**, so the libvirt operator who only fetched the qcow2
   293	  can verify it without the metadata present (AGY-HIGH-1).
   294	- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
   295	  If unset, bake prints a loud WARNING and skips signing (dev ergonomics);
   296	  the publish-time guard (§5.5) then REFUSES to publish unsigned artifacts —
   297	  signing is fail-OPEN at bake but fail-CLOSED at publish.
   298	- The pinned PUBLIC key ships in-repo as `scripts/dist/xpf-image.pub` and is
   299	  copied into `dist/` so the published tree is self-describing. **Its root of
   300	  trust is the in-repo checked-in copy obtained via `git clone`/GitHub —
   301	  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
   302	  NEVER the root** (SMR-F1, Codex-6, AGY-MEDIUM-1).
   303	
   304	### 5.2 Image verify (validate.py + xpf-deploy.py) — verify the EXACT imported file
   305	
   306	**r2 change (resolves SMR-F3 + Codex-1 + AGY-HIGH-1):** the verifier does NOT
   307	run a cwd-relative `sha256sum -c`. It:
   308	1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
   309	   the manifest is authentic.
   310	2. **Parses** the manifest, rejecting pathful entries and duplicate basenames,
   311	   into `{basename: hash}`.
   312	3. For EACH file actually being imported (the concrete `--qcow2` / `--metadata`
   313	   argument paths), computes its SHA256 and compares against the manifest entry
   314	   for that file's basename. A file not listed, or a hash mismatch, FAILS.
   315	   Files in the manifest that the operator did NOT fetch are simply not checked
   316	   (per-file, so qcow2-only libvirt verifies fine).
   317	Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
   318	reused by both consumers.
   319	Wire it as:
   320	- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
   321	  to the artifacts; `--no-verify-sig` escape hatch for local dev bakes).
   322	- **r3 (resolves N1) — image verify lives at IMPORT time, not alias-launch.**
   323	  Today `xpf-deploy.py` does NOT import an image: it `incus init <alias>` /
   324	  `virt-install --import <existing qcow2>` against an artifact the operator
   325	  ALREADY placed locally. There is no qcow2/metadata path at deploy time for
   326	  the incus-alias flow, so the deploy path CANNOT bind image bytes — and the
   327	  plan no longer claims it does. Image verification is wired in the TWO places
   328	  that actually touch raw image bytes:
   329	  1. `validate.py` (the bake gate) — it DOES `incus image import <meta>
   330	     <qcow2>`; verify the exact `--qcow2`/`--metadata` files there.
   331	  2. A NEW `xpf-deploy.py fetch` / `--image-url` subcommand that downloads from
   332	     `XPF_IMAGE_BASE_URL`, verifies the EXACT downloaded file, then imports it
   333	     to a local alias. The existing `deploy` (alias-launch) path is unchanged
   334	     and simply consumes a previously-verified alias (documented: "verify at
   335	     fetch/import, not at launch").
   336	- Pinned pubkey path is a checked-in constant; `XPF_IMAGE_PUBKEY` overrides for
   337	  rotation/testing.
   338	
   339	### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh)
   340	Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
   341	- Inputs: the existing pool (synced down from `XPF_APT_BASE_URL` if present),
   342	  the freshly built `dist/deb/xpf_*.deb` + `xpf-appliance_*.deb`, the channel
   343	  (`stable`/`edge`), the PGP key (OQ-2).
   344	- Flat path: lay out `pool/main/x/xpf/*.deb`; `apt-ftparchive packages` →
   345	  `dists/<suite>/main/binary-amd64/Packages{,.gz}`; `apt-ftparchive release` →
   346	  `dists/<suite>/Release`; `gpg --clearsign -o InRelease` + `gpg -abs -o
   347	  Release.gpg`; include `Valid-Until` (§5.6 freshness).
   348	- reprepro path (opt-in `XPF_APT_TOOL=reprepro`): `conf/distributions` with
   349	  `stable`/`edge`, `Components: main`, `Architectures: amd64`,
   350	  `SignWith: <KEYID>`; `reprepro includedeb <suite> …`.
   351	- Output: standard `dists/` + `pool/` tree under `dist/apt/`, ready to publish.
   352	- **r2 GitHub-Releases caveat (AGY-MEDIUM-3):** if OQ-1 = GitHub Releases, a
   353	  per-tag flat-asset layout CANNOT serve a `dists/`+`pool/` directory tree;
   354	  GitHub Pages or a bucket is required for the APT pool even when the IMAGES
   355	  use Release assets. The plan flags this as an OQ-1 constraint, not a blocker
   356	  to the mechanism (the flat tree is identical wherever it is served from).
   357	
   358	### 5.4 install.sh (NEW)
   359	Tailscale-shaped, POSIX sh, idempotent:
   360	1. PREFLIGHT (r3 N5): refuse non-amd64 / non-Debian-family / kernel <6.18 /
   361	   no systemd-networkd, each with a clear actionable message.
   362	2. Install the pinned archive keyring to `/etc/apt/keyrings/
   363	   xpf-archive-keyring.asc` (embedded inline, `0644`).
   364	3. Write `/etc/apt/sources.list.d/xpf.sources` (deb822, `Signed-By`,
   365	   `XPF_APT_BASE_URL` substituted; default channel `stable`,
   366	   `XPF_CHANNEL=edge` override).
   367	4. `apt-get update && apt-get install -y xpf-appliance`.
   368	
   369	**r3 (resolves NIT-2) — the archive keyring also ships in the PACKAGE payload.**
   370	install.sh's inline keyring bootstraps NEW hosts, but existing hosts never
   371	re-run install.sh, so a key rotation would lock them out of `apt update` once
   372	the old key retires. The mechanism therefore ALSO ships the keyring as a
   373	package-owned conffile at `/etc/apt/keyrings/xpf-archive-keyring.asc` (in the
   374	`xpf` package). During a dual-sign rotation window a normal `apt upgrade`
   375	delivers the new key to existing hosts BEFORE the old key is retired — the
   376	standard apt-keyring-in-package pattern. (This is the one place #1924 touches
   377	`debian/` — a packaged keyring file + its `debian/install` line; no postinst
   378	logic. It is in scope because without it rotation is a fleet lockout.)
   379	5. Print next steps (day-0 config, `cli`, mgmt reachability caveat — the
   380	   interface-takeover warning from #1879 is RESTATED here because a bare-metal
   381	   `apt install` on a remote box can cut mgmt if fxp0 mapping is wrong).
   382	- `install.sh` is itself published at `XPF_IMAGE_BASE_URL/install.sh` and the
   383	  doc gives both Tier A (one-liner) and Tier B (verify-before-run) per §4C.
   384	
   385	**r2 (resolves AGY-HIGH-2) — apt UPGRADE inherits #1917's postinst cut-over.**
   386	install.sh's FIRST install is safe (no running daemon to cut). But a later
   387	`apt upgrade xpf-appliance` (the whole point of the repo) runs the `xpf`
   388	package's postinst, which on a STANDALONE node invokes `xpfd upgrade` — a
   389	verified STOP→FLIP→START with a bounded MEASURED multi-second DATAPLANE gap
   390	(it does not cut the mgmt path; fxp0/SSH is not forward-switched, and the
   391	postinst has a safety-net `systemctl is-active` restart). This is #1917's
   392	existing, reviewed mechanism — **#1924 does NOT change it**. The plan's only
   393	obligations here are DOCUMENTATION:
   394	- `docs/distribution.md` states that `apt upgrade` triggers a dataplane blip on
   395	  standalone nodes, and documents `XPF_NO_POSTINST_CUT=1 apt-get upgrade` (the
   396	  existing postinst escape hatch) for operators who want stage-only + manual
   397	  `xpfd upgrade` at a chosen time.
   398	- For HA nodes (`/etc/xpf/node-id` present) the postinst is already STAGE-ONLY;
   399	  the repo upgrade does NOT cut — `xpfd upgrade --rolling` does. Doc restates
   400	  this so an operator does not `apt upgrade` both nodes expecting auto-rolling.
   401	- No `postinst` / `pkg/upgrade` code is in scope for #1924.
   402	
   403	### 5.5 Makefile + docs + fail-closed publish
   404	
   405	- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
   406	  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
   407	- **r2 fail-closed publish (resolves Codex-2 + SMR-F6):** `make dist-publish`
   408	  runs a PRECONDITION gate before invoking `XPF_PUBLISH_CMD`. It REFUSES (exit
   409	  non-zero, nothing uploaded) unless, for every artifact in the publish set:
   410	  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
   411	  pinned pubkey; (b) the apt `InRelease` verifies against the archive pubkey;
   412	  (c) `install.sh.minisig` verifies (if install.sh is in the set); **(d) r3
   413	  (resolves N2): the per-channel `latest.json` verifies against the image pubkey
   414	  AND names a version present in the publish set** (so a stale/unsigned
   415	  freshness pointer can never ship). Bake may be
   416	  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
   417	  can never reach the channel.
   418	- **r2 `XPF_PUBLISH_CMD` contract (resolves SMR-F5):** invoked exactly as
   419	  `$XPF_PUBLISH_CMD <local-dist-dir> <dest-base-url>`; called once per URL
   420	  (image tree → `XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`); idempotent
   421	  and exit non-zero on failure. The plan documents this signature so the
   422	  backend (rsync / `aws s3 sync` / `gh release upload` wrapper) is a thin shim.
   423	- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
   424	  channel policy, retention, publish backends, the `apt upgrade` blip note from
   425	  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
   426	  image verify steps, the out-of-band pubkey source).
   427	- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
   428	  verify from `XPF_DIST_BASE_URL`"; document the per-version
   429	  `xpf-<ver>.SHA256SUMS.minisig`.
   430	
   431	### 5.6 Freshness / anti-rollback (r2 — resolves Codex-4)
   432	
   433	Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
   434	Mitigations, scaled to a single-publisher appliance (not full TUF):
   435	- **Apt:** the signed `Release`/`InRelease` carries `Valid-Until` (flat path
   436	  sets it explicitly; reprepro via `conf/distributions` `ValidFor`). apt warns/
   437	  refuses a stale `Release` — built-in replay protection for the package path,
   438	  re-signed each publish. **r3 (resolves NIT-1): with MANUAL/air-gap signing
   439	  (OQ-4) a SHORT `Valid-Until` would expire the repo between releases and break
   440	  `apt update`. The mechanism therefore sets a LONG default `Valid-Until` (1
   441	  year) aligned to a manual cadence, and documents that a shorter window
   442	  REQUIRES an automated re-sign job. The duration is a config input
   443	  (`XPF_APT_VALID_DAYS`).**
   444	- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
   445	  bake date + the per-version manifest name) signed with the image key. The
   446	  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
   447	  older than a locally-remembered version (simple monotonic check), then
   448	  fetches the named version. **r3 (resolves NIT-3): the watermark is persisted
   449	  at `${XDG_STATE_HOME:-~/.local/state}/xpf/image-watermark.json`; because
   450	  xpf-deploy is a stateless multi-operator CLI, this check is documented as
   451	  BEST-EFFORT (a fresh workstation has no watermark and trusts latest.json's
   452	  own signature + date).** This is a LIGHTWEIGHT anti-rollback signal, not a
   453	  guarantee against a sophisticated freeze attack — documented honestly as
   454	  "detects stale mirrors / accidental rollback," with TUF-grade freshness
   455	  called out as a future option (not in #1924 scope). Flagged so reviewers do
   456	  not read it as a strong guarantee.
   457	
   458	## 6. Test / validation strategy (research scope = how /engineer will prove it)
   459	
   460	No loss-cluster smoke (no forwarding change). Validation is local + CI-shaped:
   461	
   462	1. **Sign/verify round-trip (image):** bake (or a stub per-version
   463	   `xpf-<ver>.SHA256SUMS`) → sign with a throwaway minisign key →
   464	   `verify_image_artifact` PASSES; flip one byte of the qcow2 → verify FAILS at
   465	   the parsed-hash comparison (§5.2); flip the `.minisig` → verify FAILS at
   466	   `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
   467	   verify that can't fail is theater.)
   468	2. **Apt repo:** build the signed repo into a temp dir → spin a Debian
   469	   container (or the local incus image flow) → run install.sh pointed at a
   470	   `file://` or `http://localhost` serving of the temp repo → `apt install
   471	   xpf-appliance` succeeds → `apt-get update` against a TAMPERED `Release`
   472	   FAILS with apt's signature error (negative test).
   473	3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
   474	   wrong arch; the inline-embedded keyring matches the archive signing key used
   475	   to sign the test repo's `InRelease` (so apt accepts it). `--dry-run` mode
   476	   prints the actions without mutating the host (for CI).
   477	3b. **Fail-closed publish (r2):** `make dist-publish` with an UNSIGNED image in
   478	   the set EXITS non-zero and uploads NOTHING (assert the publish shim is never
   479	   invoked). With everything signed it proceeds. (The single most likely
   480	   production mistake — publishing an unsigned dev bake — is blocked here.)
   481	3c. **Freshness (r2):** an apt `Release` past `Valid-Until` makes `apt-get
   482	   update` fail; `latest.json` older than the remembered version is rejected by
   483	   the image fetch path.
   484	4. **bake.py unchanged paths:** the existing image-validation matrix
   485	   (`scripts/image/validate.py a|b|c`) still passes; signing is additive and
   486	   does not perturb the boot/day-0 contract.
   487	5. **Doc accuracy:** the `curl | sh` one-liner and the manual steps are
   488	   copy-pasteable against a local test publish.
   489	
   490	The signing key used in tests is a generated throwaway, NEVER OQ-2's real key.
   491	
   492	## 7. Rollout / sequencing
   493	
   494	`/engineer` should land this as small, independently-reviewable increments
   495	(each its own commit, true-merge per project policy):
   496	
   497	- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
   498	  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
   499	  negative tests; docs). Shippable alone; gives signed images immediately.
   500	- **Inc 2 — apt repo build tooling** (`scripts/dist/build-apt-repo.sh` —
   501	  FLAT signed repo default per §4B, reprepro opt-in via `XPF_APT_TOOL`;
   502	  `make dist-repo`; PGP archive pubkey placeholder; container repo test).
   503	  Shippable alone.
   504	- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
   505	  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
   506	- **Inc 4 (optional, deferrable) — CI release workflow** (`.github/workflows/
   507	  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
   508	  OQ-2 being real, and on the user wanting CI to hold the secret key (a
   509	  security decision — may prefer manual signing on an air-gapped host).
   510	
   511	The two OPEN QUESTIONS are NOT blockers to Inc 1–3 landing as MECHANISM with
   512	placeholder keys + parametrised URLs; they ARE blockers to a real public
   513	release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
   514	the values are dropped in at engineer/release time.
   515	
   516	## 8. Risks & mitigations
   517	
   518	- **R1 — install.sh is the trust root over the network.** A compromised host
   519	  serving a bad install.sh defeats everything. Mitigation: publish install.sh
   520	  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
   521	  self-authenticating once install.sh runs); document a verify-before-run
   522	  variant (publish `install.sh.minisig` too, signed by the image key, so the
   523	  paranoid operator verifies install.sh with the SAME pinned pubkey they used
   524	  for the image). This closes the loop: ONE pinned pubkey authenticates both
   525	  the image and install.sh.
   526	- **R2 — key compromise / rotation.** OQ-2 owns the policy, but the mechanism
   527	  must not hardcode a single key. Mitigation: pubkey paths are overridable
   528	  (`XPF_IMAGE_PUBKEY`, apt `Signed-By` is a file), and the plan documents a
   529	  rotation runbook (publish new pubkey, dual-sign during overlap, retire old).
   530	- **R3 — apt repo correctness (stale Packages index, missing arch).** The flat
   531	  default uses `apt-ftparchive` (a maintained tool that owns index generation —
   532	  NOT ad-hoc scanning); reprepro is the opt-in for persistent publishers. Either
   533	  way, a negative test (tampered `Release` must fail apt) is the gate. (NOTE:
   534	  this is the FLAT-default path of §4B — earlier r1 prose that said "use
   535	  reprepro" is superseded.)
   536	- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
   537	  may not be installed. Mitigation: `require()`-style preflight in the new
   538	  scripts with an apt-install hint (matches bake.py's existing `require`
   539	  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
   540	  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
   541	  warning, same posture as `--skip-validate`).
   542	- **R5 — mgmt cut-off on bare-metal apt install.** #1879's interface-takeover
   543	  hazard applies harder to `apt install xpf-appliance` on a remote box than to
   544	  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
   545	  a config that takes over interfaces; the package's first-boot/day-0 contract
   546	  (already built in #1879/#1917) governs safe bootstrap. (This is a
   547	  documentation + sequencing mitigation; no new safe-bootstrap code is in
   548	  scope for #1924 — it was #1879's deliverable.)
   549	- **R6 — two keys confuse operators.** Mitigation: docs/distribution.md has a
   550	  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
   551	  archive, PGP), each with its fingerprint and pin location. The single-tool
   552	  §4A-alt remains the fallback if the user wants exactly one identity.
   553	
   554	## 9. Open questions (engineer-time inputs — NOT blockers to PLAN-READY)
   555	
   556	- **OQ-1 (hosting target):** the values of `XPF_IMAGE_BASE_URL` (images +
   557	  install.sh + latest.json) and `XPF_APT_BASE_URL` (the dists/+pool/ tree — NOT
   558	  GitHub Releases; needs a directory-serving host), the channel layout (which
   559	  suites exist), and the retention policy. Mechanism treats it as
   560	  a parameter; the user supplies the URL + picks GitHub Releases / bucket /

exec
/bin/bash -lc "rg -n 'N1|N2|N3|N4|N5|NIT|AGY|XPF_IMAGE_BASE_URL|XPF_APT_BASE_URL|PREFLIGHT|latest\\.json|reprepro|flat signed|flat repo|sha256sum -c|code fence|debian/install|archive-keyring|install\\.sh|minisig|GitHub Releases|XPF_DIST_BASE_URL|XPF_PUBLISH_CMD' docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
5:> PLAN-NEEDS-MAJOR + AGY PLAN-READY-WITH-NITS). r3 resolves the r2-introduced
6:> contradictions (N1–N5) + the key-rotation lockout (NIT-2). Change logs §12.
20:  has no cryptographic proof of origin — `sha256sum -c` only proves the file
31:  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
52:These are surfaced as config inputs — `XPF_IMAGE_BASE_URL` + `XPF_APT_BASE_URL`
53:(§3 N4 two-URL split) and a checked-in public key file + `XPF_SIGN_SECKEY`
55:"XPF_DIST_BASE_URL" mean whichever of the two URLs serves the artifact in
68:| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
69:| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
70:| Packaged archive keyring (r3 NIT-2) | NEW (one `debian/install` line, no postinst logic) | ships `xpf-archive-keyring.asc` to `/etc/apt/keyrings/` so existing hosts get rotated keys via `apt upgrade` |
89:3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
94:**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
99:`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
105:**r3 (resolves N4) — TWO base URLs, not one.** Images and the apt pool have
107:- `XPF_IMAGE_BASE_URL` (OQ-1a): serves the image artifacts + sigs +
108:  `latest.json` + `install.sh`. Satisfiable by ANY static host INCLUDING
109:  GitHub Releases (flat assets are fine for images).
110:- `XPF_APT_BASE_URL` (OQ-1b): serves the `dists/`+`pool/` tree. Requires a
112:  Releases CANNOT serve this** (flat assets only). install.sh writes
113:  `URIs: <XPF_APT_BASE_URL>`.
116:`XPF_PUBLISH_CMD`). The mechanism is host-agnostic per URL.
129:The `install.sh` bootstrap is the ONLY moment trust is established over the
131:**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
133:install.sh's own integrity is therefore the bootstrap root. The minisign
136:GitHub — independent of `XPF_DIST_BASE_URL`**; the copy served from the dist
146:| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
147:| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
148:| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
152:- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
155:  call `minisign -V` directly — we are not constrained to apt's PGP.
157:  mandates it. This is unavoidable: apt will not trust a minisign signature.
159:This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
163:dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
164:the recommendation is the two-tool split because minisign's single-pubkey pin
165:is dramatically simpler to verify in install.sh and in our Python consumers.)
170:(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
171:with a keyring, which is heavier and more error-prone to pin than `minisign
180:| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
182:| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |
184:**Recommendation (r2 REVISED — resolves AGY-MEDIUM-2):** the choice now
186:prescribing reprepro unconditionally:
188:  releases): reprepro.** Smallest mature tool, signed `Release`/`InRelease`,
192:  flat signed repo** generated from scratch via `apt-ftparchive` /
197:  `db/` is destroyed (AGY-MEDIUM-2).
201:**Default recommendation: the flat signed repo**, because it is robust to BOTH
203:reprepro only if the publisher is known-persistent and the operator prefers its
205:signed `InRelease`), so the install.sh side is unaffected by the choice.
212:Channel layout (deb822, the contract install.sh writes):
216:  URIs: <XPF_APT_BASE_URL>             # OQ-1b (dists/+pool/ tree)
220:  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
223:### 4C. install.sh trust-bootstrap (the security-critical step)
227:| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
228:| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
232:install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
233:through apt's own signed `Release`. The keyring-in-install.sh means there is
234:exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
235:and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
238:from §3. The trust model is therefore precisely: *"an authentic install.sh
243:- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
244:  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
245:  Docker / rustup accept. The `.minisig` does NOT retroactively protect this
248:  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
249:  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
252:  release notes, NEVER from `XPF_DIST_BASE_URL`."
258:| **GitHub Releases** (per-tag assets) | free, TLS, no infra, matches `gh release`; the repo is already on GitHub | not an apt repo by itself (need GitHub Pages or a bucket for the apt pool); release assets are per-tag not channel-stable URLs |
263:release upload`s the image tree (images + sigs + `latest.json` + install.sh) to
264:`XPF_IMAGE_BASE_URL` and the flat `apt/` pool tree to `XPF_APT_BASE_URL` (§3 N4
265:two-URL split). The plan provides a pluggable `XPF_PUBLISH_CMD` so the user
274:**r2 change (resolves Codex-3 retention + AGY-HIGH-1 partial-download +
280:dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
284:minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
285:         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
293:  can verify it without the metadata present (AGY-HIGH-1).
301:  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
302:  NEVER the root** (SMR-F1, Codex-6, AGY-MEDIUM-1).
306:**r2 change (resolves SMR-F3 + Codex-1 + AGY-HIGH-1):** the verifier does NOT
307:run a cwd-relative `sha256sum -c`. It:
308:1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
317:Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
320:- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
322:- **r3 (resolves N1) — image verify lives at IMPORT time, not alias-launch.**
332:     `XPF_IMAGE_BASE_URL`, verifies the EXACT downloaded file, then imports it
340:Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
341:- Inputs: the existing pool (synced down from `XPF_APT_BASE_URL` if present),
348:- reprepro path (opt-in `XPF_APT_TOOL=reprepro`): `conf/distributions` with
350:  `SignWith: <KEYID>`; `reprepro includedeb <suite> …`.
352:- **r2 GitHub-Releases caveat (AGY-MEDIUM-3):** if OQ-1 = GitHub Releases, a
358:### 5.4 install.sh (NEW)
360:1. PREFLIGHT (r3 N5): refuse non-amd64 / non-Debian-family / kernel <6.18 /
363:   xpf-archive-keyring.asc` (embedded inline, `0644`).
365:   `XPF_APT_BASE_URL` substituted; default channel `stable`,
369:**r3 (resolves NIT-2) — the archive keyring also ships in the PACKAGE payload.**
370:install.sh's inline keyring bootstraps NEW hosts, but existing hosts never
371:re-run install.sh, so a key rotation would lock them out of `apt update` once
373:package-owned conffile at `/etc/apt/keyrings/xpf-archive-keyring.asc` (in the
377:`debian/` — a packaged keyring file + its `debian/install` line; no postinst
382:- `install.sh` is itself published at `XPF_IMAGE_BASE_URL/install.sh` and the
385:**r2 (resolves AGY-HIGH-2) — apt UPGRADE inherits #1917's postinst cut-over.**
386:install.sh's FIRST install is safe (no running daemon to cut). But a later
406:  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
408:  runs a PRECONDITION gate before invoking `XPF_PUBLISH_CMD`. It REFUSES (exit
410:  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
412:  (c) `install.sh.minisig` verifies (if install.sh is in the set); **(d) r3
413:  (resolves N2): the per-channel `latest.json` verifies against the image pubkey
418:- **r2 `XPF_PUBLISH_CMD` contract (resolves SMR-F5):** invoked exactly as
419:  `$XPF_PUBLISH_CMD <local-dist-dir> <dest-base-url>`; called once per URL
420:  (image tree → `XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`); idempotent
425:  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
428:  verify from `XPF_DIST_BASE_URL`"; document the per-version
429:  `xpf-<ver>.SHA256SUMS.minisig`.
436:  sets it explicitly; reprepro via `conf/distributions` `ValidFor`). apt warns/
438:  re-signed each publish. **r3 (resolves NIT-1): with MANUAL/air-gap signing
444:- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
446:  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
448:  fetches the named version. **r3 (resolves NIT-3): the watermark is persisted
451:  BEST-EFFORT (a fresh workstation has no watermark and trusts latest.json's
463:   `xpf-<ver>.SHA256SUMS`) → sign with a throwaway minisign key →
465:   the parsed-hash comparison (§5.2); flip the `.minisig` → verify FAILS at
466:   `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
469:   container (or the local incus image flow) → run install.sh pointed at a
473:3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
482:   update` fail; `latest.json` older than the remembered version is rejected by
497:- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
501:  FLAT signed repo default per §4B, reprepro opt-in via `XPF_APT_TOOL`;
504:- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
505:  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
518:- **R1 — install.sh is the trust root over the network.** A compromised host
519:  serving a bad install.sh defeats everything. Mitigation: publish install.sh
521:  self-authenticating once install.sh runs); document a verify-before-run
522:  variant (publish `install.sh.minisig` too, signed by the image key, so the
523:  paranoid operator verifies install.sh with the SAME pinned pubkey they used
525:  the image and install.sh.
532:  NOT ad-hoc scanning); reprepro is the opt-in for persistent publishers. Either
535:  reprepro" is superseded.)
536:- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
539:  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
544:  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
550:  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
556:- **OQ-1 (hosting target):** the values of `XPF_IMAGE_BASE_URL` (images +
557:  install.sh + latest.json) and `XPF_APT_BASE_URL` (the dists/+pool/ tree — NOT
558:  GitHub Releases; needs a directory-serving host), the channel layout (which
560:  a parameter; the user supplies the URL + picks GitHub Releases / bucket /
562:- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
566:- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
579:a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
584:- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
586:- Apt: **flat signed repo** (default, stateless-CI-safe; reprepro opt-in for
589:  shipped BOTH inline in install.sh (new installs) AND in the package payload
590:  (`/etc/apt/keyrings/xpf-archive-keyring.asc`) so existing hosts get rotated
591:  keys via `apt upgrade` (NIT-2).
592:- Bootstrap: **install.sh** with the archive keyring embedded inline +
593:  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
594:- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
595:  `XPF_IMAGE_BASE_URL` / `XPF_APT_BASE_URL`. No backend hardcoded.
606:All three r1 reviewers returned **PLAN-NEEDS-MAJOR** (Codex, AGY, Claude SMR).
611:| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
612:| Partial download (libvirt fetches only qcow2) crashes `sha256sum -c` on missing metadata | AGY-HIGH-1 | §5.1/§5.2: per-file verification; missing-but-unfetched files are not checked. |
613:| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
614:| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
617:| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
618:| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
619:| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
620:| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
621:| GitHub Releases can't host a `dists/`+`pool/` tree | AGY-MEDIUM-3 | §5.3: flagged as an OQ-1 constraint (Pages/bucket needed for the pool). |
622:| OQ coupling = hidden blockers? | AGY-MEDIUM-3 | §9: confirmed engineer-time inputs; every §5 mechanism runs with placeholder key + parametrised URL. |
623:| `XPF_PUBLISH_CMD` under-specified | SMR-F5 | §5.5: exact contract `$CMD <dist-dir> <base-url>`, idempotent. |
624:| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |
627:AGY-HIGH-2 (postinst cut-over is #1917's reviewed mechanism) and the
628:single-tool §4A-alt (kept as the user's OQ-3 fallback). The minisign(image) +
635:PLAN-NEEDS-MAJOR (same 5 + elevate NIT-2), AGY PLAN-READY-WITH-NITS (3 nits).
641:| N1 — xpf-deploy.py can't bind image bytes (incus alias-launch flow has no qcow2 path) | Codex-1, SMR-N1 | §5.2: image verify lives at IMPORT (validate.py) + a NEW `xpf-deploy.py fetch`/`--image-url`; the alias-launch path no longer claims to verify. |
642:| N2 — fail-closed publish omits the freshness `latest.json` | Codex-2, SMR-N2 | §5.5 gate clause (d): `latest.json` must verify AND name a version in the publish set. |
643:| N3 — apt backend self-contradiction (flat-default vs §8/§11 "use reprepro") | Codex-3, SMR-N3 | §8 R3 + §11 summary rewritten to flat-default (`apt-ftparchive`), reprepro opt-in; Inc-2 wording fixed. |
644:| N4 — GitHub Releases listed as a full hosting target but can't serve dists/pool | Codex-4, SMR-N4 | §3: TWO base URLs — `XPF_IMAGE_BASE_URL` (GH Releases OK) vs `XPF_APT_BASE_URL` (directory host required); §9 OQ-1 + all functional refs split. |
645:| N5 — "fresh Debian/Ubuntu host" overpromise (kernel ≥6.18 floor) | Codex-5, SMR-N5 | §3 + §5.4: install.sh PREFLIGHT refuses kernel <6.18 / non-amd64 / no-networkd with a clear message; image stays the turnkey path. |
646:| NIT-2 — key rotation strands existing hosts (inline-only keyring) | AGY-NIT-2, SMR (elevated) | §5.4 + §2 + §11: archive keyring ALSO ships in the package payload (`/etc/apt/keyrings/`), so `apt upgrade` delivers rotated keys during the dual-sign window. One `debian/install` line, no postinst logic. |
647:| NIT-1 — Valid-Until vs manual signing expiry deadlock | AGY-NIT-1, SMR | §5.6: long default `Valid-Until` (1y, `XPF_APT_VALID_DAYS`) for manual cadence; short window requires an automated re-sign job. |
648:| NIT-3 — monotonic freshness watermark has no storage | AGY-NIT-3, SMR | §5.6: watermark at `${XDG_STATE_HOME}/xpf/image-watermark.json`; documented best-effort for stateless/multi-operator CLI. |
649:| Nit — §6 "fails at sha256sum -c" stale vs parsed verifier | Codex nit | §6 test 1 reworded to the parsed-hash comparison. |
650:| Nit — stray code fence before §12 | Codex nit | Removed. |
652:Affirmed unchanged across all rounds: minisign(image) + PGP(apt) split, deb822
654:`debian/` touch in #1924 scope is the packaged keyring conffile (NIT-2); no
655:postinst / `pkg/upgrade` code (AGY-HIGH-2 confirmed #1917-owned, documentation

exec
/bin/bash -lc "nl -ba scripts/deploy/xpf-deploy.py | sed -n '260,620p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   260	def pci_parts(addr):
   261	    m = re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", addr)
   262	    if not m:
   263	        die(f"pci address '{addr}' is not DDDD:BB:DD.F")
   264	    return {"domain": "0x" + m.group(1), "bus": "0x" + m.group(2),
   265	            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}
   266	
   267	
   268	class Runner:
   269	    def __init__(self, dry):
   270	        self.dry = dry
   271	
   272	    def run(self, argv):
   273	        if self.dry:
   274	            print(" ".join(shlex.quote(a) for a in argv))
   275	            return ""
   276	        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
   277	
   278	
   279	# ── deploy backends ───────────────────────────────────────────────────
   280	def print_map(ap):
   281	    tag = ap["mode"] + (f" node {ap['node_id']}" if ap["mode"] == "cluster" else "")
   282	    print(f"==> {ap['name']}: {tag}, {len(ap['interfaces'])} NICs")
   283	    for i, ic in enumerate(ap["interfaces"]):
   284	        print(f"      pos {i + 1}: {ic['_name']:<10} <- {ic['backing']}:{ic['source']}")
   285	
   286	
   287	def deploy_incus(ap, runner, start):
   288	    name = ap["name"]
   289	    print_map(ap)
   290	    iso = build_config_drive(ap, runner)
   291	    # --no-profiles: the default profile usually carries an `eth0` NIC,
   292	    # which would be an extra virtio device the guest names positionally
   293	    # alongside the declared dev00.. — a phantom interface that pollutes
   294	    # the NIC->name map. Suppress all profile devices and provide the root
   295	    # disk explicitly from the storage pool (default "default", override
   296	    # with `pool:` in YAML) so the device set is EXACTLY the declared NICs.
   297	    pool = ap.get("pool", "default")
   298	    # incus -d sets ONE key=value per flag (<device>,<key>=<value>), so the
   299	    # root disk needs three -d flags, not one comma-joined value.
   300	    runner.run(["incus", "init", ap["image"], name, "--vm", "--no-profiles",
   301	                "-c", f"limits.cpu={ap['cpu']}", "-c", f"limits.memory={ap['memory']}",
   302	                "-d", "root,type=disk", "-d", f"root,pool={pool}", "-d", "root,path=/"])
   303	    pins = []
   304	    for i, ic in enumerate(ap["interfaces"]):
   305	        dev = f"dev{i:02d}"
   306	        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
   307	        if b == "net":
   308	            args = ["nic", f"network={src}"]
   309	        elif b == "bridge":
   310	            args = ["nic", "nictype=bridged", f"parent={src}"]
   311	        elif b == "macvlan":
   312	            args = ["nic", "nictype=macvlan", f"parent={src}"]
   313	        elif b == "sriov":
   314	            args = ["nic", "nictype=sriov", f"parent={src}"]
   315	        elif b == "physical":
   316	            args = ["nic", "nictype=physical", f"parent={src}"]
   317	        elif b == "pci":
   318	            args = ["pci", f"address={src}"]
   319	        if mac and b in ("net", "bridge", "macvlan", "sriov"):
   320	            args.append(f"hwaddr={mac}")
   321	        if mac and b == "pci":
   322	            par = None if runner.dry else vf_parent(src)
   323	            if par:
   324	                pins.append(["sudo", "ip", "link", "set", "dev", par[0], "vf", par[1], "mac", mac])
   325	            elif runner.dry:
   326	                print(f"      (dry-run) would pin VF MAC for pci:{src}")
   327	            else:
   328	                die(f"pci:{src} with mac= is not an SR-IOV VF here (drop mac= for whole-PF)")
   329	        runner.run(["incus", "config", "device", "add", name, dev] + args)
   330	    if iso:
   331	        runner.run(["incus", "config", "device", "add", name, "day0", "disk", f"source={iso}"])
   332	    for pin in pins:
   333	        runner.run(["sudo", "ip", "link", "set", "dev", pin[5], "up"])
   334	        print(f"==> pinning VF MAC: {' '.join(pin)}")
   335	        runner.run(pin)
   336	    if start:
   337	        runner.run(["incus", "start", name])
   338	        print(f"\n{name} launched. Verify the NIC->name map:\n"
   339	              f"  incus exec {name} -- cli -c \"show interfaces terse\"")
   340	    else:
   341	        print(f"{name} created (not started): incus start {name}")
   342	
   343	
   344	def deploy_libvirt(ap, runner, start):
   345	    name = ap["name"]
   346	    print_map(ap)
   347	    iso = build_config_drive(ap, runner)
   348	    argv = ["virt-install", "--name", name, "--memory", str(memory_mb(ap["memory"])),
   349	            "--vcpus", str(ap["cpu"]), "--import",
   350	            "--disk", f"path=/var/lib/libvirt/images/{ap['image']}.qcow2",
   351	            "--osinfo", "ubuntu26.04", "--noautoconsole"]
   352	    if iso:
   353	        argv += ["--disk", f"path={iso},device=cdrom"]
   354	    notes = []
   355	    for ic in ap["interfaces"]:
   356	        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
   357	        if b in ("net", "bridge"):
   358	            net = f"{'network' if b == 'net' else 'bridge'}={src},model=virtio"
   359	            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
   360	        elif b == "macvlan":
   361	            net = f"type=direct,source={src},source_mode=bridge,model=virtio"
   362	            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
   363	        elif b == "physical":
   364	            argv += ["--hostdev", src]
   365	        elif b == "pci":
   366	            if mac:
   367	                p = pci_parts(src)
   368	                argv += ["--network",
   369	                         "type=hostdev,source.address.type=pci,"
   370	                         f"source.address.domain={p['domain']},source.address.bus={p['bus']},"
   371	                         f"source.address.slot={p['slot']},source.address.function={p['function']},"
   372	                         f"mac.address={mac}"]
   373	            else:
   374	                argv += ["--hostdev", src]
   375	        elif b == "sriov":
   376	            pool = f"{src}-vfpool"
   377	            argv += ["--network", f"network={pool}" + (f",mac.address={mac}" if mac else "")]
   378	            notes.append(f"sriov:{src} -> libvirt VF pool '{pool}'. Define once:\n"
   379	                         f"      <network><name>{pool}</name>"
   380	                         f"<forward mode='hostdev' managed='yes'><pf dev='{src}'/></forward></network>\n"
   381	                         f"      virsh net-define <f> && virsh net-start {pool} && virsh net-autostart {pool}")
   382	    print("# virt-install — NIC order = guest PCI-slot order = positional names.")
   383	    for n in notes:
   384	        print(f"# NOTE: {n}")
   385	    runner.run(argv)
   386	    if start:
   387	        print(f"\n{name}: verify with `virsh console {name}` then "
   388	              f"`cli -c \"show interfaces terse\"`.")
   389	
   390	
   391	def deploy(ap, args):
   392	    runner = Runner(args.dry_run)
   393	    if args.image:
   394	        ap["image"] = args.image
   395	    (deploy_incus if args.hypervisor == "incus" else deploy_libvirt)(
   396	        ap, runner, not args.no_start)
   397	
   398	
   399	# ── subcommands ───────────────────────────────────────────────────────
   400	def cmd_deploy(args):
   401	    if not args.yamls:
   402	        die("deploy needs at least one YAML file")
   403	    for path in args.yamls:
   404	        deploy(load_yaml_appliance(path), args)
   405	    return 0
   406	
   407	
   408	def cmd_launch(args):
   409	    ifaces = []
   410	    for spec in args.nic:
   411	        kind, _, rest = spec.partition(":")
   412	        if not rest:
   413	            kind, rest = "net", spec
   414	        src, _, tail = rest.partition(",")
   415	        mac = None
   416	        m = re.search(r"mac=([^,]+)", tail)
   417	        if m:
   418	            mac = m.group(1)
   419	        ic = {"backing": kind, "source": src}
   420	        if mac:
   421	            ic["mac"] = mac
   422	        ifaces.append(ic)
   423	    ap = {"name": args.name, "mode": args.mode, "node_id": args.node_id,
   424	          "image": args.image or "xpf-appliance", "cpu": args.cpu,
   425	          "memory": args.mem, "config": args.config, "interfaces": ifaces,
   426	          "base_dir": os.getcwd()}
   427	    validate_appliance(ap, "launch")
   428	    deploy(ap, args)
   429	    return 0
   430	
   431	
   432	def main():
   433	    argv = sys.argv[1:]
   434	    if "-h" in argv or "--help" in argv or not argv:
   435	        print(__doc__)
   436	        return 0 if ("-h" in argv or "--help" in argv) else 2
   437	
   438	    # Peel the global options from ANYWHERE on the command line with a
   439	    # globals-only pre-parser. parse_known_args picks up --dry-run /
   440	    # --hypervisor / --no-start / --image whether they appear before or
   441	    # after the subcommand, and (critically) it CONSUMES their values, so
   442	    # an option value can never be mistaken for the subcommand token.
   443	    g = argparse.ArgumentParser(add_help=False)
   444	    g.add_argument("--dry-run", action="store_true")
   445	    g.add_argument("--hypervisor", default="incus", choices=["incus", "libvirt"])
   446	    g.add_argument("--no-start", action="store_true")
   447	    g.add_argument("--image")
   448	    gargs, rest = g.parse_known_args(argv)
   449	
   450	    # `rest` now holds only the subcommand + its own args. The first token
   451	    # is the subcommand; if it isn't one, treat the whole of `rest` as
   452	    # YAML files for `deploy` (the bare-`xpf-deploy.py foo.yaml` shorthand).
   453	    if rest and rest[0] in ("deploy", "launch", "inventory"):
   454	        cmd, cmd_argv = rest[0], rest[1:]
   455	    else:
   456	        cmd, cmd_argv = "deploy", rest
   457	
   458	    if cmd == "inventory":
   459	        sub = argparse.ArgumentParser(prog="xpf-deploy.py inventory", add_help=False)
   460	        args = sub.parse_args(cmd_argv)
   461	    elif cmd == "launch":
   462	        sub = argparse.ArgumentParser(prog="xpf-deploy.py launch", add_help=False)
   463	        sub.add_argument("--name", required=True)
   464	        sub.add_argument("--mode", default="standalone", choices=["standalone", "cluster"])
   465	        sub.add_argument("--node-id", type=int, dest="node_id")
   466	        sub.add_argument("--cpu", type=int, default=4)
   467	        sub.add_argument("--mem", default="4GiB")
   468	        sub.add_argument("--config")
   469	        sub.add_argument("--nic", action="append", default=[])
   470	        args = sub.parse_args(cmd_argv)
   471	    else:  # deploy
   472	        sub = argparse.ArgumentParser(prog="xpf-deploy.py deploy", add_help=False)
   473	        sub.add_argument("yamls", nargs="*")
   474	        args = sub.parse_args(cmd_argv)
   475	
   476	    # Fold the peeled globals into the namespace the command handlers read.
   477	    args.cmd = cmd
   478	    args.dry_run = gargs.dry_run
   479	    args.hypervisor = gargs.hypervisor
   480	    args.no_start = gargs.no_start
   481	    args.image = gargs.image
   482	
   483	    if cmd == "inventory":
   484	        return cmd_inventory(args)
   485	    if cmd == "launch":
   486	        return cmd_launch(args)
   487	    return cmd_deploy(args)
   488	
   489	
   490	if __name__ == "__main__":
   491	    sys.exit(main())

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '561,920p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   561	  self-host at `/engineer`/release time.
   562	- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
   563	  archive key (apt), who holds the secret keys, rotation cadence, and where the
   564	  public keys are pinned/published. Mechanism ships placeholder pubkeys + reads
   565	  the secret-key PATH from env; the user supplies real keys at release time.
   566	- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
   567	  is the PGP-only single-identity fallback. The user MAY collapse to one PGP
   568	  identity if they prefer one key to manage — flag for the user, default is the
   569	  two-tool split.
   570	- **OQ-4 (CI signing):** does the secret key live in CI (automated release) or
   571	  on an air-gapped host (manual sign+publish)? Drives whether Inc 4 ships. A
   572	  security posture choice; default assumption is manual until the user opts in.
   573	
   574	## 10. Why not just keep SHA256SUMS?
   575	
   576	A plain checksum file proves integrity against accidental corruption, not
   577	authenticity against an adversary. The issue's explicit goal is "a TRUSTED,
   578	SIGNED source." Without a signature, any party who can serve the file can serve
   579	a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
   580	is the usability bar (the issue's "rather than copying files by hand").
   581	
   582	## 11. Recommendation summary
   583	
   584	- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
   585	  in validate.py + xpf-deploy.py. Additive to bake.py.
   586	- Apt: **flat signed repo** (default, stateless-CI-safe; reprepro opt-in for
   587	  persistent publishers) with PGP-signed `InRelease`/`Release`, `stable`/`edge`
   588	  suites, deb822 `Signed-By`, `Valid-Until` freshness. The archive keyring is
   589	  shipped BOTH inline in install.sh (new installs) AND in the package payload
   590	  (`/etc/apt/keyrings/xpf-archive-keyring.asc`) so existing hosts get rotated
   591	  keys via `apt upgrade` (NIT-2).
   592	- Bootstrap: **install.sh** with the archive keyring embedded inline +
   593	  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
   594	- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
   595	  `XPF_IMAGE_BASE_URL` / `XPF_APT_BASE_URL`. No backend hardcoded.
   596	- Ship as Inc 1–3 (each independently reviewable); Inc 4 (CI release) is
   597	  optional + gated on OQ-1/OQ-2/OQ-4.
   598	- The two OPEN QUESTIONS (hosting target, signing identity) are engineer-time
   599	  inputs, not PLAN-READY blockers; the mechanism is complete pending only their
   600	  values.
   601	
   602	## 12. Change logs (response to hostile review)
   603	
   604	### 12a. r1 → r2
   605	
   606	All three r1 reviewers returned **PLAN-NEEDS-MAJOR** (Codex, AGY, Claude SMR).
   607	The convergent + unique findings and their resolutions:
   608	
   609	| Finding | Source(s) | Resolution in r2 |
   610	|---|---|---|
   611	| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
   612	| Partial download (libvirt fetches only qcow2) crashes `sha256sum -c` on missing metadata | AGY-HIGH-1 | §5.1/§5.2: per-file verification; missing-but-unfetched files are not checked. |
   613	| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
   614	| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
   615	| `curl \| sh` honest trust level | SMR-F2 | §4C: Tier A = TLS + first-fetch trust (same as Tailscale/Docker/rustup), stated plainly. |
   616	| Publish not fail-closed (unsigned dev bake can ship) | Codex-2, SMR-F6 | §5.5: `make dist-publish` precondition gate refuses unsigned artifacts. |
   617	| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
   618	| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
   619	| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
   620	| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
   621	| GitHub Releases can't host a `dists/`+`pool/` tree | AGY-MEDIUM-3 | §5.3: flagged as an OQ-1 constraint (Pages/bucket needed for the pool). |
   622	| OQ coupling = hidden blockers? | AGY-MEDIUM-3 | §9: confirmed engineer-time inputs; every §5 mechanism runs with placeholder key + parametrised URL. |
   623	| `XPF_PUBLISH_CMD` under-specified | SMR-F5 | §5.5: exact contract `$CMD <dist-dir> <base-url>`, idempotent. |
   624	| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |
   625	
   626	Two findings examined and held as documentation-only (not #1924 code scope):
   627	AGY-HIGH-2 (postinst cut-over is #1917's reviewed mechanism) and the
   628	single-tool §4A-alt (kept as the user's OQ-3 fallback). The minisign(image) +
   629	PGP(apt) split, deb822 `Signed-By`, and TOFU-rejection were affirmed by all
   630	three reviewers as correct and are unchanged.
   631	
   632	### 12b. r2 → r3
   633	
   634	r2 verdicts: Codex PLAN-NEEDS-MAJOR (5 contract contradictions), Claude SMR
   635	PLAN-NEEDS-MAJOR (same 5 + elevate NIT-2), AGY PLAN-READY-WITH-NITS (3 nits).
   636	All r1 findings were confirmed RESOLVED by all three; r3 fixes the contradictions
   637	the r2 restructuring introduced + the rotation lockout.
   638	
   639	| Finding | Source(s) | Resolution in r3 |
   640	|---|---|---|
   641	| N1 — xpf-deploy.py can't bind image bytes (incus alias-launch flow has no qcow2 path) | Codex-1, SMR-N1 | §5.2: image verify lives at IMPORT (validate.py) + a NEW `xpf-deploy.py fetch`/`--image-url`; the alias-launch path no longer claims to verify. |
   642	| N2 — fail-closed publish omits the freshness `latest.json` | Codex-2, SMR-N2 | §5.5 gate clause (d): `latest.json` must verify AND name a version in the publish set. |
   643	| N3 — apt backend self-contradiction (flat-default vs §8/§11 "use reprepro") | Codex-3, SMR-N3 | §8 R3 + §11 summary rewritten to flat-default (`apt-ftparchive`), reprepro opt-in; Inc-2 wording fixed. |
   644	| N4 — GitHub Releases listed as a full hosting target but can't serve dists/pool | Codex-4, SMR-N4 | §3: TWO base URLs — `XPF_IMAGE_BASE_URL` (GH Releases OK) vs `XPF_APT_BASE_URL` (directory host required); §9 OQ-1 + all functional refs split. |
   645	| N5 — "fresh Debian/Ubuntu host" overpromise (kernel ≥6.18 floor) | Codex-5, SMR-N5 | §3 + §5.4: install.sh PREFLIGHT refuses kernel <6.18 / non-amd64 / no-networkd with a clear message; image stays the turnkey path. |
   646	| NIT-2 — key rotation strands existing hosts (inline-only keyring) | AGY-NIT-2, SMR (elevated) | §5.4 + §2 + §11: archive keyring ALSO ships in the package payload (`/etc/apt/keyrings/`), so `apt upgrade` delivers rotated keys during the dual-sign window. One `debian/install` line, no postinst logic. |
   647	| NIT-1 — Valid-Until vs manual signing expiry deadlock | AGY-NIT-1, SMR | §5.6: long default `Valid-Until` (1y, `XPF_APT_VALID_DAYS`) for manual cadence; short window requires an automated re-sign job. |
   648	| NIT-3 — monotonic freshness watermark has no storage | AGY-NIT-3, SMR | §5.6: watermark at `${XDG_STATE_HOME}/xpf/image-watermark.json`; documented best-effort for stateless/multi-operator CLI. |
   649	| Nit — §6 "fails at sha256sum -c" stale vs parsed verifier | Codex nit | §6 test 1 reworded to the parsed-hash comparison. |
   650	| Nit — stray code fence before §12 | Codex nit | Removed. |
   651	
   652	Affirmed unchanged across all rounds: minisign(image) + PGP(apt) split, deb822
   653	`Signed-By` (not apt-key), TOFU rejection, the additive blast radius. The only
   654	`debian/` touch in #1924 scope is the packaged keyring conffile (NIT-2); no
   655	postinst / `pkg/upgrade` code (AGY-HIGH-2 confirmed #1917-owned, documentation
   656	only).

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# Plan of action — #1924: signed, hosted appliance distribution
     2	
     3	> Revision: r3 (2026-06-16)
     4	> Status: REVISED after r2 review (Codex PLAN-NEEDS-MAJOR + Claude SMR
     5	> PLAN-NEEDS-MAJOR + AGY PLAN-READY-WITH-NITS). r3 resolves the r2-introduced
     6	> contradictions (N1–N5) + the key-rotation lockout (NIT-2). Change logs §12.
     7	> Branch: research/1924-signed-hosted-dist
     8	> Mode: `/research` convergence; implementation begins only on the user's own
     9	> `/engineer 1924`. No production source touched in this doc.
    10	
    11	## 1. Problem statement
    12	
    13	Follow-up from #1879 / PR #1906 (appliance images, Path C) and #1917/#1923
    14	(the `xpf` / `xpf-appliance` `.deb` + `make deb` + bake-installs-the-deb).
    15	Today the distribution story stops at "build the artifacts locally":
    16	
    17	- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
    18	  (plain sha256 of the qcow2 + incus metadata) and a `dist/xpf-<ver>.manifest`
    19	  (provenance text). Neither is signed. An operator who downloads the image
    20	  has no cryptographic proof of origin — `sha256sum -c` only proves the file
    21	  matches a checksum file that itself is unauthenticated. A MITM or a
    22	  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
    23	- **No published distribution channel.** `make deb` writes to `dist/deb/`;
    24	  `make image` writes to `dist/`. There is no hosted location, no retention
    25	  policy, no stable/edge channel layout. The CLAUDE.md "Quick Start" and
    26	  `docs/install-images.md` assume the operator builds locally or copies
    27	  files by hand.
    28	- **No `apt` path.** The `xpf-appliance` metapackage (debian/control) is
    29	  explicitly designed as "the operator-facing entry point: `apt install
    30	  xpf-appliance` … e.g. from a hosted apt repo" — but no such repo exists.
    31	  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
    32	- **No verification on the consumer side.** `scripts/deploy/xpf-deploy.py`
    33	  and `scripts/image/validate.py` consume `--qcow2 … --metadata …` paths
    34	  directly with no signature import or check; `build_config_drive` in
    35	  xpf-deploy.py validates the day-0 *config*, not the *image*.
    36	
    37	Goal (issue): an operator fetches + verifies the appliance image and the
    38	packages from a trusted, signed source instead of copying files by hand.
    39	
    40	### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)
    41	
    42	This plan deliberately does NOT invent answers to two inputs that are
    43	operator/infra/security decisions. The mechanism is designed so both are
    44	**config inputs**, not hardcoded constants, so the plan converges PLAN-READY
    45	pending only these two engineer-time values:
    46	
    47	- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
    48	  repo host), the retention policy, and the channel layout (stable / edge).
    49	- **OQ-2 — Signing identity.** WHICH signing key, and key management: who
    50	  holds the secret key, rotation cadence, and where the public key is pinned.
    51	
    52	These are surfaced as config inputs — `XPF_IMAGE_BASE_URL` + `XPF_APT_BASE_URL`
    53	(§3 N4 two-URL split) and a checked-in public key file + `XPF_SIGN_SECKEY`
    54	(path, never the key itself). See §9. (References below to "the dist host" /
    55	"XPF_DIST_BASE_URL" mean whichever of the two URLs serves the artifact in
    56	question — the trust-model point is identical for both.)
    57	
    58	## 2. Blast radius / affected surface
    59	
    60	New work is almost entirely ADDITIVE — no production dataplane / control-plane
    61	source is touched. Surface:
    62	
    63	| Area | Change class | Files |
    64	|---|---|---|
    65	| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
    66	| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
    67	| `.deb` repo build tooling | NEW | `scripts/dist/` (repo builder + signer) |
    68	| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
    69	| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
    70	| Packaged archive keyring (r3 NIT-2) | NEW (one `debian/install` line, no postinst logic) | ships `xpf-archive-keyring.asc` to `/etc/apt/keyrings/` so existing hosts get rotated keys via `apt upgrade` |
    71	| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
    72	| Docs | extend / NEW | `docs/install-images.md`, NEW `docs/distribution.md` |
    73	| CI/release (optional) | NEW (deferrable) | `.github/workflows/release.yml` |
    74	
    75	Zero changes to: `pkg/**` (Go control plane), `userspace-dp/**` (Rust
    76	dataplane), `bpf/**`, the daemon, CLI, or the wire protocol. No smoke-test
    77	exposure on the loss cluster (no forwarding-path change). This is build/release
    78	plumbing.
    79	
    80	## 3. Design overview
    81	
    82	Three independent-but-coordinated mechanisms, each gated by a config input:
    83	
    84	1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
    85	   checksum manifest), so one signature transitively authenticates the qcow2 +
    86	   incus metadata. Verify on import in `validate.py` / `xpf-deploy.py`.
    87	2. **Build + sign an apt repo** for the `xpf` / `xpf-appliance` `.deb`s, so
    88	   `apt install xpf-appliance` works from a hosted, authenticated index.
    89	3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
    90	   ≥6.18 + systemd-networkd present), bootstraps trust (installs the archive
    91	   keyring), adds the apt source, and runs `apt install xpf-appliance` — one
    92	   command on a Debian/Ubuntu host **that already meets the kernel floor**.
    93	
    94	**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
    95	floor; it does NOT install a kernel.** The appliance's verifier floor is kernel
    96	≥6.18 + the mlx5/i40e driver set (the IMAGE owns that closure; `debian/control`
    97	states kernel handling is out of scope). A bare-metal `apt install
    98	xpf-appliance` on Debian 12 / Ubuntu 24.04 would install the packages but
    99	`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
   100	and REFUSES with a clear message ("xpf requires kernel ≥6.18 + native-XDP NIC;
   101	use the appliance image, or upgrade the host kernel") rather than leaving a
   102	broken install. The image (bake.py) remains the turnkey path for hosts that do
   103	not meet the floor.
   104	
   105	**r3 (resolves N4) — TWO base URLs, not one.** Images and the apt pool have
   106	different hosting shapes, so the mechanism takes two parameters:
   107	- `XPF_IMAGE_BASE_URL` (OQ-1a): serves the image artifacts + sigs +
   108	  `latest.json` + `install.sh`. Satisfiable by ANY static host INCLUDING
   109	  GitHub Releases (flat assets are fine for images).
   110	- `XPF_APT_BASE_URL` (OQ-1b): serves the `dists/`+`pool/` tree. Requires a
   111	  real directory-serving host (static bucket / Pages / file server) — **GitHub
   112	  Releases CANNOT serve this** (flat assets only). install.sh writes
   113	  `URIs: <XPF_APT_BASE_URL>`.
   114	They MAY be the same host (a bucket serves both); they need not be. Publishing
   115	is a thin `dist-publish` target parametrised by both (each fed to
   116	`XPF_PUBLISH_CMD`). The mechanism is host-agnostic per URL.
   117	
   118	### Trust model (the spine of the design)
   119	
   120	There are TWO distinct trust roots, and the plan keeps them clean:
   121	
   122	- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
   123	  PUBLIC key out-of-band ONCE (checked into the repo + published at a
   124	  well-known URL) and pins it. Every image download is verified against it.
   125	- **Apt trust** — the apt archive signing key. `apt` itself enforces this via
   126	  signed `Release`/`InRelease` once the archive keyring is installed under
   127	  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
   128	
   129	The `install.sh` bootstrap is the ONLY moment trust is established over the
   130	network, so it is the highest-risk step and gets the most scrutiny (§4C, §8).
   131	**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
   132	pin a fingerprint — those were mutually exclusive in r1; we picked inline).
   133	install.sh's own integrity is therefore the bootstrap root. The minisign
   134	**image** pubkey (`xpf-image.pub`) used for Tier-B verify-before-run has its
   135	root of trust in the **in-repo checked-in copy obtained via `git clone` /
   136	GitHub — independent of `XPF_DIST_BASE_URL`**; the copy served from the dist
   137	host is a convenience, NEVER the trust root (else verification is circular).
   138	Mitigations and the honest trust tiers are in §4C + §8.
   139	
   140	## 4. Multiple Path Options
   141	
   142	### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
   143	
   144	| Option | Pros | Cons |
   145	|---|---|---|
   146	| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
   147	| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
   148	| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
   149	| **cosign / sigstore** | keyless OIDC option, transparency log | requires Fulcio/Rekor infra or a static key; new dep; apt still needs PGP; over-engineered for a single-publisher appliance |
   150	
   151	**Recommendation (mechanism, value deferred to OQ-2):**
   152	- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
   153	  exactly the issue's lead, one pinned Ed25519 pubkey. The image consumer
   154	  (validate.py / xpf-deploy.py / operator) is a script we control, so it can
   155	  call `minisign -V` directly — we are not constrained to apt's PGP.
   156	- **Apt repo → OpenPGP** (`gpg`/`sequoia`) over `Release`, because apt
   157	  mandates it. This is unavoidable: apt will not trust a minisign signature.
   158	
   159	This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
   160	the apt archive. It is NOT redundancy — they authenticate different artifacts
   161	to different consumers (our scripts vs apt). Both public keys are checked into
   162	the repo and published. (An ALTERNATIVE single-tool variant — PGP for both,
   163	dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
   164	the recommendation is the two-tool split because minisign's single-pubkey pin
   165	is dramatically simpler to verify in install.sh and in our Python consumers.)
   166	
   167	#### 4A-alt. Single-tool (PGP-only) variant
   168	Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
   169	Pros: one key to manage (one OQ-2 answer), apt-native. Cons: image consumers
   170	(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
   171	with a keyring, which is heavier and more error-prone to pin than `minisign
   172	-V -p key.pub`; PGP's web-of-trust/expiry semantics add footguns for a
   173	single-publisher appliance. Kept as a fallback if the user prefers exactly one
   174	signing identity.
   175	
   176	### 4B. Apt repository tooling
   177	
   178	| Option | Pros | Cons |
   179	|---|---|---|
   180	| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
   181	| **aptly** | snapshots, multi-version, mirroring, publish to S3 natively, channels (stable/edge) map to "distributions" cleanly | larger, its own DB, more moving parts than we need for one package |
   182	| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |
   183	
   184	**Recommendation (r2 REVISED — resolves AGY-MEDIUM-2):** the choice now
   185	DEPENDS on the publish model (OQ-1), and the plan says so instead of
   186	prescribing reprepro unconditionally:
   187	- **Stateful publisher (a persistent host/bucket that survives between
   188	  releases): reprepro.** Smallest mature tool, signed `Release`/`InRelease`,
   189	  `stable`/`edge` as distinct distributions, one readable `conf/distributions`.
   190	  Its Berkeley-DB under `db/` is fine when that state persists.
   191	- **Stateless CI publisher (e.g. a fresh GitHub Actions runner each release):
   192	  flat signed repo** generated from scratch via `apt-ftparchive` /
   193	  `dpkg-scanpackages` + `gpg --clearsign` over `Release`/`InRelease`. No DB to
   194	  carry between runs; the existing pool is `aws s3 sync`'d down (or `gh release
   195	  download`'d), the new `.deb` added, the indices regenerated, re-signed,
   196	  re-uploaded. This is the model that does NOT break when the runner's local
   197	  `db/` is destroyed (AGY-MEDIUM-2).
   198	- **aptly** remains the option if S3-native publish + snapshots/mirroring are
   199	  wanted (it manages its own state + publishes to S3 directly).
   200	
   201	**Default recommendation: the flat signed repo**, because it is robust to BOTH
   202	stateful and stateless publishers and has zero non-dpkg/gpg dependencies; pick
   203	reprepro only if the publisher is known-persistent and the operator prefers its
   204	ergonomics. Either way the on-disk contract is identical (deb822 `Signed-By`,
   205	signed `InRelease`), so the install.sh side is unaffected by the choice.
   206	
   207	**r2 retention (resolves Codex-3 for the apt side):** apt suites keep the
   208	latest `.deb` per arch; apt-level rollback to an older `.deb` is NOT a goal —
   209	rollback is `xpfd upgrade`'s job (#1917). If apt-pin-to-old IS wanted, that is
   210	the aptly/multi-version path (a user OQ, flagged in §9).
   211	
   212	Channel layout (deb822, the contract install.sh writes):
   213	```
   214	/etc/apt/sources.list.d/xpf.sources:
   215	  Types: deb
   216	  URIs: <XPF_APT_BASE_URL>             # OQ-1b (dists/+pool/ tree)
   217	  Suites: stable                       # or edge
   218	  Components: main
   219	  Architectures: amd64
   220	  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
   221	```
   222	
   223	### 4C. install.sh trust-bootstrap (the security-critical step)
   224	
   225	| Option | Pros | Cons |
   226	|---|---|---|
   227	| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
   228	| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
   229	| **TOFU (trust on first use)** — just `apt-key add` whatever is served | trivial | INSECURE — rejected; defeats the entire point of the issue |
   230	
   231	**Recommendation:** **embed the ASCII-armored archive pubkey inline** in
   232	install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
   233	through apt's own signed `Release`. The keyring-in-install.sh means there is
   234	exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
   235	and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
   236	the inline-embed and the "fetch keyring + pin fingerprint" options are mutually
   237	exclusive — the plan picks inline-embed and drops the fingerprint-pin language
   238	from §3. The trust model is therefore precisely: *"an authentic install.sh
   239	CONTAINS the apt archive key."* TOFU is rejected.
   240	
   241	**r2 honest trust tiers (resolves SMR-F2 + Codex-6):** there are two clearly
   242	separated UX tiers, labeled as such in the docs:
   243	- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
   244	  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
   245	  Docker / rustup accept. The `.minisig` does NOT retroactively protect this
   246	  user (they ran the script before verifying). State this honestly.
   247	- **Tier B — verify-before-run.** The operator obtains `xpf-image.pub` **via
   248	  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
   249	  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
   250	  The loop closes ONLY because the pubkey came from the repo, not the dist host
   251	  (SMR-F1). Docs MUST say: "get the pubkey/fingerprint from the source repo or
   252	  release notes, NEVER from `XPF_DIST_BASE_URL`."
   253	
   254	### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)
   255	
   256	| Option | Pros | Cons |
   257	|---|---|---|
   258	| **GitHub Releases** (per-tag assets) | free, TLS, no infra, matches `gh release`; the repo is already on GitHub | not an apt repo by itself (need GitHub Pages or a bucket for the apt pool); release assets are per-tag not channel-stable URLs |
   259	| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
   260	| **Self-hosted static file server** | full control | the user runs+secures it |

exec
/bin/bash -lc "nl -ba scripts/image/validate.py | sed -n '220,460p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   220	        if guest("xpf-image-c", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
   221	            fail("invalid config was installed")
   222	        if guest("xpf-image-c", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
   223	            fail("stamp written on REJECT")
   224	        self.wait_fxp0_dhcp("xpf-image-c")
   225	        if not guest_sh("xpf-image-c", '[ "$(hostname)" != xpf-day0-c ]'):
   226	            fail("invalid config changed the hostname")
   227	        info("Scenario C PASS (fallback reachable, boot survived)")
   228	        self.drop("xpf-image-c")
   229	
   230	
   231	def _kver_ge(ver, floor):
   232	    try:
   233	        parts = tuple(int(x) for x in ver.split(".")[:2])
   234	    except ValueError:
   235	        return False
   236	    return parts >= floor
   237	
   238	
   239	def maybe_reexec_incus_admin():
   240	    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
   241	        return
   242	    import grp
   243	    try:
   244	        in_grp = "incus-admin" in [g.gr_name for g in grp.getgrall()
   245	                                   if os.getlogin() in g.gr_mem]
   246	    except Exception:
   247	        in_grp = False
   248	    if in_grp:
   249	        # Quote every token — a qcow2/metadata path with spaces or shell
   250	        # metacharacters must not break (or inject into) the `sg -c` shell.
   251	        cmd = " ".join(shlex.quote(a) for a in [sys.executable] + sys.argv)
   252	        os.execvp("sg", ["sg", "incus-admin", "-c", cmd])
   253	
   254	
   255	def main():
   256	    maybe_reexec_incus_admin()
   257	    p = argparse.ArgumentParser(description=__doc__,
   258	                                formatter_class=argparse.RawDescriptionHelpFormatter)
   259	    p.add_argument("--qcow2", required=True)
   260	    p.add_argument("--metadata", required=True)
   261	    p.add_argument("--keep", action="store_true")
   262	    p.add_argument("scenario", nargs="?", default="all", choices=["a", "b", "c", "all"])
   263	    a = p.parse_args()
   264	    if not os.path.isfile(a.qcow2):
   265	        fail(f"--qcow2 not found: {a.qcow2}")
   266	    if not os.path.isfile(a.metadata):
   267	        fail(f"--metadata not found: {a.metadata}")
   268	    net = os.environ.get("XPF_VALIDATE_NETWORK", "xpf-image-net")
   269	    h = Harness(a.qcow2, a.metadata, net, a.keep)
   270	    try:
   271	        h.ensure_network()
   272	        h.import_image()
   273	        scenarios = {"a": [h.scenario_a], "b": [h.scenario_b], "c": [h.scenario_c],
   274	                     "all": [h.scenario_a, h.scenario_b, h.scenario_c]}[a.scenario]
   275	        for s in scenarios:
   276	            s()
   277	        info("Validation complete.")
   278	        return 0
   279	    finally:
   280	        h.cleanup()
   281	
   282	
   283	if __name__ == "__main__":
   284	    sys.exit(main())

codex
The r3 text now explicitly separates import-time verification from alias launch, and the current deploy code backs that: `deploy_incus` launches an alias, while `validate.py` imports raw `--metadata`/`--qcow2`. I’m checking the Debian packaging layout and bake/runtime package context next because the keyring-in-package fix is the likeliest place for a hidden scope or package-ownership contradiction.
exec
/bin/bash -lc 'find debian -maxdepth 2 -type f -print' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
debian/changelog
debian/xpf.needrestart
debian/rules
debian/control
debian/xpf.postrm
debian/.gitignore
debian/source/format
debian/xpf.postinst

exec
/bin/bash -lc "rg -n 'RUNTIME_PACKAGES|kernel|linux|6\\.18|xpf-appliance|xpf_|install|keyring|apt|deb|dpkg|verify-dataplane' scripts/image/bake.py debian docs/install-images.md Makefile" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
Makefile:14:.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity
Makefile:46:	install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp
Makefile:48:# Manual build check for the diagnostic `debug-log` feature (#1678).
Makefile:49:# The debug-log build is not the production target and is deliberately
Makefile:55:# command before a commit. Compile-only; does not install.
Makefile:56:build-userspace-dp-debug-log:
Makefile:57:	$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release --features debug-log
Makefile:66:install: build build-ctl
Makefile:67:	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
Makefile:68:	install -m 0755 cli $(PREFIX)/bin/cli
Makefile:99:# discovered at bake time — XPF_BASE_RELEASE pins; linux-generic
Makefile:100:# kernel >= 6.18, xpfd + cli + xpf-userspace-dp + day-0 config-drive
Makefile:103:# verify-dataplane validation gate. See docs/install-images.md.
Makefile:290:# Build the xpf Debian package (#1917 increment A). Produces ../xpf_*.deb
Makefile:291:# and ../xpf-appliance_*.deb relative to the source tree (dpkg's default
Makefile:292:# parent-dir output), then copies them into dist/deb/.
Makefile:295:# (see debian/rules), so it picks up the embedded #1864 shim and the
Makefile:307:DEB_OUT ?= $(CURDIR)/dist/deb
Makefile:309:.PHONY: deb
Makefile:310:deb:
Makefile:311:	@echo "==> xpf .deb version: $(DEB_VERSION)"
Makefile:315:	@# failed dpkg-buildpackage. (A backup FILE under debian/ would be
Makefile:316:	@# deleted by dpkg-buildpackage's own clean phase, so re-sed instead.)
Makefile:319:	@# of the entry/trailer stays dpkg-parseable. dpkg-buildpackage writes
Makefile:320:	@# the .deb/.changes/.buildinfo to the PARENT dir (not configurable);
Makefile:321:	@# we keep the canonical copies in dist/deb/ and scrub the parent so it
Makefile:327:	@# trap covers normal completion + dpkg-buildpackage failure (set -e).
Makefile:330:	    sed -i "1s/^xpf ([^)]*)/xpf (0.0.0)/" debian/changelog; \
Makefile:331:	    rm -f ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb \
Makefile:332:	          ../xpf_$(DEB_VERSION)_*.changes ../xpf_$(DEB_VERSION)_*.buildinfo; \
Makefile:337:	  sed -i "1s/^xpf ([^)]*)/xpf ($(DEB_VERSION))/" debian/changelog; \
Makefile:338:	  dpkg-buildpackage -us -uc -b --no-sign; \
Makefile:340:	  cp ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb $(DEB_OUT)/
Makefile:342:	@ls -1 $(DEB_OUT)/*.deb
docs/install-images.md:6:time), a >= 6.18 kernel (the AF_XDP shim's verifier floor; 26.04 ships
docs/install-images.md:9:There is no dependency matrix to install and no kernel hunt: the image
docs/install-images.md:16:| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
docs/install-images.md:17:| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
docs/install-images.md:34:1. `make deb` (#1917 increment A). This runs `make build build-ctl
docs/install-images.md:35:   build-userspace-dp` via `debian/rules`, so the #1864 pinned-toolchain
docs/install-images.md:39:   `/usr/local/share/xpf/staged`). The bake installs that `.deb` instead
docs/install-images.md:49:   `linux-virtual` kernel replaced by `linux-generic` (full driver set
docs/install-images.md:50:   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
docs/install-images.md:51:   with in-bake asserts that the kernel meets the >= 6.18 verifier
docs/install-images.md:53:   (a competing network manager), snapd, and the virtual-kernel
docs/install-images.md:58:   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
docs/install-images.md:64:   directly. A plain `apt upgrade xpf` only refreshes the staging path
docs/install-images.md:65:   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
docs/install-images.md:73:   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
docs/install-images.md:74:   driver set check) with `xpfd verify-dataplane` IN-GUEST against
docs/install-images.md:75:   the image's own kernel, plus the valid- and invalid-day-0-drive
docs/install-images.md:83:date/host kernel). Bakes are not bit-reproducible (the base tracks
docs/install-images.md:108:    dist/xpf-<ver>.qcow2 --alias xpf-appliance
docs/install-images.md:113:incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
docs/install-images.md:125:virt-install --name xpf1 --memory 4096 --vcpus 4 \
docs/install-images.md:142:| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
docs/install-images.md:152:- On PASS the config is installed as `/etc/xpf/xpf.conf` (mode 0600 —
docs/install-images.md:196:`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
docs/install-images.md:198:implementation). A native .deb + `xpf-upgrade` wrapper is the M1a
docs/install-images.md:220:single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
docs/install-images.md:230:kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
scripts/image/bake.py:7:  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
scripts/image/bake.py:11:Pipeline: build the xpf .deb (`make deb`; no `make generate` — embeds the
scripts/image/bake.py:14:virt-customize (runtime packages, linux-generic >= 6.18 with the full
scripts/image/bake.py:15:driver set, purge cloud-init/snapd/stale kernels, networkd,
scripts/image/bake.py:16:init_on_alloc=0, `apt-get install ./xpf.deb` which stages the binaries +
scripts/image/bake.py:19:manifest -> in-guest verify-dataplane validation gate (validate.py).
scripts/image/bake.py:40:# Runtime dependency set installed explicitly into the image. This is the
scripts/image/bake.py:41:# same set the xpf-appliance metapackage Depends on (debian/control). The
scripts/image/bake.py:42:# bake installs the runtime packages explicitly + the xpf BINARY package,
scripts/image/bake.py:43:# rather than the metapackage, so apt does not have to resolve the full
scripts/image/bake.py:44:# dependency closure against a single local .deb during the offline bake;
scripts/image/bake.py:45:# the xpf-appliance metapackage is the operator-facing `apt install`
scripts/image/bake.py:47:# the metapackage Depends in debian/control in sync.
scripts/image/bake.py:48:RUNTIME_PACKAGES = [
scripts/image/bake.py:64:# apt-get update exits 0 even when an index fetch fails; --error-on=any
scripts/image/bake.py:66:APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
scripts/image/bake.py:67:              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
scripts/image/bake.py:68:              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")
scripts/image/bake.py:104:    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
scripts/image/bake.py:119:    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
scripts/image/bake.py:185:def virt_customize(work_qcow, xpf_deb):
scripts/image/bake.py:186:    pkgs = " ".join(RUNTIME_PACKAGES)
scripts/image/bake.py:187:    deb_name = os.path.basename(xpf_deb)
scripts/image/bake.py:191:        # #1917 increment A: install xpf via the .deb instead of copying raw
scripts/image/bake.py:196:        # enable xpfd`. The git-tracked, kernel-verified shim travels
scripts/image/bake.py:198:        "--copy-in", f"{xpf_deb}:/var/tmp",
scripts/image/bake.py:207:                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
scripts/image/bake.py:209:                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
scripts/image/bake.py:212:        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
scripts/image/bake.py:213:        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
scripts/image/bake.py:214:        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
scripts/image/bake.py:216:        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
scripts/image/bake.py:217:        '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }',
scripts/image/bake.py:218:        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
scripts/image/bake.py:219:                         "linux-virtual linux-image-virtual linux-headers-virtual 2>/dev/null || true",
scripts/image/bake.py:220:        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
scripts/image/bake.py:221:        # -generic kernel, so `apt install linux-generic` pulls a NEWER
scripts/image/bake.py:224:        # (linux-main-modules-zfs-<ver>, linux-headers-<ver>, …) AND
scripts/image/bake.py:225:        # depmod-generated files dpkg doesn't own. So for every non-newest
scripts/image/bake.py:226:        # version: purge ALL its packages via an apt glob, then rm -rf the
scripts/image/bake.py:228:        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
scripts/image/bake.py:230:        # (this assert caught a real 2-kernel image during #1879 live bake).
scripts/image/bake.py:234:        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
scripts/image/bake.py:236:        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
scripts/image/bake.py:239:        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
scripts/image/bake.py:240:        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
scripts/image/bake.py:242:        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
scripts/image/bake.py:245:        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
scripts/image/bake.py:253:        # Install the xpf .deb. apt resolves the package's deps (adduser,
scripts/image/bake.py:258:        # postinst's deb-systemd-invoke start is a harmless no-op (the units
scripts/image/bake.py:262:                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
scripts/image/bake.py:263:                         f"rm -f /var/tmp/{deb_name}",
scripts/image/bake.py:283:    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
scripts/image/bake.py:284:                    ("virt-customize", "apt-get install libguestfs-tools"),
scripts/image/bake.py:285:                    ("virt-resize", "apt-get install libguestfs-tools"),
scripts/image/bake.py:286:                    ("virt-sysprep", "apt-get install libguestfs-tools"),
scripts/image/bake.py:287:                    ("virt-sparsify", "apt-get install libguestfs-tools"),
scripts/image/bake.py:288:                    ("virt-filesystems", "apt-get install libguestfs-tools"),
scripts/image/bake.py:289:                    ("curl", "apt-get install curl")]:
scripts/image/bake.py:303:        # 1. build the xpf .deb (#1917 increment A). `make deb` runs
scripts/image/bake.py:304:        #    `make build build-ctl build-userspace-dp` via debian/rules, so
scripts/image/bake.py:307:        #    .deb instead of raw --copy-in binaries.
scripts/image/bake.py:308:        deb_dir = os.path.join(ROOT, "dist", "deb")
scripts/image/bake.py:310:            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
scripts/image/bake.py:311:            run(["make", "-C", ROOT, "deb"])
scripts/image/bake.py:313:        # binary package (NOT the xpf-appliance metapackage) and pick the
scripts/image/bake.py:314:        # NEWEST by mtime so a stale deb from an earlier (e.g. dirty-tree)
scripts/image/bake.py:315:        # build in dist/deb/ is never selected over the one just built.
scripts/image/bake.py:316:        debs = sorted((g for g in glob.glob(os.path.join(deb_dir, "xpf_*.deb"))
scripts/image/bake.py:317:                       if "xpf-appliance" not in os.path.basename(g)),
scripts/image/bake.py:319:        if not debs:
scripts/image/bake.py:320:            die(f"no xpf_*.deb in {deb_dir} (run without --skip-build, or run `make deb`)")
scripts/image/bake.py:321:        xpf_deb = debs[-1]
scripts/image/bake.py:322:        info(f"using package: {xpf_deb}")
scripts/image/bake.py:324:        # the build-host kernel before baking it in (#1864). Verify the xpfd
scripts/image/bake.py:325:        # that is ACTUALLY IN THE SELECTED .deb (extracted from the staging
scripts/image/bake.py:331:        run(["dpkg-deb", "-x", xpf_deb, os.path.join(work, "pregate")])
scripts/image/bake.py:333:            die(f"package {xpf_deb} does not contain an executable staged xpfd")
scripts/image/bake.py:334:        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
scripts/image/bake.py:335:            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
scripts/image/bake.py:336:                 f"(host kernel {os.uname().release})...")
scripts/image/bake.py:338:                               staged_xpfd, "verify-dataplane"]).returncode != 0:
scripts/image/bake.py:339:                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
scripts/image/bake.py:361:        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
scripts/image/bake.py:362:        virt_customize(work_qcow, xpf_deb)
scripts/image/bake.py:371:             "/var/lib/apt/lists/* 2>/dev/null || true"])
scripts/image/bake.py:386:                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
scripts/image/bake.py:390:                    "  variant: xpf-appliance\n")
scripts/image/bake.py:410:                    f"bake_host_kernel: {os.uname().release}\n")
scripts/image/bake.py:416:                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
scripts/image/bake.py:418:            info("running validation gate (factory boot + in-guest verify-dataplane + "
scripts/image/bake.py:425:        info("deploy quickstarts: docs/install-images.md")
debian/xpf.postinst:4:# dpkg installs the binary set to the dpkg-static staging path
debian/xpf.postinst:6:# binaries via /usr/local/sbin/* which are SYMLINKS. On FIRST install
debian/xpf.postinst:14:#    copies staging into a versioned runtime dir, runs the kernel
debian/xpf.postinst:31:        # $2 is the previously-configured version, empty on first install.
debian/xpf.postinst:35:                # First install: point the live path at the staged binary.
debian/xpf.postinst:61:            # dpkg has refreshed the staging path. Whether we now CUT OVER
debian/xpf.postinst:72:            #    down at apt time) must NOT fall through to a standalone cut.
debian/xpf.postinst:93:                # staging into the versioned runtime dir, runs the kernel
debian/xpf.postinst:94:                # verify-dataplane gate, and on PASS does the atomic
debian/xpf.postinst:97:                # install on a cut-over abort (the operator can re-run
debian/xpf.postinst:108:                    # offline after `apt upgrade`.
debian/xpf.needrestart:3:# Ubuntu server installs needrestart by default; at the end of an apt
debian/xpf.needrestart:5:# auto-restarts their services. That would cut the dataplane mid-apt
debian/xpf.needrestart:8:#   1. The running xpfd binary lives under the non-dpkg runtime path
debian/xpf.needrestart:9:#      (the live /usr/local/sbin symlink chain), which an `apt upgrade
debian/xpf.needrestart:10:#      xpf` only refreshes in the dpkg-static staging area — so the
debian/changelog:5:    and the systemd units. Binaries install to a dpkg-static staging
debian/changelog:6:    path; live symlinks are created on first install only. The
debian/changelog:8:  * The version field above is a placeholder; `make deb` rewrites it
debian/control:5:Build-Depends: debhelper-compat (= 13)
debian/control:21: installed to a dpkg-static staging path; the live /usr/local/sbin
debian/control:22: symlinks are created on first install (the in-place upgrade cut-over
debian/control:29:Package: xpf-appliance
debian/control:55: tooling). This is the operator-facing entry point: `apt install
debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
debian/control:57: hosted apt repo).
debian/control:59: NOTE: the appliance image bake (scripts/image/bake.py) installs the
debian/control:61: than this metapackage, so apt does not have to resolve the full
debian/control:62: dependency closure against a single local .deb during the offline bake.
debian/control:64: RUNTIME_PACKAGES.
debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade
debian/xpf.postrm:31:    upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
debian/rules:5:# xpfd embeds the kernel-verified AF_XDP shim (#1864) and the helper
debian/rules:8:# delegates to the project Makefile and the install step copies the
debian/rules:9:# freshly built binaries into the dpkg-static staging path.
debian/rules:13:#       dpkg-static staging path. dpkg owns ONLY this path. It never
debian/rules:18:#   the maintainer scripts on FIRST install only (no running version
debian/rules:19:#   to protect). On upgrade dpkg only refreshes the staging path; the
debian/rules:20:#   live symlinks are left untouched so a plain apt upgrade never cuts
debian/rules:34:# installs from userspace-dp/target/release/, and overriding the target
debian/rules:35:# dir to a scratch path would install a stale binary.
debian/rules:37:# Stage the systemd units into debian/ under the package-canonical
debian/rules:38:# names so dh_installsystemd finds them. The unit sources remain in
debian/rules:42:# The package-owned xpfd.service gets an ExecStartPre verify-dataplane
debian/rules:43:# gate injected (plan §6.2 / §7): the #1864/#1869 kernel-verifier gate
debian/rules:44:# must run at EVERY boot, not only once at bake time — a later kernel
debian/rules:56:	sed -E '/^[[:space:]]*ExecStart[[:space:]]*=/i ExecStartPre=/usr/local/sbin/xpfd verify-dataplane' \
debian/rules:57:	    test/incus/xpfd.service > debian/xpf.xpfd.service
debian/rules:58:	grep -q '^ExecStartPre=/usr/local/sbin/xpfd verify-dataplane$$' debian/xpf.xpfd.service || \
debian/rules:59:	    { echo "FATAL: ExecStartPre verify-dataplane injection failed (xpfd.service ExecStart line not matched)" >&2; exit 1; }
debian/rules:60:	cp scripts/image/xpf-day0-config.service debian/xpf.xpf-day0-config.service
debian/rules:66:override_dh_auto_install:
debian/rules:67:	install -d debian/xpf$(STAGED)
debian/rules:68:	install -m 0755 xpfd              debian/xpf$(STAGED)/xpfd
debian/rules:69:	install -m 0755 cli               debian/xpf$(STAGED)/cli
debian/rules:70:	install -m 0755 xpf-userspace-dp  debian/xpf$(STAGED)/xpf-userspace-dp
debian/rules:71:	install -m 0755 scripts/image/xpf-day0-config \
debian/rules:72:	                                  debian/xpf$(STAGED)/xpf-day0-config
debian/rules:73:	install -d debian/xpf/etc/needrestart/conf.d
debian/rules:74:	install -m 0644 debian/xpf.needrestart \
debian/rules:75:	                debian/xpf/etc/needrestart/conf.d/xpf.conf
debian/rules:77:# Disable the auto-restart-on-upgrade block dh_installsystemd would
debian/rules:78:# otherwise append to postinst. A plain `apt upgrade xpf` must NOT
debian/rules:82:# The units are still enabled on install via dh_installsystemd.
debian/rules:83:override_dh_installsystemd:
debian/rules:84:	dh_installsystemd --no-stop-on-upgrade --name=xpfd
debian/rules:85:	dh_installsystemd --no-stop-on-upgrade --name=xpf-day0-config
debian/rules:88:	rm -f debian/xpf.xpfd.service debian/xpf.xpf-day0-config.service

exec
/bin/bash -lc "nl -ba scripts/image/bake.py | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf appliance image bake (#1879 Path C — vSRX-style prebuilt image), in Python.
     3	
     4	Builds ONE bootable root-disk image OFFLINE (libguestfs — never boots the
     5	image to provision it) and exports it for both hypervisors:
     6	
     7	  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
     8	  dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata
     9	  dist/SHA256SUMS
    10	
    11	Pipeline: build the xpf .deb (`make deb`; no `make generate` — embeds the
    12	#1864 tracked shim) -> discover + SHA256-verify the latest Ubuntu cloud
    13	image (XPF_BASE_RELEASE pins) -> virt-resize root into a work disk ->
    14	virt-customize (runtime packages, linux-generic >= 6.18 with the full
    15	driver set, purge cloud-init/snapd/stale kernels, networkd,
    16	init_on_alloc=0, `apt-get install ./xpf.deb` which stages the binaries +
    17	creates the /usr/local/sbin symlinks + enables the units via its postinst)
    18	-> virt-sysprep seal -> virt-sparsify+compress export -> checksums +
    19	manifest -> in-guest verify-dataplane validation gate (validate.py).
    20	
    21	Requirements: make/go/cargo, libguestfs-tools, qemu-utils, curl; incus for
    22	the validation gate. /dev/kvm makes libguestfs fast.
    23	
    24	Usage:
    25	  bake.py [--version V] [--out DIR] [--skip-build] [--skip-validate] [--keep-work]
    26	"""
    27	
    28	import argparse
    29	import os
    30	import resource
    31	import shutil
    32	import subprocess
    33	import sys
    34	import tempfile
    35	import time
    36	
    37	HERE = os.path.dirname(os.path.abspath(__file__))
    38	ROOT = os.path.dirname(os.path.dirname(HERE))
    39	
    40	# Runtime dependency set installed explicitly into the image. This is the
    41	# same set the xpf-appliance metapackage Depends on (debian/control). The
    42	# bake installs the runtime packages explicitly + the xpf BINARY package,
    43	# rather than the metapackage, so apt does not have to resolve the full
    44	# dependency closure against a single local .deb during the offline bake;
    45	# the xpf-appliance metapackage is the operator-facing `apt install`
    46	# entry point (e.g. from a future hosted repo, #1924). Keep this list and
    47	# the metapackage Depends in debian/control in sync.
    48	RUNTIME_PACKAGES = [
    49	    "frr", "strongswan", "strongswan-swanctl",
    50	    "kea-dhcp4-server", "kea-dhcp6-server", "chrony",
    51	    "iproute2", "nftables", "ethtool", "tcpdump", "pciutils",
    52	    "iputils-ping", "traceroute", "openssh-server", "openssh-client",
    53	    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
    54	]
    55	
    56	SYSCTL_CONF = (
    57	    "net.core.bpf_jit_enable=1\n"
    58	    "net.ipv4.ip_forward=1\n"
    59	    "net.ipv6.conf.all.forwarding=1\n"
    60	    "net.ipv6.conf.all.accept_ra=0\n"
    61	    "net.ipv6.conf.default.accept_ra=0\n"
    62	)
    63	
    64	# apt-get update exits 0 even when an index fetch fails; --error-on=any
    65	# makes that fatal, one retry covers a transient blip.
    66	APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
    67	              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
    68	              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")
    69	
    70	GRUB_DROPIN = (
    71	    '# xpf (#1879): init_on_alloc=0 — CONFIG_INIT_ON_ALLOC_DEFAULT_ON zeroes\n'
    72	    '# every allocated page (~20% CPU in the virtio-net XDP path). A grub.d\n'
    73	    '# drop-in, NOT a sed on /etc/default/grub: Ubuntu cloud images override\n'
    74	    '# GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub.d/50-cloudimg-settings.cfg.\n'
    75	    'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"'
    76	)
    77	
    78	SSHD_DROPIN = (
    79	    '# xpf factory posture (#1879): root password is EMPTY (console-only\n'
    80	    '# login, vSRX parity). Pin the OpenSSH defaults explicitly.\n'
    81	    'PermitRootLogin prohibit-password\n'
    82	    'PermitEmptyPasswords no'
    83	)
    84	
    85	
    86	def info(m):
    87	    print(f"==> {m}")
    88	
    89	
    90	def die(m):
    91	    sys.exit(f"ERROR: {m}")
    92	
    93	
    94	def require(tool, hint):
    95	    if not shutil.which(tool):
    96	        die(f"{tool} not found — {hint}")
    97	
    98	
    99	def run(argv, **kw):
   100	    return subprocess.run(argv, check=True, **kw)
   101	
   102	
   103	def out_text(argv):
   104	    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
   105	
   106	
   107	def git_version():
   108	    try:
   109	        return out_text(["git", "-C", ROOT, "describe", "--tags", "--always", "--dirty"]).strip()
   110	    except Exception:
   111	        return "dev"
   112	
   113	
   114	def ensure_memlock():
   115	    """qemu io_uring needs locked memory beyond the 8 MiB default."""
   116	    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
   117	    if hard == resource.RLIM_INFINITY or hard >= 1048576 * 1024:
   118	        return
   119	    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
   120	        # The shell original died if this failed; preserve that — a silent
   121	        # drop just relocates the failure into libguestfs/qemu later.
   122	        if subprocess.run(["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited",
   123	                           "--pid", str(os.getpid())]).returncode != 0:
   124	            die("could not raise RLIMIT_MEMLOCK (libguestfs/qemu io_uring needs it)")
   125	    else:
   126	        die("RLIMIT_MEMLOCK too low for libguestfs/qemu io_uring — raise it "
   127	            "(sudo prlimit --memlock=unlimited:unlimited --pid $$) and re-run")
   128	
   129	
   130	def discover_base_release():
   131	    if os.environ.get("XPF_BASE_RELEASE"):
   132	        return os.environ["XPF_BASE_RELEASE"]
   133	    url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
   134	                         "https://cloud-images.ubuntu.com/releases")
   135	    import re
   136	    html = out_text(["curl", "-fsSL", url + "/"])
   137	    rels = sorted(set(re.findall(r'href="(\d{2}\.\d{2})/"', html)),
   138	                  key=lambda v: tuple(int(x) for x in v.split(".")))
   139	    if not rels:
   140	        die(f"could not discover the latest Ubuntu release from {url}/ "
   141	            "(set XPF_BASE_RELEASE to pin one)")
   142	    return rels[-1]
   143	
   144	
   145	def sha256(path):
   146	    import hashlib
   147	    h = hashlib.sha256()
   148	    with open(path, "rb") as f:
   149	        for chunk in iter(lambda: f.read(1 << 20), b""):
   150	            h.update(chunk)
   151	    return h.hexdigest()
   152	
   153	
   154	def fetch_base(cache_dir, work_dir):
   155	    releases_url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
   156	                                  "https://cloud-images.ubuntu.com/releases")
   157	    rel = discover_base_release()
   158	    base_url = os.environ.get("XPF_BASE_URL", f"{releases_url}/{rel}/release")
   159	    img = f"ubuntu-{rel}-server-cloudimg-amd64.img"
   160	    info(f"fetching Ubuntu {rel} server cloud image base ({base_url})")
   161	    cached = os.path.join(cache_dir, img)
   162	    if not os.path.isfile(cached):
   163	        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
   164	        os.replace(cached + ".tmp", cached)
   165	    # Re-verify the cache against the upstream checksum (cache not trusted).
   166	    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
   167	    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
   168	    expected = None
   169	    with open(sums) as f:
   170	        for line in f:
   171	            parts = line.split()
   172	            if len(parts) == 2 and parts[1].lstrip("*") == img:
   173	                expected = parts[0]
   174	                break
   175	    if not expected:
   176	        die(f"no SHA256 for {img} in upstream SHA256SUMS")
   177	    actual = sha256(cached)
   178	    if expected != actual:
   179	        os.remove(cached)
   180	        die("base image SHA256 mismatch (cache removed — re-run)")
   181	    info("base image checksum verified.")
   182	    return rel, base_url, img, cached, actual
   183	
   184	
   185	def virt_customize(work_qcow, xpf_deb):
   186	    pkgs = " ".join(RUNTIME_PACKAGES)
   187	    deb_name = os.path.basename(xpf_deb)
   188	    argv = [
   189	        "virt-customize", "-a", work_qcow, "--smp", "4", "--memsize", "2048",
   190	        "--hostname", "xpf",
   191	        # #1917 increment A: install xpf via the .deb instead of copying raw
   192	        # binaries. The package stages the binary set under
   193	        # /usr/local/share/xpf/staged, creates the live /usr/local/sbin
   194	        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
   195	        # the bake no longer hand-copies binaries/units or runs `systemctl
   196	        # enable xpfd`. The git-tracked, kernel-verified shim travels
   197	        # embedded inside the staged xpfd binary (#1864 contract preserved).
   198	        "--copy-in", f"{xpf_deb}:/var/tmp",
   199	        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
   200	        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
   201	        "--copy-in", f"{HERE}/99-incus-agent.rules:/usr/lib/udev/rules.d",
   202	        "--run-command", "chmod 0755 /usr/lib/systemd/incus-agent-setup",
   203	        "--write", f"/etc/sysctl.d/99-xpf.conf:{SYSCTL_CONF}",
   204	        "--run-command", "mkdir -p /etc/xpf && chmod 0750 /etc/xpf",
   205	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && {APT_UPDATE}",
   206	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && "
   207	                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
   208	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
   209	                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
   210	        "--run-command",
   211	        'latest=$(ls /lib/modules | sort -V | tail -1) && case "$latest" in [0-9]*) ;; '
   212	        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
   213	        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
   214	        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
   215	        "--run-command",
   216	        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
   217	        '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }',
   218	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
   219	                         "linux-virtual linux-image-virtual linux-headers-virtual 2>/dev/null || true",
   220	        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
   221	        # -generic kernel, so `apt install linux-generic` pulls a NEWER
   222	        # point release (e.g. 7.0.0-22 over the stock 7.0.0-15) and leaves
   223	        # the original — across packages a narrow name regex misses
   224	        # (linux-main-modules-zfs-<ver>, linux-headers-<ver>, …) AND
   225	        # depmod-generated files dpkg doesn't own. So for every non-newest
   226	        # version: purge ALL its packages via an apt glob, then rm -rf the
   227	        # leftover module dir + its /boot files. update-grub (below)
   228	        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
   229	        # bake must catch this itself, not only the boot validation
   230	        # (this assert caught a real 2-kernel image during #1879 live bake).
   231	        "--run-command",
   232	        'export DEBIAN_FRONTEND=noninteractive; newest=$(ls /lib/modules | sort -V | tail -1); '
   233	        'for v in $(ls /lib/modules | grep -vxF "$newest"); do '
   234	        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
   235	        'rm -rf "/lib/modules/$v" /boot/*"$v"*; done; '
   236	        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
   237	        "--run-command",
   238	        'n=$(ls /lib/modules | wc -l); [ "$n" -eq 1 ] || '
   239	        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
   240	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
   241	                         "2>/dev/null || true; rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd",
   242	        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
   243	                         "2>/dev/null || true; rm -rf /etc/cloud /var/lib/cloud",
   244	        "--run-command", "rm -f /etc/network/interfaces.d/* /etc/netplan/*.yaml 2>/dev/null || true",
   245	        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
   246	                         f"{{ {APT_UPDATE}; }}",
   247	        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
   248	        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
   249	        "--run-command", "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
   250	        "--run-command", "systemctl enable frr chrony",
   251	        "--run-command", 'sed -i "s/^pool /#pool /; s/^server /#server /" /etc/chrony/chrony.conf '
   252	                         "&& mkdir -p /etc/chrony/sources.d",
   253	        # Install the xpf .deb. apt resolves the package's deps (adduser,
   254	        # present) from the local file. The postinst stages the binaries,
   255	        # creates the /usr/local/sbin symlinks, and enables xpfd +
   256	        # xpf-day0-config — so there is no separate `systemctl enable xpfd`
   257	        # here. systemd is not running under virt-customize, so the
   258	        # postinst's deb-systemd-invoke start is a harmless no-op (the units
   259	        # are enabled and start on the real first boot). The xpfd version
   260	        # check below confirms the symlink resolves the staged binary.

exec
/bin/bash -lc "nl -ba debian/rules | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/usr/bin/make -f
     2	# xpf Debian package rules (increment A of #1917).
     3	#
     4	# We deliberately do NOT use dh-golang or dh's auto Go/Cargo build:
     5	# xpfd embeds the kernel-verified AF_XDP shim (#1864) and the helper
     6	# is built with a pinned cargo via the project Makefile. Re-deriving
     7	# the build inside dh would bypass that discipline. So the build step
     8	# delegates to the project Makefile and the install step copies the
     9	# freshly built binaries into the dpkg-static staging path.
    10	#
    11	# Layout (plan #1917 §6.1 / §6.3c):
    12	#   /usr/local/share/xpf/staged/{xpfd,xpf-userspace-dp,cli,xpf-day0-config}
    13	#       dpkg-static staging path. dpkg owns ONLY this path. It never
    14	#       writes the live /usr/local/sbin symlinks or any runtime
    15	#       versioned dir. The in-place cut-over mechanism (increment B)
    16	#       owns /var/lib/xpf/versions/<v>/ and the atomic symlink flip.
    17	#   The live /usr/local/sbin/{xpfd,cli,...} symlinks are created by
    18	#   the maintainer scripts on FIRST install only (no running version
    19	#   to protect). On upgrade dpkg only refreshes the staging path; the
    20	#   live symlinks are left untouched so a plain apt upgrade never cuts
    21	#   the dataplane (increment B drives the verified cut explicitly).
    22	
    23	export DH_VERBOSE = 1
    24	export DEB_BUILD_MAINT_OPTIONS = hardening=+all
    25	
    26	STAGED = /usr/local/share/xpf/staged
    27	
    28	%:
    29		dh $@
    30	
    31	# Build the binary set via the project Makefile so the embedded shim
    32	# and pinned cargo build are used unchanged. CARGO_TARGET_DIR is left
    33	# at the project default on purpose: the Makefile's build-userspace-dp
    34	# installs from userspace-dp/target/release/, and overriding the target
    35	# dir to a scratch path would install a stale binary.
    36	#
    37	# Stage the systemd units into debian/ under the package-canonical
    38	# names so dh_installsystemd finds them. The unit sources remain in
    39	# test/incus/ and scripts/image/ (the test env and bake consume the
    40	# same files); the package re-homes them at /lib/systemd/system.
    41	#
    42	# The package-owned xpfd.service gets an ExecStartPre verify-dataplane
    43	# gate injected (plan §6.2 / §7): the #1864/#1869 kernel-verifier gate
    44	# must run at EVERY boot, not only once at bake time — a later kernel
    45	# change or a skipped bake validation must never reach ExecStart with a
    46	# verifier-failing shim. exit 3 = REJECT aborts the start. We inject it
    47	# here (rather than editing test/incus/xpfd.service) so the gate ships in
    48	# the appliance package without changing the dev/test unit source; the
    49	# binary the gate runs is the live /usr/local/sbin/xpfd symlink.
    50	override_dh_auto_build:
    51		$(MAKE) build build-ctl build-userspace-dp
    52		@# Match ExecStart tolerating leading whitespace and spaces around '='
    53		@# (systemd accepts those), then HARD-ASSERT the gate landed — a silent
    54		@# sed miss (e.g. if the unit source is reformatted) must FAIL the build,
    55		@# never ship a package-staged unit that skips the verifier (AGY r2).
    56		sed -E '/^[[:space:]]*ExecStart[[:space:]]*=/i ExecStartPre=/usr/local/sbin/xpfd verify-dataplane' \
    57		    test/incus/xpfd.service > debian/xpf.xpfd.service
    58		grep -q '^ExecStartPre=/usr/local/sbin/xpfd verify-dataplane$$' debian/xpf.xpfd.service || \
    59		    { echo "FATAL: ExecStartPre verify-dataplane injection failed (xpfd.service ExecStart line not matched)" >&2; exit 1; }
    60		cp scripts/image/xpf-day0-config.service debian/xpf.xpf-day0-config.service
    61	
    62	# Nothing to test in the package build itself; the project test suite
    63	# is run separately. Skip dh's auto test (it would try `go test`).
    64	override_dh_auto_test:
    65	
    66	override_dh_auto_install:
    67		install -d debian/xpf$(STAGED)
    68		install -m 0755 xpfd              debian/xpf$(STAGED)/xpfd
    69		install -m 0755 cli               debian/xpf$(STAGED)/cli
    70		install -m 0755 xpf-userspace-dp  debian/xpf$(STAGED)/xpf-userspace-dp
    71		install -m 0755 scripts/image/xpf-day0-config \
    72		                                  debian/xpf$(STAGED)/xpf-day0-config
    73		install -d debian/xpf/etc/needrestart/conf.d
    74		install -m 0644 debian/xpf.needrestart \
    75		                debian/xpf/etc/needrestart/conf.d/xpf.conf
    76	
    77	# Disable the auto-restart-on-upgrade block dh_installsystemd would
    78	# otherwise append to postinst. A plain `apt upgrade xpf` must NOT
    79	# cycle xpfd (a full dataplane gap); the verified cut-over is driven
    80	# explicitly by the increment-B mechanism. --no-stop-on-upgrade is the
    81	# documented directive (--no-restart-on-upgrade is a deprecated alias).
    82	# The units are still enabled on install via dh_installsystemd.
    83	override_dh_installsystemd:
    84		dh_installsystemd --no-stop-on-upgrade --name=xpfd
    85		dh_installsystemd --no-stop-on-upgrade --name=xpf-day0-config
    86	
    87	override_dh_clean:
    88		rm -f debian/xpf.xpfd.service debian/xpf.xpf-day0-config.service
    89		dh_clean
    90	
    91	# xpf is an APPLIANCE package, not a Debian-archive package: it
    92	# deliberately owns /usr/local (the staged binary set under
    93	# /usr/local/share/xpf/staged and the live /usr/local/sbin symlinks the
    94	# maintainer scripts manage) because the appliance image, the systemd
    95	# units, and the in-place upgrade mechanism all key off /usr/local/sbin.
    96	# dh_usrlocal enforces the Debian Policy rule that archive packages must
    97	# not ship FILES under /usr/local; we accept that deviation here and
    98	# skip it. Removal of the /usr/local dirs/symlinks is handled by our own
    99	# postrm (symlinks) and is otherwise harmless (shared, admin-owned tree).
   100	override_dh_usrlocal:
   101	
   102	# The staged binaries are stripped by the upstream build already where
   103	# applicable; do not let dh strip / instrument them further (the Go
   104	# binaries are static and the Rust binary carries its own settings).
   105	override_dh_strip:
   106	
   107	override_dh_dwz:

exec
/bin/bash -lc 'rg --files debian scripts/image scripts/deploy scripts/dist Makefile docs/install-images.md docs/distribution.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 exited 2 in 0ms:
rg: scripts/dist: No such file or directory (os error 2)
rg: docs/distribution.md: No such file or directory (os error 2)
docs/install-images.md
Makefile
scripts/deploy/xpf-deploy.py
scripts/image/validate.py
scripts/image/incus-agent.service
scripts/image/xpf-day0-config.service
scripts/image/incus-agent-setup
scripts/image/99-incus-agent.rules
scripts/image/bake.py
scripts/image/make_config_drive.py
scripts/image/xpf-day0-config
debian/xpf.postinst
debian/source/format
debian/xpf.postrm
debian/control
debian/rules
debian/xpf.needrestart
debian/changelog

exec
/bin/bash -lc "nl -ba debian/xpf.install | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
nl: debian/xpf.install: No such file or directory

codex
The existing package has no `debian/xpf.install` yet and installs payload directly in `debian/rules`; that matters for the plan’s “one `debian/install` line” phrasing. I’m checking whether that is just an implementation-detail nit or a real contradiction with current packaging behavior.
exec
/bin/bash -lc "nl -ba scripts/image/bake.py | sed -n '260,460p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   260	        # check below confirms the symlink resolves the staged binary.
   261	        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
   262	                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
   263	                         f"rm -f /var/tmp/{deb_name}",
   264	        "--write", f"/etc/default/grub.d/99-xpf.cfg:{GRUB_DROPIN}",
   265	        "--run-command", "update-grub",
   266	        "--write", f"/etc/ssh/sshd_config.d/10-xpf-factory.conf:{SSHD_DROPIN}",
   267	        "--run-command", "passwd -d root",
   268	        "--run-command", "/usr/local/sbin/xpfd version",
   269	    ]
   270	    run(argv)
   271	
   272	
   273	def main():
   274	    p = argparse.ArgumentParser(description=__doc__,
   275	                                formatter_class=argparse.RawDescriptionHelpFormatter)
   276	    p.add_argument("--version", default=git_version())
   277	    p.add_argument("--out", default=os.path.join(ROOT, "dist"))
   278	    p.add_argument("--skip-build", action="store_true")
   279	    p.add_argument("--skip-validate", action="store_true")
   280	    p.add_argument("--keep-work", action="store_true")
   281	    a = p.parse_args()
   282	
   283	    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
   284	                    ("virt-customize", "apt-get install libguestfs-tools"),
   285	                    ("virt-resize", "apt-get install libguestfs-tools"),
   286	                    ("virt-sysprep", "apt-get install libguestfs-tools"),
   287	                    ("virt-sparsify", "apt-get install libguestfs-tools"),
   288	                    ("virt-filesystems", "apt-get install libguestfs-tools"),
   289	                    ("curl", "apt-get install curl")]:
   290	        require(t, hint)
   291	    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
   292	        print("WARNING: no /dev/kvm access — libguestfs will use TCG (slow).", file=sys.stderr)
   293	    ensure_memlock()
   294	
   295	    cache_dir = os.path.join(os.environ.get("XDG_CACHE_HOME",
   296	                             os.path.expanduser("~/.cache")), "xpf-image-bake")
   297	    os.makedirs(a.out, exist_ok=True)
   298	    os.makedirs(cache_dir, exist_ok=True)
   299	    work = tempfile.mkdtemp(prefix="xpf-bake-", dir=os.environ.get("TMPDIR", "/tmp"))
   300	
   301	    import glob
   302	    try:
   303	        # 1. build the xpf .deb (#1917 increment A). `make deb` runs
   304	        #    `make build build-ctl build-userspace-dp` via debian/rules, so
   305	        #    it picks up the embedded #1864 shim and the pinned cargo helper,
   306	        #    then packages the freshly-built binaries. The image consumes the
   307	        #    .deb instead of raw --copy-in binaries.
   308	        deb_dir = os.path.join(ROOT, "dist", "deb")
   309	        if not a.skip_build:
   310	            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
   311	            run(["make", "-C", ROOT, "deb"])
   312	        # The git-derived version is computed by the Makefile; glob for the
   313	        # binary package (NOT the xpf-appliance metapackage) and pick the
   314	        # NEWEST by mtime so a stale deb from an earlier (e.g. dirty-tree)
   315	        # build in dist/deb/ is never selected over the one just built.
   316	        debs = sorted((g for g in glob.glob(os.path.join(deb_dir, "xpf_*.deb"))
   317	                       if "xpf-appliance" not in os.path.basename(g)),
   318	                      key=os.path.getmtime)
   319	        if not debs:
   320	            die(f"no xpf_*.deb in {deb_dir} (run without --skip-build, or run `make deb`)")
   321	        xpf_deb = debs[-1]
   322	        info(f"using package: {xpf_deb}")
   323	        # build-host pre-gate (best-effort): verify the embedded shim against
   324	        # the build-host kernel before baking it in (#1864). Verify the xpfd
   325	        # that is ACTUALLY IN THE SELECTED .deb (extracted from the staging
   326	        # path), not ROOT/xpfd — under --skip-build those can diverge (a
   327	        # stale loose ROOT/xpfd next to a newer packaged binary), and the
   328	        # one that ships is the packaged one.
   329	        staged_xpfd = os.path.join(work, "pregate", "usr", "local",
   330	                                   "share", "xpf", "staged", "xpfd")
   331	        run(["dpkg-deb", "-x", xpf_deb, os.path.join(work, "pregate")])
   332	        if not os.access(staged_xpfd, os.X_OK):
   333	            die(f"package {xpf_deb} does not contain an executable staged xpfd")
   334	        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
   335	            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
   336	                 f"(host kernel {os.uname().release})...")
   337	            if subprocess.run(["sudo", "-n", "nice", "-n", "19",
   338	                               staged_xpfd, "verify-dataplane"]).returncode != 0:
   339	                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
   340	        else:
   341	            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
   342	                  "(in-guest gate still enforces).", file=sys.stderr)
   343	
   344	        # 2. base
   345	        rel, base_url, base_img, cached, base_sha = fetch_base(cache_dir, work)
   346	
   347	        # 3. resize
   348	        disk = os.environ.get("XPF_IMAGE_DISK_SIZE", "8G")
   349	        info(f"creating {disk} work disk + expanding root partition...")
   350	        fs = out_text(["virt-filesystems", "-a", cached, "--filesystems", "--long", "--no-title"])
   351	        root_part = next((ln.split()[0] for ln in fs.splitlines()
   352	                          if len(ln.split()) >= 3 and ln.split()[2] == "ext4"), None)
   353	        if not root_part:
   354	            die("could not locate the ext4 root partition in the base image")
   355	        work_qcow = os.path.join(work, "work.qcow2")
   356	        run(["qemu-img", "create", "-f", "qcow2", "-o", "preallocation=off", work_qcow, disk],
   357	            stdout=subprocess.DEVNULL)
   358	        run(["virt-resize", "--quiet", "--expand", root_part, cached, work_qcow])
   359	
   360	        # 4. customize
   361	        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
   362	        virt_customize(work_qcow, xpf_deb)
   363	
   364	        # 5. seal
   365	        info("sealing image (virt-sysprep)...")
   366	        run(["virt-sysprep", "-a", work_qcow, "--quiet", "--enable",
   367	             "machine-id,ssh-hostkeys,ssh-userdir,logfiles,tmp-files,bash-history,"
   368	             "package-manager-cache,backup-files,passwd-backups,utmp",
   369	             "--run-command", "rm -rf /etc/xpf/.configdb /etc/xpf/xpf.conf "
   370	             "/etc/xpf/.day0-config-applied /var/lib/systemd/random-seed "
   371	             "/var/lib/apt/lists/* 2>/dev/null || true"])
   372	
   373	        # 6. export
   374	        ver = a.version
   375	        qcow_out = os.path.join(a.out, f"xpf-{ver}.qcow2")
   376	        meta_out = os.path.join(a.out, f"xpf-{ver}.incus-metadata.tar.gz")
   377	        info(f"exporting {qcow_out} (sparsified + compressed qcow2)...")
   378	        run(["virt-sparsify", "--quiet", "--tmp", work, "--compress", work_qcow, qcow_out])
   379	
   380	        info(f"exporting {meta_out} (incus VM image metadata)...")
   381	        meta = os.path.join(work, "metadata.yaml")
   382	        with open(meta, "w") as f:
   383	            f.write("architecture: x86_64\n"
   384	                    f"creation_date: {int(time.time())}\n"
   385	                    "properties:\n"
   386	                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
   387	                    "AF_XDP userspace dataplane)\n"
   388	                    "  os: Ubuntu\n"
   389	                    f"  release: {rel}\n"
   390	                    "  variant: xpf-appliance\n")
   391	        run(["tar", "-C", work, "-czf", meta_out, "metadata.yaml"])
   392	
   393	        sums = os.path.join(a.out, "SHA256SUMS")
   394	        with open(sums, "w") as f:
   395	            for path in (qcow_out, meta_out):
   396	                f.write(f"{sha256(path)}  {os.path.basename(path)}\n")
   397	        info("checksums:")
   398	        print(open(sums).read(), end="")
   399	
   400	        try:
   401	            commit = out_text(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
   402	        except Exception:
   403	            commit = "unknown"
   404	        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
   405	        with open(manifest, "w") as f:
   406	            f.write(f"version: {ver}\ngit_commit: {commit}\n"
   407	                    f"base_image: {base_url}/{base_img}\nbase_release: {rel}\n"
   408	                    f"base_image_sha256: {base_sha}\n"
   409	                    f"bake_date: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
   410	                    f"bake_host_kernel: {os.uname().release}\n")
   411	        info(f"manifest: {manifest}")
   412	
   413	        # 7. validation gate
   414	        if a.skip_validate:
   415	            print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
   416	                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
   417	        else:
   418	            info("running validation gate (factory boot + in-guest verify-dataplane + "
   419	                 "valid/invalid day-0 drives)...")
   420	            if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
   421	                               "--qcow2", qcow_out, "--metadata", meta_out, "all"]).returncode != 0:
   422	                die(f"validation gate FAILED — artifacts in {a.out} are NOT publishable")
   423	
   424	        info(f"bake complete: {qcow_out}")
   425	        info("deploy quickstarts: docs/install-images.md")
   426	        return 0
   427	    finally:
   428	        if a.keep_work:
   429	            print(f"keeping work dir: {work}")
   430	        else:
   431	            shutil.rmtree(work, ignore_errors=True)
   432	
   433	
   434	if __name__ == "__main__":
   435	    sys.exit(main())

exec
/bin/bash -lc "nl -ba debian/xpf.postinst | sed -n '1,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/bin/sh
     2	# xpf postinst (#1917 — increment A packaging + increment B cut-over hook).
     3	#
     4	# dpkg installs the binary set to the dpkg-static staging path
     5	# /usr/local/share/xpf/staged/. The running daemon resolves its
     6	# binaries via /usr/local/sbin/* which are SYMLINKS. On FIRST install
     7	# (no previously configured version) we create those symlinks so xpfd
     8	# runs. On UPGRADE we leave the live symlinks untouched and hand the
     9	# verified cut-over to the increment-B mechanism (`xpfd upgrade`):
    10	#
    11	#  - STANDALONE node: the postinst invokes `xpfd upgrade` — the
    12	#    verified, atomic, rollback-capable STOP->FLIP->START cut to the
    13	#    staged version (the increment-A window is now closed: the cut
    14	#    copies staging into a versioned runtime dir, runs the kernel
    15	#    verify gate, flips atomically, and pins the unit ExecStart to the
    16	#    concrete version so a respawn never resolves a mismatched helper).
    17	#  - CLUSTERED node (/etc/xpf/node-id present): STAGE-ONLY. The postinst
    18	#    does NOT cut — a clustered node is cut ONLY by `xpfd upgrade
    19	#    --rolling`, which sequences a controlled per-node drain so the
    20	#    cluster keeps forwarding. Keyed on node-id ALONE so a degraded-HA
    21	#    node never falls through to an uncoordinated standalone cut.
    22	
    23	set -e
    24	
    25	STAGED=/usr/local/share/xpf/staged
    26	SBIN=/usr/local/sbin
    27	BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
    28	
    29	case "$1" in
    30	    configure)
    31	        # $2 is the previously-configured version, empty on first install.
    32	        if [ -z "$2" ]; then
    33	            mkdir -p "$SBIN"
    34	            for b in $BINS; do
    35	                # First install: point the live path at the staged binary.
    36	                # ln -sfnT replaces a pre-existing symlink atomically and,
    37	                # crucially, FAILS (under set -e) rather than nesting a
    38	                # symlink INSIDE the target if it happens to be a real
    39	                # directory — a directory at /usr/local/sbin/xpfd would
    40	                # otherwise leave the daemon unlaunchable with a "success".
    41	                ln -sfnT "$STAGED/$b" "$SBIN/$b"
    42	            done
    43	        else
    44	            # Upgrade: do NOT touch the live symlinks. Only create one that
    45	            # is COMPLETELY absent (not even a broken symlink); never repoint
    46	            # an existing OR dangling link. Repointing while the daemon is up
    47	            # would let the running xpfd resolve a different-version helper,
    48	            # and stealing a dangling link that increment-B repointed to a
    49	            # transiently-missing /var/lib/xpf/versions/<v>/ target would
    50	            # bypass its verify gate. -e alone follows the link (a broken
    51	            # link reads as absent), so guard with -L too.
    52	            for b in $BINS; do
    53	                if [ ! -e "$SBIN/$b" ] && [ ! -L "$SBIN/$b" ]; then
    54	                    mkdir -p "$SBIN"
    55	                    ln -sfnT "$STAGED/$b" "$SBIN/$b"
    56	                fi
    57	            done
    58	
    59	            # === increment-B cut-over (HA-mode contract, plan §6.3) ===
    60	            #
    61	            # dpkg has refreshed the staging path. Whether we now CUT OVER
    62	            # to it depends on whether this is a clustered node:
    63	            #
    64	            #  - CLUSTERED node (/etc/xpf/node-id present): STAGE-ONLY. We
    65	            #    MUST NOT perform a local single-node cut — that would take
    66	            #    one node down uncoordinated and bypass the rolling drain.
    67	            #    The cut is driven ONLY by `xpfd upgrade --rolling` (operator
    68	            #    or the dogfood deploy driver), which sequences the
    69	            #    controlled drain and itself checks peer liveness. The gate
    70	            #    is keyed on the node-id file ALONE, NOT on a "live cluster"
    71	            #    check: a degraded-HA node (node-id present but peer/daemon
    72	            #    down at apt time) must NOT fall through to a standalone cut.
    73	            #    "live cluster" is a ROLLING-readiness check, not postinst
    74	            #    cut permission.
    75	            #
    76	            #  - STANDALONE node (no node-id): invoke the verified
    77	            #    single-node STOP->FLIP->START cut. This is a bounded,
    78	            #    MEASURED multi-second dataplane gap (the helper cannot be
    79	            #    re-attached today — true zero-gap is future M-mech-2); the
    80	            #    verify gate + atomic flip + rollback still earn their keep
    81	            #    over a blind binary swap. The operator can suppress the
    82	            #    auto-cut with XPF_NO_POSTINST_CUT=1 and run `xpfd upgrade`
    83	            #    manually.
    84	            if [ -f /etc/xpf/node-id ]; then
    85	                echo "xpf: clustered node (node-id present) — staged only;" \
    86	                     "cut over with: xpfd upgrade --rolling" >&2
    87	            elif [ "${XPF_NO_POSTINST_CUT:-}" = "1" ]; then
    88	                echo "xpf: XPF_NO_POSTINST_CUT=1 — staged only;" \
    89	                     "cut over with: xpfd upgrade" >&2
    90	            else
    91	                echo "xpf: standalone node — performing verified in-place cut-over" >&2
    92	                # Run the staged binary's upgrade subcommand: it copies
    93	                # staging into the versioned runtime dir, runs the kernel
    94	                # verify-dataplane gate, and on PASS does the atomic
    95	                # STOP->FLIP->START with rollback. A REJECT/abort leaves the
    96	                # running daemon untouched. We do NOT fail the package
    97	                # install on a cut-over abort (the operator can re-run
    98	                # xpf-upgrade); surface it loudly instead.
    99	                if ! "$STAGED/xpfd" upgrade; then
   100	                    echo "xpf: WARNING in-place cut-over did not complete." >&2
   101	                    # Safety net (Copilot): the cut STOPs the unit before it
   102	                    # FLIPs. Most failures (preflight/copy/verify) abort
   103	                    # BEFORE the stop and leave the daemon running; the
   104	                    # standalone START failure path auto-rolls-back and
   105	                    # restarts. But a flip/daemon-reload error between STOP
   106	                    # and START could leave the unit stopped. If it is not
   107	                    # active, try to bring it back up so the node is not left
   108	                    # offline after `apt upgrade`.
   109	                    if ! systemctl is-active --quiet xpfd; then
   110	                        echo "xpf: unit not active after a failed cut-over; restarting" >&2
   111	                        systemctl start xpfd 2>/dev/null || \
   112	                            echo "xpf: WARNING could not restart xpfd; run: xpfd upgrade" >&2
   113	                    fi
   114	                    echo "xpf: inspect with 'journalctl -u xpfd' and re-run: xpfd upgrade" >&2
   115	                fi
   116	            fi
   117	        fi
   118	        # State under /etc/xpf (.configdb, node-id, master.key) is runtime
   119	        # state, NOT package-owned. Do not create, seed, or modify it here.
   120	        ;;
   121	    abort-upgrade|abort-remove|abort-deconfigure)
   122	        ;;
   123	    *)
   124	        echo "postinst called with unknown argument \`$1'" >&2
   125	        exit 1
   126	        ;;
   127	esac
   128	
   129	#DEBHELPER#
   130	
   131	exit 0

exec
/bin/bash -lc "nl -ba debian/xpf.postrm | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/bin/sh
     2	# xpf postrm (increment A of #1917).
     3	#
     4	# Remove ONLY the live /usr/local/sbin symlinks this package created,
     5	# and ONLY when they still point into our staging path (so we never
     6	# clobber an operator's or increment-B's relinked target). State under
     7	# /etc/xpf (.configdb, node-id, master.key) is runtime state and is
     8	# NEVER touched here, not even on purge.
     9	
    10	set -e
    11	
    12	STAGED=/usr/local/share/xpf/staged
    13	SBIN=/usr/local/sbin
    14	BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
    15	
    16	case "$1" in
    17	    remove|purge)
    18	        for b in $BINS; do
    19	            link="$SBIN/$b"
    20	            # Only remove a symlink we own (target inside the staging path).
    21	            if [ -L "$link" ]; then
    22	                target=$(readlink "$link" 2>/dev/null || true)
    23	                case "$target" in
    24	                    "$STAGED"/*)
    25	                        rm -f "$link"
    26	                        ;;
    27	                esac
    28	            fi
    29	        done
    30	        ;;
    31	    upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
    32	        ;;
    33	    *)
    34	        echo "postrm called with unknown argument \`$1'" >&2
    35	        exit 1
    36	        ;;
    37	esac
    38	
    39	#DEBHELPER#
    40	
    41	exit 0

exec
/bin/bash -lc "rg -n 'install\\.sh|XPF_DIST_BASE_URL|XPF_IMAGE_BASE_URL|XPF_APT_BASE_URL|latest\\.json|SHA256SUMS|signed|verify' docs/research/1924-signed-hosted-dist/plan.md docs/install-images.md CLAUDE.md README.md Makefile scripts/image/bake.py scripts/image/validate.py scripts/deploy/xpf-deploy.py debian/control debian/rules debian/xpf.postinst" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
debian/xpf.postinst:15:#    verify gate, flips atomically, and pins the unit ExecStart to the
debian/xpf.postinst:50:            # bypass its verify gate. -e alone follows the link (a broken
debian/xpf.postinst:80:            #    verify gate + atomic flip + rollback still earn their keep
debian/xpf.postinst:94:                # verify-dataplane gate, and on PASS does the atomic
debian/xpf.postinst:102:                    # FLIPs. Most failures (preflight/copy/verify) abort
debian/control:23: mechanism that flips them after a verify gate is a separate increment
scripts/deploy/xpf-deploy.py:387:        print(f"\n{name}: verify with `virsh console {name}` then "
debian/rules:42:# The package-owned xpfd.service gets an ExecStartPre verify-dataplane
debian/rules:56:	sed -E '/^[[:space:]]*ExecStart[[:space:]]*=/i ExecStartPre=/usr/local/sbin/xpfd verify-dataplane' \
debian/rules:58:	grep -q '^ExecStartPre=/usr/local/sbin/xpfd verify-dataplane$$' debian/xpf.xpfd.service || \
debian/rules:59:	    { echo "FATAL: ExecStartPre verify-dataplane injection failed (xpfd.service ExecStart line not matched)" >&2; exit 1; }
scripts/image/validate.py:8:     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
scripts/image/validate.py:146:        info("in-guest verify-dataplane (the bake gate, image kernel)...")
scripts/image/validate.py:147:        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
scripts/image/validate.py:149:            fail("in-guest verify-dataplane REJECTED — image must not ship")
Makefile:103:# verify-dataplane validation gate. See docs/install-images.md.
Makefile:192:# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
Makefile:196:# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
CLAUDE.md:97:verify-dataplane gate. Full protocol: `docs/engineering-style.md`.
CLAUDE.md:221:- Every interface must be defined in the firewall config and assigned to a security zone
docs/install-images.md:18:| `dist/SHA256SUMS` | both | `sha256sum -c` |
docs/install-images.md:42:   (`XPF_BASE_RELEASE` pins one), then fetch + SHA256-verify the
docs/install-images.md:70:6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
docs/install-images.md:74:   driver set check) with `xpfd verify-dataplane` IN-GUEST against
docs/install-images.md:182:- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
docs/install-images.md:196:`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
docs/install-images.md:220:single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
scripts/image/bake.py:9:  dist/SHA256SUMS
scripts/image/bake.py:12:#1864 tracked shim) -> discover + SHA256-verify the latest Ubuntu cloud
scripts/image/bake.py:19:manifest -> in-guest verify-dataplane validation gate (validate.py).
scripts/image/bake.py:165:    # Re-verify the cache against the upstream checksum (cache not trusted).
scripts/image/bake.py:166:    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
scripts/image/bake.py:167:    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
scripts/image/bake.py:176:        die(f"no SHA256 for {img} in upstream SHA256SUMS")
scripts/image/bake.py:323:        # build-host pre-gate (best-effort): verify the embedded shim against
scripts/image/bake.py:335:            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
scripts/image/bake.py:338:                               staged_xpfd, "verify-dataplane"]).returncode != 0:
scripts/image/bake.py:341:            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
scripts/image/bake.py:393:        sums = os.path.join(a.out, "SHA256SUMS")
scripts/image/bake.py:416:                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
scripts/image/bake.py:418:            info("running validation gate (factory boot + in-guest verify-dataplane + "
docs/research/1924-signed-hosted-dist/plan.md:1:# Plan of action — #1924: signed, hosted appliance distribution
docs/research/1924-signed-hosted-dist/plan.md:7:> Branch: research/1924-signed-hosted-dist
docs/research/1924-signed-hosted-dist/plan.md:17:- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
docs/research/1924-signed-hosted-dist/plan.md:19:  (provenance text). Neither is signed. An operator who downloads the image
docs/research/1924-signed-hosted-dist/plan.md:22:  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
docs/research/1924-signed-hosted-dist/plan.md:29:  explicitly designed as "the operator-facing entry point: `apt install
docs/research/1924-signed-hosted-dist/plan.md:31:  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
docs/research/1924-signed-hosted-dist/plan.md:38:packages from a trusted, signed source instead of copying files by hand.
docs/research/1924-signed-hosted-dist/plan.md:43:operator/infra/security decisions. The mechanism is designed so both are
docs/research/1924-signed-hosted-dist/plan.md:52:These are surfaced as config inputs — `XPF_IMAGE_BASE_URL` + `XPF_APT_BASE_URL`
docs/research/1924-signed-hosted-dist/plan.md:55:"XPF_DIST_BASE_URL" mean whichever of the two URLs serves the artifact in
docs/research/1924-signed-hosted-dist/plan.md:65:| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
docs/research/1924-signed-hosted-dist/plan.md:66:| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
docs/research/1924-signed-hosted-dist/plan.md:68:| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
docs/research/1924-signed-hosted-dist/plan.md:69:| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
docs/research/1924-signed-hosted-dist/plan.md:84:1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
docs/research/1924-signed-hosted-dist/plan.md:89:3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
docs/research/1924-signed-hosted-dist/plan.md:94:**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
docs/research/1924-signed-hosted-dist/plan.md:99:`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
docs/research/1924-signed-hosted-dist/plan.md:107:- `XPF_IMAGE_BASE_URL` (OQ-1a): serves the image artifacts + sigs +
docs/research/1924-signed-hosted-dist/plan.md:108:  `latest.json` + `install.sh`. Satisfiable by ANY static host INCLUDING
docs/research/1924-signed-hosted-dist/plan.md:110:- `XPF_APT_BASE_URL` (OQ-1b): serves the `dists/`+`pool/` tree. Requires a
docs/research/1924-signed-hosted-dist/plan.md:112:  Releases CANNOT serve this** (flat assets only). install.sh writes
docs/research/1924-signed-hosted-dist/plan.md:113:  `URIs: <XPF_APT_BASE_URL>`.
docs/research/1924-signed-hosted-dist/plan.md:122:- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
docs/research/1924-signed-hosted-dist/plan.md:126:  signed `Release`/`InRelease` once the archive keyring is installed under
docs/research/1924-signed-hosted-dist/plan.md:127:  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
docs/research/1924-signed-hosted-dist/plan.md:129:The `install.sh` bootstrap is the ONLY moment trust is established over the
docs/research/1924-signed-hosted-dist/plan.md:131:**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
docs/research/1924-signed-hosted-dist/plan.md:133:install.sh's own integrity is therefore the bootstrap root. The minisign
docs/research/1924-signed-hosted-dist/plan.md:134:**image** pubkey (`xpf-image.pub`) used for Tier-B verify-before-run has its
docs/research/1924-signed-hosted-dist/plan.md:136:GitHub — independent of `XPF_DIST_BASE_URL`**; the copy served from the dist
docs/research/1924-signed-hosted-dist/plan.md:142:### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
docs/research/1924-signed-hosted-dist/plan.md:152:- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
docs/research/1924-signed-hosted-dist/plan.md:165:is dramatically simpler to verify in install.sh and in our Python consumers.)
docs/research/1924-signed-hosted-dist/plan.md:168:Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
docs/research/1924-signed-hosted-dist/plan.md:170:(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
docs/research/1924-signed-hosted-dist/plan.md:182:| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |
docs/research/1924-signed-hosted-dist/plan.md:188:  releases): reprepro.** Smallest mature tool, signed `Release`/`InRelease`,
docs/research/1924-signed-hosted-dist/plan.md:192:  flat signed repo** generated from scratch via `apt-ftparchive` /
docs/research/1924-signed-hosted-dist/plan.md:195:  download`'d), the new `.deb` added, the indices regenerated, re-signed,
docs/research/1924-signed-hosted-dist/plan.md:201:**Default recommendation: the flat signed repo**, because it is robust to BOTH
docs/research/1924-signed-hosted-dist/plan.md:205:signed `InRelease`), so the install.sh side is unaffected by the choice.
docs/research/1924-signed-hosted-dist/plan.md:212:Channel layout (deb822, the contract install.sh writes):
docs/research/1924-signed-hosted-dist/plan.md:216:  URIs: <XPF_APT_BASE_URL>             # OQ-1b (dists/+pool/ tree)
docs/research/1924-signed-hosted-dist/plan.md:223:### 4C. install.sh trust-bootstrap (the security-critical step)
docs/research/1924-signed-hosted-dist/plan.md:227:| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
docs/research/1924-signed-hosted-dist/plan.md:228:| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
docs/research/1924-signed-hosted-dist/plan.md:232:install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
docs/research/1924-signed-hosted-dist/plan.md:233:through apt's own signed `Release`. The keyring-in-install.sh means there is
docs/research/1924-signed-hosted-dist/plan.md:234:exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
docs/research/1924-signed-hosted-dist/plan.md:235:and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
docs/research/1924-signed-hosted-dist/plan.md:238:from §3. The trust model is therefore precisely: *"an authentic install.sh
docs/research/1924-signed-hosted-dist/plan.md:243:- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
docs/research/1924-signed-hosted-dist/plan.md:244:  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
docs/research/1924-signed-hosted-dist/plan.md:246:  user (they ran the script before verifying). State this honestly.
docs/research/1924-signed-hosted-dist/plan.md:247:- **Tier B — verify-before-run.** The operator obtains `xpf-image.pub` **via
docs/research/1924-signed-hosted-dist/plan.md:248:  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
docs/research/1924-signed-hosted-dist/plan.md:249:  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
docs/research/1924-signed-hosted-dist/plan.md:252:  release notes, NEVER from `XPF_DIST_BASE_URL`."
docs/research/1924-signed-hosted-dist/plan.md:263:release upload`s the image tree (images + sigs + `latest.json` + install.sh) to
docs/research/1924-signed-hosted-dist/plan.md:264:`XPF_IMAGE_BASE_URL` and the flat `apt/` pool tree to `XPF_APT_BASE_URL` (§3 N4
docs/research/1924-signed-hosted-dist/plan.md:272:### 5.1 Image signing (bake.py, additive) — PER-VERSION, not a global SHA256SUMS
docs/research/1924-signed-hosted-dist/plan.md:276:`dist/SHA256SUMS`. Instead each bake writes a **per-version, version-named**
docs/research/1924-signed-hosted-dist/plan.md:279:dist/xpf-<ver>.SHA256SUMS          # lists exactly this version's qcow2 + metadata
docs/research/1924-signed-hosted-dist/plan.md:280:dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
docs/research/1924-signed-hosted-dist/plan.md:284:minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
docs/research/1924-signed-hosted-dist/plan.md:285:         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
docs/research/1924-signed-hosted-dist/plan.md:288:  v1's checksums — each version owns its signed manifest. A `latest` symlink/
docs/research/1924-signed-hosted-dist/plan.md:293:  can verify it without the metadata present (AGY-HIGH-1).
docs/research/1924-signed-hosted-dist/plan.md:296:  the publish-time guard (§5.5) then REFUSES to publish unsigned artifacts —
docs/research/1924-signed-hosted-dist/plan.md:301:  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
docs/research/1924-signed-hosted-dist/plan.md:304:### 5.2 Image verify (validate.py + xpf-deploy.py) — verify the EXACT imported file
docs/research/1924-signed-hosted-dist/plan.md:308:1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
docs/research/1924-signed-hosted-dist/plan.md:317:Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
docs/research/1924-signed-hosted-dist/plan.md:320:- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
docs/research/1924-signed-hosted-dist/plan.md:321:  to the artifacts; `--no-verify-sig` escape hatch for local dev bakes).
docs/research/1924-signed-hosted-dist/plan.md:322:- **r3 (resolves N1) — image verify lives at IMPORT time, not alias-launch.**
docs/research/1924-signed-hosted-dist/plan.md:330:     <qcow2>`; verify the exact `--qcow2`/`--metadata` files there.
docs/research/1924-signed-hosted-dist/plan.md:332:     `XPF_IMAGE_BASE_URL`, verifies the EXACT downloaded file, then imports it
docs/research/1924-signed-hosted-dist/plan.md:334:     and simply consumes a previously-verified alias (documented: "verify at
docs/research/1924-signed-hosted-dist/plan.md:340:Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
docs/research/1924-signed-hosted-dist/plan.md:341:- Inputs: the existing pool (synced down from `XPF_APT_BASE_URL` if present),
docs/research/1924-signed-hosted-dist/plan.md:358:### 5.4 install.sh (NEW)
docs/research/1924-signed-hosted-dist/plan.md:365:   `XPF_APT_BASE_URL` substituted; default channel `stable`,
docs/research/1924-signed-hosted-dist/plan.md:370:install.sh's inline keyring bootstraps NEW hosts, but existing hosts never
docs/research/1924-signed-hosted-dist/plan.md:371:re-run install.sh, so a key rotation would lock them out of `apt update` once
docs/research/1924-signed-hosted-dist/plan.md:382:- `install.sh` is itself published at `XPF_IMAGE_BASE_URL/install.sh` and the
docs/research/1924-signed-hosted-dist/plan.md:383:  doc gives both Tier A (one-liner) and Tier B (verify-before-run) per §4C.
docs/research/1924-signed-hosted-dist/plan.md:386:install.sh's FIRST install is safe (no running daemon to cut). But a later
docs/research/1924-signed-hosted-dist/plan.md:406:  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
docs/research/1924-signed-hosted-dist/plan.md:410:  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
docs/research/1924-signed-hosted-dist/plan.md:412:  (c) `install.sh.minisig` verifies (if install.sh is in the set); **(d) r3
docs/research/1924-signed-hosted-dist/plan.md:413:  (resolves N2): the per-channel `latest.json` verifies against the image pubkey
docs/research/1924-signed-hosted-dist/plan.md:414:  AND names a version present in the publish set** (so a stale/unsigned
docs/research/1924-signed-hosted-dist/plan.md:416:  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
docs/research/1924-signed-hosted-dist/plan.md:420:  (image tree → `XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`); idempotent
docs/research/1924-signed-hosted-dist/plan.md:425:  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
docs/research/1924-signed-hosted-dist/plan.md:426:  image verify steps, the out-of-band pubkey source).
docs/research/1924-signed-hosted-dist/plan.md:428:  verify from `XPF_DIST_BASE_URL`"; document the per-version
docs/research/1924-signed-hosted-dist/plan.md:429:  `xpf-<ver>.SHA256SUMS.minisig`.
docs/research/1924-signed-hosted-dist/plan.md:433:Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
docs/research/1924-signed-hosted-dist/plan.md:435:- **Apt:** the signed `Release`/`InRelease` carries `Valid-Until` (flat path
docs/research/1924-signed-hosted-dist/plan.md:438:  re-signed each publish. **r3 (resolves NIT-1): with MANUAL/air-gap signing
docs/research/1924-signed-hosted-dist/plan.md:444:- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
docs/research/1924-signed-hosted-dist/plan.md:445:  bake date + the per-version manifest name) signed with the image key. The
docs/research/1924-signed-hosted-dist/plan.md:446:  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
docs/research/1924-signed-hosted-dist/plan.md:451:  BEST-EFFORT (a fresh workstation has no watermark and trusts latest.json's
docs/research/1924-signed-hosted-dist/plan.md:462:1. **Sign/verify round-trip (image):** bake (or a stub per-version
docs/research/1924-signed-hosted-dist/plan.md:463:   `xpf-<ver>.SHA256SUMS`) → sign with a throwaway minisign key →
docs/research/1924-signed-hosted-dist/plan.md:464:   `verify_image_artifact` PASSES; flip one byte of the qcow2 → verify FAILS at
docs/research/1924-signed-hosted-dist/plan.md:465:   the parsed-hash comparison (§5.2); flip the `.minisig` → verify FAILS at
docs/research/1924-signed-hosted-dist/plan.md:467:   verify that can't fail is theater.)
docs/research/1924-signed-hosted-dist/plan.md:468:2. **Apt repo:** build the signed repo into a temp dir → spin a Debian
docs/research/1924-signed-hosted-dist/plan.md:469:   container (or the local incus image flow) → run install.sh pointed at a
docs/research/1924-signed-hosted-dist/plan.md:473:3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
docs/research/1924-signed-hosted-dist/plan.md:479:   invoked). With everything signed it proceeds. (The single most likely
docs/research/1924-signed-hosted-dist/plan.md:480:   production mistake — publishing an unsigned dev bake — is blocked here.)
docs/research/1924-signed-hosted-dist/plan.md:482:   update` fail; `latest.json` older than the remembered version is rejected by
docs/research/1924-signed-hosted-dist/plan.md:497:- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
docs/research/1924-signed-hosted-dist/plan.md:498:  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
docs/research/1924-signed-hosted-dist/plan.md:499:  negative tests; docs). Shippable alone; gives signed images immediately.
docs/research/1924-signed-hosted-dist/plan.md:501:  FLAT signed repo default per §4B, reprepro opt-in via `XPF_APT_TOOL`;
docs/research/1924-signed-hosted-dist/plan.md:504:- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
docs/research/1924-signed-hosted-dist/plan.md:505:  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
docs/research/1924-signed-hosted-dist/plan.md:518:- **R1 — install.sh is the trust root over the network.** A compromised host
docs/research/1924-signed-hosted-dist/plan.md:519:  serving a bad install.sh defeats everything. Mitigation: publish install.sh
docs/research/1924-signed-hosted-dist/plan.md:521:  self-authenticating once install.sh runs); document a verify-before-run
docs/research/1924-signed-hosted-dist/plan.md:522:  variant (publish `install.sh.minisig` too, signed by the image key, so the
docs/research/1924-signed-hosted-dist/plan.md:523:  paranoid operator verifies install.sh with the SAME pinned pubkey they used
docs/research/1924-signed-hosted-dist/plan.md:525:  the image and install.sh.
docs/research/1924-signed-hosted-dist/plan.md:544:  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
docs/research/1924-signed-hosted-dist/plan.md:550:  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
docs/research/1924-signed-hosted-dist/plan.md:556:- **OQ-1 (hosting target):** the values of `XPF_IMAGE_BASE_URL` (images +
docs/research/1924-signed-hosted-dist/plan.md:557:  install.sh + latest.json) and `XPF_APT_BASE_URL` (the dists/+pool/ tree — NOT
docs/research/1924-signed-hosted-dist/plan.md:574:## 10. Why not just keep SHA256SUMS?
docs/research/1924-signed-hosted-dist/plan.md:579:a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
docs/research/1924-signed-hosted-dist/plan.md:584:- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
docs/research/1924-signed-hosted-dist/plan.md:586:- Apt: **flat signed repo** (default, stateless-CI-safe; reprepro opt-in for
docs/research/1924-signed-hosted-dist/plan.md:587:  persistent publishers) with PGP-signed `InRelease`/`Release`, `stable`/`edge`
docs/research/1924-signed-hosted-dist/plan.md:589:  shipped BOTH inline in install.sh (new installs) AND in the package payload
docs/research/1924-signed-hosted-dist/plan.md:592:- Bootstrap: **install.sh** with the archive keyring embedded inline +
docs/research/1924-signed-hosted-dist/plan.md:593:  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
docs/research/1924-signed-hosted-dist/plan.md:595:  `XPF_IMAGE_BASE_URL` / `XPF_APT_BASE_URL`. No backend hardcoded.
docs/research/1924-signed-hosted-dist/plan.md:611:| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
docs/research/1924-signed-hosted-dist/plan.md:613:| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
docs/research/1924-signed-hosted-dist/plan.md:614:| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
docs/research/1924-signed-hosted-dist/plan.md:616:| Publish not fail-closed (unsigned dev bake can ship) | Codex-2, SMR-F6 | §5.5: `make dist-publish` precondition gate refuses unsigned artifacts. |
docs/research/1924-signed-hosted-dist/plan.md:617:| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
docs/research/1924-signed-hosted-dist/plan.md:618:| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
docs/research/1924-signed-hosted-dist/plan.md:619:| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
docs/research/1924-signed-hosted-dist/plan.md:641:| N1 — xpf-deploy.py can't bind image bytes (incus alias-launch flow has no qcow2 path) | Codex-1, SMR-N1 | §5.2: image verify lives at IMPORT (validate.py) + a NEW `xpf-deploy.py fetch`/`--image-url`; the alias-launch path no longer claims to verify. |
docs/research/1924-signed-hosted-dist/plan.md:642:| N2 — fail-closed publish omits the freshness `latest.json` | Codex-2, SMR-N2 | §5.5 gate clause (d): `latest.json` must verify AND name a version in the publish set. |
docs/research/1924-signed-hosted-dist/plan.md:644:| N4 — GitHub Releases listed as a full hosting target but can't serve dists/pool | Codex-4, SMR-N4 | §3: TWO base URLs — `XPF_IMAGE_BASE_URL` (GH Releases OK) vs `XPF_APT_BASE_URL` (directory host required); §9 OQ-1 + all functional refs split. |
docs/research/1924-signed-hosted-dist/plan.md:645:| N5 — "fresh Debian/Ubuntu host" overpromise (kernel ≥6.18 floor) | Codex-5, SMR-N5 | §3 + §5.4: install.sh PREFLIGHT refuses kernel <6.18 / non-amd64 / no-networkd with a clear message; image stays the turnkey path. |

exec
/bin/bash -lc "rg -n 'Package:|Depends:|Description:|conffile|keyring|systemd-networkd|networkd|kernel|linux-generic|6\\.18|xpf-appliance' debian/control debian/rules debian/xpf.postinst scripts/image/bake.py docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
docs/research/1924-signed-hosted-dist/plan.md:14:(the `xpf` / `xpf-appliance` `.deb` + `make deb` + bake-installs-the-deb).
docs/research/1924-signed-hosted-dist/plan.md:28:- **No `apt` path.** The `xpf-appliance` metapackage (debian/control) is
docs/research/1924-signed-hosted-dist/plan.md:30:  xpf-appliance` … e.g. from a hosted apt repo" — but no such repo exists.
docs/research/1924-signed-hosted-dist/plan.md:69:| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
docs/research/1924-signed-hosted-dist/plan.md:70:| Packaged archive keyring (r3 NIT-2) | NEW (one `debian/install` line, no postinst logic) | ships `xpf-archive-keyring.asc` to `/etc/apt/keyrings/` so existing hosts get rotated keys via `apt upgrade` |
docs/research/1924-signed-hosted-dist/plan.md:87:2. **Build + sign an apt repo** for the `xpf` / `xpf-appliance` `.deb`s, so
docs/research/1924-signed-hosted-dist/plan.md:88:   `apt install xpf-appliance` works from a hosted, authenticated index.
docs/research/1924-signed-hosted-dist/plan.md:89:3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
docs/research/1924-signed-hosted-dist/plan.md:90:   ≥6.18 + systemd-networkd present), bootstraps trust (installs the archive
docs/research/1924-signed-hosted-dist/plan.md:91:   keyring), adds the apt source, and runs `apt install xpf-appliance` — one
docs/research/1924-signed-hosted-dist/plan.md:92:   command on a Debian/Ubuntu host **that already meets the kernel floor**.
docs/research/1924-signed-hosted-dist/plan.md:94:**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
docs/research/1924-signed-hosted-dist/plan.md:95:floor; it does NOT install a kernel.** The appliance's verifier floor is kernel
docs/research/1924-signed-hosted-dist/plan.md:96:≥6.18 + the mlx5/i40e driver set (the IMAGE owns that closure; `debian/control`
docs/research/1924-signed-hosted-dist/plan.md:97:states kernel handling is out of scope). A bare-metal `apt install
docs/research/1924-signed-hosted-dist/plan.md:98:xpf-appliance` on Debian 12 / Ubuntu 24.04 would install the packages but
docs/research/1924-signed-hosted-dist/plan.md:99:`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
docs/research/1924-signed-hosted-dist/plan.md:100:and REFUSES with a clear message ("xpf requires kernel ≥6.18 + native-XDP NIC;
docs/research/1924-signed-hosted-dist/plan.md:101:use the appliance image, or upgrade the host kernel") rather than leaving a
docs/research/1924-signed-hosted-dist/plan.md:126:  signed `Release`/`InRelease` once the archive keyring is installed under
docs/research/1924-signed-hosted-dist/plan.md:127:  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
docs/research/1924-signed-hosted-dist/plan.md:131:**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
docs/research/1924-signed-hosted-dist/plan.md:146:| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
docs/research/1924-signed-hosted-dist/plan.md:148:| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
docs/research/1924-signed-hosted-dist/plan.md:171:with a keyring, which is heavier and more error-prone to pin than `minisign
docs/research/1924-signed-hosted-dist/plan.md:220:  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
docs/research/1924-signed-hosted-dist/plan.md:227:| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
docs/research/1924-signed-hosted-dist/plan.md:228:| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
docs/research/1924-signed-hosted-dist/plan.md:233:through apt's own signed `Release`. The keyring-in-install.sh means there is
docs/research/1924-signed-hosted-dist/plan.md:236:the inline-embed and the "fetch keyring + pin fingerprint" options are mutually
docs/research/1924-signed-hosted-dist/plan.md:342:  the freshly built `dist/deb/xpf_*.deb` + `xpf-appliance_*.deb`, the channel
docs/research/1924-signed-hosted-dist/plan.md:360:1. PREFLIGHT (r3 N5): refuse non-amd64 / non-Debian-family / kernel <6.18 /
docs/research/1924-signed-hosted-dist/plan.md:361:   no systemd-networkd, each with a clear actionable message.
docs/research/1924-signed-hosted-dist/plan.md:362:2. Install the pinned archive keyring to `/etc/apt/keyrings/
docs/research/1924-signed-hosted-dist/plan.md:363:   xpf-archive-keyring.asc` (embedded inline, `0644`).
docs/research/1924-signed-hosted-dist/plan.md:367:4. `apt-get update && apt-get install -y xpf-appliance`.
docs/research/1924-signed-hosted-dist/plan.md:369:**r3 (resolves NIT-2) — the archive keyring also ships in the PACKAGE payload.**
docs/research/1924-signed-hosted-dist/plan.md:370:install.sh's inline keyring bootstraps NEW hosts, but existing hosts never
docs/research/1924-signed-hosted-dist/plan.md:372:the old key retires. The mechanism therefore ALSO ships the keyring as a
docs/research/1924-signed-hosted-dist/plan.md:373:package-owned conffile at `/etc/apt/keyrings/xpf-archive-keyring.asc` (in the
docs/research/1924-signed-hosted-dist/plan.md:376:standard apt-keyring-in-package pattern. (This is the one place #1924 touches
docs/research/1924-signed-hosted-dist/plan.md:377:`debian/` — a packaged keyring file + its `debian/install` line; no postinst
docs/research/1924-signed-hosted-dist/plan.md:387:`apt upgrade xpf-appliance` (the whole point of the repo) runs the `xpf`
docs/research/1924-signed-hosted-dist/plan.md:471:   xpf-appliance` succeeds → `apt-get update` against a TAMPERED `Release`
docs/research/1924-signed-hosted-dist/plan.md:474:   wrong arch; the inline-embedded keyring matches the archive signing key used
docs/research/1924-signed-hosted-dist/plan.md:520:  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
docs/research/1924-signed-hosted-dist/plan.md:543:  hazard applies harder to `apt install xpf-appliance` on a remote box than to
docs/research/1924-signed-hosted-dist/plan.md:588:  suites, deb822 `Signed-By`, `Valid-Until` freshness. The archive keyring is
docs/research/1924-signed-hosted-dist/plan.md:590:  (`/etc/apt/keyrings/xpf-archive-keyring.asc`) so existing hosts get rotated
docs/research/1924-signed-hosted-dist/plan.md:592:- Bootstrap: **install.sh** with the archive keyring embedded inline +
docs/research/1924-signed-hosted-dist/plan.md:614:| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
docs/research/1924-signed-hosted-dist/plan.md:624:| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |
docs/research/1924-signed-hosted-dist/plan.md:645:| N5 — "fresh Debian/Ubuntu host" overpromise (kernel ≥6.18 floor) | Codex-5, SMR-N5 | §3 + §5.4: install.sh PREFLIGHT refuses kernel <6.18 / non-amd64 / no-networkd with a clear message; image stays the turnkey path. |
docs/research/1924-signed-hosted-dist/plan.md:646:| NIT-2 — key rotation strands existing hosts (inline-only keyring) | AGY-NIT-2, SMR (elevated) | §5.4 + §2 + §11: archive keyring ALSO ships in the package payload (`/etc/apt/keyrings/`), so `apt upgrade` delivers rotated keys during the dual-sign window. One `debian/install` line, no postinst logic. |
docs/research/1924-signed-hosted-dist/plan.md:654:`debian/` touch in #1924 scope is the packaged keyring conffile (NIT-2); no
debian/xpf.postinst:14:#    copies staging into a versioned runtime dir, runs the kernel
debian/xpf.postinst:93:                # staging into the versioned runtime dir, runs the kernel
debian/rules:5:# xpfd embeds the kernel-verified AF_XDP shim (#1864) and the helper
debian/rules:43:# gate injected (plan §6.2 / §7): the #1864/#1869 kernel-verifier gate
debian/rules:44:# must run at EVERY boot, not only once at bake time — a later kernel
scripts/image/bake.py:14:virt-customize (runtime packages, linux-generic >= 6.18 with the full
scripts/image/bake.py:15:driver set, purge cloud-init/snapd/stale kernels, networkd,
scripts/image/bake.py:41:# same set the xpf-appliance metapackage Depends on (debian/control). The
scripts/image/bake.py:45:# the xpf-appliance metapackage is the operator-facing `apt install`
scripts/image/bake.py:196:        # enable xpfd`. The git-tracked, kernel-verified shim travels
scripts/image/bake.py:209:                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
scripts/image/bake.py:212:        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
scripts/image/bake.py:213:        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
scripts/image/bake.py:214:        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
scripts/image/bake.py:216:        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
scripts/image/bake.py:220:        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
scripts/image/bake.py:221:        # -generic kernel, so `apt install linux-generic` pulls a NEWER
scripts/image/bake.py:228:        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
scripts/image/bake.py:230:        # (this assert caught a real 2-kernel image during #1879 live bake).
scripts/image/bake.py:239:        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
scripts/image/bake.py:247:        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
scripts/image/bake.py:248:        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
scripts/image/bake.py:313:        # binary package (NOT the xpf-appliance metapackage) and pick the
scripts/image/bake.py:317:                       if "xpf-appliance" not in os.path.basename(g)),
scripts/image/bake.py:324:        # the build-host kernel before baking it in (#1864). Verify the xpfd
scripts/image/bake.py:336:                 f"(host kernel {os.uname().release})...")
scripts/image/bake.py:339:                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
scripts/image/bake.py:361:        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
scripts/image/bake.py:386:                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
scripts/image/bake.py:390:                    "  variant: xpf-appliance\n")
scripts/image/bake.py:410:                    f"bake_host_kernel: {os.uname().release}\n")
debian/control:5:Build-Depends: debhelper-compat (= 13)
debian/control:10:Package: xpf
debian/control:12:Depends: ${shlibs:Depends}, ${misc:Depends}
debian/control:13:Description: Junos-style firewall with AF_XDP userspace dataplane
debian/control:29:Package: xpf-appliance
debian/control:31:Depends: ${misc:Depends},
debian/control:52:Description: xpf firewall appliance metapackage
debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade

codex
The Debian touch is scoped correctly in spirit, but the wording is rubbing against this repo’s actual packaging style: the repo has two binary packages and currently installs `xpf` payload in `debian/rules`, not via an existing `.install` file. I’m verifying whether that rises above a wording nit before I call the verdict.
exec
/bin/bash -lc 'ls /usr/share/doc/debhelper 2>/dev/null' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
PROGRAMMING.md.gz
README
SUPPORT-POLICY
TODO
changelog.gz
copyright
examples

exec
/bin/bash -lc "dpkg -l debhelper 2>/dev/null | sed -n '1,20p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
+-- Desired=Unknown/Install/Remove/Purge/Hold
|+- Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
||+ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||| Name           Version      Architecture Description
+++-==============-============-============-=================================
ii  debhelper      13.31        all          helper programs for debian/rules

exec
/bin/bash -lc "rg -n 'debian/install|package\\.install|debian/.+\\.install|dh_install|single binary|multiple binary' /usr/share/doc/debhelper /usr/share/man/man1/dh_install.1.gz /usr/share/man/man7/debhelper.7.gz 2>/dev/null" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
/usr/share/doc/debhelper/TODO:7:* dh_installmanpages.
/usr/share/doc/debhelper/TODO:10:* dh_installinit --init-script (make it warn)
/usr/share/doc/debhelper/copyright:23:Files: dh_installcatalogs
/usr/share/doc/debhelper/copyright:31:Files: dh_installlogcheck
/usr/share/doc/debhelper/copyright:35:Files: dh_installudev
/usr/share/doc/debhelper/copyright:51:Files: dh_installinit
/usr/share/doc/debhelper/copyright:56:Files: dh_installgsettings

exec
/bin/bash -lc "man dh_install 2>/dev/null | col -b | rg -n 'debian/(package\\.)?install|debian/install|package\\.install|single binary|multiple binary|first package' -C 2" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
21-       two that the upstream Makefile does not install for you, you can run
22-       dh_install on them to move them into place. On the other hand, maybe you
23:       have a large package that builds multiple binary packages. You can use
24-       the upstream Makefile to install it all into debian/tmp, and then use
25-       dh_install to copy directories and files from there into the proper
--
31-
32-FILES
33:       debian/package.install
34-	   List	 the  files to install into each package and the directory they
35-	   should be installed to. The format is a set	of  lines,  where  each
--
81-	   Guess as the destination directory to install things to. If this  is
82-	   specified,	you   should   not   list  destination	directories  in
83:	   debian/package.install  files  or  on  the  command	line.  Instead,
84-	   dh_install will guess as follows:
85-
--
93-       file|dir ... destdir
94-	   Lists files (or directories) to install and where  to  install  them
95:	   to.	 The  files will be installed into the first package dh_install
96-	   acts on.
97-
--
126-
127-       However,	 renaming  and	filtering can be achieved by using dh-exec with
128:       compatibility level 9 or later.	An example debian/package.install  file
129-       using dh-exec could look like:
130-

codex
Debhelper’s local docs confirm the normal form is `debian/package.install`, and an unqualified install spec targets the first package `dh_install` acts on. Since the source package’s first binary package is `xpf`, a literal unqualified line probably lands in the intended package today, but it is brittle wording for a two-package source.
codex
I’ve found no architecture-level regression. The only things that still look worth calling out are wording-level: one stale functional `XPF_DIST_BASE_URL` reference and the literal “`debian/install` line” phrasing against a two-binary-package debhelper layout.
exec
/bin/bash -lc "nl -ba scripts/image/validate.py | sed -n '50,85p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
    50	                          check=check, capture_output=capture, text=True)
    51	
    52	
    53	def guest_sh(inst, script):
    54	    """Run a shell snippet in the guest; return True on exit 0."""
    55	    return subprocess.run(["incus", "exec", inst, "--", "sh", "-c", script],
    56	                          capture_output=True, text=True).returncode == 0
    57	
    58	
    59	class Harness:
    60	    def __init__(self, qcow2, metadata, net, keep):
    61	        self.qcow2, self.metadata, self.net, self.keep = qcow2, metadata, net, keep
    62	        self.created_net = False
    63	        self.instances = []
    64	        self.work = tempfile.mkdtemp(prefix="xpf-validate-")
    65	
    66	    # ── lifecycle ──
    67	    def ensure_network(self):
    68	        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
    69	            info(f"creating validation network {self.net} (NAT + DHCP)")
    70	            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
    71	                  "ipv4.nat=true", "ipv6.address=none")
    72	            self.created_net = True
    73	
    74	    def import_image(self):
    75	        incus("image", "delete", ALIAS, check=False, capture=True)
    76	        info(f"importing image into local incus as {ALIAS}")
    77	        incus("image", "import", self.metadata, self.qcow2, "--alias", ALIAS)
    78	
    79	    def launch(self, name, iso=None):
    80	        incus("delete", "-f", name, check=False, capture=True)
    81	        incus("init", ALIAS, name, "--vm", "--network", self.net,
    82	              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB", capture=True)
    83	        if iso:
    84	            incus("config", "device", "add", name, "day0", "disk",
    85	                  f"source={os.path.realpath(iso)}", capture=True)

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '400,456p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   400	  this so an operator does not `apt upgrade` both nodes expecting auto-rolling.
   401	- No `postinst` / `pkg/upgrade` code is in scope for #1924.
   402	
   403	### 5.5 Makefile + docs + fail-closed publish
   404	
   405	- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
   406	  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
   407	- **r2 fail-closed publish (resolves Codex-2 + SMR-F6):** `make dist-publish`
   408	  runs a PRECONDITION gate before invoking `XPF_PUBLISH_CMD`. It REFUSES (exit
   409	  non-zero, nothing uploaded) unless, for every artifact in the publish set:
   410	  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
   411	  pinned pubkey; (b) the apt `InRelease` verifies against the archive pubkey;
   412	  (c) `install.sh.minisig` verifies (if install.sh is in the set); **(d) r3
   413	  (resolves N2): the per-channel `latest.json` verifies against the image pubkey
   414	  AND names a version present in the publish set** (so a stale/unsigned
   415	  freshness pointer can never ship). Bake may be
   416	  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
   417	  can never reach the channel.
   418	- **r2 `XPF_PUBLISH_CMD` contract (resolves SMR-F5):** invoked exactly as
   419	  `$XPF_PUBLISH_CMD <local-dist-dir> <dest-base-url>`; called once per URL
   420	  (image tree → `XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`); idempotent
   421	  and exit non-zero on failure. The plan documents this signature so the
   422	  backend (rsync / `aws s3 sync` / `gh release upload` wrapper) is a thin shim.
   423	- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
   424	  channel policy, retention, publish backends, the `apt upgrade` blip note from
   425	  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
   426	  image verify steps, the out-of-band pubkey source).
   427	- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
   428	  verify from `XPF_DIST_BASE_URL`"; document the per-version
   429	  `xpf-<ver>.SHA256SUMS.minisig`.
   430	
   431	### 5.6 Freshness / anti-rollback (r2 — resolves Codex-4)
   432	
   433	Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
   434	Mitigations, scaled to a single-publisher appliance (not full TUF):
   435	- **Apt:** the signed `Release`/`InRelease` carries `Valid-Until` (flat path
   436	  sets it explicitly; reprepro via `conf/distributions` `ValidFor`). apt warns/
   437	  refuses a stale `Release` — built-in replay protection for the package path,
   438	  re-signed each publish. **r3 (resolves NIT-1): with MANUAL/air-gap signing
   439	  (OQ-4) a SHORT `Valid-Until` would expire the repo between releases and break
   440	  `apt update`. The mechanism therefore sets a LONG default `Valid-Until` (1
   441	  year) aligned to a manual cadence, and documents that a shorter window
   442	  REQUIRES an automated re-sign job. The duration is a config input
   443	  (`XPF_APT_VALID_DAYS`).**
   444	- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
   445	  bake date + the per-version manifest name) signed with the image key. The
   446	  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
   447	  older than a locally-remembered version (simple monotonic check), then
   448	  fetches the named version. **r3 (resolves NIT-3): the watermark is persisted
   449	  at `${XDG_STATE_HOME:-~/.local/state}/xpf/image-watermark.json`; because
   450	  xpf-deploy is a stateless multi-operator CLI, this check is documented as
   451	  BEST-EFFORT (a fresh workstation has no watermark and trusts latest.json's
   452	  own signature + date).** This is a LIGHTWEIGHT anti-rollback signal, not a
   453	  guarantee against a sophisticated freeze attack — documented honestly as
   454	  "detects stale mirrors / accidental rollback," with TUF-grade freshness
   455	  called out as a future option (not in #1924 scope). Flagged so reviewers do
   456	  not read it as a strong guarantee.

exec
/bin/bash -lc "rg -n '"'^```'"' docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
213:```
221:```
278:```
281:```
283:```
286:```

exec
/bin/bash -lc "nl -ba debian/control | sed -n '1,80p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	Source: xpf
     2	Section: net
     3	Priority: optional
     4	Maintainer: xpf maintainers <noreply@anthropic.com>
     5	Build-Depends: debhelper-compat (= 13)
     6	Standards-Version: 4.6.2
     7	Homepage: https://github.com/psaab/xpf
     8	Rules-Requires-Root: no
     9	
    10	Package: xpf
    11	Architecture: amd64
    12	Depends: ${shlibs:Depends}, ${misc:Depends}
    13	Description: Junos-style firewall with AF_XDP userspace dataplane
    14	 xpf is a Junos-style stateful firewall that clones Juniper vSRX
    15	 capabilities using native Junos configuration syntax. The runtime
    16	 forwarding path is a Rust AF_XDP userspace dataplane driven by the
    17	 Go control plane (xpfd).
    18	 .
    19	 This package ships the binary set (xpfd, xpf-userspace-dp, cli),
    20	 the day-0 config-drive loader, and the systemd units. Binaries are
    21	 installed to a dpkg-static staging path; the live /usr/local/sbin
    22	 symlinks are created on first install (the in-place upgrade cut-over
    23	 mechanism that flips them after a verify gate is a separate increment
    24	 and is intentionally not part of this package's postinst).
    25	 .
    26	 The AF_XDP shim is embedded into the xpfd binary (go:embed), so no
    27	 separate shim object is shipped.
    28	
    29	Package: xpf-appliance
    30	Architecture: amd64
    31	Depends: ${misc:Depends},
    32	 xpf (= ${binary:Version}),
    33	 frr,
    34	 strongswan,
    35	 strongswan-swanctl,
    36	 kea-dhcp4-server,
    37	 kea-dhcp6-server,
    38	 chrony,
    39	 iproute2,
    40	 nftables,
    41	 ethtool,
    42	 tcpdump,
    43	 pciutils,
    44	 iputils-ping,
    45	 traceroute,
    46	 openssh-server,
    47	 openssh-client,
    48	 systemd-resolved,
    49	 rsyslog,
    50	 curl,
    51	 ca-certificates
    52	Description: xpf firewall appliance metapackage
    53	 Pulls in the xpf firewall binary package plus the full runtime
    54	 dependency set (routing, IPsec, DHCP server, time sync, networking
    55	 tooling). This is the operator-facing entry point: `apt install
    56	 xpf-appliance` provisions a complete firewall in one step (e.g. from a
    57	 hosted apt repo).
    58	 .
    59	 NOTE: the appliance image bake (scripts/image/bake.py) installs the
    60	 runtime dependency set explicitly plus the xpf binary package, rather
    61	 than this metapackage, so apt does not have to resolve the full
    62	 dependency closure against a single local .deb during the offline bake.
    63	 The dependency set here MUST stay in sync with bake.py's
    64	 RUNTIME_PACKAGES.
    65	 .
    66	 The held/pinned kernel channel and the in-place kernel-upgrade
    67	 mechanism are out of scope for this package and tracked separately.

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '88,116p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
    88	   `apt install xpf-appliance` works from a hosted, authenticated index.
    89	3. **`install.sh`** (Tailscale-style) that runs a PREFLIGHT (amd64 + kernel
    90	   ≥6.18 + systemd-networkd present), bootstraps trust (installs the archive
    91	   keyring), adds the apt source, and runs `apt install xpf-appliance` — one
    92	   command on a Debian/Ubuntu host **that already meets the kernel floor**.
    93	
    94	**r3 (resolves N5) — install.sh targets a host that meets the IMAGE's kernel
    95	floor; it does NOT install a kernel.** The appliance's verifier floor is kernel
    96	≥6.18 + the mlx5/i40e driver set (the IMAGE owns that closure; `debian/control`
    97	states kernel handling is out of scope). A bare-metal `apt install
    98	xpf-appliance` on Debian 12 / Ubuntu 24.04 would install the packages but
    99	`xpfd verify-dataplane` would REJECT the host kernel. So install.sh PREFLIGHTS
   100	and REFUSES with a clear message ("xpf requires kernel ≥6.18 + native-XDP NIC;
   101	use the appliance image, or upgrade the host kernel") rather than leaving a
   102	broken install. The image (bake.py) remains the turnkey path for hosts that do
   103	not meet the floor.
   104	
   105	**r3 (resolves N4) — TWO base URLs, not one.** Images and the apt pool have
   106	different hosting shapes, so the mechanism takes two parameters:
   107	- `XPF_IMAGE_BASE_URL` (OQ-1a): serves the image artifacts + sigs +
   108	  `latest.json` + `install.sh`. Satisfiable by ANY static host INCLUDING
   109	  GitHub Releases (flat assets are fine for images).
   110	- `XPF_APT_BASE_URL` (OQ-1b): serves the `dists/`+`pool/` tree. Requires a
   111	  real directory-serving host (static bucket / Pages / file server) — **GitHub
   112	  Releases CANNOT serve this** (flat assets only). install.sh writes
   113	  `URIs: <XPF_APT_BASE_URL>`.
   114	They MAY be the same host (a bucket serves both); they need not be. Publishing
   115	is a thin `dist-publish` target parametrised by both (each fed to
   116	`XPF_PUBLISH_CMD`). The mechanism is host-agnostic per URL.

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '636,656p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   636	All r1 findings were confirmed RESOLVED by all three; r3 fixes the contradictions
   637	the r2 restructuring introduced + the rotation lockout.
   638	
   639	| Finding | Source(s) | Resolution in r3 |
   640	|---|---|---|
   641	| N1 — xpf-deploy.py can't bind image bytes (incus alias-launch flow has no qcow2 path) | Codex-1, SMR-N1 | §5.2: image verify lives at IMPORT (validate.py) + a NEW `xpf-deploy.py fetch`/`--image-url`; the alias-launch path no longer claims to verify. |
   642	| N2 — fail-closed publish omits the freshness `latest.json` | Codex-2, SMR-N2 | §5.5 gate clause (d): `latest.json` must verify AND name a version in the publish set. |
   643	| N3 — apt backend self-contradiction (flat-default vs §8/§11 "use reprepro") | Codex-3, SMR-N3 | §8 R3 + §11 summary rewritten to flat-default (`apt-ftparchive`), reprepro opt-in; Inc-2 wording fixed. |
   644	| N4 — GitHub Releases listed as a full hosting target but can't serve dists/pool | Codex-4, SMR-N4 | §3: TWO base URLs — `XPF_IMAGE_BASE_URL` (GH Releases OK) vs `XPF_APT_BASE_URL` (directory host required); §9 OQ-1 + all functional refs split. |
   645	| N5 — "fresh Debian/Ubuntu host" overpromise (kernel ≥6.18 floor) | Codex-5, SMR-N5 | §3 + §5.4: install.sh PREFLIGHT refuses kernel <6.18 / non-amd64 / no-networkd with a clear message; image stays the turnkey path. |
   646	| NIT-2 — key rotation strands existing hosts (inline-only keyring) | AGY-NIT-2, SMR (elevated) | §5.4 + §2 + §11: archive keyring ALSO ships in the package payload (`/etc/apt/keyrings/`), so `apt upgrade` delivers rotated keys during the dual-sign window. One `debian/install` line, no postinst logic. |
   647	| NIT-1 — Valid-Until vs manual signing expiry deadlock | AGY-NIT-1, SMR | §5.6: long default `Valid-Until` (1y, `XPF_APT_VALID_DAYS`) for manual cadence; short window requires an automated re-sign job. |
   648	| NIT-3 — monotonic freshness watermark has no storage | AGY-NIT-3, SMR | §5.6: watermark at `${XDG_STATE_HOME}/xpf/image-watermark.json`; documented best-effort for stateless/multi-operator CLI. |
   649	| Nit — §6 "fails at sha256sum -c" stale vs parsed verifier | Codex nit | §6 test 1 reworded to the parsed-hash comparison. |
   650	| Nit — stray code fence before §12 | Codex nit | Removed. |
   651	
   652	Affirmed unchanged across all rounds: minisign(image) + PGP(apt) split, deb822
   653	`Signed-By` (not apt-key), TOFU rejection, the additive blast radius. The only
   654	`debian/` touch in #1924 scope is the packaged keyring conffile (NIT-2); no
   655	postinst / `pkg/upgrade` code (AGY-HIGH-2 confirmed #1917-owned, documentation
   656	only).

codex
**Findings**

1. Nit: one stale functional URL name remains. r3 says “**TWO base URLs, not one**” and defines `XPF_IMAGE_BASE_URL` for images/install/latest plus `XPF_APT_BASE_URL` for `dists/`+`pool/` in [plan.md:105](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:105)-[113](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:113), but [plan.md:427](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:427)-[428](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:428) still says docs should “fetch + verify from `XPF_DIST_BASE_URL`”. Not a blocker because publish/install mechanics use the split URLs, but that line should say `XPF_IMAGE_BASE_URL`.

2. Nit: “one `debian/install` line” is sloppy for this repo. r3 says “one `debian/install` line” at [plan.md:70](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:70) and [plan.md:377](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:377), but `debian/control` has two binary packages, `xpf` and `xpf-appliance`, at [debian/control:10](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:10) and [debian/control:29](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:29), and current payload install is in [debian/rules:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/rules:66)-[75](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/rules:75). Say `debian/xpf.install` or “an xpf package install stanza/rules install”; the intended scope is otherwise correct.

**Verified**

N1 is resolved: [plan.md:322](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:322)-[335](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:335) now says verify at import/fetch, not alias launch. Current `xpf-deploy.py` backs that: incus uses `incus init ap["image"]` at [xpf-deploy.py:300](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/deploy/xpf-deploy.py:300), while `validate.py` imports exact `self.metadata, self.qcow2` at [validate.py:77](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/image/validate.py:77).

N2 is resolved: publish gate clause (d) now says “the per-channel `latest.json` verifies against the image pubkey AND names a version present in the publish set” at [plan.md:412](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:412)-[415](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:415).

N3 is resolved: r3 consistently defaults to flat signed repo: “Default recommendation: the flat signed repo” at [plan.md:201](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:201)-[205](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:205), and §5.3 says “Default = the flat signed repo” with `reprepro` opt-in at [plan.md:339](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:339)-[350](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:350).

N4 is resolved architecturally: image hosting and apt hosting are split in [plan.md:105](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:105)-[116](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:116), and OQ-1 explicitly says `XPF_APT_BASE_URL` is “NOT GitHub Releases; needs a directory-serving host” at [plan.md:556](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:556)-[558](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:558).

N5 is resolved: r3 now says install.sh “does NOT install a kernel” and refuses unsupported hosts with “xpf requires kernel ≥6.18…” at [plan.md:94](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:94)-[102](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:102), with PREFLIGHT spelled out at [plan.md:360](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:360)-[361](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:361). That matches `debian/control`, which says kernel handling is out of scope at [debian/control:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:66)-[67](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:67).

AGY NIT-1/2/3 are resolved: long `Valid-Until` is at [plan.md:438](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:438)-[443](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:443); packaged keyring rotation is at [plan.md:369](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:369)-[378](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:378); watermark storage and best-effort scope are at [plan.md:448](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:448)-[455](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:455). The old `sha256sum -c` test wording is fixed to “parsed-hash comparison” at [plan.md:464](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:464)-[465](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:465), and the code fences are balanced before §12.

PLAN-READY-WITH-NITS: r3 clears the five prior blocking contradictions and resolves AGY’s three nits without introducing a new architecture blocker; the remaining issues are wording precision only: replace the stale `XPF_DIST_BASE_URL` docs reference with `XPF_IMAGE_BASE_URL`, and phrase the keyring packaging change as `debian/xpf.install` or an `xpf` package install/rules addition rather than a generic `debian/install` line.
tokens used
93,737
**Findings**

1. Nit: one stale functional URL name remains. r3 says “**TWO base URLs, not one**” and defines `XPF_IMAGE_BASE_URL` for images/install/latest plus `XPF_APT_BASE_URL` for `dists/`+`pool/` in [plan.md:105](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:105)-[113](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:113), but [plan.md:427](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:427)-[428](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:428) still says docs should “fetch + verify from `XPF_DIST_BASE_URL`”. Not a blocker because publish/install mechanics use the split URLs, but that line should say `XPF_IMAGE_BASE_URL`.

2. Nit: “one `debian/install` line” is sloppy for this repo. r3 says “one `debian/install` line” at [plan.md:70](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:70) and [plan.md:377](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:377), but `debian/control` has two binary packages, `xpf` and `xpf-appliance`, at [debian/control:10](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:10) and [debian/control:29](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:29), and current payload install is in [debian/rules:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/rules:66)-[75](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/rules:75). Say `debian/xpf.install` or “an xpf package install stanza/rules install”; the intended scope is otherwise correct.

**Verified**

N1 is resolved: [plan.md:322](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:322)-[335](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:335) now says verify at import/fetch, not alias launch. Current `xpf-deploy.py` backs that: incus uses `incus init ap["image"]` at [xpf-deploy.py:300](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/deploy/xpf-deploy.py:300), while `validate.py` imports exact `self.metadata, self.qcow2` at [validate.py:77](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/image/validate.py:77).

N2 is resolved: publish gate clause (d) now says “the per-channel `latest.json` verifies against the image pubkey AND names a version present in the publish set” at [plan.md:412](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:412)-[415](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:415).

N3 is resolved: r3 consistently defaults to flat signed repo: “Default recommendation: the flat signed repo” at [plan.md:201](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:201)-[205](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:205), and §5.3 says “Default = the flat signed repo” with `reprepro` opt-in at [plan.md:339](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:339)-[350](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:350).

N4 is resolved architecturally: image hosting and apt hosting are split in [plan.md:105](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:105)-[116](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:116), and OQ-1 explicitly says `XPF_APT_BASE_URL` is “NOT GitHub Releases; needs a directory-serving host” at [plan.md:556](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:556)-[558](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:558).

N5 is resolved: r3 now says install.sh “does NOT install a kernel” and refuses unsupported hosts with “xpf requires kernel ≥6.18…” at [plan.md:94](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:94)-[102](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:102), with PREFLIGHT spelled out at [plan.md:360](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:360)-[361](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:361). That matches `debian/control`, which says kernel handling is out of scope at [debian/control:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:66)-[67](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:67).

AGY NIT-1/2/3 are resolved: long `Valid-Until` is at [plan.md:438](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:438)-[443](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:443); packaged keyring rotation is at [plan.md:369](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:369)-[378](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:378); watermark storage and best-effort scope are at [plan.md:448](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:448)-[455](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:455). The old `sha256sum -c` test wording is fixed to “parsed-hash comparison” at [plan.md:464](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:464)-[465](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:465), and the code fences are balanced before §12.

PLAN-READY-WITH-NITS: r3 clears the five prior blocking contradictions and resolves AGY’s three nits without introducing a new architecture blocker; the remaining issues are wording precision only: replace the stale `XPF_DIST_BASE_URL` docs reference with `XPF_IMAGE_BASE_URL`, and phrase the keyring packaging change as `debian/xpf.install` or an `xpf` package install/rules addition rather than a generic `debian/install` line.
