#!/usr/bin/env python3
"""xpf signed-distribution publish gate (#1924 §5.5).

Fail-CLOSED: refuses to publish (exits non-zero, uploads nothing) unless every
artifact in the publish set is properly signed:

  (a) each image manifest (xpf-<ver>.SHA256SUMS) has a verifying .minisig
      against the pinned image pubkey, AND the qcow2/metadata it lists are
      present and hash-match;
  (b) the apt InRelease verifies against the archive pubkey (when an apt tree
      is being published);
  (c) install.sh is PRESENT (required by default — the Tier-A one-liner URL
      404s without it; opt out with --no-installer), carries NO placeholder
      key and NO unsubstituted %%…%% marker (it must be stamped first), and
      has a verifying install.sh.minisig;
  (d) the per-channel latest.json verifies against the image pubkey AND names
      a version present in the image set.

The bake may be fail-OPEN (a dev bake without a key still produces artifacts),
but PUBLISH is fail-CLOSED — an unsigned dev bake can never reach the channel.

After the gate passes, dispatch the operator's backend exactly once per URL:

  $XPF_PUBLISH_CMD <local-dir> <dest-base-url>     # idempotent, exit!=0 on fail

  image tree (dist/, sigs, install.sh, latest.json) -> XPF_IMAGE_BASE_URL
  apt tree    (dist/apt/dists + pool)               -> XPF_APT_BASE_URL

XPF_PUBLISH_CMD is a thin shim the operator supplies (rsync / aws s3 sync /
gh release upload wrapper). No backend is hardcoded.

The two operator decisions (hosting URLs, signing identity) are config inputs:
XPF_IMAGE_BASE_URL / XPF_APT_BASE_URL and the pinned pubkeys / signing keys.

Usage:
  publish.py --channel stable [--dist DIR] [--no-image] [--no-apt]
             [--no-installer] [--dry-run]
  publish.py make-latest --channel stable --version V [--dist DIR]   # sign latest.json
  publish.py stamp-installer --out dist/install.sh [--apt-base-url URL]
             [--channel stable] [--archive-key PATH]  # bake key+URL then sign
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import sign  # noqa: E402


def info(m):
    print(f"==> {m}")


def die(m):
    sys.exit(f"PUBLISH ERROR: {m}")


def image_pubkey():
    """Resolve the minisign IMAGE pubkey ONCE, honoring XPF_IMAGE_PUBKEY
    (Codex-r2-3). Fail-CLOSED on the placeholder (Codex-r2-2): the gate must
    never verify against a key whose secret is held by no one."""
    pub = os.environ.get("XPF_IMAGE_PUBKEY") or sign.DEFAULT_IMAGE_PUBKEY
    if sign.is_placeholder_pubkey(pub):
        die("image pubkey is the #1924 PLACEHOLDER — cannot verify image "
            "signatures. Supply the real key (XPF_IMAGE_PUBKEY / "
            "scripts/dist/xpf-image.pub) before publishing.")
    if not os.path.isfile(pub):
        die(f"image pubkey not found: {pub}")
    return pub


# Image artifact basenames we sweep for orphans (Codex-r2-1): any of these in
# `dist` that is NOT covered by a verified manifest blocks the publish, because
# the whole dist tree is uploaded.
IMAGE_ARTIFACT_SUFFIXES = (".qcow2", ".incus-metadata.tar.gz")


def archive_pubkey():
    """Resolve the OpenPGP archive pubkey path (override or pinned, else
    placeholder). gpg verifies InRelease against an ephemeral keyring built
    from this file so we never depend on the publisher's global gpg keyring."""
    override = os.environ.get("XPF_ARCHIVE_PUBKEY")
    if override:
        return override
    real = os.path.join(HERE, "xpf-archive-keyring.asc")
    if os.path.isfile(real):
        return real
    return os.path.join(HERE, "xpf-archive-keyring.asc.placeholder")


def _is_placeholder(path):
    try:
        with open(path) as f:
            return "PLACEHOLDER-xpf-archive-keyring" in f.read()
    except OSError:
        return False


INSTALLSH_SRC = os.path.join(HERE, "install.sh")
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
MARKER_RE = re.compile(r"%%[A-Za-z0-9_]+%%")


def _installer_key_block(text):
    """Return install.sh's embedded ASCII-armored ARCHIVE_KEY block, or None.
    Isolating the block matters: the placeholder token also appears OUTSIDE the
    key (in the is_placeholder_key grep pattern), so a whole-file substring
    scan cannot tell a stamped installer from an unstamped one — the check must
    look at the key block alone."""
    m = PGP_BLOCK_RE.search(text)
    return m.group(0) if m else None


def _read_real_archive_key(path):
    """Return the ASCII-armored archive PUBLIC KEY block from `path`, refusing
    the placeholder. The stamp bakes this block into install.sh in place of the
    placeholder key so a fresh install can verify the apt repo."""
    if not os.path.isfile(path):
        die(f"archive key not found: {path} — commit the real "
            "scripts/dist/xpf-archive-keyring.asc (drop the .placeholder) or "
            "pass --archive-key <path> before stamping install.sh.")
    if _is_placeholder(path):
        die(f"archive key {path} is the #1924 PLACEHOLDER — refusing to stamp "
            "an installer that cannot verify the repo. Supply the real key.")
    with open(path) as f:
        text = f.read()
    m = PGP_BLOCK_RE.search(text)
    if not m:
        die(f"archive key {path} has no PGP PUBLIC KEY BLOCK — expected an "
            "ASCII-armored OpenPGP public key.")
    return m.group(0)


def stamp_installer(out, src=INSTALLSH_SRC, archive_key=None, apt_url=None,
                    channel="stable"):
    """Bake the real archive key + apt base URL + default channel into
    install.sh (H-2/H-14), producing the publishable installer at `out`. The
    piped Tier-A one-liner then needs no env. This is the substitute half of
    the substitute-THEN-sign flow: sign `out` with minisign afterwards. The
    output is asserted to carry no placeholder key and no unsubstituted %%…%%
    marker, so publish gate_images accepts it."""
    if not apt_url:
        die("apt base URL required — set XPF_APT_BASE_URL or pass "
            "--apt-base-url. It is baked into install.sh so the Tier-A "
            "one-liner needs no env.")
    if channel not in ("stable", "edge"):
        die(f"channel must be stable|edge (got {channel!r}).")
    if archive_key is None:
        archive_key = archive_pubkey()
    key_block = _read_real_archive_key(archive_key)

    if not os.path.isfile(src):
        die(f"installer source not found: {src}")
    with open(src) as f:
        text = f.read()
    src_block = _installer_key_block(text)
    if src_block is None:
        die(f"{src} has no PGP PUBLIC KEY BLOCK to substitute.")
    if "PLACEHOLDER-xpf-archive-keyring" not in src_block:
        die(f"{src} key block is not the placeholder (already stamped?) — "
            "refusing to re-stamp an installer of unclear key provenance.")
    for marker in ("%%XPF_APT_BASE_URL%%", "%%XPF_CHANNEL%%"):
        if marker not in text:
            die(f"{src} is missing the {marker} substitution marker — cannot "
                "bake the installer. Restore the marker.")

    # 1. swap the placeholder PGP block for the real armored key (once). A
    #    function replacement keeps backslashes in the key literal.
    text, n = PGP_BLOCK_RE.subn(lambda _m: key_block, text, count=1)
    if n != 1:
        die(f"{src} has no PGP PUBLIC KEY BLOCK to substitute.")
    # 2. bake the apt base URL + default channel (literal token replace).
    text = text.replace("%%XPF_APT_BASE_URL%%", apt_url)
    text = text.replace("%%XPF_CHANNEL%%", channel)

    # 3. fail-closed: assert NOTHING unsubstituted survived. Check the KEY
    #    BLOCK (not the whole file — the placeholder token also lives in the
    #    is_placeholder_key grep pattern, which correctly stays).
    out_block = _installer_key_block(text)
    if out_block is None or "PLACEHOLDER-xpf-archive-keyring" in out_block:
        die("internal: placeholder archive key survived stamping.")
    leftover = MARKER_RE.search(text)
    if leftover:
        die(f"internal: unsubstituted marker {leftover.group(0)} survived "
            "stamping — refusing to write a half-baked installer.")

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as f:
        f.write(text)
    os.chmod(out, 0o755)
    info(f"stamped installer -> {out} (apt={apt_url} channel={channel}; real "
         "archive key baked). Sign it next, then publish.")


def list_versions(dist):
    """Discover baked versions from manifests in `dist`. FAIL-CLOSED
    (Codex-H1/AGY-A2): if ANY xpf-*.SHA256SUMS lacks a .minisig, refuse the
    whole publish — the upload step pushes the entire dist tree, so an
    unsigned dev bake sitting next to a signed one would otherwise be
    uploaded. Do not silently skip the unsigned one."""
    out = {}
    for m in sorted(glob.glob(os.path.join(dist, "xpf-*.SHA256SUMS"))):
        if not os.path.isfile(m + ".minisig"):
            die(f"unsigned manifest in the publish set: {os.path.basename(m)} "
                "has no .minisig. The whole dist tree is uploaded — refusing to "
                "publish an unsigned artifact. Sign it or remove it.")
        base = os.path.basename(m)
        ver = base[len("xpf-"):-len(".SHA256SUMS")]
        out[ver] = m
    return out


def gate_images(dist, require_installer=True):
    """(a)+(c): every signed image manifest verifies and the listed files
    hash-match; EVERY image artifact in dist is covered by a verified manifest
    (no orphans); install.sh is PRESENT (unless require_installer is False),
    has a verifying signature, is not the placeholder, and carries no
    unsubstituted %%…%% marker."""
    versions = list_versions(dist)
    if not versions:
        die(f"no signed image manifests (xpf-*.SHA256SUMS + .minisig) in {dist} "
            "— nothing publishable. Set XPF_SIGN_SECKEY and re-bake.")
    pub = image_pubkey()
    covered = set()
    for ver, manifest in sorted(versions.items()):
        sig = manifest + ".minisig"
        try:
            # Verify + parse from the VERIFIED bytes (Codex-L6 + AGY-r3-F3
            # TOCTOU): never parse a live manifest that could be swapped after
            # the signature check.
            checks = sign.verify_manifest_map(manifest, sig, pub)
        except sign.SignError as e:
            die(f"image manifest {os.path.basename(manifest)} failed verify: {e}")
        # Every file the manifest lists must be present + hash-match.
        for base in checks:
            path = os.path.join(dist, base)
            if not os.path.isfile(path):
                die(f"manifest {os.path.basename(manifest)} lists {base} but it "
                    f"is absent from {dist} — refusing to publish a partial set.")
            try:
                sign.verify_image_artifact(path, manifest, sig, pub)
            except sign.SignError as e:
                die(f"image artifact {base} failed verify: {e}")
            covered.add(base)
        info(f"image set {ver}: signature + {len(checks)} file hashes OK")
    # Orphan sweep (Codex-r2-1 / r3): the WHOLE dist tree is uploaded
    # RECURSIVELY (rsync -a / aws s3 sync), so walk the tree — not just the top
    # level — and refuse any image artifact NOT covered by a verified manifest,
    # wherever it sits (e.g. a nested dist/stable/xpf-evil.qcow2). The apt pool
    # is gated separately (gate_apt) so skip apt/.
    apt_dir = os.path.join(dist, "apt")
    for root, dirs, files in os.walk(dist):
        if root == apt_dir or root.startswith(apt_dir + os.sep):
            dirs[:] = []
            continue
        # Reject symlinks under the image publish root (Codex-r4): os.walk
        # does not follow dir symlinks, but a backend that dereferences them
        # (some sync tools) could upload nested unverified bytes the sweep
        # never saw. Refuse any symlink (dir or file) outside apt/.
        for d in list(dirs):
            if os.path.islink(os.path.join(root, d)):
                rel = os.path.relpath(os.path.join(root, d), dist)
                die(f"symlinked directory in the image publish set: {rel} — "
                    "refusing (a dereferencing backend could upload "
                    "unverified bytes).")
        for name in sorted(files):
            full = os.path.join(root, name)
            if os.path.islink(full):
                rel = os.path.relpath(full, dist)
                die(f"symlink in the image publish set: {rel} — refusing "
                    "(a dereferencing backend could upload unverified bytes).")
            if not name.endswith(IMAGE_ARTIFACT_SUFFIXES):
                continue
            rel = os.path.relpath(os.path.join(root, name), dist)
            # Image artifacts live ONLY at the top level (the bake writes
            # dist/xpf-<ver>.*). A nested one (e.g. dist/stable/xpf-evil.qcow2)
            # can never be a verified artifact — a manifest binds BASENAMES, so
            # a nested duplicate basename would also escape a basename-only
            # `covered` check. Refuse any image artifact below the top level.
            if os.path.abspath(root) != os.path.abspath(dist):
                die(f"image artifact outside the top-level dist dir: {rel} — "
                    "images belong at dist/xpf-<ver>.*; refusing to publish "
                    "unverified nested bytes.")
            if name not in covered:
                die(f"orphan image artifact in the publish set: {rel} is not "
                    "listed in any verified manifest — refusing to publish "
                    "unverified bytes. Remove it or sign a manifest covering it.")
    # (c) install.sh — PRESENT (mandatory unless --no-installer), stamped
    # (no placeholder key, no unsubstituted marker), AND signed. Presence is
    # mandatory by default because a missing installer makes the Tier-A
    # one-liner URL 404 (H-14): shipping no install.sh must not silently pass.
    installsh = os.path.join(dist, "install.sh")
    if not os.path.isfile(installsh):
        if require_installer:
            die("install.sh is MISSING from the image publish set — the Tier-A "
                "one-liner (curl … | sudo sh) URL would 404. Stamp + sign it "
                "(`publish.py stamp-installer --out dist/install.sh` then "
                "`minisign -S`), or pass --no-installer to publish images "
                "without the one-liner.")
        info("install.sh absent (--no-installer) — Tier-A one-liner unavailable")
        return versions, pub
    with open(installsh) as f:
        content = f.read()
    # Inspect the KEY BLOCK, not the whole file: the placeholder token also
    # appears in the is_placeholder_key grep pattern (which correctly stays in
    # a stamped installer), so a whole-file substring scan would reject even a
    # properly stamped install.sh.
    key_block = _installer_key_block(content)
    if key_block is None:
        die("install.sh in the publish set has no ASCII-armored archive key "
            "block — refusing to publish a malformed installer.")
    if "PLACEHOLDER-xpf-archive-keyring" in key_block:
        die("install.sh in the publish set still embeds the PLACEHOLDER "
            "archive key — refusing to publish an installer that cannot "
            "verify the repo. Stamp it first (`publish.py stamp-installer`).")
    # H-2: refuse an installer whose apt base URL / channel was never baked —
    # a piped `curl … | sudo sh` cannot deliver these via env, so an
    # unsubstituted marker means a 100%-failing one-liner. Mirror the
    # placeholder-KEY refusal above.
    for marker in ("%%XPF_APT_BASE_URL%%", "%%XPF_CHANNEL%%"):
        if marker in content:
            die(f"install.sh in the publish set still carries the unsubstituted "
                f"{marker} marker — the piped one-liner cannot receive it via "
                "env. Run `publish.py stamp-installer` to bake the apt base URL "
                "+ channel before signing/publishing.")
    isig = installsh + ".minisig"
    if not os.path.isfile(isig):
        die("install.sh is in the publish set but install.sh.minisig is "
            "missing — sign it before publishing.")
    try:
        sign.verify_signature(installsh, isig, pub)
        info("install.sh signature OK")
    except sign.SignError as e:
        die(f"install.sh signature failed verify: {e}")
    return versions, pub


def gate_latest(dist, channel, versions, pub):
    """(d): latest.json verifies and names a present version."""
    latest = os.path.join(dist, channel, "latest.json")
    if not os.path.isfile(latest):
        die(f"{channel}/latest.json missing — run "
            f"`publish.py make-latest --channel {channel} --version <V>` first.")
    sig = latest + ".minisig"
    if not os.path.isfile(sig):
        die(f"{channel}/latest.json.minisig missing — the freshness pointer "
            "must be signed.")
    # Verify + parse from the VERIFIED bytes (AGY-r3-F1 TOCTOU): do not re-open
    # the live latest.json after the signature check.
    try:
        data = json.loads(sign.verify_and_read(latest, sig, pub).decode())
    except sign.SignError as e:
        die(f"latest.json signature failed verify: {e}")
    except (ValueError, UnicodeDecodeError) as e:
        die(f"latest.json is not valid JSON after verify: {e}")
    ver = data.get("version")
    if ver not in versions:
        die(f"latest.json names version {ver!r} which is NOT in the publish set "
            f"{sorted(versions)} — refusing to advertise a missing version.")
    info(f"latest.json OK (channel {channel} -> {ver})")


def gate_apt(dist, channel):
    """(b): the apt InRelease verifies against the archive key. The whole
    apt/ tree is uploaded (rsync/s3 sync), so EVERY suite present under
    dists/ — not just the target `channel` — must carry a verifying
    InRelease (AGY-r3-F2). The target channel must exist."""
    apt_root = os.path.join(dist, "apt")
    # Reject symlinks anywhere under apt/ (Codex-r5): the apt tree is uploaded
    # as part of the dist root, and a dereferencing backend could follow a
    # symlink to publish unverified bytes — the same class as the image-sweep
    # symlink rejection, through the apt subtree.
    if os.path.isdir(apt_root):
        for root, dirs, files in os.walk(apt_root):
            for nm in list(dirs) + files:
                if os.path.islink(os.path.join(root, nm)):
                    rel = os.path.relpath(os.path.join(root, nm), dist)
                    die(f"symlink in the apt publish set: {rel} — refusing "
                        "(a dereferencing backend could upload unverified bytes).")
    distsdir = os.path.join(dist, "apt", "dists")
    target = os.path.join(distsdir, channel, "InRelease")
    if not os.path.isfile(target):
        die(f"apt InRelease for the target suite {channel} missing "
            f"({target}) — build a SIGNED repo (XPF_GPG_KEY) first.")
    pub = archive_pubkey()
    if _is_placeholder(pub):
        die("archive pubkey is the #1924 PLACEHOLDER — cannot verify InRelease. "
            "Supply the real archive key (XPF_ARCHIVE_PUBKEY / "
            "scripts/dist/xpf-archive-keyring.asc) before publishing.")
    suites = sorted(d for d in os.listdir(distsdir)
                    if os.path.isdir(os.path.join(distsdir, d)))
    # Verify against an ephemeral keyring built only from the pinned pubkey.
    import tempfile
    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupghome)
        r = subprocess.run(["gpg", "--batch", "--import", pub],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not import archive pubkey {pub}: {r.stderr.strip()}")
        for suite in suites:
            inrel = os.path.join(distsdir, suite, "InRelease")
            if not os.path.isfile(inrel):
                die(f"suite {suite} under dists/ has no InRelease — the whole "
                    "apt tree is uploaded, so every suite must be signed. "
                    "Rebuild or remove it.")
            r = subprocess.run(["gpg", "--batch", "--verify", inrel],
                               env=env, capture_output=True, text=True)
            if r.returncode != 0:
                die(f"apt InRelease ({suite}) signature FAILED: {r.stderr.strip()}")
            info(f"apt InRelease ({suite}) signature OK")
    # The pooled .deb must not carry the PLACEHOLDER archive keyring
    # (Codex-r2-2): a package built before the real key existed would, once
    # installed, overwrite a host's real /usr/share/keyrings key with the
    # placeholder and break `apt update`. Refuse to publish such a pool.
    pool = os.path.join(dist, "apt", "pool")
    if os.path.isdir(pool):
        import tempfile as _tf
        for root, _dirs, files in os.walk(pool):
            for fn in files:
                if not fn.endswith(".deb"):
                    continue
                debp = os.path.join(root, fn)
                with _tf.TemporaryDirectory() as td:
                    r = subprocess.run(["dpkg-deb", "-x", debp, td],
                                       capture_output=True, text=True)
                    if r.returncode != 0:
                        # Fail-CLOSED (Codex-r3): an uninspectable pooled .deb
                        # must NOT be published — we cannot confirm it does not
                        # ship the placeholder keyring.
                        die(f"cannot extract pooled package {fn} for inspection "
                            f"(dpkg-deb rc={r.returncode}): {r.stderr.strip()} — "
                            "refusing to publish an uninspectable package.")
                    kp = os.path.join(td, "usr/share/keyrings/"
                                      "xpf-archive-keyring.asc")
                    if os.path.isfile(kp) and _is_placeholder(kp):
                        die(f"pooled package {fn} ships the PLACEHOLDER archive "
                            "keyring — refusing to publish (it would clobber a "
                            "host's real key on upgrade). Rebuild the .deb after "
                            "dropping in scripts/dist/xpf-archive-keyring.asc.")


def make_latest(dist, channel, version):
    """Write + sign the per-channel latest.json freshness pointer (§5.6)."""
    manifest = os.path.join(dist, f"xpf-{version}.SHA256SUMS")
    if not os.path.isfile(manifest):
        die(f"no manifest for version {version} in {dist}")
    seckey = os.environ.get("XPF_SIGN_SECKEY")
    if not seckey:
        die("XPF_SIGN_SECKEY (path to the minisign secret key) is required to "
            "sign latest.json.")
    cdir = os.path.join(dist, channel)
    os.makedirs(cdir, exist_ok=True)
    latest = os.path.join(cdir, "latest.json")
    data = {
        "channel": channel,
        "version": version,
        "manifest": f"xpf-{version}.SHA256SUMS",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(latest, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    sign.sign_manifest(latest, seckey, comment=f"xpf {channel} latest {version}")
    info(f"wrote + signed {latest} -> {version}")


def dispatch(cmd, local_dir, base_url, dry):
    info(f"publish: {cmd} {local_dir} {base_url}")
    if dry:
        print(f"  (dry-run) {cmd} {local_dir} {base_url}")
        return
    r = subprocess.run([cmd, local_dir, base_url])
    if r.returncode != 0:
        die(f"XPF_PUBLISH_CMD failed (rc={r.returncode}) for {base_url}")


def main(argv):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    ml = sub.add_parser("make-latest")
    ml.add_argument("--channel", default="stable")
    ml.add_argument("--version", required=True)
    ml.add_argument("--dist", default=os.path.join(ROOT, "dist"))

    st = sub.add_parser("stamp-installer",
                        help="bake the real archive key + apt base URL + "
                             "channel into install.sh (substitute-then-sign)")
    st.add_argument("--out", required=True,
                    help="output path for the baked installer (e.g. dist/install.sh)")
    st.add_argument("--src", default=INSTALLSH_SRC)
    st.add_argument("--archive-key", default=None,
                    help="ASCII-armored archive pubkey (default: the pinned "
                         "scripts/dist/xpf-archive-keyring.asc)")
    st.add_argument("--apt-base-url", default=os.environ.get("XPF_APT_BASE_URL"))
    st.add_argument("--channel", default=os.environ.get("XPF_CHANNEL", "stable"))

    p.add_argument("--channel", default="stable")
    p.add_argument("--dist", default=os.path.join(ROOT, "dist"))
    p.add_argument("--no-image", action="store_true")
    p.add_argument("--no-apt", action="store_true")
    p.add_argument("--no-installer", action="store_true",
                   help="publish images WITHOUT install.sh (Tier-A one-liner "
                        "unavailable); default REQUIRES a stamped+signed one")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "make-latest":
        make_latest(a.dist, a.channel, a.version)
        return 0

    if a.cmd == "stamp-installer":
        stamp_installer(a.out, src=a.src, archive_key=a.archive_key,
                        apt_url=a.apt_base_url, channel=a.channel)
        return 0

    dist = a.dist
    if not os.path.isdir(dist):
        die(f"dist dir not found: {dist}")

    # An image-only publish (--no-apt) dispatches the WHOLE dist root, which
    # includes dist/apt if present — so apt bytes would ship UNGATED
    # (Codex-r4). Refuse --no-apt when an apt tree exists; either gate it too
    # or publish from a tree without apt/.
    if a.no_apt and not a.no_image and os.path.isdir(os.path.join(dist, "apt")):
        die("--no-apt but dist/apt exists: an image publish uploads the whole "
            "dist tree (including apt/), so the apt repo would ship UNGATED. "
            "Drop --no-apt (gate apt too), or move dist/apt out of the publish "
            "root.")

    # ── fail-closed gate ──
    if not a.no_image:
        versions, pub = gate_images(dist, require_installer=not a.no_installer)
        gate_latest(dist, a.channel, versions, pub)
    if not a.no_apt:
        gate_apt(dist, a.channel)

    pubcmd = os.environ.get("XPF_PUBLISH_CMD")
    if not pubcmd:
        info("gate PASSED. XPF_PUBLISH_CMD unset — nothing uploaded. Set it to "
             "the backend shim ($CMD <local-dir> <dest-base-url>) to publish.")
        return 0

    if not a.no_image:
        img_url = os.environ.get("XPF_IMAGE_BASE_URL") or die(
            "XPF_IMAGE_BASE_URL required to publish the image tree.")
        dispatch(pubcmd, dist, img_url, a.dry_run)
    if not a.no_apt:
        apt_url = os.environ.get("XPF_APT_BASE_URL") or die(
            "XPF_APT_BASE_URL required to publish the apt tree.")
        dispatch(pubcmd, os.path.join(dist, "apt"), apt_url, a.dry_run)
    info("publish complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
