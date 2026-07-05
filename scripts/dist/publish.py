#!/usr/bin/env python3
"""xpf signed-distribution publish gate (#1924 §5.5).

Fail-CLOSED: refuses to publish (exits non-zero, uploads nothing) unless every
artifact in the publish set is properly signed:

  (a) each image manifest (xpf-<ver>.SHA256SUMS) has a verifying .minisig
      against the pinned image pubkey, AND the qcow2/metadata it lists are
      present and hash-match;
  (b) the apt InRelease verifies against the archive pubkey (when an apt tree
      is being published);
  (c) install.sh has a verifying install.sh.minisig (when install.sh is in
      the image set);
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
  publish.py --channel stable [--dist DIR] [--no-image] [--no-apt] [--dry-run]
  publish.py make-latest --channel stable --version V [--dist DIR]   # sign latest.json
"""

import argparse
import glob
import json
import os
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


def _primary_fprs_from_gpg_colons(colon_text):
    """Extract the set of PRIMARY key fingerprints from `gpg --with-colons`
    output. The `fpr:` line immediately following a `pub:` record is the
    primary key's fingerprint; `fpr:` lines after `sub:` records (subkeys) are
    ignored so we compare primary fingerprints consistently with the InRelease
    signer's primary fpr (the last VALIDSIG field)."""
    fprs = set()
    want = False
    for line in colon_text.splitlines():
        f = line.split(":")
        if not f:
            continue
        if f[0] == "pub":
            want = True
        elif f[0] == "sub":
            want = False
        elif f[0] == "fpr" and want:
            if len(f) > 9 and f[9]:
                fprs.add(f[9])
            want = False
    return fprs


def _key_fingerprints(key_source):
    """Return the set of PRIMARY key fingerprints in an armored key file by
    importing it into an ephemeral keyring (matching gate_apt's import style)
    so we never touch the publisher's global gpg keyring."""
    import tempfile
    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupghome)
        r = subprocess.run(["gpg", "--batch", "--import", key_source],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not import key {key_source} for fingerprint "
                f"cross-check: {r.stderr.strip()}")
        r = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys"],
            env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not list fingerprints for {key_source}: "
                f"{r.stderr.strip()}")
        return _primary_fprs_from_gpg_colons(r.stdout)


def _extract_installsh_key(installsh_path):
    """Return install.sh's embedded ASCII-armored OpenPGP key block (the exact
    bytes between the PGP BEGIN/END markers), or None if there is no block. The
    block sits in a single-quoted heredoc so it is literal armor with no shell
    interpolation."""
    try:
        with open(installsh_path) as f:
            text = f.read()
    except OSError:
        return None
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    i = text.find(begin)
    j = text.find(end)
    if i == -1 or j == -1 or j < i:
        return None
    return text[i:j + len(end)] + "\n"


def _gate_key_agreement(dist, archive_pub, signer_fprs):
    """H-15: cross-check that the installer's embedded key, the packaged
    keyring, and the InRelease signer AGREE by fingerprint. publish.py
    otherwise only checked each source for placeholder-ness independently, so a
    stale install.sh (an old, real, retired key) could publish cleanly after a
    rotation and brick every new Tier-A install at `apt-get update`.

    Requires (fingerprints are PRIMARY key fprs):
      - the InRelease signer(s) S are covered by the packaged keyring K
        (existing hosts verify the repo on `apt upgrade`); and, when install.sh
        is in the publish set,
      - install.sh's embedded key set I is a SUBSET of K (a keyring superset is
        allowed during a documented dual-sign window), and
      - the InRelease signer(s) S are covered by I so a fresh Tier-A install's
        `apt-get update` (which runs against install.sh's embedded key BEFORE
        the packaged keyring lands) verifies the published repo.
    """
    keyring_fprs = _key_fingerprints(archive_pub)
    if not keyring_fprs:
        die("archive keyring has no importable keys — cannot cross-check the "
            "InRelease signer against the packaged keyring.")
    if not signer_fprs:
        die("could not determine the InRelease signer fingerprint — refusing "
            "to publish without confirming key agreement.")
    if not signer_fprs <= keyring_fprs:
        die(f"InRelease signer {sorted(signer_fprs)} is NOT in the packaged "
            f"keyring {sorted(keyring_fprs)} — the repo is signed by a key the "
            "shipped keyring does not carry; existing hosts would fail apt "
            "update. Ship the signing key in the keyring or re-sign the repo.")

    installsh = os.path.join(dist, "install.sh")
    if not os.path.isfile(installsh):
        info("key-agreement: install.sh not in publish set — "
             "installer cross-check skipped (signer vs keyring OK)")
        return
    armored = _extract_installsh_key(installsh)
    if armored is None:
        die("install.sh is in the publish set but has no embedded PGP key "
            "block to cross-check against the keyring/InRelease signer.")
    if "PLACEHOLDER-xpf-archive-keyring" in armored:
        die("install.sh embeds the #1924 PLACEHOLDER archive key — cannot "
            "cross-check key agreement. Substitute the real key first.")
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".asc", delete=False) as tf:
        tf.write(armored)
        keypath = tf.name
    try:
        inst_fprs = _key_fingerprints(keypath)
    finally:
        os.unlink(keypath)
    if not inst_fprs:
        die("install.sh embedded key could not be parsed for fingerprints — "
            "refusing to publish without confirming key agreement.")
    if not inst_fprs <= keyring_fprs:
        die(f"install.sh embedded key {sorted(inst_fprs)} is NOT a subset of "
            f"the packaged keyring {sorted(keyring_fprs)} — the installer "
            "trusts a key the shipped keyring lacks (stale installer or "
            "un-rotated keyring). Re-embed the current archive key in "
            "install.sh (a keyring superset is allowed during dual-sign).")
    if not signer_fprs <= inst_fprs:
        die(f"InRelease signer {sorted(signer_fprs)} is NOT covered by "
            f"install.sh's embedded key {sorted(inst_fprs)} — a fresh Tier-A "
            "install would fail `apt-get update` against the published repo "
            "(stale install.sh key). Re-embed the signing key in install.sh "
            "before publishing.")
    info(f"key-agreement OK (installer {sorted(inst_fprs)} subset of keyring; "
         f"InRelease signer {sorted(signer_fprs)} covered by installer + keyring)")


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


def gate_images(dist):
    """(a)+(c): every signed image manifest verifies and the listed files
    hash-match; EVERY image artifact in dist is covered by a verified manifest
    (no orphans); install.sh has a verifying signature and is not the
    placeholder."""
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
    # (c) install.sh — signed AND not the placeholder.
    installsh = os.path.join(dist, "install.sh")
    if os.path.isfile(installsh):
        with open(installsh) as f:
            if "PLACEHOLDER-xpf-archive-keyring" in f.read():
                die("install.sh in the publish set still embeds the PLACEHOLDER "
                    "archive key — refusing to publish an installer that cannot "
                    "verify the repo. Substitute the real key first.")
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
        signer_fprs = set()
        for suite in suites:
            inrel = os.path.join(distsdir, suite, "InRelease")
            if not os.path.isfile(inrel):
                die(f"suite {suite} under dists/ has no InRelease — the whole "
                    "apt tree is uploaded, so every suite must be signed. "
                    "Rebuild or remove it.")
            # --status-fd 1 emits a machine-readable VALIDSIG line whose LAST
            # field is the signer's PRIMARY key fingerprint (#4203 key
            # agreement). rc still reflects verify success/failure.
            r = subprocess.run(["gpg", "--batch", "--status-fd", "1",
                                "--verify", inrel],
                               env=env, capture_output=True, text=True)
            if r.returncode != 0:
                die(f"apt InRelease ({suite}) signature FAILED: {r.stderr.strip()}")
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "VALIDSIG":
                    signer_fprs.add(parts[-1])
            info(f"apt InRelease ({suite}) signature OK")
        # H-15 (#4203): the installer's embedded key, the packaged keyring, and
        # the InRelease signer must AGREE by fingerprint — three independent
        # placeholder checks never caught a stale-but-real install.sh key.
        _gate_key_agreement(dist, pub, signer_fprs)
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

    p.add_argument("--channel", default="stable")
    p.add_argument("--dist", default=os.path.join(ROOT, "dist"))
    p.add_argument("--no-image", action="store_true")
    p.add_argument("--no-apt", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "make-latest":
        make_latest(a.dist, a.channel, a.version)
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
        versions, pub = gate_images(dist)
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
