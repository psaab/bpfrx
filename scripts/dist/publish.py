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


def list_versions(dist):
    """Discover baked versions from signed manifests in `dist`."""
    out = {}
    for m in glob.glob(os.path.join(dist, "xpf-*.SHA256SUMS")):
        if not os.path.isfile(m + ".minisig"):
            continue
        base = os.path.basename(m)
        ver = base[len("xpf-"):-len(".SHA256SUMS")]
        out[ver] = m
    return out


def gate_images(dist):
    """(a)+(c): every signed image manifest verifies and the listed files
    hash-match; install.sh has a verifying signature if present."""
    versions = list_versions(dist)
    if not versions:
        die(f"no signed image manifests (xpf-*.SHA256SUMS + .minisig) in {dist} "
            "— nothing publishable. Set XPF_SIGN_SECKEY and re-bake.")
    for ver, manifest in sorted(versions.items()):
        sig = manifest + ".minisig"
        try:
            checks = sign.parse_manifest(manifest)  # structural
            sign.verify_signature(manifest, sig, sign.DEFAULT_IMAGE_PUBKEY)
        except sign.SignError as e:
            die(f"image manifest {os.path.basename(manifest)} failed verify: {e}")
        # Every file the manifest lists must be present + hash-match.
        for base in checks:
            path = os.path.join(dist, base)
            if not os.path.isfile(path):
                die(f"manifest {os.path.basename(manifest)} lists {base} but it "
                    f"is absent from {dist} — refusing to publish a partial set.")
            try:
                sign.verify_image_artifact(path, manifest, sig)
            except sign.SignError as e:
                die(f"image artifact {base} failed verify: {e}")
        info(f"image set {ver}: signature + {len(checks)} file hashes OK")
    # (c) install.sh
    installsh = os.path.join(dist, "install.sh")
    if os.path.isfile(installsh):
        isig = installsh + ".minisig"
        if not os.path.isfile(isig):
            die("install.sh is in the publish set but install.sh.minisig is "
                "missing — sign it before publishing.")
        try:
            sign.verify_signature(installsh, isig, sign.DEFAULT_IMAGE_PUBKEY)
            info("install.sh signature OK")
        except sign.SignError as e:
            die(f"install.sh signature failed verify: {e}")
    return versions


def gate_latest(dist, channel, versions):
    """(d): latest.json verifies and names a present version."""
    latest = os.path.join(dist, channel, "latest.json")
    if not os.path.isfile(latest):
        die(f"{channel}/latest.json missing — run "
            f"`publish.py make-latest --channel {channel} --version <V>` first.")
    sig = latest + ".minisig"
    if not os.path.isfile(sig):
        die(f"{channel}/latest.json.minisig missing — the freshness pointer "
            "must be signed.")
    try:
        sign.verify_signature(latest, sig, sign.DEFAULT_IMAGE_PUBKEY)
    except sign.SignError as e:
        die(f"latest.json signature failed verify: {e}")
    with open(latest) as f:
        data = json.load(f)
    ver = data.get("version")
    if ver not in versions:
        die(f"latest.json names version {ver!r} which is NOT in the publish set "
            f"{sorted(versions)} — refusing to advertise a missing version.")
    info(f"latest.json OK (channel {channel} -> {ver})")


def gate_apt(dist, channel):
    """(b): the apt InRelease for `channel` verifies against the archive key."""
    inrelease = os.path.join(dist, "apt", "dists", channel, "InRelease")
    if not os.path.isfile(inrelease):
        die(f"apt InRelease for suite {channel} missing "
            f"({inrelease}) — build a SIGNED repo (XPF_GPG_KEY) first.")
    pub = archive_pubkey()
    if _is_placeholder(pub):
        die("archive pubkey is the #1924 PLACEHOLDER — cannot verify InRelease. "
            "Supply the real archive key (XPF_ARCHIVE_PUBKEY / "
            "scripts/dist/xpf-archive-keyring.asc) before publishing.")
    # Verify against an ephemeral keyring built only from the pinned pubkey.
    import tempfile
    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupghome)
        r = subprocess.run(["gpg", "--batch", "--import", pub],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not import archive pubkey {pub}: {r.stderr.strip()}")
        r = subprocess.run(["gpg", "--batch", "--verify", inrelease],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"apt InRelease signature FAILED: {r.stderr.strip()}")
    info(f"apt InRelease ({channel}) signature OK")


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

    # ── fail-closed gate ──
    versions = {}
    if not a.no_image:
        versions = gate_images(dist)
        gate_latest(dist, a.channel, versions)
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
