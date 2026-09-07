#!/usr/bin/env python3
"""xpf signed-distribution signing/verification helpers (#1924).

Shared by the image bake (scripts/image/bake.py), the image validation
gate (scripts/image/validate.py), the deployer fetch path
(scripts/deploy/xpf-deploy.py), and the publish gate
(scripts/dist/publish.py). Implements the IMAGE trust root:

  minisign over a PER-VERSION checksum manifest (xpf-<ver>.SHA256SUMS),
  then PER-FILE hash verification of the exact bytes being consumed.

Design contract (docs/research/1924-signed-hosted-dist/plan.md §5.1/§5.2):

- The signing tool is `minisign` (Ed25519). We shell out to the system
  binary rather than reimplement Ed25519 — `require_minisign()` preflights
  it with an apt-install hint.
- The secret key is referenced by PATH via XPF_SIGN_SECKEY (or an explicit
  argument); the key bytes are NEVER embedded, logged, or committed.
- The public key is a checked-in, pinned file (scripts/dist/xpf-image.pub);
  its root of trust is the in-repo git copy, independent of any hosting URL.
- Verification is PER-FILE: the signed manifest authenticates a {basename:
  sha256} map; each consumer hashes the EXACT file it is about to use and
  compares to the manifest entry for that file's basename. A file absent
  from the manifest, or a hash mismatch, FAILS. Files listed but not
  fetched are simply not checked (so a qcow2-only libvirt fetch verifies).
"""

import hashlib
import os
import shutil
import subprocess
import sys

# Pinned, checked-in public key (the trust root for image artifacts).
# Overridable via XPF_IMAGE_PUBKEY for rotation/testing — the override is a
# PATH, and the pinned in-repo copy remains the documented default root.
# Until OQ-2 supplies a real key, only `xpf-image.pub.placeholder` ships (its
# secret was shredded at generation, held by no one — so verify FAILS until
# the operator drops in the real `xpf-image.pub`, the correct fail-safe).
HERE = os.path.dirname(os.path.abspath(__file__))


def default_image_pubkey():
    real = os.path.join(HERE, "xpf-image.pub")
    if os.path.isfile(real):
        return real
    return os.path.join(HERE, "xpf-image.pub.placeholder")


DEFAULT_IMAGE_PUBKEY = default_image_pubkey()


class SignError(Exception):
    """Signing/verification failure — fatal to the caller's gate."""


def require_minisign():
    """Ensure the minisign binary is present; raise with an install hint."""
    exe = shutil.which("minisign")
    if not exe:
        raise SignError(
            "minisign not found — install it (apt-get install minisign) to "
            "sign or verify image artifacts (#1924).")
    return exe


def is_placeholder_pubkey(pubkey_path):
    """True if `pubkey_path` is the shipped placeholder (its secret was
    shredded at generation, so it can never authenticate a real release)."""
    return os.path.basename(pubkey_path).endswith(".placeholder")


def require_real_pubkey(pubkey_path):
    """Fail-CLOSED if the image pubkey is the placeholder (Codex-M4). The
    placeholder exists only so the mechanism + tests have a key-path shape;
    a real verify against it would either always fail (no holder of its
    secret) or — worse — pass if an attacker re-signed with a self-generated
    placeholder secret. Refuse it explicitly, mirroring the apt-key
    placeholder refusal in publish.py."""
    if is_placeholder_pubkey(pubkey_path):
        raise SignError(
            f"image public key {os.path.basename(pubkey_path)} is the #1924 "
            "PLACEHOLDER — refusing to verify against it. Supply the real key "
            "(XPF_IMAGE_PUBKEY or scripts/dist/xpf-image.pub) — see "
            "scripts/dist/README.md.")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(manifest_path, files):
    """Write a sha256sum-format manifest listing `files` by BASENAME only.

    Basename-only (never a path) so the manifest is location-independent and
    a consumer that fetched the file to any directory can verify it. Refuses
    duplicate basenames at write time — a duplicate would make the
    {basename: hash} map ambiguous on the verify side.
    """
    seen = set()
    lines = []
    for path in files:
        base = os.path.basename(path)
        if base in seen:
            raise SignError(f"duplicate basename in manifest set: {base}")
        seen.add(base)
        lines.append(f"{sha256_file(path)}  {base}\n")
    with open(manifest_path, "w") as f:
        f.writelines(lines)
    return manifest_path


def sign_manifest(manifest_path, seckey_path, comment=None, sig_path=None):
    """minisign-sign `manifest_path` with the secret key at `seckey_path`.

    Returns the .minisig path. The secret key is passed by PATH to the
    minisign binary; its bytes never touch this process's memory. minisign
    prompts for a passphrase on a TTY; for unattended signing the key must be
    passwordless (operator policy, OQ-2) — we pass an empty passphrase on
    stdin so a passwordless key signs non-interactively and a
    password-protected key fails loudly rather than hanging.
    """
    exe = require_minisign()
    if sig_path is None:
        sig_path = manifest_path + ".minisig"
    argv = [exe, "-S", "-s", seckey_path, "-m", manifest_path, "-x", sig_path]
    if comment:
        argv += ["-t", comment]
    r = subprocess.run(argv, input="\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise SignError(
            f"minisign sign failed (rc={r.returncode}): {r.stderr.strip()}\n"
            "(a password-protected key cannot sign unattended — OQ-2 requires "
            "a passwordless image-signing key or an interactive signer).")
    return sig_path


def verify_signature(manifest_path, sig_path, pubkey_path):
    """minisign-verify the manifest's signature. Raise on failure."""
    exe = require_minisign()
    r = subprocess.run(
        [exe, "-V", "-p", pubkey_path, "-m", manifest_path, "-x", sig_path],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise SignError(
            f"minisign signature verification FAILED for "
            f"{os.path.basename(manifest_path)}: {r.stderr.strip() or r.stdout.strip()}")


def parse_manifest(manifest_path):
    """Parse a sha256sum-format manifest into {basename: hexhash}.

    Rejects pathful entries (a basename must not contain '/') and duplicate
    basenames — both would let a verifier bind the wrong bytes. Call this
    only AFTER verify_signature() has authenticated the manifest.
    """
    result = {}
    with open(manifest_path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                raise SignError(
                    f"{manifest_path}:{lineno}: malformed manifest line: {raw!r}")
            digest, name = parts
            name = name.lstrip("*")  # sha256sum binary-mode marker
            if "/" in name or "\\" in name or name in ("", ".", ".."):
                raise SignError(
                    f"{manifest_path}:{lineno}: manifest entry must be a bare "
                    f"basename, got {name!r}")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
                raise SignError(
                    f"{manifest_path}:{lineno}: not a sha256 hex digest: {digest!r}")
            if name in result:
                raise SignError(
                    f"{manifest_path}:{lineno}: duplicate basename in manifest: {name}")
            result[name] = digest.lower()
    if not result:
        raise SignError(f"{manifest_path}: manifest has no entries")
    return result


def _resolve_pubkey(pubkey_path):
    if pubkey_path is None:
        pubkey_path = os.environ.get("XPF_IMAGE_PUBKEY", DEFAULT_IMAGE_PUBKEY)
    if not os.path.isfile(pubkey_path):
        raise SignError(
            f"image public key not found: {pubkey_path} "
            "(set XPF_IMAGE_PUBKEY or ship scripts/dist/xpf-image.pub).")
    require_real_pubkey(pubkey_path)
    return pubkey_path


def verify_and_read(signed_path, sig_path, pubkey_path=None):
    """minisign-verify `signed_path` and return its VERIFIED bytes.

    TOCTOU-safe (Codex-M5/AGY-A4/AGY-r3): the file may live in a user-writable
    dir, so a concurrent process could swap its bytes between the signature
    check and a later read. Copy the file + its signature into a private 0700
    temp dir, verify the COPY, and return the COPY's bytes — so what the caller
    parses/uses is exactly what was verified. Use this for every signed text
    artifact (the per-version manifest, latest.json, ...).
    """
    pubkey_path = _resolve_pubkey(pubkey_path)
    import shutil as _sh
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-verify-")
    try:
        os.chmod(tmp, 0o700)
        f_copy = os.path.join(tmp, os.path.basename(signed_path))
        s_copy = f_copy + ".minisig"
        _sh.copyfile(signed_path, f_copy)
        _sh.copyfile(sig_path, s_copy)
        verify_signature(f_copy, s_copy, pubkey_path)
        with open(f_copy, "rb") as fh:
            return fh.read()
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


def verify_manifest_map(manifest_path, sig_path, pubkey_path=None):
    """Verify a signed manifest and return its {basename: hash} map, parsed
    from the VERIFIED bytes (TOCTOU-safe)."""
    data = verify_and_read(manifest_path, sig_path, pubkey_path)
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-manifest-")
    try:
        os.chmod(tmp, 0o700)
        p = os.path.join(tmp, "m")
        with open(p, "wb") as fh:
            fh.write(data)
        return parse_manifest(p)
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)


def verify_image_artifact(path, manifest_path, sig_path, pubkey_path=None):
    """Verify ONE artifact `path` against a signed manifest and RETURN the
    signed digest that authorised it.

    1. verify+parse the manifest from its VERIFIED bytes (TOCTOU-safe).
    2. hash the EXACT `path` and compare to the manifest entry for its
       basename. Missing entry or mismatch -> raise.

    Binds the bytes the caller is about to import/use, not a cwd-relative
    `sha256sum -c` (which could pass against a stale local copy).

    #9170: the return value is the manifest's hex digest, not a bare `True`.
    A caller that needs to PRINT or re-check that digest — `xpf-deploy.py
    fetch --no-import`, which hands the operator a `sha256sum -c` line to run
    later — must take it from HERE. Re-hashing the file afterwards binds the
    bytes at hash time rather than the bytes that passed the signature, and
    the artifact typically sits in a public `--out` another local process can
    write. The value was already computed inside this call; discarding it was
    what forced the second read.
    """
    manifest = verify_manifest_map(manifest_path, sig_path, pubkey_path)
    base = os.path.basename(path)
    if base not in manifest:
        raise SignError(
            f"{base} is not listed in the signed manifest "
            f"{os.path.basename(manifest_path)} — refusing to trust it.")
    actual = sha256_file(path)
    if actual != manifest[base]:
        raise SignError(
            f"{base}: SHA256 MISMATCH — manifest {manifest[base]}, actual "
            f"{actual}. The file does not match the signed checksum.")
    return manifest[base]


def verify_listed_artifact_bytes(path, manifest_path, sig_path, pubkey_path=None):
    """Verify ONE manifest-listed artifact `path` against a signed manifest and
    return its VERIFIED bytes (TOCTOU-safe).

    Like verify_image_artifact, but for a file the caller must READ and act on
    (not merely trust in place): the returned bytes come from a private 0700
    copy whose sha256 was compared to the signed manifest entry, so a
    concurrent swap of the on-disk `path` AFTER the check cannot feed
    unverified bytes to the caller (the Codex-M5/AGY-A4 TOCTOU class the
    verify_and_read primitive already guards for directly-signed files).

    Use this for an artifact that is COVERED by the signed checksum manifest
    but is not itself minisigned — e.g. the mixed-base protocol sidecar
    xpf-<ver>.manifest (#5042), whose ha-protocol / session-sync fields drive
    the deployer's HA session-safety gate and therefore must be read from
    signed bytes."""
    manifest = verify_manifest_map(manifest_path, sig_path, pubkey_path)
    base = os.path.basename(path)
    if base not in manifest:
        raise SignError(
            f"{base} is not listed in the signed manifest "
            f"{os.path.basename(manifest_path)} — refusing to trust it.")
    import shutil as _sh
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-listed-")
    try:
        os.chmod(tmp, 0o700)
        copy = os.path.join(tmp, base)
        _sh.copyfile(path, copy)
        actual = sha256_file(copy)
        if actual != manifest[base]:
            raise SignError(
                f"{base}: SHA256 MISMATCH — manifest {manifest[base]}, actual "
                f"{actual}. The file does not match the signed checksum.")
        with open(copy, "rb") as fh:
            return fh.read()
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


# ── CLI shim for the test gate + manual use ──────────────────────────────
def _main(argv):
    import argparse
    p = argparse.ArgumentParser(description="xpf image signing helper (#1924)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sign-manifest", help="write+sign a per-version manifest")
    s.add_argument("--manifest", required=True)
    s.add_argument("--seckey", required=True)
    s.add_argument("--comment", default=None)
    s.add_argument("files", nargs="+")

    v = sub.add_parser("verify", help="verify ONE artifact against a signed manifest")
    v.add_argument("--manifest", required=True)
    v.add_argument("--sig", default=None)
    v.add_argument("--pubkey", default=None)
    v.add_argument("file")

    a = p.parse_args(argv)
    try:
        if a.cmd == "sign-manifest":
            write_manifest(a.manifest, a.files)
            sig = sign_manifest(a.manifest, a.seckey, a.comment)
            print(f"signed: {a.manifest} -> {sig}")
            return 0
        if a.cmd == "verify":
            sig = a.sig or (a.manifest + ".minisig")
            verify_image_artifact(a.file, a.manifest, sig, a.pubkey)
            print(f"OK: {os.path.basename(a.file)} verified against "
                  f"{os.path.basename(a.manifest)}")
            return 0
    except SignError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
