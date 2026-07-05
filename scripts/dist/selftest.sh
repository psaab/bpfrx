#!/bin/sh
# xpf signed-distribution self-test (#1924) — the local roundtrip gate.
#
# Proves, end to end, with a THROWAWAY keypair (generated in a temp dir,
# never committed) and NO hosting:
#   1. sign a per-version manifest over fake qcow2 + metadata;
#   2. verify each artifact against the signed manifest (PASS);
#   3. tamper-detection: a modified artifact, a tampered manifest, a
#      tampered signature, and a wrong pubkey each MUST FAIL verify;
#   4. build a flat signed apt repo over a fake .deb and verify InRelease;
#   5. install.sh --dry-run preflight/source rendering.
#
# Exit 0 only if every positive check passes AND every tamper check fails.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST="$ROOT/scripts/dist"
PY=python3
PASS=0
FAIL=0

ok()   { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }
info() { echo "==> $*"; }

command -v minisign >/dev/null 2>&1 || { echo "SKIP: minisign not installed (apt-get install minisign)"; exit 77; }
command -v gpg >/dev/null 2>&1 || { echo "SKIP: gpg not installed"; exit 77; }
command -v apt-ftparchive >/dev/null 2>&1 || { echo "SKIP: apt-ftparchive not installed (apt-utils)"; exit 77; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/xpf-dist-selftest.XXXXXX")
GNUPGHOME="$WORK/gnupg"; export GNUPGHOME
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

VER="0.0.0-selftest"
OUT="$WORK/dist"
mkdir -p "$OUT"

# ── throwaway image keypair ───────────────────────────────────────────────
info "1. generate throwaway minisign image keypair (passwordless)"
minisign -G -W -p "$WORK/img.pub" -s "$WORK/img.sec" >/dev/null 2>&1
WRONGPUB="$WORK/wrong.pub"
minisign -G -W -p "$WRONGPUB" -s "$WORK/wrong.sec" >/dev/null 2>&1

# ── fake artifacts + signed manifest ──────────────────────────────────────
info "2. create fake artifacts + signed per-version manifest"
QCOW="$OUT/xpf-$VER.qcow2"
META="$OUT/xpf-$VER.incus-metadata.tar.gz"
head -c 4096 /dev/urandom > "$QCOW"
head -c 1024 /dev/urandom > "$META"
MANIFEST="$OUT/xpf-$VER.SHA256SUMS"
XPF_IMAGE_PUBKEY="$WORK/img.pub" \
  $PY "$DIST/sign.py" sign-manifest --manifest "$MANIFEST" \
      --seckey "$WORK/img.sec" --comment "selftest" "$QCOW" "$META" >/dev/null
[ -f "$MANIFEST.minisig" ] && ok "manifest signed" || bad "manifest not signed"

verify() {  # verify <file> with pubkey; prints OK/err, returns rc
    XPF_IMAGE_PUBKEY="$1" $PY "$DIST/sign.py" verify \
        --manifest "$MANIFEST" --pubkey "$1" "$2" >/dev/null 2>&1
}

# ── 3. positive verification ──────────────────────────────────────────────
info "3. positive verification (must PASS)"
verify "$WORK/img.pub" "$QCOW"  && ok "qcow2 verifies"     || bad "qcow2 should verify"
verify "$WORK/img.pub" "$META"  && ok "metadata verifies"  || bad "metadata should verify"

# Per-file: qcow2-only operator can verify without metadata present.
QONLY="$WORK/qonly"; mkdir -p "$QONLY"
cp "$QCOW" "$MANIFEST" "$MANIFEST.minisig" "$QONLY/"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$QONLY/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$QONLY/xpf-$VER.qcow2" >/dev/null 2>&1; then
    ok "qcow2-only verifies without metadata present"
else
    bad "qcow2-only should verify (per-file)"
fi

# ── 4. tamper-detection (each MUST FAIL) ──────────────────────────────────
info "4. tamper-detection (each MUST FAIL verify)"

# 4a. modified artifact
TQ="$WORK/tamper"; mkdir -p "$TQ"
cp "$MANIFEST" "$MANIFEST.minisig" "$TQ/"
head -c 4096 /dev/urandom > "$TQ/xpf-$VER.qcow2"   # different bytes
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TQ/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$TQ/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "modified qcow2 MUST fail verify but PASSED"
else
    ok "modified qcow2 fails verify"
fi

# 4b. tampered manifest (flip a hash) — signature must no longer match
TM="$WORK/tmanifest"; mkdir -p "$TM"
cp "$QCOW" "$META" "$MANIFEST.minisig" "$TM/"
sed 's/^./0/' "$MANIFEST" > "$TM/xpf-$VER.SHA256SUMS"   # corrupt first hex char
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TM/xpf-$VER.SHA256SUMS" \
     --sig "$TM/xpf-$VER.SHA256SUMS.minisig" --pubkey "$WORK/img.pub" \
     "$TM/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "tampered manifest MUST fail verify but PASSED"
else
    ok "tampered manifest fails verify"
fi

# 4c. tampered signature
TS="$WORK/tsig"; mkdir -p "$TS"
cp "$QCOW" "$META" "$MANIFEST" "$TS/"
sed '$ s/.$/X/' "$MANIFEST.minisig" > "$TS/xpf-$VER.SHA256SUMS.minisig" 2>/dev/null \
  || tr 'A' 'B' < "$MANIFEST.minisig" > "$TS/xpf-$VER.SHA256SUMS.minisig"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TS/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$TS/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "tampered signature MUST fail verify but PASSED"
else
    ok "tampered signature fails verify"
fi

# 4d. wrong pubkey
if verify "$WRONGPUB" "$QCOW"; then
    bad "wrong pubkey MUST fail verify but PASSED"
else
    ok "wrong pubkey fails verify"
fi

# ── 5. flat signed apt repo + InRelease verify ─────────────────────────────
info "5. flat signed apt repo build + InRelease verify"
# Throwaway gpg archive key (unattended, no passphrase).
cat > "$WORK/gpg-batch" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: xpf selftest archive
Name-Email: selftest@xpf.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/gpg-batch" >/dev/null 2>&1
GPGKEY=$(gpg --batch --list-keys --with-colons selftest@xpf.invalid | awk -F: '/^fpr:/{print $10; exit}')
[ -n "$GPGKEY" ] && ok "archive key generated ($GPGKEY)" || { bad "archive key gen failed"; }

# Fake .deb (apt-ftparchive only reads control metadata; a minimal valid .deb).
DEBDIR="$WORK/pkg"; mkdir -p "$DEBDIR/DEBIAN"
cat > "$DEBDIR/DEBIAN/control" <<EOF
Package: xpf-appliance
Version: $VER
Architecture: amd64
Maintainer: selftest <selftest@xpf.invalid>
Description: xpf selftest fake package
EOF
mkdir -p "$ROOT/dist/deb"
FAKEDEB="$ROOT/dist/deb/xpf-appliance_${VER}_amd64.selftest.deb"
dpkg-deb --build "$DEBDIR" "$FAKEDEB" >/dev/null 2>&1
cleanup_deb() { rm -f "$FAKEDEB"; }
trap 'cleanup; cleanup_deb' EXIT INT TERM

if XPF_GPG_KEY="$GPGKEY" XPF_APT_VALID_DAYS=365 \
   sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite stable --debs "$FAKEDEB" >/dev/null 2>&1; then
    ok "flat signed apt repo built"
else
    bad "apt repo build failed"
fi

INREL="$OUT/apt/dists/stable/InRelease"
if [ -f "$INREL" ] && gpg --batch --verify "$INREL" >/dev/null 2>&1; then
    ok "InRelease signature verifies"
else
    bad "InRelease missing or signature failed"
fi
# Valid-Until must actually be emitted (Codex-M3 regression).
if grep -q "^Valid-Until:" "$OUT/apt/dists/stable/Release"; then
    ok "Release carries Valid-Until"
else
    bad "Release missing Valid-Until (ValidTime knob regression)"
fi
# Negative: a tampered InRelease must fail.
if [ -f "$INREL" ]; then
    cp "$INREL" "$WORK/InRelease.tampered"
    sed 's/Codename: stable/Codename: EVIL/' "$INREL" > "$WORK/InRelease.tampered" || true
    if gpg --batch --verify "$WORK/InRelease.tampered" >/dev/null 2>&1; then
        bad "tampered InRelease MUST fail verify but PASSED"
    else
        ok "tampered InRelease fails verify"
    fi
fi

# ── 5b. publish gate fail-closed (Codex-H1 / AGY-A2) ──────────────────────
info "5b. publish gate fail-closed on an unsigned manifest"
PG="$WORK/pgate"; mkdir -p "$PG"
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  xpf-9.9.9.qcow2\n' \
    > "$PG/xpf-9.9.9.SHA256SUMS"   # NO .minisig
if $PY "$DIST/publish.py" --dist "$PG" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unsigned manifest but PASSED"
else
    ok "publish refuses an unsigned manifest"
fi

# Orphan image artifact NOT covered by any manifest (Codex-r2-1).
PGO="$WORK/pgorphan"; mkdir -p "$PGO"
cp "$QCOW" "$META" "$MANIFEST" "$MANIFEST.minisig" "$PGO/"
head -c 64 /dev/urandom > "$PGO/xpf-9.9.9.qcow2"   # orphan, no manifest covers it
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PGO" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an orphan image artifact but PASSED"
else
    ok "publish refuses an orphan image artifact"
fi

# Symlink under the image publish root (Codex-r4).
PGS="$WORK/pgsym"; mkdir -p "$PGS"
cp "$QCOW" "$META" "$MANIFEST" "$MANIFEST.minisig" "$PGS/"
ln -s /etc/passwd "$PGS/sneaky.qcow2"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PGS" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse a symlink in the image set but PASSED"
else
    ok "publish refuses a symlink in the image set"
fi

# ── 5c. apt channel isolation (#4201, HB165 H-4) ──────────────────────────
info "5c. apt channel isolation: a stable rebuild after edge must not list edge"
EDGEDEB="$ROOT/dist/deb/xpf-appliance_0.0.0-edge.selftest.deb"
EDGEDIR="$WORK/pkg-edge"; mkdir -p "$EDGEDIR/DEBIAN"
cat > "$EDGEDIR/DEBIAN/control" <<EOF
Package: xpf-appliance
Version: 0.0.0-edge
Architecture: amd64
Maintainer: selftest <selftest@xpf.invalid>
Description: xpf selftest edge package
EOF
dpkg-deb --build "$EDGEDIR" "$EDGEDEB" >/dev/null 2>&1
trap 'cleanup; cleanup_deb; rm -f "$EDGEDEB"' EXIT INT TERM
XPF_GPG_KEY="$GPGKEY" sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite edge \
    --debs "$EDGEDEB" >/dev/null 2>&1 || bad "edge repo build failed"
# Rebuild stable AFTER edge exists — the exact H-4 trigger.
XPF_GPG_KEY="$GPGKEY" sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite stable \
    --debs "$FAKEDEB" >/dev/null 2>&1 || bad "stable rebuild failed"
SPKG="$OUT/apt/dists/stable/main/binary-amd64/Packages"
if grep -q "Version: 0.0.0-edge" "$SPKG"; then
    bad "stable Packages lists the EDGE version (channel bleed)"
else
    ok "stable Packages does not list the edge version (isolated per-suite pool)"
fi
if grep -q "^Filename: pool/stable/main/x/xpf/" "$SPKG"; then
    ok "stable Filename points at the suite-scoped pool"
else
    bad "stable Filename is not suite-scoped"
fi

# ── 5d. publish key-agreement gate (#4203, HB165 H-15) ────────────────────
info "5d. publish key-agreement: installer/keyring/InRelease signer must match"
mk_installsh() {  # mk_installsh <dest-install.sh> <armored-key-file>
    { echo '#!/bin/sh'
      echo "ARCHIVE_KEY=\$(cat <<'KEYEOF'"
      cat "$2"
      echo "KEYEOF"
      echo ")"
    } > "$1"
}
ARCHASC="$WORK/archive.asc"
gpg --batch --armor --export selftest@xpf.invalid > "$ARCHASC"
# Positive: install.sh embeds the SIGNER key -> gate passes.
KAOK="$WORK/kagree-ok"; mkdir -p "$KAOK"; cp -r "$OUT/apt" "$KAOK/apt"
mk_installsh "$KAOK/install.sh" "$ARCHASC"
if XPF_ARCHIVE_PUBKEY="$ARCHASC" $PY "$DIST/publish.py" \
     --dist "$KAOK" --channel stable --no-image >/dev/null 2>&1; then
    ok "publish passes when install.sh embeds the signer key"
else
    bad "publish should PASS when install.sh embeds the signer key"
fi
# Negative: a DIFFERENT (stale) embedded key must be rejected.
cat > "$WORK/gpg-batch2" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: xpf selftest stale
Name-Email: stale@xpf.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/gpg-batch2" >/dev/null 2>&1
gpg --batch --armor --export stale@xpf.invalid > "$WORK/stale.asc"
KABAD="$WORK/kagree-bad"; mkdir -p "$KABAD"; cp -r "$OUT/apt" "$KABAD/apt"
mk_installsh "$KABAD/install.sh" "$WORK/stale.asc"
if XPF_ARCHIVE_PUBKEY="$ARCHASC" $PY "$DIST/publish.py" \
     --dist "$KABAD" --channel stable --no-image >/dev/null 2>&1; then
    bad "publish MUST reject a stale install.sh key but PASSED"
else
    ok "publish rejects install.sh embedding a non-signer key"
fi
# Negative: InRelease signer absent from the packaged keyring must be rejected.
if XPF_ARCHIVE_PUBKEY="$WORK/stale.asc" $PY "$DIST/publish.py" \
     --dist "$KAOK" --channel stable --no-image >/dev/null 2>&1; then
    bad "publish MUST reject a signer absent from the keyring but PASSED"
else
    ok "publish rejects an InRelease signer absent from the packaged keyring"
fi

# ── 5e. deb ships the kernel-promote OnFailure= recovery unit (#4202, H-6) ─
info "5e. packaging: the promote unit's OnFailure= recovery unit ships in the .deb"
PROMOTE="$ROOT/scripts/image/xpf-kernel-promote.service"
ONFAIL=$(sed -n 's/^OnFailure=//p' "$PROMOTE" | head -n1)
if [ -n "$ONFAIL" ] && [ -f "$ROOT/scripts/image/$ONFAIL" ] \
   && grep -q "cp scripts/image/$ONFAIL" "$ROOT/debian/rules" \
   && grep -q "name=${ONFAIL%.service}" "$ROOT/debian/rules"; then
    ok "debian/rules stages the OnFailure= recovery unit ($ONFAIL)"
else
    bad "debian/rules does NOT stage the promote OnFailure= unit ($ONFAIL) — dangling recovery reference"
fi

# ── 6. install.sh dry-run ──────────────────────────────────────────────────
info "6. install.sh --dry-run (preflight + source rendering)"
if XPF_DRY_RUN=1 XPF_APT_BASE_URL="https://example.invalid/apt" XPF_CHANNEL=stable \
   sh "$DIST/install.sh" >"$WORK/install.out" 2>&1; then
    if grep -q "preflight OK" "$WORK/install.out" \
       && grep -q "Suites: stable" "$WORK/install.out"; then
        ok "install.sh dry-run preflight + source render OK"
    else
        bad "install.sh dry-run output missing expected lines"; cat "$WORK/install.out" >&2
    fi
else
    # Dry-run on THIS host may legitimately fail preflight (kernel < 6.18 etc.).
    # That is a valid PASS for the preflight logic — assert it failed for a
    # preflight reason, not a script error.
    if grep -q "ERROR:" "$WORK/install.out" && \
       grep -qE "kernel|arch|distro|os-release" "$WORK/install.out"; then
        ok "install.sh dry-run preflight correctly refused this host"
    else
        bad "install.sh dry-run errored unexpectedly"; cat "$WORK/install.out" >&2
    fi
fi

# ── tally ──────────────────────────────────────────────────────────────────
echo
echo "==> selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "==> #1924 signed-distribution roundtrip OK (throwaway key; no real key, no host)"
