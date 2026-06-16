# Claude SMR hostile plan-review — #1924 r1

Reviewer: Claude (domain SMR + security/build-release + SW-design).
Posture: HOSTILE. The plan must EARN PLAN-READY.

## What the plan gets right (briefly)
- Correctly identifies the real gap: `bake.py` emits unsigned `SHA256SUMS`;
  no channel; the `xpf-appliance` metapackage exists but has no repo. Grounded
  in the actual source (verified against bake.py step 6 + debian/control).
- Correctly keeps the two USER decisions as parametrised inputs, not invented.
- Correctly rejects TOFU and legacy `apt-key`.
- Blast radius is honestly additive (no pkg/** or userspace-dp/** touched).

## Hostile findings

### F1 (MAJOR → resolve before READY): the install.sh.minisig "loop closure" is weak as stated
§8 R1 says publishing `install.sh.minisig` signed by the IMAGE key lets the
paranoid operator "verify install.sh with the SAME pinned pubkey." But to
verify install.sh the operator must FIRST obtain the pinned minisign pubkey
out-of-band. The plan says the pubkey "ships in-repo + published at a
well-known URL" (§3, §5.1). If the operator fetches the pubkey from the SAME
host that serves install.sh, the loop is CIRCULAR — a host that tampers
install.sh also serves a matching pubkey + sig. The ONLY real root is an
out-of-band pubkey (the in-repo checked-in copy via `git clone` over a
different trust path, or a fingerprint the operator already knows). The plan
must state explicitly that the pinned pubkey's authenticity comes from the
in-repo checked-in copy (GitHub repo trust) or a documented fingerprint, NOT
from the dist host. Otherwise §8 R1's mitigation is theater. FIX: add one
sentence in §3 + §8 R1: "the minisign pubkey's root of trust is the in-repo
checked-in copy obtained via `git clone`/GitHub, independent of
`XPF_DIST_BASE_URL`; the published copy is a convenience, never the root."

### F2 (MAJOR → resolve): `apt-get update && apt install` over the network still needs the pubkey-trust chain spelled out for the `curl | sh` case
The headline UX is `curl -fsSL <url>/install.sh | sh`. In that flow the
operator runs install.sh BEFORE any verification. The embedded keyring then
makes apt self-authenticating — GOOD. But the plan should explicitly concede
that `curl | sh` trusts install.sh on first fetch (TLS only), and that this is
the SAME trust level Tailscale/Docker/rustup accept. The plan currently frames
R1 as if the .minisig closes this, but F1 shows it doesn't for the `curl | sh`
user (who by definition didn't verify first). FIX: state the honest trust
level of the one-liner (TLS + first-fetch trust of install.sh), and reserve
the .minisig path for the "download-read-verify-run" operator who got the
pubkey via git. Two clearly-separated UX tiers, honestly labeled.

### F3 (MEDIUM): minisign signs SHA256SUMS but the incus metadata + qcow2 must BOTH be in SHA256SUMS, and validate.py/xpf-deploy.py must verify the FILE THEY IMPORT is the one listed
Transitive trust only holds if (a) every consumed artifact is listed in
SHA256SUMS and (b) the verifier checks the imported file's hash against the
signed list, not just that *a* file matches. bake.py step 6 today lists exactly
`qcow_out` and `meta_out` — good. But the plan's §5.2 says "`sha256sum -c
SHA256SUMS`" which checks files in CWD; if the operator imports from a
different path, the check can silently pass on stale local copies. FIX: §5.2
must verify the EXACT files passed to `--qcow2`/`--metadata` against their
entries (compute hash of the import target, compare to the signed list), not a
cwd-relative `sha256sum -c`. Minor wording but a real correctness hole.

### F4 (MEDIUM): reprepro single-version-per-distribution vs the appliance's versioned .deb + the in-place upgrade story
debian/control + docs/in-place-upgrade.md show the `.deb` version is git-derived
(DEB_VERSION) and the upgrade path is `apt upgrade xpf` → staging refresh (no
restart) then `xpfd upgrade`. reprepro by default keeps ONE version per
suite/arch. That is FINE for "latest in stable," but it means an operator
cannot `apt install xpf=<oldver>` to pin/rollback via apt — rollback is the
`xpfd upgrade` mechanism's job (#1917), not apt's. The plan should state this
explicitly so reviewers don't expect apt-level version pinning. If apt-level
multi-version pinning IS wanted, that's the aptly path (§4B). FIX: §4B add a
sentence: "reprepro keeps latest-per-suite; apt-level rollback is NOT provided
— rollback is `xpfd upgrade`'s job (#1917). Choose aptly only if apt-pin to an
older version is a requirement (OQ for the user)."

### F5 (MINOR): `XPF_PUBLISH_CMD` is under-specified as a contract
§4D/§5.5 make publish pluggable via `XPF_PUBLISH_CMD`, but a free-form command
string is a footgun (what args? what cwd? does it get the dist tree path?).
FIX: define the contract precisely — e.g. `XPF_PUBLISH_CMD` is invoked as
`$XPF_PUBLISH_CMD <local-dist-dir> <XPF_DIST_BASE_URL>` and must be idempotent.
One line; prevents the engineer from inventing an ad-hoc interface.

### F6 (MINOR): test strategy lacks a "verify rejects the dev/unsigned bake" case
§6 covers tamper-negative tests (good). But the most likely PRODUCTION mistake
is publishing an UNSIGNED dev bake (the `--skip-validate`-style escape hatch in
§5.1). Add a test: when `XPF_SIGN_SECKEY` is unset, bake emits NO `.minisig`
AND prints the "do not publish" warning, AND a publish-time guard (`make
dist-publish`) REFUSES to push image artifacts lacking a `.minisig`. The
publish-time refusal is the real safety net and isn't in the plan. FIX: add a
`dist-publish` precondition: refuse to publish any image artifact without a
verifying `.minisig`.

### F7 (NIT): two-key split is the right call but name the keys consistently
§4A "xpf-image.pub" vs §3 "xpf.pub" vs §2 "xpf-archive-keyring.asc" — three
names floating. Pin the naming: `xpf-image.pub` (minisign, image+install.sh),
`xpf-archive-keyring.asc` (PGP, apt). Cosmetic but the doc is the contract.

## Verdict

**PLAN-NEEDS-MAJOR** (r1).

The architecture is sound and the path-option analysis is genuinely good
(minisign-image + PGP-apt split is correct; reprepro is the right default;
TOFU correctly rejected). But two MAJOR issues (F1 circular-trust framing of
the .minisig loop; F2 honest trust level of `curl | sh`) and one correctness
hole (F3 verify-the-imported-file-not-cwd) must be fixed before this is a plan
an engineer can implement without re-deriving the trust model. F4–F7 are
tighten-ups. None of these are kills — the design is right; the trust-model
PROSE is imprecise in exactly the place where imprecision becomes a security
bug. Fix F1–F3, address F4–F7, and this is PLAN-READY.

The two OPEN QUESTIONS are correctly NOT blockers — verified: every mechanism
in §5 functions with a placeholder pubkey + parametrised URL; only the actual
public release needs the values.
