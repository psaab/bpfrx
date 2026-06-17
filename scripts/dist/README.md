# xpf signed distribution tooling (#1924)

Mechanism for a signed, hosted appliance distribution. Spec:
`docs/research/1924-signed-hosted-dist/plan.md`. Operator runbook:
`docs/distribution.md`.

## Files

| File | Role |
|---|---|
| `sign.py` | minisign sign/verify + per-version manifest helpers (shared by bake/validate/deploy/publish) |
| `build-apt-repo.sh` | builds a flat signed apt repo (default) or reprepro (opt-in) |
| `install.sh` | Tailscale-style one-command installer (preflight + keyring + apt source + install) |
| `publish.py` | fail-closed publish gate + `XPF_PUBLISH_CMD` dispatch |
| `xpf-image.pub.placeholder` | PLACEHOLDER minisign public key (see below) |
| `xpf-archive-keyring.asc.placeholder` | PLACEHOLDER OpenPGP apt archive key (see below) |

## The two operator inputs (OPEN QUESTIONS — not wired to real values here)

This tooling is complete as a MECHANISM. Going live needs two operator
decisions, supplied at release time as config inputs (never hardcoded):

1. **Hosting target** — `XPF_IMAGE_BASE_URL` (images + `install.sh` +
   `latest.json`; any static host incl. GitHub Releases) and
   `XPF_APT_BASE_URL` (the `dists/`+`pool/` apt tree; needs a
   directory-serving host — NOT GitHub Releases flat assets). Plus the
   retention policy and channel layout (`stable`/`edge`).
2. **Signing identity** — the minisign keypair (images) and the OpenPGP
   archive key (apt): who holds the secret keys, rotation cadence, and where
   the public keys are pinned/published.

## Placeholder keys — replace before any real publish

`xpf-image.pub.placeholder` and `xpf-archive-keyring.asc.placeholder` are
generated placeholders whose SECRET keys were shredded at generation and are
held by NO ONE. They exist so the mechanism + tests have a concrete pubkey
path shape, and so the repo never ships a key that anyone can sign for.

To go live (engineer/release time, after OQ-2 is decided):

1. Generate the real image keypair on the signing host:
   `minisign -G -p xpf-image.pub -s xpf-image.sec` (keep `.sec` OFF the repo
   and off CI unless OQ-4 chooses CI signing).
2. Generate the real OpenPGP archive key; export the public key to
   `xpf-archive-keyring.asc`.
3. Commit the real PUBLIC keys as `scripts/dist/xpf-image.pub` and
   `scripts/dist/xpf-archive-keyring.asc` (drop the `.placeholder` suffix).
   These public files are the pinned trust roots; their authenticity comes
   from the in-repo git copy, NOT from any hosting URL.
4. Point signing at the secret key by PATH: `XPF_SIGN_SECKEY=/secure/xpf-image.sec`
   for the bake, and the OpenPGP key id for `build-apt-repo.sh`.

The signing secret key is referenced by PATH only. It is NEVER committed,
logged, or embedded. Tests use a throwaway keypair generated in a temp dir.

## Roundtrip (the local gate — no hosting, no real key)

```bash
scripts/dist/selftest.sh     # generates a throwaway key, signs, verifies,
                             # proves tamper-detection, builds a flat repo,
                             # and dry-runs install.sh
```
