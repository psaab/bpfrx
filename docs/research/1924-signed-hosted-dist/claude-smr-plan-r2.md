# Claude SMR hostile plan-review — #1924 r2

Reviewer: Claude (domain SMR). Posture: HOSTILE.

## r1 findings — all resolved (verified)
F1 circular trust (out-of-band git pubkey root, §3/§4C/§8), F2 honest curl|sh
tier (§4C Tier A), F3 verify-exact-file (§5.2 per-file parse+hash), F4 reprepro
single-version (§4B note), F5 XPF_PUBLISH_CMD contract (§5.5), F6 fail-closed
publish (§5.5), F7 naming (unified). Confirmed in the r2 text.

## NEW findings introduced by / surviving r2 (agree with Codex r2)

- **N1 (MAJOR) — `xpf-deploy.py` cannot bind bytes for the incus alias flow.**
  §5.2 says xpf-deploy verifies the `--qcow2`/`--metadata` paths "before incus
  image import", but xpf-deploy.py today does NOT import an image — it `incus
  init ap["image"]` against a pre-existing alias (xpf-deploy.py ~L300). There
  is no qcow2 path at deploy time. The verify hook belongs at the IMPORT step,
  which is a NEW `--image-url` / explicit-import mode, OR in `validate.py`
  (which DOES import). Fix: scope image-verify to (a) bake-time + validate.py,
  and (b) a NEW explicit fetch/import path; STOP claiming the current
  alias-launch path verifies bytes.
- **N2 (MAJOR) — fail-closed publish omits latest.json.** §5.5 gate lists image
  manifests + InRelease + install.sh.minisig but not the §5.6 signed
  latest.json. An unsigned/stale latest.json would publish. Fix: add
  latest.json to the gate.
- **N3 (MAJOR) — apt backend self-contradiction.** §4B/§5.3 say "default = flat
  signed repo"; §8 R3 + §11 still say "use reprepro". An implementer reading §8
  picks reprepro and regresses the stateless-CI fix. Fix: make §8 R3 + §11
  consistent with flat-default.
- **N4 (MAJOR) — GitHub Releases presented as a full hosting target.** §3 lists
  GitHub Releases as satisfying the base-URL contract, but install.sh writes
  `URIs: <base>/apt` (a dists/pool tree) which §5.3 admits GH Releases cannot
  serve. Fix: split IMAGE base URL from APT base URL (two parameters), or drop
  GH Releases as a full target (it can host images, not the apt pool).
- **N5 (MEDIUM) — "fresh Debian/Ubuntu host" overpromise.** §3 promises one-cmd
  apt install on "a fresh Debian/Ubuntu host," but the kernel ≥6.18 verifier
  floor + driver set are the IMAGE's closure; debian/control says kernel is out
  of scope. A Debian 12 / Ubuntu 24.04 host installs the packages but xpfd's
  verify-dataplane rejects the kernel. Fix: install.sh PREFLIGHT (kernel ≥6.18,
  amd64, networkd) that refuses with a clear message; restate that bare-metal
  apt-install targets a host that already meets the kernel floor, else use the
  image.

## AGY r2 nits — all valid, fold in
- **NIT-2 (elevate to MEDIUM) — key rotation strands existing hosts.** If the
  archive keyring lives ONLY inline in install.sh, existing hosts never re-run
  it and lock out when the old key retires. Fix: the `xpf`/`xpf-appliance`
  package PAYLOAD must own `/etc/apt/keyrings/xpf-archive-keyring.asc` so a
  normal `apt upgrade` ships the rotated key during the dual-sign window. This
  is the standard apt-keyring-in-package pattern; it MUST be in the plan.
- **NIT-1 — Valid-Until vs manual signing deadlock.** Short Valid-Until + manual
  air-gap signing = repo expires with no re-sign. Fix: document a LONG
  Valid-Until (e.g. 1 year) for manual cadence, or require an automated
  re-sign job; make it an OQ.
- **NIT-3 — monotonic freshness watermark has no storage.** xpf-deploy is
  stateless. Fix: define the watermark location + label the image freshness
  check best-effort.

## Nits
- §6 still references "byte-flip fails at sha256sum -c" — stale vs the parsed
  verifier (Codex nit). Fix wording.
- stray code fence near §11 (Codex nit).

## Verdict
**PLAN-NEEDS-MAJOR** (r2). r2 correctly fixed every r1 finding, but the
restructuring introduced internal contradictions (N1–N4) and surfaced a real
operational lockout (NIT-2 key rotation) that an implementer would hit. These
are plan-consistency + one genuine design gap, not architecture errors — the
trust model and tool choices are right. Fix N1–N5 + fold NIT-1/2/3 and this is
PLAN-READY. I align with Codex's NEEDS-MAJOR over AGY's READY-WITH-NITS: N1 and
N4 are contract bugs an engineer cannot implement around without re-deciding.
