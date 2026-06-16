Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed29e-1e1d-7891-87ff-38e02d698588
--------
user
You are a HOSTILE plan reviewer (research-only, NO code). xpf project, GitHub
issue #1924: signed, hosted appliance distribution. This is ROUND 2 — you
PLAN-NEEDS-MAJOR'd r1. Verify your r1 findings are ACTUALLY resolved in r2, and
hunt for NEW issues introduced by the r2 changes.

Read docs/research/1924-signed-hosted-dist/plan.md (now r2, see §12 change log
mapping each r1 finding to its fix). Re-ground in scripts/image/bake.py,
scripts/deploy/{validate.py,xpf-deploy.py}, debian/control, debian/xpf.postinst,
docs/in-place-upgrade.md, docs/install-images.md.

Your r1 findings were: (1) verify-wrong-bytes/path-binding; (2) publish not
fail-closed; (3) retention breaks global SHA256SUMS; (4) replay/freshness;
(5) install.sh inline-vs-pin inconsistency; (6) loop closes only with
out-of-band image key. CHECK each is resolved (per-file verify §5.2;
fail-closed publish §5.5; per-version manifests §5.1; freshness §5.6;
inline-keyring §3/§4C; out-of-band pubkey root §3/§4C/§8).

Be hostile. Quote exact r2 lines. No KILL without a counter-example. If all
your r1 findings are resolved AND no new blocker exists, you may PLAN-READY.
End with EXACTLY one verdict: PLAN-READY / PLAN-READY-WITH-NITS /
PLAN-NEEDS-MAJOR / PLAN-KILL + one-paragraph rationale.
codex
I’ll re-read the r2 plan against the exact files the plan claims to constrain, then I’ll test each r1 fix as a concrete invariant rather than accepting the changelog mapping.
exec
/bin/bash -lc 'wc -l docs/research/1924-signed-hosted-dist/plan.md scripts/image/bake.py scripts/deploy/validate.py scripts/deploy/xpf-deploy.py debian/control debian/xpf.postinst docs/in-place-upgrade.md docs/install-images.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 exited 1 in 0ms:
   556 docs/research/1924-signed-hosted-dist/plan.md
wc: scripts/deploy/validate.py: No such file or directory
   435 scripts/image/bake.py
   491 scripts/deploy/xpf-deploy.py
    67 debian/control
   131 debian/xpf.postinst
   169 docs/in-place-upgrade.md
   231 docs/install-images.md
  2080 total

exec
/bin/bash -lc 'rg -n "''^(#|##|###|####)|r1|R1|finding|verify|publish|retention|fresh|replay|install'"\\.sh|inline|keyring|pubkey|SHA256SUMS|manifest|fail-closed|fail closed|out-of-band|loop|§|Change|Round\" docs/research/1924-signed-hosted-dist/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
1:# Plan of action — #1924: signed, hosted appliance distribution
4:> Status: REVISED after r1 3-way hostile review (Codex + AGY + Claude SMR all
5:> PLAN-NEEDS-MAJOR). r2 changes log at the bottom (§12).
10:## 1. Problem statement
16:- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
17:  (plain sha256 of the qcow2 + incus metadata) and a `dist/xpf-<ver>.manifest`
21:  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
22:- **No published distribution channel.** `make deb` writes to `dist/deb/`;
23:  `make image` writes to `dist/`. There is no hosted location, no retention
30:  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
39:### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)
46:- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
47:  repo host), the retention policy, and the channel layout (stable / edge).
52:public key file + `XPF_SIGN_SECKEY` (path, never the key itself). See §9.
54:## 2. Blast radius / affected surface
59:| Area | Change class | Files |
61:| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
62:| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
64:| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
65:| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
66:| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
75:## 3. Design overview
79:1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
80:   checksum manifest), so one signature transitively authenticates the qcow2 +
84:3. **`install.sh`** (Tailscale-style) that bootstraps trust (installs the
85:   pinned archive keyring), adds the apt source, and runs `apt install
86:   xpf-appliance` — one command on a fresh Debian/Ubuntu host.
88:Publishing (where bytes land) is a thin `dist-publish` target parametrised by
93:### Trust model (the spine of the design)
97:- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
98:  PUBLIC key out-of-band ONCE (checked into the repo + published at a
101:  signed `Release`/`InRelease` once the archive keyring is installed under
102:  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
104:The `install.sh` bootstrap is the ONLY moment trust is established over the
105:network, so it is the highest-risk step and gets the most scrutiny (§4C, §8).
106:**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
107:pin a fingerprint — those were mutually exclusive in r1; we picked inline).
108:install.sh's own integrity is therefore the bootstrap root. The minisign
109:**image** pubkey (`xpf-image.pub`) used for Tier-B verify-before-run has its
113:Mitigations and the honest trust tiers are in §4C + §8.
115:## 4. Multiple Path Options
117:### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
121:| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
123:| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
124:| **cosign / sigstore** | keyless OIDC option, transparency log | requires Fulcio/Rekor infra or a static key; new dep; apt still needs PGP; over-engineered for a single-publisher appliance |
127:- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
128:  exactly the issue's lead, one pinned Ed25519 pubkey. The image consumer
137:the repo and published. (An ALTERNATIVE single-tool variant — PGP for both,
138:dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
139:the recommendation is the two-tool split because minisign's single-pubkey pin
140:is dramatically simpler to verify in install.sh and in our Python consumers.)
142:#### 4A-alt. Single-tool (PGP-only) variant
143:Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
145:(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
146:with a keyring, which is heavier and more error-prone to pin than `minisign
148:single-publisher appliance. Kept as a fallback if the user prefers exactly one
151:### 4B. Apt repository tooling
156:| **aptly** | snapshots, multi-version, mirroring, publish to S3 natively, channels (stable/edge) map to "distributions" cleanly | larger, its own DB, more moving parts than we need for one package |
160:DEPENDS on the publish model (OQ-1), and the plan says so instead of
162:- **Stateful publisher (a persistent host/bucket that survives between
166:- **Stateless CI publisher (e.g. a fresh GitHub Actions runner each release):
173:- **aptly** remains the option if S3-native publish + snapshots/mirroring are
174:  wanted (it manages its own state + publishes to S3 directly).
177:stateful and stateless publishers and has zero non-dpkg/gpg dependencies; pick
178:reprepro only if the publisher is known-persistent and the operator prefers its
180:signed `InRelease`), so the install.sh side is unaffected by the choice.
182:**r2 retention (resolves Codex-3 for the apt side):** apt suites keep the
185:the aptly/multi-version path (a user OQ, flagged in §9).
187:Channel layout (deb822, the contract install.sh writes):
195:  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
198:### 4C. install.sh trust-bootstrap (the security-critical step)
202:| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
203:| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
206:**Recommendation:** **embed the ASCII-armored archive pubkey inline** in
207:install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
208:through apt's own signed `Release`. The keyring-in-install.sh means there is
209:exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
210:and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
211:the inline-embed and the "fetch keyring + pin fingerprint" options are mutually
212:exclusive — the plan picks inline-embed and drops the fingerprint-pin language
213:from §3. The trust model is therefore precisely: *"an authentic install.sh
218:- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
219:  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
221:  user (they ran the script before verifying). State this honestly.
222:- **Tier B — verify-before-run.** The operator obtains `xpf-image.pub` **via
223:  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
224:  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
225:  The loop closes ONLY because the pubkey came from the repo, not the dist host
226:  (SMR-F1). Docs MUST say: "get the pubkey/fingerprint from the source repo or
229:### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)
234:| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
237:**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
244:## 5. Detailed mechanism (recommended path)
246:### 5.1 Image signing (bake.py, additive) — PER-VERSION, not a global SHA256SUMS
248:**r2 change (resolves Codex-3 retention + AGY-HIGH-1 partial-download +
250:`dist/SHA256SUMS`. Instead each bake writes a **per-version, version-named**
251:checksum manifest and signs THAT:
253:dist/xpf-<ver>.SHA256SUMS          # lists exactly this version's qcow2 + metadata
254:dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
258:minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
259:         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
262:  v1's checksums — each version owns its signed manifest. A `latest` symlink/
265:- The manifest lists BOTH the qcow2 and the incus metadata, BUT verification
266:  (§5.2) is **per-file**, so the libvirt operator who only fetched the qcow2
267:  can verify it without the metadata present (AGY-HIGH-1).
270:  the publish-time guard (§5.5) then REFUSES to publish unsigned artifacts —
271:  signing is fail-OPEN at bake but fail-CLOSED at publish.
273:  copied into `dist/` so the published tree is self-describing. **Its root of
275:  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
278:### 5.2 Image verify (validate.py + xpf-deploy.py) — verify the EXACT imported file
282:1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
283:   the manifest is authentic.
284:2. **Parses** the manifest, rejecting pathful entries and duplicate basenames,
287:   argument paths), computes its SHA256 and compares against the manifest entry
289:   Files in the manifest that the operator did NOT fetch are simply not checked
291:Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
294:- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
295:  to the artifacts; `--no-verify-sig` escape hatch for local dev bakes).
296:- `xpf-deploy.py`: verify each image file before `incus image import` /
299:- Pinned pubkey path is a checked-in constant; `XPF_IMAGE_PUBKEY` overrides for
302:### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh)
303:Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
305:  the freshly built `dist/deb/xpf_*.deb` + `xpf-appliance_*.deb`, the channel
310:  Release.gpg`; include `Valid-Until` (§5.6 freshness).
314:- Output: standard `dists/` + `pool/` tree under `dist/apt/`, ready to publish.
321:### 5.4 install.sh (NEW)
324:2. Install the pinned archive keyring to `/etc/apt/keyrings/
325:   xpf-archive-keyring.asc` (embedded inline, `0644`).
333:- `install.sh` is itself published at `XPF_DIST_BASE_URL/install.sh` and the
334:  doc gives both Tier A (one-liner) and Tier B (verify-before-run) per §4C.
337:install.sh's FIRST install is safe (no running daemon to cut). But a later
354:### 5.5 Makefile + docs + fail-closed publish
357:  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
358:- **r2 fail-closed publish (resolves Codex-2 + SMR-F6):** `make dist-publish`
360:  non-zero, nothing uploaded) unless, for every artifact in the publish set:
361:  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
362:  pinned pubkey; (b) the apt `InRelease` verifies against the archive pubkey;
363:  (c) `install.sh.minisig` verifies (if install.sh is in the set). Bake may be
364:  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
370:- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
371:  channel policy, retention, publish backends, the `apt upgrade` blip note from
372:  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
373:  image verify steps, the out-of-band pubkey source).
375:  verify from `XPF_DIST_BASE_URL`"; document the per-version
376:  `xpf-<ver>.SHA256SUMS.minisig`.
378:### 5.6 Freshness / anti-rollback (r2 — resolves Codex-4)
380:Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
381:Mitigations, scaled to a single-publisher appliance (not full TUF):
384:  refuses a stale `Release` — built-in replay protection for the package path,
385:  re-signed each publish.
387:  bake date + the per-version manifest name) signed with the image key. The
392:  "detects stale mirrors / accidental rollback," with TUF-grade freshness
396:## 6. Test / validation strategy (research scope = how /engineer will prove it)
400:1. **Sign/verify round-trip (image):** bake (or a stub SHA256SUMS) → sign with
401:   a throwaway minisign key → `verify_artifacts` PASSES; flip one byte of the
402:   qcow2 → verify FAILS at `sha256sum -c`; flip the `.minisig` → verify FAILS
403:   at `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
404:   verify that can't fail is theater.)
406:   container (or the local incus image flow) → run install.sh pointed at a
410:3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
411:   wrong arch; the inline-embedded keyring matches the archive signing key used
414:3b. **Fail-closed publish (r2):** `make dist-publish` with an UNSIGNED image in
415:   the set EXITS non-zero and uploads NOTHING (assert the publish shim is never
417:   production mistake — publishing an unsigned dev bake — is blocked here.)
425:   copy-pasteable against a local test publish.
429:## 7. Rollout / sequencing
434:- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
435:  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
438:  reprepro `conf/distributions`, `make dist-repo`, PGP archive pubkey
440:- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
441:  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
443:  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
449:release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
452:## 8. Risks & mitigations
454:- **R1 — install.sh is the trust root over the network.** A compromised host
455:  serving a bad install.sh defeats everything. Mitigation: publish install.sh
456:  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
457:  self-authenticating once install.sh runs); document a verify-before-run
458:  variant (publish `install.sh.minisig` too, signed by the image key, so the
459:  paranoid operator verifies install.sh with the SAME pinned pubkey they used
460:  for the image). This closes the loop: ONE pinned pubkey authenticates both
461:  the image and install.sh.
463:  must not hardcode a single key. Mitigation: pubkey paths are overridable
465:  rotation runbook (publish new pubkey, dual-sign during overlap, retire old).
473:  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
477:  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
483:  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
485:  §4A-alt remains the fallback if the user wants exactly one identity.
487:## 9. Open questions (engineer-time inputs — NOT blockers to PLAN-READY)
490:  layout (which suites exist), and the retention policy. Mechanism treats it as
495:  public keys are pinned/published. Mechanism ships placeholder pubkeys + reads
497:- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
502:  on an air-gapped host (manual sign+publish)? Drives whether Inc 4 ships. A
505:## 10. Why not just keep SHA256SUMS?
510:a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
513:## 11. Recommendation summary
515:- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
519:- Bootstrap: **install.sh** with the archive keyring embedded inline +
520:  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
521:- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
530:## 12. r1 → r2 change log (response to 3-way hostile review)
532:All three r1 reviewers returned **PLAN-NEEDS-MAJOR** (Codex, AGY, Claude SMR).
533:The convergent + unique findings and their resolutions:
537:| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
538:| Partial download (libvirt fetches only qcow2) crashes `sha256sum -c` on missing metadata | AGY-HIGH-1 | §5.1/§5.2: per-file verification; missing-but-unfetched files are not checked. |
539:| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
540:| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
541:| `curl \| sh` honest trust level | SMR-F2 | §4C: Tier A = TLS + first-fetch trust (same as Tailscale/Docker/rustup), stated plainly. |
542:| Publish not fail-closed (unsigned dev bake can ship) | Codex-2, SMR-F6 | §5.5: `make dist-publish` precondition gate refuses unsigned artifacts. |
543:| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
544:| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
545:| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
546:| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
547:| GitHub Releases can't host a `dists/`+`pool/` tree | AGY-MEDIUM-3 | §5.3: flagged as an OQ-1 constraint (Pages/bucket needed for the pool). |
548:| OQ coupling = hidden blockers? | AGY-MEDIUM-3 | §9: confirmed engineer-time inputs; every §5 mechanism runs with placeholder key + parametrised URL. |
549:| `XPF_PUBLISH_CMD` under-specified | SMR-F5 | §5.5: exact contract `$CMD <dist-dir> <base-url>`, idempotent. |
550:| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |
552:Two findings examined and held as documentation-only (not #1924 code scope):
554:single-tool §4A-alt (kept as the user's OQ-3 fallback). The minisign(image) +

exec
/bin/bash -lc 'pwd && git rev-parse HEAD && git status --short && git worktree list' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
fb70ef7cc617be8ede11b3f9eb465d53cf87cbaf
?? docs/research/1924-signed-hosted-dist/codex-plan-r2.md
/home/ps/git/bpfrx                                                          ecdc16f2e [master]
/home/ps/git/bpfrx-prs                                                      a17f308e1 [pr/license-autoupdate-url-tracking]
/home/ps/git/bpfrx/.claude/worktrees/1614-research-v2                       9ebbd158e [research/1614-residual-v2]
/home/ps/git/bpfrx/.claude/worktrees/1693-rate-aware-placement              c8afabb43 [refactor/1693-rate-aware-placement]
/home/ps/git/bpfrx/.claude/worktrees/1736-research                          95d7a016a [research/1736-wg-interop]
/home/ps/git/bpfrx/.claude/worktrees/1741-cos-active-flow-overcount         194bc6d81 [refactor/1741-cos-active-flow-overcount]
/home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count               b4ad1811a [research/1741-flow-count]
/home/ps/git/bpfrx/.claude/worktrees/1742-research-xsk-fanout               7c04f0733 [research/1742-same-queue-xsk-fanout]
/home/ps/git/bpfrx/.claude/worktrees/1746-research-equal-flow-target-policy fb4f2fd6a [research/1746-equal-flow-target-policy]
/home/ps/git/bpfrx/.claude/worktrees/1748-ntuple-rebalance                  d937500c8 [engineer/1748-ntuple-rebalance]
/home/ps/git/bpfrx/.claude/worktrees/1748-research-mlx5-flow-rebalance      9784ad382 [research/1748-mlx5-flow-rebalance]
/home/ps/git/bpfrx/.claude/worktrees/1751-count-balance                     b5c0af33a [engineer/1751-count-balance]
/home/ps/git/bpfrx/.claude/worktrees/1751-research-count-balance            65a70501d [research/1751-count-balance]
/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2                       4d64dad07 [research/1760-reverse-key-v2]
/home/ps/git/bpfrx/.claude/worktrees/1771-research-per-key-resolver         d24417ca1 [research/1771-per-key-resolver]
/home/ps/git/bpfrx/.claude/worktrees/1800-research-sweep-triage             7261e914b [research/1800-sweep-triage]
/home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead                 4368ccb8b [research/1849-overhead-comp]
/home/ps/git/bpfrx/.claude/worktrees/1852-research                          b797c4c2f [research/1852-frag-nat]
/home/ps/git/bpfrx/.claude/worktrees/1855-research                          5547e8a5e [research/1855-inplace-contract]
/home/ps/git/bpfrx/.claude/worktrees/1861-research                          ca1bde0c1 [research/1861-install-txn]
/home/ps/git/bpfrx/.claude/worktrees/1863-research                          776327062 [research/1863-realization-gap]
/home/ps/git/bpfrx/.claude/worktrees/1864-research                          a0ecce536 [research/1864-toolchain-pin]
/home/ps/git/bpfrx/.claude/worktrees/1865-research                          d9d8c69ed [research/1865-wg-telemetry]
/home/ps/git/bpfrx/.claude/worktrees/1866-research                          bea589a7c [research/1866-wg-teardown]
/home/ps/git/bpfrx/.claude/worktrees/1870-research                          a59f32dae [research/1870-local-tunnel-pair]
/home/ps/git/bpfrx/.claude/worktrees/1873-research                          9a93964d1 [research/1873-tunnel-ids]
/home/ps/git/bpfrx/.claude/worktrees/1875-research                          33cc213a7 [research/1875-cluster-ownership]
/home/ps/git/bpfrx/.claude/worktrees/1879-pathc                             6b77a03f6 [engineer/1879-pathc-images]
/home/ps/git/bpfrx/.claude/worktrees/1879-research                          ad37d95a8 [research/1879-install-simplify]
/home/ps/git/bpfrx/.claude/worktrees/1880-research                          9d9dde892 [research/1880-boot-budget]
/home/ps/git/bpfrx/.claude/worktrees/1881-research                          6d824b24f [research/1881-gre-frozen-state]
/home/ps/git/bpfrx/.claude/worktrees/1884-research                          ac74e6d63 [research/1884-tunnel-flap]
/home/ps/git/bpfrx/.claude/worktrees/1888-research                          d5ee82aea [research/1888-wg-timers]
/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade               16317ab61 [research/1917-deb-inplace-upgrade]
/home/ps/git/bpfrx/.claude/worktrees/1917a                                  5dabbc564 [engineer/1917a-xpf-deb]
/home/ps/git/bpfrx/.claude/worktrees/1917b-eng                              fbbd6e616 [chore/rm-resmoke-marker]
/home/ps/git/bpfrx/.claude/worktrees/1917b-inplace-upgrade-mechanism        6b6e86de4 [research/1917b-inplace-upgrade-mechanism]
/home/ps/git/bpfrx/.claude/worktrees/1921-virtio-mq-bind                    016bc7634 [engineer/1921-virtio-mq-bind]
/home/ps/git/bpfrx/.claude/worktrees/1922-pr1                               bde418374 (detached HEAD)
/home/ps/git/bpfrx/.claude/worktrees/1922-pr2                               c857f77fe (detached HEAD)
/home/ps/git/bpfrx/.claude/worktrees/1922-research-safe-bootstrap-daemon    65e4a49df [research/1922-safe-bootstrap-daemon]
/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist       fb70ef7cc [research/1924-signed-hosted-dist]
/home/ps/git/bpfrx/.claude/worktrees/1928-eng                               cef2d34c7 (detached HEAD)
/home/ps/git/bpfrx/.claude/worktrees/1928-virtio-copy-xsk-rx                22998b377 [research/1928-virtio-copy-xsk-rx]
/home/ps/git/bpfrx/.claude/worktrees/1930-research-kernel-os-upgrades       203fab2dd [research/1930-kernel-os-upgrades]
/home/ps/git/bpfrx/.claude/worktrees/research-1782-v2                       9bf29b4e9 [research/1782-v2-cold-stall]
/home/ps/git/bpfrx/.claude/worktrees/research-1824-fuzz                     fe0ac6240 [research/1824-fuzz-harness]
/home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon                   510e5cef5 [research/1825-daemon-restructure]
/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan                 883cdb7f1 [research/1827-multiwan]
/home/ps/git/bpfrx/.claude/worktrees/research-1828-sq                       d68a7fa5f [research/1828-wan-sq]
/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm                      ebb716101 [research/1829-fqcodel-aqm]
/home/ps/git/bpfrx/.claude/worktrees/research-1838-trio                     13666b4d3 [research/1838-nat-v6-trio]
/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp                     0e6a13e26 [research/1844-dhcp-nexthop]

codex
The first grounding pass found one immediate mismatch: the requested `scripts/deploy/validate.py` path does not exist in this worktree. The plan’s blast-radius table also names `scripts/image/validate.py`, so I’m checking whether that is the intended file or another path was renamed.
exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '140,320p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   140	is dramatically simpler to verify in install.sh and in our Python consumers.)
   141	
   142	#### 4A-alt. Single-tool (PGP-only) variant
   143	Use one OpenPGP key for BOTH the image `SHA256SUMS.asc` and the apt `Release`.
   144	Pros: one key to manage (one OQ-2 answer), apt-native. Cons: image consumers
   145	(validate.py, install.sh trust-bootstrap) must shell out to `gpg --verify`
   146	with a keyring, which is heavier and more error-prone to pin than `minisign
   147	-V -p key.pub`; PGP's web-of-trust/expiry semantics add footguns for a
   148	single-publisher appliance. Kept as a fallback if the user prefers exactly one
   149	signing identity.
   150	
   151	### 4B. Apt repository tooling
   152	
   153	| Option | Pros | Cons |
   154	|---|---|---|
   155	| **reprepro** | mature, deb-native, simple `conf/distributions`, signs `Release` with gpg, deterministic pool layout, no DB server | single-version-per-arch by default (fine for an appliance; multi-version needs care) |
   156	| **aptly** | snapshots, multi-version, mirroring, publish to S3 natively, channels (stable/edge) map to "distributions" cleanly | larger, its own DB, more moving parts than we need for one package |
   157	| **flat signed repo** (hand-rolled `dpkg-scanpackages` + `apt-ftparchive` + `gpg` over a flat `Release`) | zero extra tooling beyond dpkg + gpg; trivially scriptable; matches the appliance's "small set of debs" reality | we own all the index correctness; flat repos are slightly less standard for deb822 `signed-by` (work fine though) |
   158	
   159	**Recommendation (r2 REVISED — resolves AGY-MEDIUM-2):** the choice now
   160	DEPENDS on the publish model (OQ-1), and the plan says so instead of
   161	prescribing reprepro unconditionally:
   162	- **Stateful publisher (a persistent host/bucket that survives between
   163	  releases): reprepro.** Smallest mature tool, signed `Release`/`InRelease`,
   164	  `stable`/`edge` as distinct distributions, one readable `conf/distributions`.
   165	  Its Berkeley-DB under `db/` is fine when that state persists.
   166	- **Stateless CI publisher (e.g. a fresh GitHub Actions runner each release):
   167	  flat signed repo** generated from scratch via `apt-ftparchive` /
   168	  `dpkg-scanpackages` + `gpg --clearsign` over `Release`/`InRelease`. No DB to
   169	  carry between runs; the existing pool is `aws s3 sync`'d down (or `gh release
   170	  download`'d), the new `.deb` added, the indices regenerated, re-signed,
   171	  re-uploaded. This is the model that does NOT break when the runner's local
   172	  `db/` is destroyed (AGY-MEDIUM-2).
   173	- **aptly** remains the option if S3-native publish + snapshots/mirroring are
   174	  wanted (it manages its own state + publishes to S3 directly).
   175	
   176	**Default recommendation: the flat signed repo**, because it is robust to BOTH
   177	stateful and stateless publishers and has zero non-dpkg/gpg dependencies; pick
   178	reprepro only if the publisher is known-persistent and the operator prefers its
   179	ergonomics. Either way the on-disk contract is identical (deb822 `Signed-By`,
   180	signed `InRelease`), so the install.sh side is unaffected by the choice.
   181	
   182	**r2 retention (resolves Codex-3 for the apt side):** apt suites keep the
   183	latest `.deb` per arch; apt-level rollback to an older `.deb` is NOT a goal —
   184	rollback is `xpfd upgrade`'s job (#1917). If apt-pin-to-old IS wanted, that is
   185	the aptly/multi-version path (a user OQ, flagged in §9).
   186	
   187	Channel layout (deb822, the contract install.sh writes):
   188	```
   189	/etc/apt/sources.list.d/xpf.sources:
   190	  Types: deb
   191	  URIs: <XPF_DIST_BASE_URL>/apt        # OQ-1
   192	  Suites: stable                       # or edge
   193	  Components: main
   194	  Architectures: amd64
   195	  Signed-By: /etc/apt/keyrings/xpf-archive-keyring.asc
   196	```
   197	
   198	### 4C. install.sh trust-bootstrap (the security-critical step)
   199	
   200	| Option | Pros | Cons |
   201	|---|---|---|
   202	| **Embed the full keyring inline** (heredoc the ASCII-armored pubkey INTO install.sh) | no second network fetch; install.sh integrity == keyring integrity (one thing to trust) | install.sh is bigger; rotating the key means re-issuing install.sh |
   203	| **Fetch keyring + verify against a pinned fingerprint** in install.sh | install.sh stays small; key rotation = republish keyring | install.sh must still embed the fingerprint (a hash), which is the real pin; two fetches |
   204	| **TOFU (trust on first use)** — just `apt-key add` whatever is served | trivial | INSECURE — rejected; defeats the entire point of the issue |
   205	
   206	**Recommendation:** **embed the ASCII-armored archive pubkey inline** in
   207	install.sh (Tailscale does exactly this) AND verify the fetched `.deb`/repo
   208	through apt's own signed `Release`. The keyring-in-install.sh means there is
   209	exactly ONE artifact whose integrity matters at bootstrap (install.sh itself),
   210	and we publish install.sh over HTTPS at a stable URL. **r2 (resolves Codex-5):**
   211	the inline-embed and the "fetch keyring + pin fingerprint" options are mutually
   212	exclusive — the plan picks inline-embed and drops the fingerprint-pin language
   213	from §3. The trust model is therefore precisely: *"an authentic install.sh
   214	CONTAINS the apt archive key."* TOFU is rejected.
   215	
   216	**r2 honest trust tiers (resolves SMR-F2 + Codex-6):** there are two clearly
   217	separated UX tiers, labeled as such in the docs:
   218	- **Tier A — `curl -fsSL <url>/install.sh | sh`** (the one-liner). Trust level:
   219	  TLS + first-fetch trust of install.sh. This is the SAME level Tailscale /
   220	  Docker / rustup accept. The `.minisig` does NOT retroactively protect this
   221	  user (they ran the script before verifying). State this honestly.
   222	- **Tier B — verify-before-run.** The operator obtains `xpf-image.pub` **via
   223	  `git clone` of the source repo (out-of-band root)**, fetches install.sh +
   224	  `install.sh.minisig`, runs `minisign -V`, reads the script, THEN runs it.
   225	  The loop closes ONLY because the pubkey came from the repo, not the dist host
   226	  (SMR-F1). Docs MUST say: "get the pubkey/fingerprint from the source repo or
   227	  release notes, NEVER from `XPF_DIST_BASE_URL`."
   228	
   229	### 4D. Hosting / publish (OQ-1 — value is the user's; mechanism here)
   230	
   231	| Option | Pros | Cons |
   232	|---|---|---|
   233	| **GitHub Releases** (per-tag assets) | free, TLS, no infra, matches `gh release`; the repo is already on GitHub | not an apt repo by itself (need GitHub Pages or a bucket for the apt pool); release assets are per-tag not channel-stable URLs |
   234	| **Static bucket (S3/GCS/R2) behind HTTPS** | stable channel URLs, cheap, aptly publishes to S3 natively, retention via lifecycle rules | the user must own/configure the bucket + CDN/TLS (OQ-1) |
   235	| **Self-hosted static file server** | full control | the user runs+secures it |
   236	
   237	**Mechanism (host-agnostic):** `make dist-publish` rsync/`aws s3 sync`/`gh
   238	release upload`s the `dist/` tree (images + sigs) and the reprepro `apt/` pool
   239	to `XPF_DIST_BASE_URL`. The plan provides a pluggable `XPF_PUBLISH_CMD` so the
   240	user wires their chosen backend without the mechanism caring. Retention +
   241	channel layout are documented defaults (keep last N images per channel) the
   242	user tunes. **No backend is hardcoded.**
   243	
   244	## 5. Detailed mechanism (recommended path)
   245	
   246	### 5.1 Image signing (bake.py, additive) — PER-VERSION, not a global SHA256SUMS
   247	
   248	**r2 change (resolves Codex-3 retention + AGY-HIGH-1 partial-download +
   249	SMR-F3/Codex-1 path-binding):** the bake stops emitting a single global
   250	`dist/SHA256SUMS`. Instead each bake writes a **per-version, version-named**
   251	checksum manifest and signs THAT:
   252	```
   253	dist/xpf-<ver>.SHA256SUMS          # lists exactly this version's qcow2 + metadata
   254	dist/xpf-<ver>.SHA256SUMS.minisig  # minisign over the per-version manifest
   255	```
   256	Signing step (after step 6):
   257	```
   258	minisign -S -s "$XPF_SIGN_SECKEY" -m dist/xpf-<ver>.SHA256SUMS \
   259	         -t "xpf image <ver> sha256sums" -x dist/xpf-<ver>.SHA256SUMS.minisig
   260	```
   261	- **Why per-version:** retaining v1 alongside v2 (Codex-3) no longer orphans
   262	  v1's checksums — each version owns its signed manifest. A `latest` symlink/
   263	  pointer (`dist/<channel>/latest -> xpf-<ver>.*`) is a convenience, never the
   264	  trust root.
   265	- The manifest lists BOTH the qcow2 and the incus metadata, BUT verification
   266	  (§5.2) is **per-file**, so the libvirt operator who only fetched the qcow2
   267	  can verify it without the metadata present (AGY-HIGH-1).
   268	- `XPF_SIGN_SECKEY` is a PATH to the secret key (OQ-2), never the key bytes.
   269	  If unset, bake prints a loud WARNING and skips signing (dev ergonomics);
   270	  the publish-time guard (§5.5) then REFUSES to publish unsigned artifacts —
   271	  signing is fail-OPEN at bake but fail-CLOSED at publish.
   272	- The pinned PUBLIC key ships in-repo as `scripts/dist/xpf-image.pub` and is
   273	  copied into `dist/` so the published tree is self-describing. **Its root of
   274	  trust is the in-repo checked-in copy obtained via `git clone`/GitHub —
   275	  independent of `XPF_DIST_BASE_URL`. The published copy is convenience only,
   276	  NEVER the root** (SMR-F1, Codex-6, AGY-MEDIUM-1).
   277	
   278	### 5.2 Image verify (validate.py + xpf-deploy.py) — verify the EXACT imported file
   279	
   280	**r2 change (resolves SMR-F3 + Codex-1 + AGY-HIGH-1):** the verifier does NOT
   281	run a cwd-relative `sha256sum -c`. It:
   282	1. `minisign -V -p <pinned pub> -m xpf-<ver>.SHA256SUMS -x …minisig` — proves
   283	   the manifest is authentic.
   284	2. **Parses** the manifest, rejecting pathful entries and duplicate basenames,
   285	   into `{basename: hash}`.
   286	3. For EACH file actually being imported (the concrete `--qcow2` / `--metadata`
   287	   argument paths), computes its SHA256 and compares against the manifest entry
   288	   for that file's basename. A file not listed, or a hash mismatch, FAILS.
   289	   Files in the manifest that the operator did NOT fetch are simply not checked
   290	   (per-file, so qcow2-only libvirt verifies fine).
   291	Helper: `verify_image_artifact(path, manifest, minisig, pubkey)` — single-file,
   292	reused by both consumers.
   293	Wire it as:
   294	- `validate.py`: `--verify-sig` (default ON when a `.minisig` is present next
   295	  to the artifacts; `--no-verify-sig` escape hatch for local dev bakes).
   296	- `xpf-deploy.py`: verify each image file before `incus image import` /
   297	  `virt-install --import`. Future `--image-url` fetches then verifies then
   298	  imports the EXACT downloaded file.
   299	- Pinned pubkey path is a checked-in constant; `XPF_IMAGE_PUBKEY` overrides for
   300	  rotation/testing.
   301	
   302	### 5.3 Apt repo (NEW scripts/dist/build-apt-repo.sh)
   303	Default = the flat signed repo (stateless-safe, §4B); reprepro is an opt-in.
   304	- Inputs: the existing pool (synced down from `XPF_DIST_BASE_URL` if present),
   305	  the freshly built `dist/deb/xpf_*.deb` + `xpf-appliance_*.deb`, the channel
   306	  (`stable`/`edge`), the PGP key (OQ-2).
   307	- Flat path: lay out `pool/main/x/xpf/*.deb`; `apt-ftparchive packages` →
   308	  `dists/<suite>/main/binary-amd64/Packages{,.gz}`; `apt-ftparchive release` →
   309	  `dists/<suite>/Release`; `gpg --clearsign -o InRelease` + `gpg -abs -o
   310	  Release.gpg`; include `Valid-Until` (§5.6 freshness).
   311	- reprepro path (opt-in `XPF_APT_TOOL=reprepro`): `conf/distributions` with
   312	  `stable`/`edge`, `Components: main`, `Architectures: amd64`,
   313	  `SignWith: <KEYID>`; `reprepro includedeb <suite> …`.
   314	- Output: standard `dists/` + `pool/` tree under `dist/apt/`, ready to publish.
   315	- **r2 GitHub-Releases caveat (AGY-MEDIUM-3):** if OQ-1 = GitHub Releases, a
   316	  per-tag flat-asset layout CANNOT serve a `dists/`+`pool/` directory tree;
   317	  GitHub Pages or a bucket is required for the APT pool even when the IMAGES
   318	  use Release assets. The plan flags this as an OQ-1 constraint, not a blocker
   319	  to the mechanism (the flat tree is identical wherever it is served from).
   320	

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '1,140p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# Plan of action — #1924: signed, hosted appliance distribution
     2	
     3	> Revision: r2 (2026-06-16)
     4	> Status: REVISED after r1 3-way hostile review (Codex + AGY + Claude SMR all
     5	> PLAN-NEEDS-MAJOR). r2 changes log at the bottom (§12).
     6	> Branch: research/1924-signed-hosted-dist
     7	> Mode: `/research` — STOPS at PLAN-READY. No implementation, no PR, no
     8	> production source touched until `/engineer 1924`.
     9	
    10	## 1. Problem statement
    11	
    12	Follow-up from #1879 / PR #1906 (appliance images, Path C) and #1917/#1923
    13	(the `xpf` / `xpf-appliance` `.deb` + `make deb` + bake-installs-the-deb).
    14	Today the distribution story stops at "build the artifacts locally":
    15	
    16	- **No signatures.** `scripts/image/bake.py` step 6 emits `dist/SHA256SUMS`
    17	  (plain sha256 of the qcow2 + incus metadata) and a `dist/xpf-<ver>.manifest`
    18	  (provenance text). Neither is signed. An operator who downloads the image
    19	  has no cryptographic proof of origin — `sha256sum -c` only proves the file
    20	  matches a checksum file that itself is unauthenticated. A MITM or a
    21	  compromised mirror can serve a tampered image plus a matching `SHA256SUMS`.
    22	- **No published distribution channel.** `make deb` writes to `dist/deb/`;
    23	  `make image` writes to `dist/`. There is no hosted location, no retention
    24	  policy, no stable/edge channel layout. The CLAUDE.md "Quick Start" and
    25	  `docs/install-images.md` assume the operator builds locally or copies
    26	  files by hand.
    27	- **No `apt` path.** The `xpf-appliance` metapackage (debian/control) is
    28	  explicitly designed as "the operator-facing entry point: `apt install
    29	  xpf-appliance` … e.g. from a hosted apt repo" — but no such repo exists.
    30	  There is no `install.sh`, no signed `Release`/`InRelease`, no archive key.
    31	- **No verification on the consumer side.** `scripts/deploy/xpf-deploy.py`
    32	  and `scripts/image/validate.py` consume `--qcow2 … --metadata …` paths
    33	  directly with no signature import or check; `build_config_drive` in
    34	  xpf-deploy.py validates the day-0 *config*, not the *image*.
    35	
    36	Goal (issue): an operator fetches + verifies the appliance image and the
    37	packages from a trusted, signed source instead of copying files by hand.
    38	
    39	### Two decisions are the USER's, not this plan's (OPEN QUESTIONS)
    40	
    41	This plan deliberately does NOT invent answers to two inputs that are
    42	operator/infra/security decisions. The mechanism is designed so both are
    43	**config inputs**, not hardcoded constants, so the plan converges PLAN-READY
    44	pending only these two engineer-time values:
    45	
    46	- **OQ-1 — Hosting target.** WHERE artifacts are published (URL / S3 bucket /
    47	  repo host), the retention policy, and the channel layout (stable / edge).
    48	- **OQ-2 — Signing identity.** WHICH signing key, and key management: who
    49	  holds the secret key, rotation cadence, and where the public key is pinned.
    50	
    51	These are surfaced as `XPF_DIST_BASE_URL` (or equivalent) and a checked-in
    52	public key file + `XPF_SIGN_SECKEY` (path, never the key itself). See §9.
    53	
    54	## 2. Blast radius / affected surface
    55	
    56	New work is almost entirely ADDITIVE — no production dataplane / control-plane
    57	source is touched. Surface:
    58	
    59	| Area | Change class | Files |
    60	|---|---|---|
    61	| Image bake signing | extend (additive output) | `scripts/image/bake.py` (emit a signature next to SHA256SUMS) |
    62	| Image verify (deploy/validate) | extend (optional gate) | `scripts/deploy/xpf-deploy.py`, `scripts/image/validate.py` |
    63	| `.deb` repo build tooling | NEW | `scripts/dist/` (repo builder + signer) |
    64	| `install.sh` | NEW | `scripts/dist/install.sh` (or `dist/install.sh` template) |
    65	| Public key (pinned) | NEW (placeholder until OQ-2) | `scripts/dist/xpf-image.pub` (minisign, image+install.sh) + `scripts/dist/xpf-archive-keyring.asc` (PGP, apt) |
    66	| Makefile | extend | `dist-sign`, `dist-repo`, `dist-publish` targets |
    67	| Docs | extend / NEW | `docs/install-images.md`, NEW `docs/distribution.md` |
    68	| CI/release (optional) | NEW (deferrable) | `.github/workflows/release.yml` |
    69	
    70	Zero changes to: `pkg/**` (Go control plane), `userspace-dp/**` (Rust
    71	dataplane), `bpf/**`, the daemon, CLI, or the wire protocol. No smoke-test
    72	exposure on the loss cluster (no forwarding-path change). This is build/release
    73	plumbing.
    74	
    75	## 3. Design overview
    76	
    77	Three independent-but-coordinated mechanisms, each gated by a config input:
    78	
    79	1. **Sign the image artifacts** at bake time: sign the `SHA256SUMS` file (the
    80	   checksum manifest), so one signature transitively authenticates the qcow2 +
    81	   incus metadata. Verify on import in `validate.py` / `xpf-deploy.py`.
    82	2. **Build + sign an apt repo** for the `xpf` / `xpf-appliance` `.deb`s, so
    83	   `apt install xpf-appliance` works from a hosted, authenticated index.
    84	3. **`install.sh`** (Tailscale-style) that bootstraps trust (installs the
    85	   pinned archive keyring), adds the apt source, and runs `apt install
    86	   xpf-appliance` — one command on a fresh Debian/Ubuntu host.
    87	
    88	Publishing (where bytes land) is a thin `dist-publish` target parametrised by
    89	`XPF_DIST_BASE_URL` (OQ-1). The mechanism is host-agnostic: a static file
    90	server, an S3/GCS bucket fronted by HTTPS, or GitHub Releases all satisfy the
    91	contract "serve these files under a base URL over TLS".
    92	
    93	### Trust model (the spine of the design)
    94	
    95	There are TWO distinct trust roots, and the plan keeps them clean:
    96	
    97	- **Image trust** — the signature over `SHA256SUMS`. The operator obtains the
    98	  PUBLIC key out-of-band ONCE (checked into the repo + published at a
    99	  well-known URL) and pins it. Every image download is verified against it.
   100	- **Apt trust** — the apt archive signing key. `apt` itself enforces this via
   101	  signed `Release`/`InRelease` once the archive keyring is installed under
   102	  `/etc/apt/keyrings/` (modern deb822 / signed-by, NOT legacy `apt-key`).
   103	
   104	The `install.sh` bootstrap is the ONLY moment trust is established over the
   105	network, so it is the highest-risk step and gets the most scrutiny (§4C, §8).
   106	**r2:** install.sh **embeds the archive keyring inline** (it does NOT fetch +
   107	pin a fingerprint — those were mutually exclusive in r1; we picked inline).
   108	install.sh's own integrity is therefore the bootstrap root. The minisign
   109	**image** pubkey (`xpf-image.pub`) used for Tier-B verify-before-run has its
   110	root of trust in the **in-repo checked-in copy obtained via `git clone` /
   111	GitHub — independent of `XPF_DIST_BASE_URL`**; the copy served from the dist
   112	host is a convenience, NEVER the trust root (else verification is circular).
   113	Mitigations and the honest trust tiers are in §4C + §8.
   114	
   115	## 4. Multiple Path Options
   116	
   117	### 4A. Signing tool (image SHA256SUMS + optionally the .deb repo Release)
   118	
   119	| Option | Pros | Cons |
   120	|---|---|---|
   121	| **minisign** (issue's lead) | tiny, single static binary, no keyring DB, Ed25519, trivially scriptable, easy to pin one pubkey; matches issue text | NOT what `apt` understands natively — apt needs OpenPGP for `Release`; so minisign covers IMAGE only, apt repo still needs a PGP path |
   122	| **signify** (OpenBSD) | same shape as minisign | less ubiquitous on Debian than minisign; same apt gap |
   123	| **GPG / OpenPGP** (`sequoia`/`gpg`) | apt-native (apt verifies `Release` with PGP); ONE tool covers both image AND repo | heavier, keyring management, larger trust surface; for the IMAGE it is overkill vs minisign |
   124	| **cosign / sigstore** | keyless OIDC option, transparency log | requires Fulcio/Rekor infra or a static key; new dep; apt still needs PGP; over-engineered for a single-publisher appliance |
   125	
   126	**Recommendation (mechanism, value deferred to OQ-2):**
   127	- **Image artifacts → minisign** over `SHA256SUMS`. Smallest trust surface,
   128	  exactly the issue's lead, one pinned Ed25519 pubkey. The image consumer
   129	  (validate.py / xpf-deploy.py / operator) is a script we control, so it can
   130	  call `minisign -V` directly — we are not constrained to apt's PGP.
   131	- **Apt repo → OpenPGP** (`gpg`/`sequoia`) over `Release`, because apt
   132	  mandates it. This is unavoidable: apt will not trust a minisign signature.
   133	
   134	This is a deliberate **two-key, two-tool** split: minisign for images, PGP for
   135	the apt archive. It is NOT redundancy — they authenticate different artifacts
   136	to different consumers (our scripts vs apt). Both public keys are checked into
   137	the repo and published. (An ALTERNATIVE single-tool variant — PGP for both,
   138	dropping minisign — is documented in §4A-alt below for the reviewers to weigh;
   139	the recommendation is the two-tool split because minisign's single-pubkey pin
   140	is dramatically simpler to verify in install.sh and in our Python consumers.)

exec
/bin/bash -lc "nl -ba docs/research/1924-signed-hosted-dist/plan.md | sed -n '320,556p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
   320	
   321	### 5.4 install.sh (NEW)
   322	Tailscale-shaped, POSIX sh, idempotent:
   323	1. Detect distro/arch; refuse non-amd64 / non-Debian-family with a clear msg.
   324	2. Install the pinned archive keyring to `/etc/apt/keyrings/
   325	   xpf-archive-keyring.asc` (embedded inline, `0644`).
   326	3. Write `/etc/apt/sources.list.d/xpf.sources` (deb822, `Signed-By`,
   327	   `XPF_DIST_BASE_URL` substituted; default channel `stable`,
   328	   `XPF_CHANNEL=edge` override).
   329	4. `apt-get update && apt-get install -y xpf-appliance`.
   330	5. Print next steps (day-0 config, `cli`, mgmt reachability caveat — the
   331	   interface-takeover warning from #1879 is RESTATED here because a bare-metal
   332	   `apt install` on a remote box can cut mgmt if fxp0 mapping is wrong).
   333	- `install.sh` is itself published at `XPF_DIST_BASE_URL/install.sh` and the
   334	  doc gives both Tier A (one-liner) and Tier B (verify-before-run) per §4C.
   335	
   336	**r2 (resolves AGY-HIGH-2) — apt UPGRADE inherits #1917's postinst cut-over.**
   337	install.sh's FIRST install is safe (no running daemon to cut). But a later
   338	`apt upgrade xpf-appliance` (the whole point of the repo) runs the `xpf`
   339	package's postinst, which on a STANDALONE node invokes `xpfd upgrade` — a
   340	verified STOP→FLIP→START with a bounded MEASURED multi-second DATAPLANE gap
   341	(it does not cut the mgmt path; fxp0/SSH is not forward-switched, and the
   342	postinst has a safety-net `systemctl is-active` restart). This is #1917's
   343	existing, reviewed mechanism — **#1924 does NOT change it**. The plan's only
   344	obligations here are DOCUMENTATION:
   345	- `docs/distribution.md` states that `apt upgrade` triggers a dataplane blip on
   346	  standalone nodes, and documents `XPF_NO_POSTINST_CUT=1 apt-get upgrade` (the
   347	  existing postinst escape hatch) for operators who want stage-only + manual
   348	  `xpfd upgrade` at a chosen time.
   349	- For HA nodes (`/etc/xpf/node-id` present) the postinst is already STAGE-ONLY;
   350	  the repo upgrade does NOT cut — `xpfd upgrade --rolling` does. Doc restates
   351	  this so an operator does not `apt upgrade` both nodes expecting auto-rolling.
   352	- No `postinst` / `pkg/upgrade` code is in scope for #1924.
   353	
   354	### 5.5 Makefile + docs + fail-closed publish
   355	
   356	- `make dist-sign` (sign existing dist/ image artifacts), `make dist-repo`
   357	  (build signed apt repo), `make dist-publish` (push via `XPF_PUBLISH_CMD`).
   358	- **r2 fail-closed publish (resolves Codex-2 + SMR-F6):** `make dist-publish`
   359	  runs a PRECONDITION gate before invoking `XPF_PUBLISH_CMD`. It REFUSES (exit
   360	  non-zero, nothing uploaded) unless, for every artifact in the publish set:
   361	  (a) each image has a verifying `xpf-<ver>.SHA256SUMS.minisig` against the
   362	  pinned pubkey; (b) the apt `InRelease` verifies against the archive pubkey;
   363	  (c) `install.sh.minisig` verifies (if install.sh is in the set). Bake may be
   364	  fail-open (dev ergonomics) but PUBLISH is fail-closed — an unsigned dev bake
   365	  can never reach the channel.
   366	- **r2 `XPF_PUBLISH_CMD` contract (resolves SMR-F5):** invoked exactly as
   367	  `$XPF_PUBLISH_CMD <local-dist-dir> <XPF_DIST_BASE_URL>`; must be idempotent
   368	  and exit non-zero on failure. The plan documents this signature so the
   369	  backend (rsync / `aws s3 sync` / `gh release upload` wrapper) is a thin shim.
   370	- NEW `docs/distribution.md`: the publisher runbook (key management pointers,
   371	  channel policy, retention, publish backends, the `apt upgrade` blip note from
   372	  §5.4) + the operator runbook (install.sh Tier A/B, the manual apt steps, the
   373	  image verify steps, the out-of-band pubkey source).
   374	- Extend `docs/install-images.md`: replace "copy files by hand" with "fetch +
   375	  verify from `XPF_DIST_BASE_URL`"; document the per-version
   376	  `xpf-<ver>.SHA256SUMS.minisig`.
   377	
   378	### 5.6 Freshness / anti-rollback (r2 — resolves Codex-4)
   379	
   380	Authenticity ≠ freshness: a compromised mirror can serve OLD signed artifacts.
   381	Mitigations, scaled to a single-publisher appliance (not full TUF):
   382	- **Apt:** the signed `Release`/`InRelease` carries `Valid-Until` (flat path
   383	  sets it explicitly; reprepro via `conf/distributions` `ValidFor`). apt warns/
   384	  refuses a stale `Release` — built-in replay protection for the package path,
   385	  re-signed each publish.
   386	- **Images:** a signed, per-channel `dist/<channel>/latest.json` (version +
   387	  bake date + the per-version manifest name) signed with the image key. The
   388	  operator/`xpf-deploy.py --image-url` resolves `latest.json`, checks it is not
   389	  older than a locally-remembered version (simple monotonic check), then
   390	  fetches the named version. This is a LIGHTWEIGHT anti-rollback signal, not a
   391	  guarantee against a sophisticated freeze attack — documented honestly as
   392	  "detects stale mirrors / accidental rollback," with TUF-grade freshness
   393	  called out as a future option (not in #1924 scope). Flagged so reviewers do
   394	  not read it as a strong guarantee.
   395	
   396	## 6. Test / validation strategy (research scope = how /engineer will prove it)
   397	
   398	No loss-cluster smoke (no forwarding change). Validation is local + CI-shaped:
   399	
   400	1. **Sign/verify round-trip (image):** bake (or a stub SHA256SUMS) → sign with
   401	   a throwaway minisign key → `verify_artifacts` PASSES; flip one byte of the
   402	   qcow2 → verify FAILS at `sha256sum -c`; flip the `.minisig` → verify FAILS
   403	   at `minisign -V`; wrong pubkey → FAILS. (Negative tests are mandatory — a
   404	   verify that can't fail is theater.)
   405	2. **Apt repo:** build the signed repo into a temp dir → spin a Debian
   406	   container (or the local incus image flow) → run install.sh pointed at a
   407	   `file://` or `http://localhost` serving of the temp repo → `apt install
   408	   xpf-appliance` succeeds → `apt-get update` against a TAMPERED `Release`
   409	   FAILS with apt's signature error (negative test).
   410	3. **install.sh:** shellcheck-clean; idempotent (run twice = no error); refuses
   411	   wrong arch; the inline-embedded keyring matches the archive signing key used
   412	   to sign the test repo's `InRelease` (so apt accepts it). `--dry-run` mode
   413	   prints the actions without mutating the host (for CI).
   414	3b. **Fail-closed publish (r2):** `make dist-publish` with an UNSIGNED image in
   415	   the set EXITS non-zero and uploads NOTHING (assert the publish shim is never
   416	   invoked). With everything signed it proceeds. (The single most likely
   417	   production mistake — publishing an unsigned dev bake — is blocked here.)
   418	3c. **Freshness (r2):** an apt `Release` past `Valid-Until` makes `apt-get
   419	   update` fail; `latest.json` older than the remembered version is rejected by
   420	   the image fetch path.
   421	4. **bake.py unchanged paths:** the existing image-validation matrix
   422	   (`scripts/image/validate.py a|b|c`) still passes; signing is additive and
   423	   does not perturb the boot/day-0 contract.
   424	5. **Doc accuracy:** the `curl | sh` one-liner and the manual steps are
   425	   copy-pasteable against a local test publish.
   426	
   427	The signing key used in tests is a generated throwaway, NEVER OQ-2's real key.
   428	
   429	## 7. Rollout / sequencing
   430	
   431	`/engineer` should land this as small, independently-reviewable increments
   432	(each its own commit, true-merge per project policy):
   433	
   434	- **Inc 1 — image signing + verify** (bake.py emit `.minisig`; validate.py +
   435	  xpf-deploy.py verify; checked-in image pubkey placeholder; round-trip +
   436	  negative tests; docs). Shippable alone; gives signed images immediately.
   437	- **Inc 2 — apt repo build tooling** (`scripts/dist/build-apt-repo.sh`,
   438	  reprepro `conf/distributions`, `make dist-repo`, PGP archive pubkey
   439	  placeholder; container repo test). Shippable alone.
   440	- **Inc 3 — install.sh + publish + docs** (`install.sh`, `make dist-publish`
   441	  with `XPF_PUBLISH_CMD`, `docs/distribution.md`; install.sh container test).
   442	- **Inc 4 (optional, deferrable) — CI release workflow** (`.github/workflows/
   443	  release.yml` on tag: bake → sign → build repo → publish). GATED on OQ-1 +
   444	  OQ-2 being real, and on the user wanting CI to hold the secret key (a
   445	  security decision — may prefer manual signing on an air-gapped host).
   446	
   447	The two OPEN QUESTIONS are NOT blockers to Inc 1–3 landing as MECHANISM with
   448	placeholder keys + parametrised URLs; they ARE blockers to a real public
   449	release (Inc 4 / actual `dist-publish`). The plan converges with placeholders;
   450	the values are dropped in at engineer/release time.
   451	
   452	## 8. Risks & mitigations
   453	
   454	- **R1 — install.sh is the trust root over the network.** A compromised host
   455	  serving a bad install.sh defeats everything. Mitigation: publish install.sh
   456	  over HTTPS at a stable URL; embed the keyring inline (so the apt path is
   457	  self-authenticating once install.sh runs); document a verify-before-run
   458	  variant (publish `install.sh.minisig` too, signed by the image key, so the
   459	  paranoid operator verifies install.sh with the SAME pinned pubkey they used
   460	  for the image). This closes the loop: ONE pinned pubkey authenticates both
   461	  the image and install.sh.
   462	- **R2 — key compromise / rotation.** OQ-2 owns the policy, but the mechanism
   463	  must not hardcode a single key. Mitigation: pubkey paths are overridable
   464	  (`XPF_IMAGE_PUBKEY`, apt `Signed-By` is a file), and the plan documents a
   465	  rotation runbook (publish new pubkey, dual-sign during overlap, retire old).
   466	- **R3 — apt repo correctness (stale Packages index, missing arch).** Use
   467	  reprepro (it owns index generation) rather than hand-rolled scanning;
   468	  negative test (tampered Release must fail apt).
   469	- **R4 — signing-tool availability on build host.** `minisign` and `reprepro`
   470	  may not be installed. Mitigation: `require()`-style preflight in the new
   471	  scripts with an apt-install hint (matches bake.py's existing `require`
   472	  pattern); bake.py SKIPS signing with a loud warning if `minisign` or
   473	  `XPF_SIGN_SECKEY` is absent (dev ergonomics preserved; "do not publish"
   474	  warning, same posture as `--skip-validate`).
   475	- **R5 — mgmt cut-off on bare-metal apt install.** #1879's interface-takeover
   476	  hazard applies harder to `apt install xpf-appliance` on a remote box than to
   477	  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
   478	  a config that takes over interfaces; the package's first-boot/day-0 contract
   479	  (already built in #1879/#1917) governs safe bootstrap. (This is a
   480	  documentation + sequencing mitigation; no new safe-bootstrap code is in
   481	  scope for #1924 — it was #1879's deliverable.)
   482	- **R6 — two keys confuse operators.** Mitigation: docs/distribution.md has a
   483	  single "Trust" section: pubkey A (image+install.sh, minisign), pubkey B (apt
   484	  archive, PGP), each with its fingerprint and pin location. The single-tool
   485	  §4A-alt remains the fallback if the user wants exactly one identity.
   486	
   487	## 9. Open questions (engineer-time inputs — NOT blockers to PLAN-READY)
   488	
   489	- **OQ-1 (hosting target):** the value of `XPF_DIST_BASE_URL`, the channel
   490	  layout (which suites exist), and the retention policy. Mechanism treats it as
   491	  a parameter; the user supplies the URL + picks GitHub Releases / bucket /
   492	  self-host at `/engineer`/release time.
   493	- **OQ-2 (signing identity):** the minisign keypair (image) and the OpenPGP
   494	  archive key (apt), who holds the secret keys, rotation cadence, and where the
   495	  public keys are pinned/published. Mechanism ships placeholder pubkeys + reads
   496	  the secret-key PATH from env; the user supplies real keys at release time.
   497	- **OQ-3 (one tool vs two):** §4A recommends minisign(image)+PGP(apt); §4A-alt
   498	  is the PGP-only single-identity fallback. The user MAY collapse to one PGP
   499	  identity if they prefer one key to manage — flag for the user, default is the
   500	  two-tool split.
   501	- **OQ-4 (CI signing):** does the secret key live in CI (automated release) or
   502	  on an air-gapped host (manual sign+publish)? Drives whether Inc 4 ships. A
   503	  security posture choice; default assumption is manual until the user opts in.
   504	
   505	## 10. Why not just keep SHA256SUMS?
   506	
   507	A plain checksum file proves integrity against accidental corruption, not
   508	authenticity against an adversary. The issue's explicit goal is "a TRUSTED,
   509	SIGNED source." Without a signature, any party who can serve the file can serve
   510	a matching `SHA256SUMS`. Signing is the minimum bar; an apt repo + install.sh
   511	is the usability bar (the issue's "rather than copying files by hand").
   512	
   513	## 11. Recommendation summary
   514	
   515	- Image: **minisign** over `SHA256SUMS` (one pinned Ed25519 pubkey), verified
   516	  in validate.py + xpf-deploy.py. Additive to bake.py.
   517	- Apt: **reprepro**-built signed repo (PGP `Release`), `stable`/`edge` suites,
   518	  deb822 `Signed-By`.
   519	- Bootstrap: **install.sh** with the archive keyring embedded inline +
   520	  optional `install.sh.minisig` for verify-before-run. TOFU rejected.
   521	- Hosting: host-agnostic `make dist-publish` via `XPF_PUBLISH_CMD` +
   522	  `XPF_DIST_BASE_URL`. No backend hardcoded.
   523	- Ship as Inc 1–3 (each independently reviewable); Inc 4 (CI release) is
   524	  optional + gated on OQ-1/OQ-2/OQ-4.
   525	- The two OPEN QUESTIONS (hosting target, signing identity) are engineer-time
   526	  inputs, not PLAN-READY blockers; the mechanism is complete pending only their
   527	  values.
   528	```
   529	
   530	## 12. r1 → r2 change log (response to 3-way hostile review)
   531	
   532	All three r1 reviewers returned **PLAN-NEEDS-MAJOR** (Codex, AGY, Claude SMR).
   533	The convergent + unique findings and their resolutions:
   534	
   535	| Finding | Source(s) | Resolution in r2 |
   536	|---|---|---|
   537	| Verify can authenticate the WRONG bytes (cwd `sha256sum -c` vs the imported path) | SMR-F3, Codex-1, AGY-HIGH-1 | §5.2: verify the EXACT imported file's hash against the parsed signed manifest; reject pathful/dup entries; per-file. |
   538	| Partial download (libvirt fetches only qcow2) crashes `sha256sum -c` on missing metadata | AGY-HIGH-1 | §5.1/§5.2: per-file verification; missing-but-unfetched files are not checked. |
   539	| install.sh trust circular / pubkey from dist host | SMR-F1, Codex-6, AGY-MEDIUM-1 | §3 + §4C + §8: image pubkey root = in-repo `git clone` copy, NOT the dist host; honest Tier A/B trust labels. |
   540	| install.sh inline-keyring vs fetch+pin contradiction | Codex-5 | §3 + §4C: picked inline-embed; dropped fingerprint-pin language. |
   541	| `curl \| sh` honest trust level | SMR-F2 | §4C: Tier A = TLS + first-fetch trust (same as Tailscale/Docker/rustup), stated plainly. |
   542	| Publish not fail-closed (unsigned dev bake can ship) | Codex-2, SMR-F6 | §5.5: `make dist-publish` precondition gate refuses unsigned artifacts. |
   543	| Retention breaks the single global SHA256SUMS | Codex-3 | §5.1: per-version `xpf-<ver>.SHA256SUMS(.minisig)`; `latest` is convenience only. |
   544	| Replay / freshness missing | Codex-4 | §5.6: apt `Valid-Until` + signed per-channel `latest.json` anti-rollback (honestly scoped, not TUF). |
   545	| reprepro stateful DB breaks in stateless CI | AGY-MEDIUM-2 | §4B: default = flat signed repo (stateless-safe); reprepro opt-in for persistent publishers. |
   546	| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
   547	| GitHub Releases can't host a `dists/`+`pool/` tree | AGY-MEDIUM-3 | §5.3: flagged as an OQ-1 constraint (Pages/bucket needed for the pool). |
   548	| OQ coupling = hidden blockers? | AGY-MEDIUM-3 | §9: confirmed engineer-time inputs; every §5 mechanism runs with placeholder key + parametrised URL. |
   549	| `XPF_PUBLISH_CMD` under-specified | SMR-F5 | §5.5: exact contract `$CMD <dist-dir> <base-url>`, idempotent. |
   550	| Pubkey naming inconsistent | SMR-F7 | Unified: `xpf-image.pub` (minisign), `xpf-archive-keyring.asc` (PGP). |
   551	
   552	Two findings examined and held as documentation-only (not #1924 code scope):
   553	AGY-HIGH-2 (postinst cut-over is #1917's reviewed mechanism) and the
   554	single-tool §4A-alt (kept as the user's OQ-3 fallback). The minisign(image) +
   555	PGP(apt) split, deb822 `Signed-By`, and TOFU-rejection were affirmed by all
   556	three reviewers as correct and are unchanged.

exec
/bin/bash -lc "rg --files | rg '("'^|/)validate'"\\.py"'$|scripts/(deploy|image)/|install'"\\.sh|distribution|SHA256SUMS|minisign|apt|repo|Release|Valid-Until|xpf-image|keyring'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
test/incus/fairness_equal_flow_capture.py
test/incus/step2-sched-switch-capture.sh
pkg/cli/cli_show_chassis_adapter_test.go
test/incus/step1-capture.sh
docs/userspace-capture-plan.md
test/incus/capture-cold-stall.sh
pkg/grpcapi/server_show_forwarding_adapter_test.go
userspace-dp/src/fairness_eval/report.rs
userspace-dp/src/afxdp/worker/loop_body/debug_report.rs
scripts/test_mtr_report_check.py
scripts/mtr_report_check.py
scripts/deploy/xpf-deploy.py
scripts/image/incus-agent.service
scripts/image/xpf-day0-config.service
scripts/image/incus-agent-setup
scripts/image/99-incus-agent.rules
scripts/image/bake.py
scripts/image/make_config_drive.py
scripts/image/xpf-day0-config
scripts/image/validate.py
docs/pr/821-p1-sched-switch-capture/pyshell-code-review.md
docs/pr/827-p3-captures/codex-code-review.md
docs/pr/827-p3-captures/findings.md
docs/pr/821-p1-sched-switch-capture/codex-code-review.md
docs/pr/821-p1-sched-switch-capture/codex-plan-review.md
docs/pr/827-p3-captures/codex-plan-review.md
docs/pr/821-p1-sched-switch-capture/plan.md
docs/pr/827-p3-captures/plan.md
docs/pr/1783-cold-start-capture-instrumentation/claude-smr-code-r1.md
docs/pr/1783-cold-start-capture-instrumentation/reviewer-ids.md
docs/pr/1736-wg-interop/p1-wire-capture.txt
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/correlation-report.diag.json
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/correlation-report.meta.json
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/tx-kick/correlation-report.md
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/sched-switch/correlation-report.diag.json
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/sched-switch/correlation-report.meta.json
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/sched-switch/correlation-report.md
docs/pr/819-step2-discriminator-design/evidence/p5201-fwd-with-cos/sched-switch/step1-capture.log
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/correlation-report.diag.json
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/correlation-report.meta.json
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/tx-kick/correlation-report.md
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/sched-switch/correlation-report.diag.json
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/sched-switch/correlation-report.meta.json
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/sched-switch/correlation-report.md
docs/pr/819-step2-discriminator-design/evidence/p5202-fwd-with-cos/sched-switch/step1-capture.log

codex
The r2 text does address the six named r1 findings on paper, but I’m already seeing r2-internal contradictions around the apt repository backend and GitHub Releases as a supposed full publish target. I’m grounding those against the existing deploy/image/package behavior before deciding whether they rise above nits.
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
/bin/bash -lc "nl -ba scripts/image/bake.py | sed -n '260,520p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
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
/bin/bash -lc "nl -ba scripts/image/validate.py | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf appliance image validation (#1879 Path C), in Python.
     3	
     4	Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
     5	never the shared loss cluster) and proves the first-boot contract:
     6	
     7	  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
     8	     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
     9	     the image's own kernel (the bake gate).
    10	  b  valid day-0 drive -> config validated + installed + committed at first
    11	     boot (hostname applied); a reboot does NOT re-apply (stamp).
    12	  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
    13	     boot survives, factory bootstrap still reachable.
    14	
    15	Usage:
    16	  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
    17	"""
    18	
    19	import argparse
    20	import os
    21	import shlex
    22	import subprocess
    23	import sys
    24	import tempfile
    25	import time
    26	
    27	HERE = os.path.dirname(os.path.abspath(__file__))
    28	sys.path.insert(0, HERE)
    29	import make_config_drive  # noqa: E402
    30	
    31	ALIAS = "xpf-image-validate"
    32	
    33	
    34	def info(m):
    35	    print(f"==> {m}")
    36	
    37	
    38	def fail(m):
    39	    print(f"FAIL: {m}", file=sys.stderr)
    40	    sys.exit(1)
    41	
    42	
    43	def incus(*args, check=True, capture=False):
    44	    return subprocess.run(["incus", *args], check=check,
    45	                          capture_output=capture, text=True)
    46	
    47	
    48	def guest(inst, *cmd, check=True, capture=False):
    49	    return subprocess.run(["incus", "exec", inst, "--", *cmd],
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
    86	        self.instances.append(name)
    87	        incus("start", name)
    88	        self.wait_agent(name)
    89	
    90	    def drop(self, name):
    91	        if not self.keep:
    92	            incus("delete", "-f", name, check=False, capture=True)
    93	            if name in self.instances:
    94	                self.instances.remove(name)
    95	
    96	    def cleanup(self):
    97	        if self.keep:
    98	            print(f"keeping instances {self.instances}, alias {ALIAS}, network {self.net}")
    99	        else:
   100	            for i in self.instances:
   101	                incus("delete", "-f", i, check=False, capture=True)
   102	            incus("image", "delete", ALIAS, check=False, capture=True)
   103	            if self.created_net:
   104	                incus("network", "delete", self.net, check=False, capture=True)
   105	        subprocess.run(["rm", "-rf", self.work], check=False)
   106	
   107	    # ── waiters ──
   108	    def _wait(self, name, pred, tries, secs, what):
   109	        for _ in range(tries):
   110	            if pred():
   111	                return
   112	            time.sleep(secs)
   113	        fail(f"{name}: {what}")
   114	
   115	    def wait_agent(self, name):
   116	        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
   117	                   80, 3, "incus agent not ready after 240s")
   118	
   119	    def wait_xpfd(self, name):
   120	        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
   121	                                       check=False, capture=True).returncode == 0,
   122	                   40, 3, "xpfd not active after 120s")
   123	
   124	    def wait_fxp0_dhcp(self, name):
   125	        self._wait(name, lambda: guest_sh(name, 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'),
   126	                   30, 3, "fxp0 has no IPv4 DHCP address after 90s")
   127	
   128	    # ── scenarios ──
   129	    def scenario_a(self):
   130	        info("── Scenario A: first boot, NO config drive ──")
   131	        self.launch("xpf-image-a")
   132	        self.wait_xpfd("xpf-image-a")
   133	        kver = guest("xpf-image-a", "uname", "-r", capture=True).stdout.strip()
   134	        info(f"guest kernel: {kver}")
   135	        rel = kver.split("-")[0]
   136	        if not _kver_ge(rel, (6, 18)):
   137	            fail(f"guest kernel {kver} < 6.18")
   138	        if not guest_sh("xpf-image-a", 'uname -r | grep -q -- -generic'):
   139	            fail("running kernel is not the -generic flavor")
   140	        if not guest_sh("xpf-image-a", 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
   141	            fail("linux-modules-extra (mlx5/i40e driver set) missing")
   142	        if not guest_sh("xpf-image-a", '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
   143	            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
   144	        if not guest_sh("xpf-image-a", 'grep -qw init_on_alloc=0 /proc/cmdline'):
   145	            fail("init_on_alloc=0 missing from the booted kernel cmdline")
   146	        info("in-guest verify-dataplane (the bake gate, image kernel)...")
   147	        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
   148	                 check=False).returncode != 0:
   149	            fail("in-guest verify-dataplane REJECTED — image must not ship")
   150	        self.wait_fxp0_dhcp("xpf-image-a")
   151	        if not guest_sh("xpf-image-a", 'ss -tln | grep -q ":22 "'):
   152	            fail("sshd not listening")
   153	        if not guest_sh("xpf-image-a",
   154	                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
   155	            fail("sshd effective config does not refuse root password auth")
   156	        if not guest_sh("xpf-image-a", '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
   157	            fail("sshd effective config does not pin PermitEmptyPasswords no")
   158	        if guest("xpf-image-a", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
   159	            fail("unexpected /etc/xpf/xpf.conf")
   160	        if guest("xpf-image-a", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
   161	            fail("unexpected day-0 stamp")
   162	        if not guest_sh("xpf-image-a",
   163	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
   164	            fail("day-0 loader did not log the no-medium fallback")
   165	        info("Scenario A PASS")
   166	        self.drop("xpf-image-a")
   167	
   168	    def scenario_b(self):
   169	        info("── Scenario B: first boot WITH valid day-0 config drive ──")
   170	        conf = os.path.join(self.work, "day0-valid.conf")
   171	        with open(conf, "w") as f:
   172	            f.write("system {\n    host-name xpf-day0-b;\n}\n"
   173	                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
   174	                    "            family inet {\n                dhcp;\n"
   175	                    "            }\n        }\n    }\n}\n")
   176	        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
   177	                                                   validate=False)
   178	        self.launch("xpf-image-b", iso)
   179	        self.wait_xpfd("xpf-image-b")
   180	        if guest("xpf-image-b", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
   181	            fail("day-0 stamp missing")
   182	        if guest("xpf-image-b", "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
   183	            fail("/etc/xpf/xpf.conf missing")
   184	        if not guest_sh("xpf-image-b",
   185	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
   186	            fail("day-0 loader did not log the install")
   187	        self._wait("xpf-image-b",
   188	                   lambda: guest_sh("xpf-image-b",
   189	                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
   190	                                    '| grep -q "host-name xpf-day0-b"'),
   191	                   20, 3, "committed config does not show host-name xpf-day0-b")
   192	        if not guest_sh("xpf-image-b", '[ "$(hostname)" = xpf-day0-b ]'):
   193	            fail("hostname not applied")
   194	        info("rebooting xpf-image-b — second boot must NOT re-apply...")
   195	        incus("restart", "xpf-image-b")
   196	        self.wait_agent("xpf-image-b")
   197	        self.wait_xpfd("xpf-image-b")
   198	        if not guest_sh("xpf-image-b",
   199	                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
   200	            fail("second boot re-applied the day-0 config")
   201	        if not guest_sh("xpf-image-b",
   202	                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
   203	                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
   204	            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
   205	        info("Scenario B PASS")
   206	        self.drop("xpf-image-b")
   207	
   208	    def scenario_c(self):
   209	        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
   210	        conf = os.path.join(self.work, "day0-invalid.conf")
   211	        with open(conf, "w") as f:
   212	            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
   213	        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
   214	                                                   validate=False)
   215	        self.launch("xpf-image-c", iso)
   216	        self.wait_xpfd("xpf-image-c")
   217	        if not guest_sh("xpf-image-c",
   218	                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
   219	            fail("day-0 loader did not log the commit-check REJECT")
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

exec
/bin/bash -lc "nl -ba scripts/image/validate.py | sed -n '260,560p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
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

exec
/bin/bash -lc "nl -ba debian/control | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc "nl -ba scripts/deploy/xpf-deploy.py | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
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

 succeeded in 0ms:
     1	#!/usr/bin/env python3
     2	"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.
     3	
     4	Subcommands:
     5	  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
     6	                                  is two files. (Default if args are *.yaml.)
     7	  launch --name … --nic …         imperative launch without a YAML file.
     8	  inventory                       list host NICs, SR-IOV VFs, bridges → the
     9	                                  values you drop into a definition.
    10	
    11	Interface naming is POSITIONAL (matches pkg/daemon/linksetup.go assignName):
    12	
    13	  standalone:      pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
    14	  cluster node 0:  pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
    15	  cluster node 1:  pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)
    16	
    17	A NIC's backing (virtio bridge / SR-IOV VF / PCI passthrough) is declared
    18	explicitly per interface — `backing:` in YAML, or the `<backing>:<source>`
    19	spec for --nic. The tool translates each to the right incus device / libvirt
    20	virt-install argument. The day-0 config drive is built and check-config
    21	validated in-process (no shell helpers).
    22	
    23	Global options: --dry-run  --hypervisor incus|libvirt  --no-start  --image X
    24	
    25	Examples:
    26	  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
    27	  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
    28	  xpf-deploy.py launch --name fw1 --config standalone.conf \\
    29	      --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0
    30	  xpf-deploy.py inventory
    31	"""
    32	
    33	import argparse
    34	import os
    35	import re
    36	import shlex
    37	import shutil
    38	import subprocess
    39	import sys
    40	import tempfile
    41	
    42	try:
    43	    import yaml
    44	except ImportError:
    45	    yaml = None
    46	
    47	VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}
    48	SYS_NET = "/sys/class/net"
    49	
    50	
    51	def die(msg):
    52	    sys.exit(f"ERROR: {msg}")
    53	
    54	
    55	# ── naming contract ───────────────────────────────────────────────────
    56	def expected_name(idx, mode, node_id):
    57	    """vSRX name the guest assigns to the NIC at position idx (0-based);
    58	    mirrors assignName() in pkg/daemon/linksetup.go."""
    59	    if idx == 0:
    60	        return "fxp0"
    61	    if mode == "cluster":
    62	        if idx == 1:
    63	            return "em0"
    64	        fpc = 7 if node_id == 1 else 0
    65	        return f"ge-{fpc}/0/{idx - 2}"
    66	    return f"ge-0/0/{idx - 1}"
    67	
    68	
    69	def norm_role(role):
    70	    r = role.strip()
    71	    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    72	    return f"ge-{m.group(1)}/0/{m.group(2)}" if m else r
    73	
    74	
    75	# ── host introspection ────────────────────────────────────────────────
    76	def _read(path):
    77	    try:
    78	        with open(path) as f:
    79	            return f.read().strip()
    80	    except OSError:
    81	        return ""
    82	
    83	
    84	def is_physical_nic(dev):
    85	    if dev == "lo" or not os.path.isdir(os.path.join(SYS_NET, dev, "device")):
    86	        return False
    87	    return not re.match(r"(veth|tap|br-|virbr|docker|incusbr)", dev)
    88	
    89	
    90	def driver_of(dev):
    91	    link = os.path.join(SYS_NET, dev, "device", "driver")
    92	    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"
    93	
    94	
    95	def pci_of(dev):
    96	    link = os.path.join(SYS_NET, dev, "device")
    97	    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"
    98	
    99	
   100	def native_xdp_hint(driver):
   101	    if driver in ("mlx5_core", "i40e", "ice", "ixgbe", "bnxt_en", "nfp"):
   102	        return "native"
   103	    if driver in ("iavf", "ixgbevf", "virtio_net"):
   104	        return "no (generic)"
   105	    return "unknown"
   106	
   107	
   108	def vf_parent(addr):
   109	    """(PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
   110	    if not os.path.isdir(SYS_NET):
   111	        return None
   112	    for pf in os.listdir(SYS_NET):
   113	        devdir = os.path.join(SYS_NET, pf, "device")
   114	        if not os.path.isdir(devdir):
   115	            continue
   116	        for entry in os.listdir(devdir):
   117	            if entry.startswith("virtfn") and \
   118	               os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
   119	                return pf, entry[len("virtfn"):]
   120	    return None
   121	
   122	
   123	def cmd_inventory(_args):
   124	    print(f"=== Physical NICs ===")
   125	    print(f"{'NETDEV':<14} {'DRIVER':<10} {'PCI':<14} {'MAC':<18} {'LINK':<6} NATIVE-XDP")
   126	    for dev in sorted(os.listdir(SYS_NET)):
   127	        if not is_physical_nic(dev):
   128	            continue
   129	        drv = driver_of(dev)
   130	        print(f"{dev:<14} {drv:<10} {pci_of(dev):<14} "
   131	              f"{_read(os.path.join(SYS_NET, dev, 'address')):<18} "
   132	              f"{_read(os.path.join(SYS_NET, dev, 'operstate')):<6} {native_xdp_hint(drv)}")
   133	        devdir = os.path.join(SYS_NET, dev, "device")
   134	        total = _read(os.path.join(devdir, "sriov_totalvfs"))
   135	        if total and total != "0":
   136	            num = _read(os.path.join(devdir, "sriov_numvfs")) or "0"
   137	            print(f"    SR-IOV: {num}/{total} VFs. Create N:  "
   138	                  f"echo N | sudo tee {devdir}/sriov_numvfs")
   139	            for entry in sorted(os.listdir(devdir)):
   140	                if entry.startswith("virtfn"):
   141	                    vfpci = os.path.basename(os.path.realpath(os.path.join(devdir, entry)))
   142	                    print(f"      vf{entry[len('virtfn'):]:<3} pci:{vfpci}   "
   143	                          f"(sriov:{dev}  |  pci:{vfpci},mac=02:..)")
   144	    print("\n=== Host bridges (bridge:<name>) ===")
   145	    found = False
   146	    for dev in sorted(os.listdir(SYS_NET)):
   147	        if os.path.isdir(os.path.join(SYS_NET, dev, "bridge")):
   148	            print(f"  bridge:{dev}")
   149	            found = True
   150	    if not found:
   151	        print("  (none — create: sudo ip link add br-lan type bridge; ip link set br-lan up)")
   152	    return 0
   153	
   154	
   155	# ── appliance model ───────────────────────────────────────────────────
   156	def validate_appliance(ap, where):
   157	    if not ap.get("name"):
   158	        die(f"{where}: name is required")
   159	    if ap["mode"] not in ("standalone", "cluster"):
   160	        die(f"{where}: mode must be standalone|cluster")
   161	    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
   162	        die(f"{where}: cluster needs node_id 0|1")
   163	    if not ap["interfaces"]:
   164	        die(f"{where}: at least one interface (position 1 = fxp0)")
   165	    for i, ic in enumerate(ap["interfaces"]):
   166	        if ic.get("backing") not in VALID_BACKINGS:
   167	            die(f"{where}: interface {i + 1} backing must be one of {sorted(VALID_BACKINGS)}")
   168	        if not ic.get("source"):
   169	            die(f"{where}: interface {i + 1} needs a source")
   170	        want = expected_name(i, ap["mode"], ap.get("node_id"))
   171	        if ic.get("role") and norm_role(ic["role"]) != want:
   172	            die(f"{where}: interface {i + 1} declares role '{ic['role']}' but position {i + 1} "
   173	                f"is '{want}' — reorder or fix; position is the contract.")
   174	        ic["_name"] = want
   175	
   176	
   177	def load_yaml_appliance(path):
   178	    if yaml is None:
   179	        die("PyYAML required for YAML deploy (apt install python3-yaml). "
   180	            "Use the 'launch' subcommand for a no-YAML, no-dependency path.")
   181	    with open(path) as f:
   182	        doc = yaml.safe_load(f)
   183	    if not isinstance(doc, dict):
   184	        die(f"{path}: top level must be a mapping")
   185	    a = doc.get("appliance") or {}
   186	    ap = {
   187	        "name": a.get("name"), "mode": a.get("mode", "standalone"),
   188	        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
   189	        "cpu": a.get("cpu", 4), "memory": a.get("memory", "4GiB"),
   190	        "config": a.get("config"), "interfaces": doc.get("interfaces") or [],
   191	        "pool": a.get("pool", "default"),
   192	        "base_dir": os.path.dirname(os.path.abspath(path)),
   193	    }
   194	    validate_appliance(ap, path)
   195	    return ap
   196	
   197	
   198	# ── day-0 config drive (pure Python; xorriso/genisoimage for the ISO) ──
   199	def find_xpfd():
   200	    for c in (os.environ.get("XPFD"), os.path.join(os.getcwd(), "xpfd"),
   201	              shutil.which("xpfd")):
   202	        if c and os.path.isfile(c) and os.access(c, os.X_OK):
   203	            return c
   204	    return None
   205	
   206	
   207	def build_config_drive(ap, runner):
   208	    cfg = ap.get("config")
   209	    if not cfg:
   210	        return None
   211	    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["base_dir"], cfg)
   212	    iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")
   213	    if runner.dry:
   214	        print(f"==> (dry-run) would build day-0 drive {iso} from {cfg_path} "
   215	              f"(label xpf-config, check-config validated)")
   216	        return iso
   217	    if not os.path.isfile(cfg_path):
   218	        die(f"config not found: {cfg_path}")
   219	    xpfd = find_xpfd()
   220	    if xpfd:
   221	        nodearg = ["-node-id", str(ap["node_id"])] if ap["mode"] == "cluster" else []
   222	        r = subprocess.run([xpfd, "check-config"] + nodearg + [cfg_path],
   223	                           capture_output=True, text=True)
   224	        if r.returncode != 0:
   225	            die(f"day-0 config REJECTED by check-config:\n{r.stdout}{r.stderr}")
   226	        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
   227	    else:
   228	        print("WARNING: no xpfd binary found — skipping build-host validation "
   229	              "(the appliance still validates at first boot).")
   230	    mkiso = next((t for t in ("xorriso", "genisoimage", "mkisofs") if shutil.which(t)), None)
   231	    if not mkiso:
   232	        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
   233	    stage = tempfile.mkdtemp(prefix="xpf-day0-")
   234	    try:
   235	        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
   236	        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
   237	        if ap["mode"] == "cluster":
   238	            with open(os.path.join(stage, "node-id"), "w") as f:
   239	                f.write(f"{ap['node_id']}\n")
   240	        if mkiso == "xorriso":
   241	            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
   242	                    "-J", "-r", "-o", iso, stage]
   243	        else:
   244	            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
   245	        subprocess.run(argv, check=True, capture_output=True, text=True)
   246	        print(f"==> built day-0 drive {iso} (label xpf-config)")
   247	    finally:
   248	        shutil.rmtree(stage, ignore_errors=True)
   249	    return iso
   250	
   251	
   252	# ── memory / pci helpers ──────────────────────────────────────────────
   253	def memory_mb(val):
   254	    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", str(val).strip())
   255	    if not m:
   256	        die(f"unparseable memory '{val}'")
   257	    return int(m.group(1)) * 1024 if (m.group(2) or "M").upper().startswith("G") else int(m.group(1))
   258	
   259	
   260	def pci_parts(addr):

exec
/bin/bash -lc "nl -ba scripts/deploy/xpf-deploy.py | sed -n '260,560p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
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
/bin/bash -lc "nl -ba docs/in-place-upgrade.md | sed -n '1,240p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# In-place upgrade mechanism (#1917)
     2	
     3	The `pkg/upgrade` package implements the verified, atomic,
     4	rollback-capable in-place upgrade cut-over for xpfd + the AF_XDP
     5	dataplane helper. It is invoked as `xpfd upgrade [--rolling]` and from
     6	the `.deb` postinst.
     7	
     8	This doc is the module contract for `pkg/upgrade`, the `xpfd upgrade`
     9	subcommand, the postinst HA-mode contract, and the dogfood deploy.
    10	
    11	## Layout
    12	
    13	```
    14	/usr/local/share/xpf/staged/          dpkg-static staging (increment A) — apt's write target
    15	/var/lib/xpf/versions/<ver>/          non-dpkg runtime version dirs (retain N=3)
    16	/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
    17	/usr/local/sbin/{xpfd,cli,...} -> versions/current/<bin>   operator-tool links
    18	/var/lib/xpf/upgrade.state            crash-safe state-machine journal
    19	/etc/systemd/system/xpfd.service.d/10-xpf-version.conf     ExecStart pinned to the CONCRETE version
    20	```
    21	
    22	## State machine (`pkg/upgrade`)
    23	
    24	```
    25	STAGED -> PREFLIGHT -> COPIED -> VERIFIED -> STOPPED -> FLIPPED -> STARTED -> COMMITTED
    26	```
    27	
    28	Each transition is journaled (temp+fsync+rename) so a crash is
    29	recoverable and idempotent — re-running `xpfd upgrade` resumes from the
    30	journal. The ONLY live-state mutations are STOP and FLIP-then-START;
    31	PREFLIGHT / COPY / VERIFY are pure and abortable (a failure there leaves
    32	the running daemon and config untouched).
    33	
    34	- **PREFLIGHT** — check `/var` free ≥ staged size + config-DB snapshot
    35	  size + margin; GC eligible versions if short; take the pre-upgrade
    36	  config-DB snapshot (`.partial`+rename, never torn) for rollback.
    37	- **COPY** — `staged/` → `.<ver>.partial/` + checksum + atomic rename to
    38	  `versions/<ver>/`. A crash never leaves a half-populated version dir;
    39	  stray `.partial` dirs are swept on re-run.
    40	- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
    41	  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
    42	  the live dataplane untouched.
    43	- **STOP → FLIP → START** — stop the old daemon (closes the
    44	  respawn-mismatch race: no live process can re-resolve the flipped
    45	  helper), flip `current` + the `/usr/local/sbin` links + the unit
    46	  ExecStart drop-in, then start the new daemon.
    47	
    48	### Respawn-mismatch closure (two structural guards)
    49	
    50	1. **STOP-before-FLIP** — no live old xpfd exists to respawn a helper
    51	   after the unit is stopped.
    52	2. **Concrete-version ExecStart** — the FLIP templates the unit
    53	   `ExecStart`/`ExecStartPre` to the literal `/var/lib/xpf/versions/<ver>/xpfd`
    54	   path (NOT the `current` symlink — systemd does NOT symlink-resolve
    55	   `argv[0]`). So `dir(os.Args[0])` is the matching-version dir and even
    56	   a transient respawn resolves the matching-version `xpf-userspace-dp`,
    57	   never the shared `/usr/local/sbin` link.
    58	
    59	### Rollback (binary + DB atomic)
    60	
    61	Standalone auto-rollback (on an unhealthy post-start helper) and operator
    62	rollback both restore the config DB BEFORE re-flipping the binary:
    63	
    64	```
    65	stop -> restore config-DB snapshot (PREFLIGHT) -> re-flip current/sbin/unit to previous -> start
    66	```
    67	
    68	This is mandatory because the N+1 daemon writes `active.json` in the
    69	config compatibility envelope (see below); a bare binary re-flip to N
    70	would boot an N daemon that fatal-rejects the N+1 envelope DB (a brick).
    71	The HA path disables auto-rollback — HA rollback is operator-driven (an
    72	auto re-flip mid-rolling un-coordinates the cluster).
    73	
    74	## HA rolling upgrade (`xpfd upgrade --rolling`)
    75	
    76	Cuts the LOCAL clustered node with a controlled drain so the cluster
    77	keeps forwarding. Run on each node in turn (the deploy driver sequences
    78	both); exactly one node is primary throughout.
    79	
    80	1. assert peer alive + session sync established + HA protocol compatible
    81	   (`CurrentHAProtocolVersion`) — else ABORT to image-replace (Path C),
    82	   never drop connections.
    83	2. **peer-takeover-ready precheck BEFORE demoting** — demoting a node
    84	   whose peer cannot take over strands VIPs.
    85	3. `ForceSecondary()` to start the drain.
    86	4. **strong drain predicate** — peer owns the RGs, local VRRP BACKUP with
    87	   no VIPs, `rg_active` false, sync clean (NOT merely "weight 0 set" — an
    88	   RG keeps forwarding while VRRP is still MASTER). On timeout: fail back
    89	   and ABORT WITHOUT cutting (node still forwarding — no harm).
    90	5. single-node cut (auto-rollback disabled).
    91	6. wait for session sync to re-establish, bounded by `RejoinDeadline`
    92	   (60s default). The cut just restarted xpfd, so the local gRPC socket
    93	   refuses connections for the first few seconds — that `connection
    94	   refused` is the EXPECTED transient, treated as "not ready yet" and
    95	   re-polled until the deadline (NOT a hard abort on the first dial
    96	   error). Only the deadline aborts, surfacing the last observed error;
    97	   the node is then left secondary for the operator to inspect.
    98	7. `ResetFailover()` to rejoin election; forward-verify is the natural
    99	   post-promotion check (`make test-failover`) — a passive node
   100	   structurally cannot forward, so it is never "verified while passive".
   101	
   102	## Config compatibility envelope (D1, `pkg/configstore`)
   103	
   104	`active.json` carries a magic header LINE
   105	(`#xpf-config-envelope v=1 writer=.. ast=.. min-reader=.. rollback-fmt=..`)
   106	prepended to the (possibly-encrypted) JSON body. The leading `#` makes a
   107	pre-floor reader's `json.Unmarshal` ERROR (fail closed) instead of
   108	empty-loading a wrapping object and silently wiping config. A too-new
   109	`min-reader` is rejected. A present-but-unreadable DB is tagged
   110	`ErrConfigDBUnreadable` and made FATAL at startup (daemon_run.go) — never
   111	silently overwritten by a blind bootstrap. A pre-floor (no-envelope) DB
   112	still reads, so upgrading TO the floor is non-destructive.
   113	
   114	`mgmt-never-stranded`: on the appliance the day-0 + protected-set lifeline
   115	covers a fail-closed boot; #1922 hardens the foreign/non-appliance host
   116	case (NOT implemented here — see #1922).
   117	
   118	## postinst HA-mode contract
   119	
   120	- STANDALONE node (no `/etc/xpf/node-id`): the postinst invokes
   121	  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
   122	  suppresses it.
   123	- CLUSTERED node (node-id present): STAGE-ONLY. Cut ONLY via
   124	  `xpfd upgrade --rolling`. Keyed on node-id ALONE so a degraded-HA node
   125	  never falls through to an uncoordinated standalone cut.
   126	
   127	## Dogfood deploy
   128	
   129	`XPF_DEPLOY_DEB=1 make cluster-deploy` builds the `.deb` (outside the
   130	#1875 cluster lock), `apt install`s it (stage-only on the clustered
   131	nodes), and drives `xpfd upgrade --rolling` secondary-first. The default
   132	raw push+restart path (and `XPF_DEPLOY_FAST`) is unchanged for the dev
   133	inner loop. The deb path is opt-in until validated live; it then becomes
   134	the CI/smoke default.
   135	
   136	## Peer-takeover-readiness is best-effort; DrainComplete is authoritative
   137	
   138	The local control socket renders the LOCAL node's view, so the
   139	pre-demotion `PeerTakeoverReady` check cannot directly read the PEER's
   140	takeover-readiness — it requires the peer alive and no LOCAL takeover
   141	blocker. The AUTHORITATIVE guard is `DrainComplete`, which AFTER demotion
   142	confirms the peer ACTUALLY holds primary for EVERY RG; if it does not
   143	within the deadline, the rolling driver fails back and ABORTS WITHOUT
   144	cutting. A peer that cannot take over therefore never leads to a cut — at
   145	worst the drain times out and the local node is restored to forwarding.
   146	
   147	## Rolling protocol-bump limitation
   148	
   149	`HAProtocolCompatible` compares the RUNNING local daemon's HA protocol
   150	version against the peer's. It cannot see the STAGED version's protocol
   151	before the cut. So if a release BUMPS `CurrentHAProtocolVersion`, the
   152	first node's precheck passes (running N vs peer N), it cuts to N+1, and
   153	then the SECOND node's precheck fails (running N vs peer N+1) and aborts —
   154	leaving a mixed-version cluster. This is the "not rolling-upgradable"
   155	outcome the plan flags (Path C image-replace), but it is detected on the
   156	second node, not pre-emptively. Operators MUST treat a protocol bump as a
   157	non-rolling release (image-replace both nodes). A pre-emptive guard would
   158	require the staged binary to report its protocol version to the driver
   159	before the first cut (future work).
   160	
   161	## Honest limits
   162	
   163	- **No true zero-gap standalone restart.** The helper is an `exec.Command`
   164	  child held in xpfd memory; a fresh xpfd spawns a NEW helper and clears
   165	  the XSKMAP. Standalone cut-over is a bounded, MEASURED multi-second gap
   166	  (the ~3s NAPI bootstrap window is the floor). True zero-gap
   167	  (decoupled-helper re-attach) is future M-mech-2. The HA path masks the
   168	  gap with a single ~60ms VRRP failover per node.
   169	- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.

exec
/bin/bash -lc "nl -ba docs/install-images.md | sed -n '1,280p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# xpf appliance images (#1879 Path C)
     2	
     3	vSRX-style prebuilt-image distribution: one bootable root disk, built
     4	offline, carrying everything xpf needs — the LATEST Ubuntu release
     5	(operator policy: always the newest — 26.04 today, discovered at bake
     6	time), a >= 6.18 kernel (the AF_XDP shim's verifier floor; 26.04 ships
     7	7.0), FRR, strongSwan, Kea, chrony, systemd-networkd, and the xpf
     8	binaries (`xpfd`, `cli`, `xpf-userspace-dp`) with their systemd units.
     9	There is no dependency matrix to install and no kernel hunt: the image
    10	IS the dependency closure.
    11	
    12	Two deliverables, same root disk:
    13	
    14	| Artifact | Consumer | Deploy command |
    15	|---|---|---|
    16	| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
    17	| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
    18	| `dist/SHA256SUMS` | both | `sha256sum -c` |
    19	
    20	## Bake
    21	
    22	```bash
    23	make image            # = python3 scripts/image/bake.py
    24	```
    25	
    26	Build-host requirements: the normal xpf build toolchain (Go, cargo),
    27	`libguestfs-tools`, `qemu-utils`, `curl`, `xorriso` (for config
    28	drives), and incus for the validation gate. `/dev/kvm` access makes
    29	the bake fast; the script self-raises `RLIMIT_MEMLOCK` via sudo when
    30	needed (qemu's io_uring).
    31	
    32	Pipeline (offline — the image is never booted to provision it):
    33	
    34	1. `make deb` (#1917 increment A). This runs `make build build-ctl
    35	   build-userspace-dp` via `debian/rules`, so the #1864 pinned-toolchain
    36	   contract holds — `make build` embeds the git-tracked shim object and
    37	   the bake never runs `make generate` — then packages the freshly built
    38	   binaries into the `xpf` Debian package (binary set staged under
    39	   `/usr/local/share/xpf/staged`). The bake installs that `.deb` instead
    40	   of copying raw binaries.
    41	2. Discover the LATEST Ubuntu release from the upstream listing
    42	   (`XPF_BASE_RELEASE` pins one), then fetch + SHA256-verify the
    43	   official Ubuntu *server cloudimg*. Upstream owns partitioning and
    44	   the UEFI/BIOS bootloader.
    45	3. `virt-resize` the root partition into an 8 GiB work disk
    46	   (`XPF_IMAGE_DISK_SIZE` overrides).
    47	4. `virt-customize` offline: runtime package set (the #1879 plan §5
    48	   dependency matrix; no build toolchain), the cloudimg's reduced
    49	   `linux-virtual` kernel replaced by `linux-generic` (full driver set
    50	   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
    51	   with in-bake asserts that the kernel meets the >= 6.18 verifier
    52	   floor and the extra-modules tree is present, purge of cloud-init
    53	   (a competing network manager), snapd, and the virtual-kernel
    54	   metapackages, systemd-networkd + resolved enabled, FRR + chrony
    55	   enabled (default NTP pools neutered; xpfd manages
    56	   `sources.d/xpf.sources`), sysctls, `init_on_alloc=0` (via an
    57	   `/etc/default/grub.d` drop-in — Ubuntu cloud images override
    58	   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
    59	   The package's `postinst` stages the binary set, creates the live
    60	   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
    61	   into the staging path, and enables `xpfd` + `xpf-day0-config` (so the
    62	   bake no longer hand-copies binaries/units or runs `systemctl enable
    63	   xpfd`). The incus-agent loader is still copied in and enabled
    64	   directly. A plain `apt upgrade xpf` only refreshes the staging path
    65	   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
    66	   `needrestart` blacklist); the verified in-place cut-over is a separate
    67	   increment.
    68	5. `virt-sysprep` seal: machine-id, ssh host keys, logs, tmp files,
    69	   bash history, package caches, random seed; `/etc/xpf` factory-empty.
    70	6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
    71	7. **Validation gate** (default on): the image is imported into local
    72	   incus and the FULL first-boot matrix runs — factory boot (fxp0
    73	   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
    74	   driver set check) with `xpfd verify-dataplane` IN-GUEST against
    75	   the image's own kernel, plus the valid- and invalid-day-0-drive
    76	   scenarios. A failure fails the bake — the image must never ship a
    77	   verifier-failing shim (#1864/#1869 discipline). Use
    78	   `--skip-validate` only for iteration; such artifacts are not
    79	   publishable.
    80	
    81	Each bake also writes `dist/xpf-<ver>.manifest` recording the exact
    82	inputs (base image URL + release + verified SHA256, git commit, bake
    83	date/host kernel). Bakes are not bit-reproducible (the base tracks
    84	the newest upstream release unless `XPF_BASE_RELEASE` pins one); the
    85	manifest is the traceability record.
    86	
    87	Full first-boot matrix (run after a bake, or standalone):
    88	
    89	```bash
    90	python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
    91	    --metadata dist/xpf-<ver>.incus-metadata.tar.gz all
    92	```
    93	
    94	> **Deploying at scale?** `docs/deploy-quickstart.md` +
    95	> `examples/deploy/README.md` are the operator runbook: the positional
    96	> naming contract, the Python deployer (`scripts/deploy/xpf-deploy.py`
    97	> — YAML-driven, incus/libvirt, builds the day-0 drive in-process),
    98	> validated standalone/HA example definitions, SR-IOV/passthrough, and
    99	> the fleet pattern. The sections below are the raw mechanics it builds
   100	> on. (`scripts/image/make_config_drive.py` shown here is the image
   101	> bakery's config-drive tool; the Python deployer builds drives
   102	> in-process too.)
   103	
   104	## Deploy quickstart — incus
   105	
   106	```bash
   107	incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
   108	    dist/xpf-<ver>.qcow2 --alias xpf-appliance
   109	
   110	# Optional day-0 config drive (see below):
   111	python3 scripts/image/make_config_drive.py -o day0.iso my-xpf.conf
   112	
   113	incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
   114	incus config device add xpf1 day0 disk source=$PWD/day0.iso
   115	incus start xpf1
   116	```
   117	
   118	The image carries the incus-agent loader (inert outside incus), so
   119	`incus exec xpf1 -- cli` works immediately. Add revenue NICs as extra
   120	devices before start; vNIC order maps to vSRX names (below).
   121	
   122	## Deploy quickstart — libvirt/KVM
   123	
   124	```bash
   125	virt-install --name xpf1 --memory 4096 --vcpus 4 \
   126	    --import --disk path=xpf-<ver>.qcow2 \
   127	    --disk path=day0.iso,device=cdrom \
   128	    --network bridge=br-mgmt --network bridge=br-trust \
   129	    --osinfo ubuntu26.04 --noautoconsole
   130	```
   131	
   132	Plain QEMU works the same way (`-drive file=xpf-<ver>.qcow2`
   133	`-cdrom day0.iso`); the image boots UEFI or BIOS.
   134	
   135	## First-boot contract (vSRX parity)
   136	
   137	| vSRX | xpf image |
   138	|---|---|
   139	| First vNIC is fxp0 (OOB mgmt), rest map to ge-0/0/N in attach order | Identical: `enumerateAndRenameInterfaces()` assigns fxp0 / em0 (cluster) / ge-X-0-N by PCI bus order |
   140	| Factory default: fxp0 DHCP, root console login, no password | Identical: fxp0 DHCP bootstrap; root login on the hypervisor console with empty password; sshd refuses empty/root-password auth |
   141	| Day-0 config: ISO with `juniper.conf` at the root, attached as CD-ROM | ISO (or any volume labeled `xpf-config`) with `xpf.conf` at the root — `juniper.conf` accepted as an alias; optional `node-id` file (`0`/`1`) for cluster members |
   142	| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
   143	| Day-0 applied once | Applied at most once: stamped after success; never clobbers an existing config (`.configdb` or preseeded `xpf.conf`). A REJECTED medium does not stamp — fix the config and reboot to retry while the system is still factory-default |
   144	
   145	Day-0 loader specifics (`scripts/image/xpf-day0-config`, oneshot unit
   146	`Before=xpfd.service`):
   147	
   148	- Probes volumes labeled `xpf-config` (any filesystem) plus any ISO9660
   149	  medium. Mounted `ro,nosuid,nodev,noexec`; only the two fixed
   150	  filenames at the volume root are considered; 4 MiB size cap;
   151	  validation under timeout. Nothing on the medium is executed.
   152	- On PASS the config is installed as `/etc/xpf/xpf.conf` (mode 0600 —
   153	  it may carry credential material) and xpfd's normal
   154	  bootstrap-from-file import commits it at startup. No second config
   155	  ingestion mechanism exists.
   156	- Failures never block the boot: the unit is ordering-only (no
   157	  `Requires=`), the script always exits 0, and `TimeoutStartSec`
   158	  backstops a hung mount. Fallback is always the factory bootstrap.
   159	
   160	Build a config drive:
   161	
   162	```bash
   163	python3 scripts/image/make_config_drive.py [-n 0|1] [-o day0.iso] my-xpf.conf
   164	```
   165	
   166	When an `xpfd` binary is present, the builder runs the same
   167	commit-check and refuses to build an ISO the appliance would reject.
   168	
   169	## Credentials / security posture
   170	
   171	- No default password over the network, ever. The root password is
   172	  empty: login works on the hypervisor console only. The image pins
   173	  this explicitly — `/etc/ssh/sshd_config.d/10-xpf-factory.conf` sets
   174	  `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`
   175	  (not relying on distro defaults), and the validation harness
   176	  asserts the effective `sshd -T` output.
   177	- Headless/SSH access comes from the day-0 config (`system
   178	  root-authentication`, `system login user ...`) — set credentials
   179	  there, or use the console once and `commit` a config.
   180	- The image ships no ssh host keys, no machine-id, no logs; both are
   181	  regenerated per-instance at first boot.
   182	- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
   183	  signing — minisign — is a follow-up; see the #1879 deferred list.)
   184	
   185	## Upgrades
   186	
   187	The vSRX "replace-image" model: deploy a new VM from the new image,
   188	copy `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` on cluster members),
   189	swap traffic. The text config is the portable artifact — not
   190	`.configdb`. For HA pairs this is `deploy_rolling()` at VM granularity:
   191	replace the secondary, wait for session sync, fail over, replace the
   192	primary. Kernel + userspace move as one tested unit.
   193	
   194	In-place binary upgrades inside a running appliance follow the #1869
   195	ordering invariant: push the new `xpfd` to a temp path, run
   196	`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
   197	(see `test/incus/cluster-setup.sh deploy_vm()` for the reference
   198	implementation). A native .deb + `xpf-upgrade` wrapper is the M1a
   199	follow-up, not part of this deliverable.
   200	
   201	## Recovery
   202	
   203	- Lost mgmt connectivity after a bad commit: use the hypervisor
   204	  console (`incus console xpf1` / `virsh console xpf1`), log in as
   205	  root, run `cli`, `configure`, `rollback 1`, `commit`.
   206	- Unbootable/maimed instance: this is cattle — redeploy from the image
   207	  and re-apply your config (day-0 drive or copy `xpf.conf` in).
   208	- Day-0 config rejected at first boot: `journalctl -u xpf-day0-config`
   209	  shows the commit-check error verbatim. Fix the config, rebuild the
   210	  ISO, reboot — the system is still factory-default, so the loader
   211	  retries.
   212	- Pre-flight any config on the build host:
   213	  `xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2
   214	  reject).
   215	
   216	## Validation
   217	
   218	`docs/image-validation.md` is the full validation runbook: Tier 1
   219	(automated first-boot gate via `scripts/image/validate.py` — boot,
   220	single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
   221	Tier 2 (standalone forwarding + SNAT, manual), and Tier 3 (HA pair
   222	forwarding + failover, manual). Tier 1 gates the bake; Tiers 2–3 push
   223	real traffic and prove the image actually routes.
   224	
   225	## What the image does NOT solve
   226	
   227	AF_XDP line-rate behavior remains coupled to the NIC driver exposed to
   228	the VM (mlx5/i40e native XDP vs virtio vs iavf-generic) — see
   229	`CLAUDE.md` "XDP on SR-IOV Interfaces". The image guarantees the
   230	kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
   231	passthrough/VF topology is the operator's hypervisor decision.

exec
/bin/bash -lc "rg -n \"SHA256SUMS|minisign|signature|verify|xpf-deploy|validate|install\\.sh|apt|repo|xpf-appliance|postinst|XPF_NO_POSTINST_CUT|upgrade|GitHub|Release|keyring|signed|hosted|copy|curl\" docs/install-images.md docs/in-place-upgrade.md debian/control debian/xpf.postinst scripts/image/bake.py scripts/image/validate.py scripts/deploy/xpf-deploy.py" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
scripts/deploy/xpf-deploy.py:2:"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.
scripts/deploy/xpf-deploy.py:21:validated in-process (no shell helpers).
scripts/deploy/xpf-deploy.py:26:  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
scripts/deploy/xpf-deploy.py:27:  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
scripts/deploy/xpf-deploy.py:28:  xpf-deploy.py launch --name fw1 --config standalone.conf \\
scripts/deploy/xpf-deploy.py:30:  xpf-deploy.py inventory
scripts/deploy/xpf-deploy.py:156:def validate_appliance(ap, where):
scripts/deploy/xpf-deploy.py:179:        die("PyYAML required for YAML deploy (apt install python3-yaml). "
scripts/deploy/xpf-deploy.py:188:        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
scripts/deploy/xpf-deploy.py:194:    validate_appliance(ap, path)
scripts/deploy/xpf-deploy.py:215:              f"(label xpf-config, check-config validated)")
scripts/deploy/xpf-deploy.py:223:                           capture_output=True, text=True)
scripts/deploy/xpf-deploy.py:226:        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
scripts/deploy/xpf-deploy.py:229:              "(the appliance still validates at first boot).")
scripts/deploy/xpf-deploy.py:232:        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
scripts/deploy/xpf-deploy.py:235:        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
scripts/deploy/xpf-deploy.py:245:        subprocess.run(argv, check=True, capture_output=True, text=True)
scripts/deploy/xpf-deploy.py:276:        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
scripts/deploy/xpf-deploy.py:387:        print(f"\n{name}: verify with `virsh console {name}` then "
scripts/deploy/xpf-deploy.py:424:          "image": args.image or "xpf-appliance", "cpu": args.cpu,
scripts/deploy/xpf-deploy.py:427:    validate_appliance(ap, "launch")
scripts/deploy/xpf-deploy.py:452:    # YAML files for `deploy` (the bare-`xpf-deploy.py foo.yaml` shorthand).
scripts/deploy/xpf-deploy.py:459:        sub = argparse.ArgumentParser(prog="xpf-deploy.py inventory", add_help=False)
scripts/deploy/xpf-deploy.py:462:        sub = argparse.ArgumentParser(prog="xpf-deploy.py launch", add_help=False)
scripts/deploy/xpf-deploy.py:472:        sub = argparse.ArgumentParser(prog="xpf-deploy.py deploy", add_help=False)
scripts/image/validate.py:8:     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
scripts/image/validate.py:10:  b  valid day-0 drive -> config validated + installed + committed at first
scripts/image/validate.py:16:  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
scripts/image/validate.py:31:ALIAS = "xpf-image-validate"
scripts/image/validate.py:43:def incus(*args, check=True, capture=False):
scripts/image/validate.py:45:                          capture_output=capture, text=True)
scripts/image/validate.py:48:def guest(inst, *cmd, check=True, capture=False):
scripts/image/validate.py:50:                          check=check, capture_output=capture, text=True)
scripts/image/validate.py:56:                          capture_output=True, text=True).returncode == 0
scripts/image/validate.py:64:        self.work = tempfile.mkdtemp(prefix="xpf-validate-")
scripts/image/validate.py:68:        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
scripts/image/validate.py:75:        incus("image", "delete", ALIAS, check=False, capture=True)
scripts/image/validate.py:80:        incus("delete", "-f", name, check=False, capture=True)
scripts/image/validate.py:82:              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB", capture=True)
scripts/image/validate.py:85:                  f"source={os.path.realpath(iso)}", capture=True)
scripts/image/validate.py:92:            incus("delete", "-f", name, check=False, capture=True)
scripts/image/validate.py:101:                incus("delete", "-f", i, check=False, capture=True)
scripts/image/validate.py:102:            incus("image", "delete", ALIAS, check=False, capture=True)
scripts/image/validate.py:104:                incus("network", "delete", self.net, check=False, capture=True)
scripts/image/validate.py:116:        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
scripts/image/validate.py:121:                                       check=False, capture=True).returncode == 0,
scripts/image/validate.py:133:        kver = guest("xpf-image-a", "uname", "-r", capture=True).stdout.strip()
scripts/image/validate.py:146:        info("in-guest verify-dataplane (the bake gate, image kernel)...")
scripts/image/validate.py:147:        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
scripts/image/validate.py:149:            fail("in-guest verify-dataplane REJECTED — image must not ship")
scripts/image/validate.py:177:                                                   validate=False)
scripts/image/validate.py:214:                                                   validate=False)
scripts/image/validate.py:240:    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
debian/xpf.postinst:2:# xpf postinst (#1917 — increment A packaging + increment B cut-over hook).
debian/xpf.postinst:9:# verified cut-over to the increment-B mechanism (`xpfd upgrade`):
debian/xpf.postinst:11:#  - STANDALONE node: the postinst invokes `xpfd upgrade` — the
debian/xpf.postinst:15:#    verify gate, flips atomically, and pins the unit ExecStart to the
debian/xpf.postinst:17:#  - CLUSTERED node (/etc/xpf/node-id present): STAGE-ONLY. The postinst
debian/xpf.postinst:18:#    does NOT cut — a clustered node is cut ONLY by `xpfd upgrade
debian/xpf.postinst:45:            # is COMPLETELY absent (not even a broken symlink); never repoint
debian/xpf.postinst:48:            # and stealing a dangling link that increment-B repointed to a
debian/xpf.postinst:50:            # bypass its verify gate. -e alone follows the link (a broken
debian/xpf.postinst:67:            #    The cut is driven ONLY by `xpfd upgrade --rolling` (operator
debian/xpf.postinst:72:            #    down at apt time) must NOT fall through to a standalone cut.
debian/xpf.postinst:73:            #    "live cluster" is a ROLLING-readiness check, not postinst
debian/xpf.postinst:80:            #    verify gate + atomic flip + rollback still earn their keep
debian/xpf.postinst:82:            #    auto-cut with XPF_NO_POSTINST_CUT=1 and run `xpfd upgrade`
debian/xpf.postinst:86:                     "cut over with: xpfd upgrade --rolling" >&2
debian/xpf.postinst:87:            elif [ "${XPF_NO_POSTINST_CUT:-}" = "1" ]; then
debian/xpf.postinst:88:                echo "xpf: XPF_NO_POSTINST_CUT=1 — staged only;" \
debian/xpf.postinst:89:                     "cut over with: xpfd upgrade" >&2
debian/xpf.postinst:92:                # Run the staged binary's upgrade subcommand: it copies
debian/xpf.postinst:94:                # verify-dataplane gate, and on PASS does the atomic
debian/xpf.postinst:98:                # xpf-upgrade); surface it loudly instead.
debian/xpf.postinst:99:                if ! "$STAGED/xpfd" upgrade; then
debian/xpf.postinst:102:                    # FLIPs. Most failures (preflight/copy/verify) abort
debian/xpf.postinst:108:                    # offline after `apt upgrade`.
debian/xpf.postinst:112:                            echo "xpf: WARNING could not restart xpfd; run: xpfd upgrade" >&2
debian/xpf.postinst:114:                    echo "xpf: inspect with 'journalctl -u xpfd' and re-run: xpfd upgrade" >&2
debian/xpf.postinst:121:    abort-upgrade|abort-remove|abort-deconfigure)
debian/xpf.postinst:124:        echo "postinst called with unknown argument \`$1'" >&2
debian/control:22: symlinks are created on first install (the in-place upgrade cut-over
debian/control:23: mechanism that flips them after a verify gate is a separate increment
debian/control:24: and is intentionally not part of this package's postinst).
debian/control:29:Package: xpf-appliance
debian/control:50: curl,
debian/control:55: tooling). This is the operator-facing entry point: `apt install
debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
debian/control:57: hosted apt repo).
debian/control:61: than this metapackage, so apt does not have to resolve the full
debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade
docs/in-place-upgrade.md:1:# In-place upgrade mechanism (#1917)
docs/in-place-upgrade.md:3:The `pkg/upgrade` package implements the verified, atomic,
docs/in-place-upgrade.md:4:rollback-capable in-place upgrade cut-over for xpfd + the AF_XDP
docs/in-place-upgrade.md:5:dataplane helper. It is invoked as `xpfd upgrade [--rolling]` and from
docs/in-place-upgrade.md:6:the `.deb` postinst.
docs/in-place-upgrade.md:8:This doc is the module contract for `pkg/upgrade`, the `xpfd upgrade`
docs/in-place-upgrade.md:9:subcommand, the postinst HA-mode contract, and the dogfood deploy.
docs/in-place-upgrade.md:14:/usr/local/share/xpf/staged/          dpkg-static staging (increment A) — apt's write target
docs/in-place-upgrade.md:18:/var/lib/xpf/upgrade.state            crash-safe state-machine journal
docs/in-place-upgrade.md:22:## State machine (`pkg/upgrade`)
docs/in-place-upgrade.md:29:recoverable and idempotent — re-running `xpfd upgrade` resumes from the
docs/in-place-upgrade.md:35:  size + margin; GC eligible versions if short; take the pre-upgrade
docs/in-place-upgrade.md:40:- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
docs/in-place-upgrade.md:74:## HA rolling upgrade (`xpfd upgrade --rolling`)
docs/in-place-upgrade.md:98:7. `ResetFailover()` to rejoin election; forward-verify is the natural
docs/in-place-upgrade.md:118:## postinst HA-mode contract
docs/in-place-upgrade.md:120:- STANDALONE node (no `/etc/xpf/node-id`): the postinst invokes
docs/in-place-upgrade.md:121:  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
docs/in-place-upgrade.md:124:  `xpfd upgrade --rolling`. Keyed on node-id ALONE so a degraded-HA node
docs/in-place-upgrade.md:130:#1875 cluster lock), `apt install`s it (stage-only on the clustered
docs/in-place-upgrade.md:131:nodes), and drives `xpfd upgrade --rolling` secondary-first. The default
docs/in-place-upgrade.md:133:inner loop. The deb path is opt-in until validated live; it then becomes
docs/in-place-upgrade.md:158:require the staged binary to report its protocol version to the driver
docs/in-place-upgrade.md:169:- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.
scripts/image/bake.py:9:  dist/SHA256SUMS
scripts/image/bake.py:12:#1864 tracked shim) -> discover + SHA256-verify the latest Ubuntu cloud
scripts/image/bake.py:16:init_on_alloc=0, `apt-get install ./xpf.deb` which stages the binaries +
scripts/image/bake.py:17:creates the /usr/local/sbin symlinks + enables the units via its postinst)
scripts/image/bake.py:19:manifest -> in-guest verify-dataplane validation gate (validate.py).
scripts/image/bake.py:21:Requirements: make/go/cargo, libguestfs-tools, qemu-utils, curl; incus for
scripts/image/bake.py:25:  bake.py [--version V] [--out DIR] [--skip-build] [--skip-validate] [--keep-work]
scripts/image/bake.py:41:# same set the xpf-appliance metapackage Depends on (debian/control). The
scripts/image/bake.py:43:# rather than the metapackage, so apt does not have to resolve the full
scripts/image/bake.py:45:# the xpf-appliance metapackage is the operator-facing `apt install`
scripts/image/bake.py:46:# entry point (e.g. from a future hosted repo, #1924). Keep this list and
scripts/image/bake.py:53:    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
scripts/image/bake.py:64:# apt-get update exits 0 even when an index fetch fails; --error-on=any
scripts/image/bake.py:66:APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
scripts/image/bake.py:67:              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
scripts/image/bake.py:68:              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")
scripts/image/bake.py:104:    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
scripts/image/bake.py:119:    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
scripts/image/bake.py:136:    html = out_text(["curl", "-fsSL", url + "/"])
scripts/image/bake.py:163:        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
scripts/image/bake.py:165:    # Re-verify the cache against the upstream checksum (cache not trusted).
scripts/image/bake.py:166:    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
scripts/image/bake.py:167:    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
scripts/image/bake.py:176:        die(f"no SHA256 for {img} in upstream SHA256SUMS")
scripts/image/bake.py:191:        # #1917 increment A: install xpf via the .deb instead of copying raw
scripts/image/bake.py:194:        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
scripts/image/bake.py:198:        "--copy-in", f"{xpf_deb}:/var/tmp",
scripts/image/bake.py:199:        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
scripts/image/bake.py:200:        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
scripts/image/bake.py:201:        "--copy-in", f"{HERE}/99-incus-agent.rules:/usr/lib/udev/rules.d",
scripts/image/bake.py:207:                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
scripts/image/bake.py:209:                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
scripts/image/bake.py:218:        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
scripts/image/bake.py:221:        # -generic kernel, so `apt install linux-generic` pulls a NEWER
scripts/image/bake.py:226:        # version: purge ALL its packages via an apt glob, then rm -rf the
scripts/image/bake.py:234:        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
scripts/image/bake.py:236:        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
scripts/image/bake.py:240:        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
scripts/image/bake.py:242:        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
scripts/image/bake.py:245:        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
scripts/image/bake.py:253:        # Install the xpf .deb. apt resolves the package's deps (adduser,
scripts/image/bake.py:254:        # present) from the local file. The postinst stages the binaries,
scripts/image/bake.py:258:        # postinst's deb-systemd-invoke start is a harmless no-op (the units
scripts/image/bake.py:262:                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
scripts/image/bake.py:279:    p.add_argument("--skip-validate", action="store_true")
scripts/image/bake.py:283:    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
scripts/image/bake.py:284:                    ("virt-customize", "apt-get install libguestfs-tools"),
scripts/image/bake.py:285:                    ("virt-resize", "apt-get install libguestfs-tools"),
scripts/image/bake.py:286:                    ("virt-sysprep", "apt-get install libguestfs-tools"),
scripts/image/bake.py:287:                    ("virt-sparsify", "apt-get install libguestfs-tools"),
scripts/image/bake.py:288:                    ("virt-filesystems", "apt-get install libguestfs-tools"),
scripts/image/bake.py:289:                    ("curl", "apt-get install curl")]:
scripts/image/bake.py:307:        #    .deb instead of raw --copy-in binaries.
scripts/image/bake.py:313:        # binary package (NOT the xpf-appliance metapackage) and pick the
scripts/image/bake.py:317:                       if "xpf-appliance" not in os.path.basename(g)),
scripts/image/bake.py:323:        # build-host pre-gate (best-effort): verify the embedded shim against
scripts/image/bake.py:334:        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
scripts/image/bake.py:335:            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
scripts/image/bake.py:338:                               staged_xpfd, "verify-dataplane"]).returncode != 0:
scripts/image/bake.py:341:            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
scripts/image/bake.py:371:             "/var/lib/apt/lists/* 2>/dev/null || true"])
scripts/image/bake.py:390:                    "  variant: xpf-appliance\n")
scripts/image/bake.py:393:        sums = os.path.join(a.out, "SHA256SUMS")
scripts/image/bake.py:414:        if a.skip_validate:
scripts/image/bake.py:415:            print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
scripts/image/bake.py:416:                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
scripts/image/bake.py:418:            info("running validation gate (factory boot + in-guest verify-dataplane + "
scripts/image/bake.py:420:            if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
docs/install-images.md:17:| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
docs/install-images.md:18:| `dist/SHA256SUMS` | both | `sha256sum -c` |
docs/install-images.md:27:`libguestfs-tools`, `qemu-utils`, `curl`, `xorriso` (for config
docs/install-images.md:40:   of copying raw binaries.
docs/install-images.md:42:   (`XPF_BASE_RELEASE` pins one), then fetch + SHA256-verify the
docs/install-images.md:58:   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
docs/install-images.md:59:   The package's `postinst` stages the binary set, creates the live
docs/install-images.md:64:   directly. A plain `apt upgrade xpf` only refreshes the staging path
docs/install-images.md:65:   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
docs/install-images.md:70:6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
docs/install-images.md:74:   driver set check) with `xpfd verify-dataplane` IN-GUEST against
docs/install-images.md:78:   `--skip-validate` only for iteration; such artifacts are not
docs/install-images.md:90:python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
docs/install-images.md:96:> naming contract, the Python deployer (`scripts/deploy/xpf-deploy.py`
docs/install-images.md:98:> validated standalone/HA example definitions, SR-IOV/passthrough, and
docs/install-images.md:108:    dist/xpf-<ver>.qcow2 --alias xpf-appliance
docs/install-images.md:113:incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
docs/install-images.md:142:| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
docs/install-images.md:182:- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
docs/install-images.md:183:  signing — minisign — is a follow-up; see the #1879 deferred list.)
docs/install-images.md:188:copy `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` on cluster members),
docs/install-images.md:194:In-place binary upgrades inside a running appliance follow the #1869
docs/install-images.md:196:`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
docs/install-images.md:198:implementation). A native .deb + `xpf-upgrade` wrapper is the M1a
docs/install-images.md:207:  and re-apply your config (day-0 drive or copy `xpf.conf` in).
docs/install-images.md:219:(automated first-boot gate via `scripts/image/validate.py` — boot,
docs/install-images.md:220:single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),

codex
The existing code confirms why the path-binding fix matters: `bake.py` currently writes one global `dist/SHA256SUMS`, `validate.py` imports the given qcow2/metadata directly, and `xpf-deploy.py` currently names an Incus alias or libvirt disk path rather than doing any artifact authentication. I’m checking whether r2’s new helper boundaries are precise enough for those consumers.
exec
/bin/bash -lc "nl -ba Makefile | sed -n '1,240p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	CLANG ?= clang
     2	GO ?= go
     3	CARGO ?= $(HOME)/.cargo/bin/cargo
     4	BINARY := xpfd
     5	PREFIX ?= /usr/local
     6	
     7	# Version info embedded at build time
     8	VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
     9	COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
    10	BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
    11	LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
    12	
    13	# eBPF compilation flags
    14	.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity
    15	
    16	all: generate build build-ctl
    17	
    18	# Generate dataplane artifacts. After the #1476 source-removal phase of
    19	# the #1373 eBPF retirement umbrella, the only generator step here is the
    20	# retained Rust AF_XDP shim object embedded by userspace_xdp_rust.go.
    21	generate:
    22		$(GO) generate ./pkg/dataplane/...
    23	
    24	# Generate only the retained Rust userspace XDP shim object. The
    25	# `generate` target above runs the same single directive; this alias
    26	# stays for callers wired to the older name (e.g. build scripts that
    27	# only need the shim and not full code-gen). Originally introduced as
    28	# the #1473 source-removal canary that must not invoke legacy
    29	# xdp_main/tc bpf2go (now permanently true post-#1476).
    30	generate-userspace-xdp:
    31		$(GO) generate -run '^//go:generate bash build-userspace-xdp\.sh$$' ./pkg/dataplane
    32	
    33	build-userspace-xdp: generate-userspace-xdp
    34	
    35	# Build the daemon binary
    36	build:
    37		CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/xpfd
    38	
    39	# Build the remote CLI client
    40	build-ctl:
    41		CGO_ENABLED=0 $(GO) build -o cli ./cmd/cli
    42	
    43	# Build the userspace dataplane helper
    44	build-userspace-dp:
    45		$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release
    46		install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp
    47	
    48	# Manual build check for the diagnostic `debug-log` feature (#1678).
    49	# The debug-log build is not the production target and is deliberately
    50	# NOT wired into `all`/`build`/`test`, mirroring the opt-in
    51	# `audit-check` precedent. There is no CI in this repo, so this is a
    52	# developer convenience, not an automated gate: nothing runs it unless
    53	# invoked. It exists so the feature build (which silently rotted until
    54	# #1678 because nothing compiled it) can be revalidated with one
    55	# command before a commit. Compile-only; does not install.
    56	build-userspace-dp-debug-log:
    57		$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release --features debug-log
    58	
    59	# Generate protobuf/gRPC code
    60	proto:
    61		protoc --proto_path=proto/xpf/v1 \
    62			--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
    63			--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
    64			proto/xpf/v1/xpf.proto
    65	
    66	install: build build-ctl
    67		install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
    68		install -m 0755 cli $(PREFIX)/bin/cli
    69	
    70	test:
    71		$(GO) test ./...
    72	
    73	# Drift guard for the committed refactoring heatmap (#1661 item 8).
    74	# Regenerates scripts/refactoring-audit.sh output to a temp file and
    75	# diffs it against the committed docs/refactoring-audit-current.txt.
    76	# Fails if they differ OR if the generator itself fails. Standalone by
    77	# design — deliberately NOT a dependency of `test`/`all`, so a PR that
    78	# legitimately grows a large file is not blocked until someone
    79	# regenerates the artifact (run this target, then commit the result).
    80	#
    81	# Recipe notes: Make runs the recipe in one shell without `set -e`, so
    82	# the generator is `&&`-chained to `diff` to make a generator failure
    83	# (not just a diff mismatch) take the error path. `trap ... EXIT`
    84	# guarantees the temp file is removed on every exit path.
    85	.PHONY: audit-check
    86	audit-check:
    87		@tmp=$$(mktemp); \
    88		trap 'rm -f "$$tmp"' EXIT; \
    89		bash scripts/refactoring-audit.sh > "$$tmp" && \
    90		diff -u docs/refactoring-audit-current.txt "$$tmp" || { \
    91			echo "ERROR: docs/refactoring-audit-current.txt is stale or the audit script failed."; \
    92			echo "Run: bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt"; \
    93			exit 1; \
    94		}; \
    95		echo "audit-check: refactoring-audit-current.txt is up to date"
    96	
    97	# Bake the distributable appliance image (#1879 Path C): one
    98	# offline-built bootable root disk (LATEST Ubuntu server cloudimg base
    99	# discovered at bake time — XPF_BASE_RELEASE pins; linux-generic
   100	# kernel >= 6.18, xpfd + cli + xpf-userspace-dp + day-0 config-drive
   101	# loader), exported as a qcow2 for libvirt/KVM AND as an incus VM
   102	# image (metadata tarball + the same qcow2). Includes the in-guest
   103	# verify-dataplane validation gate. See docs/install-images.md.
   104	.PHONY: image
   105	image:
   106		python3 scripts/image/bake.py
   107	
   108	clean:
   109		rm -f $(BINARY) cli xpf-userspace-dp
   110		# Narrowed glob (#1476): the retained Rust shim object lives at
   111		# pkg/dataplane/userspace_xdp_bpfel.o. Cleaning it would break
   112		# `make build` because userspace_xdp_rust.go uses //go:embed.
   113		# We restrict to the legacy bpf2go `xpf*` prefix even though
   114		# every matching file is gone after the #1476 deletion — the
   115		# pattern stays as defence-in-depth against accidental
   116		# re-introduction by a future PR.
   117		rm -f pkg/dataplane/xpf*_bpfel.go pkg/dataplane/xpf*_bpfeb.go
   118		rm -f pkg/dataplane/xpf*_bpfel.o pkg/dataplane/xpf*_bpfeb.o
   119		rm -rf userspace-dp/target
   120	
   121	# Legacy standalone test environment management (single Incus VM/container).
   122	.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal
   123	
   124	test-env-init:
   125		./test/incus/setup.sh init
   126	
   127	test-vm:
   128		./test/incus/setup.sh create-vm
   129	
   130	standalone-test-vm: test-vm
   131	
   132	test-ct:
   133		./test/incus/setup.sh create-ct
   134	
   135	test-deploy: build build-ctl
   136		./test/incus/setup.sh deploy
   137	
   138	test-ssh:
   139		./test/incus/setup.sh ssh
   140	
   141	test-destroy:
   142		./test/incus/setup.sh destroy
   143	
   144	test-status:
   145		./test/incus/setup.sh status
   146	
   147	test-start:
   148		./test/incus/setup.sh start
   149	
   150	test-stop:
   151		./test/incus/setup.sh stop
   152	
   153	test-restart:
   154		./test/incus/setup.sh restart
   155	
   156	test-logs:
   157		./test/incus/setup.sh logs
   158	
   159	test-journal:
   160		./test/incus/setup.sh journal
   161	
   162	# Connectivity tests (standalone + cluster, VRF-aware)
   163	MODE ?= all
   164	PRIVATE_RG_MODE ?= $(if $(filter all,$(MODE)),full,$(MODE))
   165	test-connectivity:
   166		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-connectivity.sh $(MODE)
   167	
   168	# Cluster failover test (iperf3 through reboot — requires cluster + iperf3 server)
   169	test-failover:
   170		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-failover.sh
   171	
   172	# Double failover test (crash fw0 → fw1 takes over → fw0 rejoins → crash fw1 → fw0 takes over)
   173	test-double-failover:
   174		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-double-failover.sh
   175	
   176	# Active/active per-RG failover test (iperf3 through RG split — requires cluster + iperf3 server)
   177	test-active-active:
   178		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-active-active.sh
   179	
   180	# Rapid failover stress test (repeated failover cycles — requires cluster + iperf3 server)
   181	test-stress-failover:
   182		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-stress-failover.sh
   183	
   184	# Hard-crash / hung-node HA test (force-stop + daemon stop + multi-cycle — requires cluster + iperf3 server)
   185	test-ha-crash:
   186		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-ha-crash.sh
   187	
   188	# Chained hard-reset failover test (fw0 crash → fw1 crash → both rejoin — requires cluster + iperf3 server)
   189	test-chained-crash:
   190		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-chained-crash.sh
   191	
   192	# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
   193	test-private-rg:
   194		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-private-rg.sh $(PRIVATE_RG_MODE)
   195	
   196	# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
   197	test-restart-connectivity:
   198		BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-restart-connectivity.sh
   199	
   200	# Canonical cluster HA test environment (isolated loss userspace cluster).
   201	# Override CLUSTER_ENV= to use cluster-setup.sh local xpf-fw0/xpf-fw1 defaults.
   202	NODE ?= all
   203	ifeq ($(origin CLUSTER_ENV),undefined)
   204	ifeq ($(origin BPFRX_CLUSTER_ENV),undefined)
   205	CLUSTER_ENV := test/incus/loss-userspace-cluster.env
   206	else
   207	CLUSTER_ENV := $(BPFRX_CLUSTER_ENV)
   208	endif
   209	endif
   210	LOSS_CLUSTER_ENV ?= test/incus/loss-cluster.env
   211	CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh
   212	LOSS_CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(LOSS_CLUSTER_ENV) ./test/incus/cluster-setup.sh
   213	.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
   214	.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart
   215	
   216	cluster-init:
   217		$(CLUSTER_SETUP) init
   218	
   219	cluster-create:
   220		$(CLUSTER_SETUP) create
   221	
   222	cluster-deploy: build build-ctl
   223		$(CLUSTER_SETUP) deploy $(NODE)
   224	
   225	cluster-destroy:
   226		$(CLUSTER_SETUP) destroy
   227	
   228	cluster-status:
   229		$(CLUSTER_SETUP) status
   230	
   231	cluster-ssh:
   232		$(CLUSTER_SETUP) ssh $(NODE)
   233	
   234	cluster-logs:
   235		$(CLUSTER_SETUP) logs $(NODE)
   236	
   237	cluster-start:
   238		$(CLUSTER_SETUP) start $(NODE)
   239	
   240	cluster-stop:

exec
/bin/bash -lc 'rg -n "''^(image|deb|dist|publish|release|'"\\.PHONY|make image|make deb|SHA256SUMS|install|debian|dpkg|apt|XPF_|reprepro|apt-ftparchive|minisign|dist-)\" Makefile .github scripts docs/research/1924-signed-hosted-dist -g '"'!docs/research/1924-signed-hosted-dist/plan.md'"'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
Makefile:14:.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity
Makefile:66:install: build build-ctl
Makefile:85:.PHONY: audit-check
Makefile:104:.PHONY: image
Makefile:105:image:
Makefile:122:.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal
Makefile:213:.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
Makefile:214:.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart
Makefile:258:.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart
Makefile:309:.PHONY: deb
Makefile:310:deb:
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:23:install.sh also serves a matching pubkey + sig. The ONLY real root is an
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:47:SHA256SUMS and (b) the verifier checks the imported file's hash against the
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:50:SHA256SUMS`" which checks files in CWD; if the operator imports from a
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:57:debian/control + docs/in-place-upgrade.md show the `.deb` version is git-derived
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:81:dist-publish`) REFUSES to push image artifacts lacking a `.minisig`. The
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md:82:publish-time refusal is the real safety net and isn't in the plan. FIX: add a
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2863:debian/xpf.postinst:2:# xpf postinst (#1917 — increment A packaging + increment B cut-over hook).
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2864:debian/xpf.postinst:9:# verified cut-over to the increment-B mechanism (`xpfd upgrade`):
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2865:debian/xpf.postinst:11:#  - STANDALONE node: the postinst invokes `xpfd upgrade` — the
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2866:debian/xpf.postinst:15:#    verify gate, flips atomically, and pins the unit ExecStart to the
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2867:debian/xpf.postinst:17:#  - CLUSTERED node (/etc/xpf/node-id present): STAGE-ONLY. The postinst
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2868:debian/xpf.postinst:18:#    does NOT cut — a clustered node is cut ONLY by `xpfd upgrade
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2869:debian/xpf.postinst:45:            # is COMPLETELY absent (not even a broken symlink); never repoint
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2870:debian/xpf.postinst:48:            # and stealing a dangling link that increment-B repointed to a
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2871:debian/xpf.postinst:50:            # bypass its verify gate. -e alone follows the link (a broken
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2872:debian/xpf.postinst:67:            #    The cut is driven ONLY by `xpfd upgrade --rolling` (operator
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2873:debian/xpf.postinst:72:            #    down at apt time) must NOT fall through to a standalone cut.
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2874:debian/xpf.postinst:73:            #    "live cluster" is a ROLLING-readiness check, not postinst
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2875:debian/xpf.postinst:80:            #    verify gate + atomic flip + rollback still earn their keep
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2876:debian/xpf.postinst:82:            #    auto-cut with XPF_NO_POSTINST_CUT=1 and run `xpfd upgrade`
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2877:debian/xpf.postinst:86:                     "cut over with: xpfd upgrade --rolling" >&2
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2878:debian/xpf.postinst:87:            elif [ "${XPF_NO_POSTINST_CUT:-}" = "1" ]; then
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2879:debian/xpf.postinst:88:                echo "xpf: XPF_NO_POSTINST_CUT=1 — staged only;" \
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2880:debian/xpf.postinst:89:                     "cut over with: xpfd upgrade" >&2
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2881:debian/xpf.postinst:92:                # Run the staged binary's upgrade subcommand: it copies
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2882:debian/xpf.postinst:94:                # verify-dataplane gate, and on PASS does the atomic
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2883:debian/xpf.postinst:98:                # xpf-upgrade); surface it loudly instead.
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2884:debian/xpf.postinst:99:                if ! "$STAGED/xpfd" upgrade; then
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2885:debian/xpf.postinst:102:                    # FLIPs. Most failures (preflight/copy/verify) abort
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2886:debian/xpf.postinst:108:                    # offline after `apt upgrade`.
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2887:debian/xpf.postinst:112:                            echo "xpf: WARNING could not restart xpfd; run: xpfd upgrade" >&2
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2888:debian/xpf.postinst:114:                    echo "xpf: inspect with 'journalctl -u xpfd' and re-run: xpfd upgrade" >&2
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2889:debian/xpf.postinst:121:    abort-upgrade|abort-remove|abort-deconfigure)
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2890:debian/xpf.postinst:124:        echo "postinst called with unknown argument \`$1'" >&2
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2891:debian/control:22: symlinks are created on first install (the in-place upgrade cut-over
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2892:debian/control:23: mechanism that flips them after a verify gate is a separate increment
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2893:debian/control:24: and is intentionally not part of this package's postinst).
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2894:debian/control:29:Package: xpf-appliance
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2895:debian/control:50: curl,
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2896:debian/control:55: tooling). This is the operator-facing entry point: `apt install
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2897:debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2898:debian/control:57: hosted apt repo).
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2899:debian/control:61: than this metapackage, so apt does not have to resolve the full
docs/research/1924-signed-hosted-dist/codex-plan-r2.md:2900:debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade
docs/research/1924-signed-hosted-dist/codex-plan-r1.md:2322:debian/control:29:Package: xpf-appliance
docs/research/1924-signed-hosted-dist/codex-plan-r1.md:2323:debian/control:55: tooling). This is the operator-facing entry point: `apt install
docs/research/1924-signed-hosted-dist/codex-plan-r1.md:2324:debian/control:56: xpf-appliance` provisions a complete firewall in one step (e.g. from a
docs/research/1924-signed-hosted-dist/codex-plan-r1.md:2325:debian/control:57: hosted apt repo).
docs/research/1924-signed-hosted-dist/codex-plan-r1.md:2326:debian/control:66: The held/pinned kernel channel and the in-place kernel-upgrade
scripts/image/bake.py:5:image to provision it) and exports it for both hypervisors:
scripts/image/bake.py:13:image (XPF_BASE_RELEASE pins) -> virt-resize root into a work disk ->
scripts/image/xpf-day0-config:42:XPF_DIR=/etc/xpf

exec
/bin/bash -lc "find docs/research/1924-signed-hosted-dist -maxdepth 2 -type f -print -exec wc -l {} \\;" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
docs/research/1924-signed-hosted-dist/plan.md
556 docs/research/1924-signed-hosted-dist/plan.md
docs/research/1924-signed-hosted-dist/codex-plan-r1.md
2368 docs/research/1924-signed-hosted-dist/codex-plan-r1.md
docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md
107 docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md
docs/research/1924-signed-hosted-dist/codex-plan-r2.md
3022 docs/research/1924-signed-hosted-dist/codex-plan-r2.md

exec
/bin/bash -lc 'find .github -maxdepth 3 -type f -print 2>/dev/null | sort' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc "nl -ba Makefile | sed -n '300,340p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
.github/instructions/*.instructions.md

 succeeded in 0ms:
   300	# project's git tags are non-numeric (e.g. userspace-forwarding-ok-*),
   301	# so synthesize 0.0.<commit-count>+g<short-sha>[.dirty] — monotonic in
   302	# commit count, carries the exact source sha, and is policy-valid.
   303	DEB_GIT_COUNT ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
   304	DEB_GIT_SHA   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
   305	DEB_GIT_DIRTY ?= $(shell git diff --quiet 2>/dev/null || echo .dirty)
   306	DEB_VERSION ?= 0.0.$(DEB_GIT_COUNT)+g$(DEB_GIT_SHA)$(DEB_GIT_DIRTY)
   307	DEB_OUT ?= $(CURDIR)/dist/deb
   308	
   309	.PHONY: deb
   310	deb:
   311		@echo "==> xpf .deb version: $(DEB_VERSION)"
   312		@# Run the whole build inside ONE shell with a trap so the changelog
   313		@# version is ALWAYS restored to the committed 0.0.0 and the parent-dir
   314		@# build byproducts are ALWAYS removed — even on SIGINT/SIGTERM or a
   315		@# failed dpkg-buildpackage. (A backup FILE under debian/ would be
   316		@# deleted by dpkg-buildpackage's own clean phase, so re-sed instead.)
   317		@# The build version is derived from git at build time, not committed;
   318		@# only the top changelog line's version token is rewritten so the rest
   319		@# of the entry/trailer stays dpkg-parseable. dpkg-buildpackage writes
   320		@# the .deb/.changes/.buildinfo to the PARENT dir (not configurable);
   321		@# we keep the canonical copies in dist/deb/ and scrub the parent so it
   322		@# never litters the tree above the source dir (a git worktree parent).
   323		@# Signal traps re-raise the caught signal after cleanup (trap - SIG;
   324		@# kill -SIG $$) so an interrupted build returns the SIGNAL exit status,
   325		@# not 0. A bare `trap cleanup INT TERM` with a cleanup that returns 0
   326		@# would mask Ctrl-C / CI-kill as success under dash (AGY r2). The EXIT
   327		@# trap covers normal completion + dpkg-buildpackage failure (set -e).
   328		set -e; \
   329		  cleanup() { \
   330		    sed -i "1s/^xpf ([^)]*)/xpf (0.0.0)/" debian/changelog; \
   331		    rm -f ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb \
   332		          ../xpf_$(DEB_VERSION)_*.changes ../xpf_$(DEB_VERSION)_*.buildinfo; \
   333		  }; \
   334		  trap cleanup EXIT; \
   335		  trap 'cleanup; trap - INT; kill -INT $$$$' INT; \
   336		  trap 'cleanup; trap - TERM; kill -TERM $$$$' TERM; \
   337		  sed -i "1s/^xpf ([^)]*)/xpf ($(DEB_VERSION))/" debian/changelog; \
   338		  dpkg-buildpackage -us -uc -b --no-sign; \
   339		  mkdir -p $(DEB_OUT); \
   340		  cp ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb $(DEB_OUT)/

exec
/bin/bash -lc "rg -n \"Package:|Version|Architecture|Filename|Packages|Release|InRelease|Valid-Until|SHA256|MD5Sum|Date|Suite|Codename|Acquire::Check-Valid-Until|apt-ftparchive|dpkg-scanpackages|reprepro|aptly\" -S . --glob '"'!docs/research/1924-signed-hosted-dist/codex-plan-r2.md'"' --glob '"'!docs/research/1924-signed-hosted-dist/codex-plan-r1.md'"' --glob '"'!docs/research/1924-signed-hosted-dist/claude-smr-plan-r1.md'"'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 290ms:
./docs/pr/1444-cli-presenters/plan.md:188:- `(*CLI).SetVersion(string)` and 11 other `Set*` methods
./docs/pr/1879-pathc/deploy-delta-reviewer-ids.md:118:    (build, Ubuntu discovery + SHA256 verify, virt-resize/customize/
./docs/pr/1879-pathc/deploy-delta-reviewer-ids.md:148:| Claude SMR | MERGE-READY | gates green (go build+test rc=0, full go test rc=0, all 4 Python py_compile); diffed deleted shell vs Python ports — every functional assert preserved (kernel>=6.18, mellanox driver-set, single-kernel, init_on_alloc=0 cmdline, sshd posture, base SHA256 verify, sparsify); expected_name==assignName; role-validation + dry-run hermeticity + per-backing incus/libvirt translation verified |
./docs/pr/1615-flooder-multithread-virtio/claude-smr-code-r1.md:99:The first_fatal Mutex provides Acquire/Release across the write
./docs/pr/959-phase9-flowcache/plan.md:22:Filename is `flow_cache_state.rs` because `flow_cache.rs` is taken
./docs/pr/1541-cluster-mgr-split/plan.md:176:  `heartbeatReceiver` goroutines, `normalizeHAProtocolVersion`.
./docs/pr/1541-cluster-mgr-split/plan.md:223:  `SetSoftwareVersion`, `SoftwareVersions`, `SetHAProtocolVersion`,
./docs/pr/1541-cluster-mgr-split/plan.md:224:  `HAProtocolVersions`, `HAProtocolVersionMismatch`,
./docs/pr/1614-multi-rss-cos/STATUS.md:21:| Version | SHA | Status | Key change |
./docs/pr/1620-binding-worker-hist-integration/agy-r2.md:69:### AXIS 1: Wire Default & Version Skew
./docs/pr/1609-multistage-policy-dag/claude-smr-plan-r7.md:17:3-of-3 convergent verdict: **PLAN-NEEDS-MAJOR**. Architecture
./docs/pr/1521-maps-sync-decouple/plan.md:246:                        pos.Filename, pos.Line, s))
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:7:[Tue Apr 21 02:41:34 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:10:[Tue Apr 21 02:44:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:13:[Tue Apr 21 02:54:13 2026] fab1 (unregistering): Released all slaves
./docs/pr/1607-hw-ceiling-microbench/claude-smr-code-r1.md:30:- Release profile `opt-level = 3, lto = "thin", codegen-units = 1,
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/1609-multistage-policy-dag/plan.md:125:## 2. Architecture — 5-fix v3
./docs/pr/1473-xdp-shim-decouple/plan.md:235:  -run 'TestUserspaceXDPGenerateTargetStaysDecoupledFromLegacyBPF|TestUserspaceXDPGoGenerateRunSelectsOnlyShim|TestUserspaceXDPShimSourceMatchesRetainedObjectAllowlist|TestUserspaceXDPShimObjectMatchesRetainedCollectionAllowlist|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestBPFShimEntryProgramStateIsNotJSONMutable|TestUserspaceXDPEntryProgramConstantNamesRetainedShim|TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports|TestRetirementBoundaryDocsMentionLegacyImportAllowlist' \
./docs/pr/wireguard-clean/plan.md:44:## Architecture
./docs/pr/1662-nat64-dscp/plan.md:86:- Version nibble `b[0][7:4] = 6` and flow-label nibble `b[1][3:0]` must
./docs/pr/1687-shared-presentation/plan.md:34:     `TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports`
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:7:[Tue Apr 21 02:41:34 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:10:[Tue Apr 21 02:44:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:13:[Tue Apr 21 02:54:13 2026] fab1 (unregistering): Released all slaves
./docs/pr/1621-cold-path-wire-prometheus/agy-r1.md:128:* **Contention Check:** The worker loop is the sole writer of the lockless seqlock. The seqlock writer never blocks, loops, or spins; it only writes sequentially under `AcqRel` and `Release` ordering.
./docs/pr/1621-cold-path-wire-prometheus/agy-code-r1.md:106:| Daemon Version (Rust) | Controller/Harness (Go) | Popul. State | Expected Outcome |
./docs/pr/1769-neighbor-resolver/reviewer-ids.md:28:- Critical: monitor bumps generation `Release` BEFORE mutating
./docs/pr/p1-tx-completion/plan.md:58:  The Release/Acquire boundary stays inside `queue_service` /
./docs/pr/p1-tx-completion/plan.md:460:Release/Acquire publish boundary is unchanged by P1.
./docs/pr/819-step2-discriminator-design/codex-plan-review.md:3:> Date: 2026-04-21
./docs/pr/819-step2-discriminator-design/codex-plan-review.md:143:> Date: 2026-04-21
./docs/pr/819-step2-discriminator-design/codex-plan-review.md:230:> Date: 2026-04-21
./docs/pr/819-step2-discriminator-design/codex-plan-review.md:295:> Date: 2026-04-21
./docs/pr/819-step2-discriminator-design/codex-plan-review.md:346:> Date: 2026-04-21
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:22:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:25:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:28:[Tue Apr 21 21:02:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:31:[Tue Apr 21 21:03:33 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:48:[Wed Apr 22 04:41:21 2026] fab1 (unregistering): Released all slaves
./docs/pr/940-942-vmin-correctness/plan.md:137:/// uses `Ordering::Release` (types.rs:1442). Peers that observe the
./docs/pr/940-942-vmin-correctness/plan.md:249:- V_min publish: `slot.publish()` uses `Ordering::Release` (types.rs:1442).
./docs/pr/940-942-vmin-correctness/plan.md:253:  Acquire pairs with the publish's Release. Peer's V_min decision is
./docs/pr/1636-cold-connect-mitigation/plan.md:430:        self.last_warm_sweep_ns.store(now, Ordering::Release);
./docs/pr/1636-cold-connect-mitigation/plan.md:436:    let gen = self.neighbors.warm_generation.fetch_add(1, Ordering::Release) + 1;
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/1829-p2/evidence.md:3:Date: 2026-06-10. Build under test: master `g00346ec1a`
./docs/pr/1529-dpdk-docs-sweep/plan.md:215:brief bullet under the existing `## Architecture` section per
./docs/pr/1529-dpdk-docs-sweep/plan.md:400:- CLAUDE.md bullet placed under `## Architecture` near line 113.
./docs/pr/1635-cold-path-hist-redesign/claude-smr-plan-r3.md:70:flag. Release builds skip the check; dev/test builds run it. The
./docs/pr/1635-cold-path-hist-redesign/agy-plan-r1.md:48:### 1.4 Wire-Protocol Version Tagging
./docs/pr/1329-shared-cos-lease-extract/plan.md:300:   `Release`) sequence is byte-identical to master. No `Ordering`
./docs/pr/917-mqfq-phase4/status.md:166:  Release / Acquire memory ordering per plan §3.4.
./docs/pr/917-mqfq-phase4/status.md:187:- HA demotion path clears `drain_enabled` Release; worker
./docs/pr/1635-cold-path-hist-redesign/plan.md:289:### §3.1 Versioning
./docs/pr/1635-cold-path-hist-redesign/plan.md:399:Mirror the sparse fields. Add `ColdPathLayoutVersion uint32` and the seven
./docs/pr/1635-cold-path-hist-redesign/plan.md:404:`emitWorkerColdPath` branches on `w.ColdPathLayoutVersion`:
./docs/pr/917-mqfq-phase4/plan.md:109:    floor.slots[worker_id as usize].publish(vtime); // Release store
./docs/pr/917-mqfq-phase4/plan.md:115:(2 Mpps / 64). One Release store per commit ≈ 2 ns × 32 K =
./docs/pr/917-mqfq-phase4/plan.md:233:**Decision: Option B with explicit Release/Acquire ordering.**
./docs/pr/917-mqfq-phase4/plan.md:251:    /// boundary publish (§3.2). Release store ensures any
./docs/pr/917-mqfq-phase4/plan.md:257:        self.vtime.store(vtime, Ordering::Release);
./docs/pr/917-mqfq-phase4/plan.md:263:        self.vtime.store(NOT_PARTICIPATING, Ordering::Release);
./docs/pr/917-mqfq-phase4/plan.md:423:  `drain_enabled: AtomicBool`. Demotion clears it Release.
./docs/pr/917-mqfq-phase4/plan.md:657:   Release/Acquire ordering** (§3.4 v2). Race-window analysis
./docs/pr/917-mqfq-phase4/plan.md:727:    (sentinel u64::MAX) with explicit Release/Acquire memory
./docs/pr/1824-proptest-harness/validation.md:24:1. **Release binary unaffected** (§9.1): with the proptest
./docs/pr/1824-proptest-harness/validation.md:38:   count is 0). Release warning count unchanged: 140 == 140.
./docs/pr/1231-iperf-c-fix/smoke-v5.5.md:3:**Date:** 2026-05-08, loss userspace cluster, recipe-doc env (sym
./docs/pr/1741-flow-count/agy-impl-r1.md:48:*   No non-test consumers of `active_entry_age` or `count_active_flows` exist in the codebase. Release compilation passes cleanly with no warnings introduced by the change.
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/964-session-multi-index/plan.md:18:3. **Release-mode alias validation**: `lookup_with_origin`'s
./docs/pr/1741-flow-count/claude-smr-impl-r1.md:35:   `count_active_flows` is already `#[cfg(test)]`. Release warning
./docs/pr/1231-iperf-c-fix/plan.md:94:        v8.epoch.bypass_grace_rotations_remaining.store(5, Release);
./docs/pr/1231-iperf-c-fix/plan.md:99:            v8.epoch.bypass_grace_rotations_remaining.store(curr - 1, Release);
./docs/pr/1231-iperf-c-fix/plan.md:334:            .store(5, Release);
./docs/pr/1231-iperf-c-fix/plan.md:343:                .store(curr - 1, Release);
./docs/pr/1231-iperf-c-fix/plan.md:469:    epoch.bypass_grace_rotations_remaining.store(5, Release);
./docs/pr/1231-iperf-c-fix/plan.md:473:        epoch.bypass_grace_rotations_remaining.store(curr - 1, Release);
./docs/pr/1231-iperf-c-fix/plan.md:562:    v8.epoch.bypass_grace_rotations_remaining.store(5, Ordering::Release);
./docs/pr/1231-iperf-c-fix/plan.md:567:        v8.epoch.bypass_grace_rotations_remaining.store(curr - 1, Ordering::Release);
./docs/pr/1231-iperf-c-fix/plan.md:573:    pg.0.store(PackedEpochGrant::pack(new_tag, 0), Ordering::Release);
./docs/pr/1231-iperf-c-fix/plan.md:860:        .store(5, Ordering::Release);
./docs/pr/1231-iperf-c-fix/plan.md:867:            .store(curr - 1, Ordering::Release);
./docs/pr/1231-iperf-c-fix/plan.md:872:    events.store(0, Ordering::Release);
./docs/pr/1231-iperf-c-fix/smoke-v5.md:3:**Date:** 2026-05-08 (loss userspace cluster)
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:22:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:25:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:28:[Tue Apr 21 21:02:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:31:[Tue Apr 21 21:03:33 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:48:[Wed Apr 22 04:41:21 2026] fab1 (unregistering): Released all slaves
./docs/pr/941-vacate-hard-cap/plan.md:117:Release.
./docs/pr/941-vacate-hard-cap/plan.md:482:`vacate()` write uses `Ordering::Release`. Peer reads use
./docs/pr/941-vacate-hard-cap/plan.md:495:independently Acquire-ordered against the corresponding Release write.
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:7:[Tue Apr 21 02:41:34 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:10:[Tue Apr 21 02:44:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:13:[Tue Apr 21 02:54:13 2026] fab1 (unregistering): Released all slaves
./docs/pr/1373-retire-ebpf-dataplane/plan-1374-syn-cookies.md:61:Use SipHash, not HMAC-SHA1/SHA256. Linux SYN cookies and the current kernel
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:7:[Tue Apr 21 02:41:34 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:10:[Tue Apr 21 02:44:55 2026] fab1 (unregistering): Released all slaves
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:13:[Tue Apr 21 02:54:13 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:45:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:48:[Tue Apr 21 18:58:57 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:48:[Tue Apr 21 18:36:00 2026] fab1 (unregistering): Released all slaves
./docs/pr/816-step1-rerun/plan.md:623:**Version emission (HIGH-5 fix).** Every

codex
One more grounded issue is emerging from `xpf-deploy.py`: today it launches an Incus alias or a libvirt disk name; it does not import the Incus image from qcow2+metadata. That makes the r2 “verify before incus image import” instruction too vague for the deployer surface unless the plan explicitly adds an import/download mode.
exec
/bin/bash -lc 'find debian -maxdepth 2 -type f -print | sort' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
debian/.gitignore
debian/changelog
debian/control
debian/rules
debian/source/format
debian/xpf.needrestart
debian/xpf.postinst
debian/xpf.postrm

exec
/bin/bash -lc "nl -ba debian/xpf.service | sed -n '1,160p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
nl: debian/xpf.service: No such file or directory

exec
/bin/bash -lc 'for f in debian/xpf.* debian/*.install debian/*.service; do [ -f "$f" ] && printf '"'%s\\n' \""'$f"; done' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 exited 1 in 0ms:
debian/xpf.needrestart
debian/xpf.postinst
debian/xpf.postrm

exec
/bin/bash -lc 'rg -n "systemd|dh_installsystemd|--no-start|--no-enable|WantedBy|ExecStart|xpfd|xpf-day0|enable|start|postinst" debian scripts/image docs/research/1924-signed-hosted-dist/plan.md docs/install-images.md' in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
docs/install-images.md:7:7.0), FRR, strongSwan, Kea, chrony, systemd-networkd, and the xpf
docs/install-images.md:8:binaries (`xpfd`, `cli`, `xpf-userspace-dp`) with their systemd units.
docs/install-images.md:54:   metapackages, systemd-networkd + resolved enabled, FRR + chrony
docs/install-images.md:55:   enabled (default NTP pools neutered; xpfd manages
docs/install-images.md:59:   The package's `postinst` stages the binary set, creates the live
docs/install-images.md:60:   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
docs/install-images.md:61:   into the staging path, and enables `xpfd` + `xpf-day0-config` (so the
docs/install-images.md:62:   bake no longer hand-copies binaries/units or runs `systemctl enable
docs/install-images.md:63:   xpfd`). The incus-agent loader is still copied in and enabled
docs/install-images.md:65:   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
docs/install-images.md:66:   `needrestart` blacklist); the verified in-place cut-over is a separate
docs/install-images.md:74:   driver set check) with `xpfd verify-dataplane` IN-GUEST against
docs/install-images.md:94:> **Deploying at scale?** `docs/deploy-quickstart.md` +
docs/install-images.md:104:## Deploy quickstart — incus
docs/install-images.md:115:incus start xpf1
docs/install-images.md:120:devices before start; vNIC order maps to vSRX names (below).
docs/install-images.md:122:## Deploy quickstart — libvirt/KVM
docs/install-images.md:142:| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
docs/install-images.md:145:Day-0 loader specifics (`scripts/image/xpf-day0-config`, oneshot unit
docs/install-images.md:146:`Before=xpfd.service`):
docs/install-images.md:153:  it may carry credential material) and xpfd's normal
docs/install-images.md:154:  bootstrap-from-file import commits it at startup. No second config
docs/install-images.md:166:When an `xpfd` binary is present, the builder runs the same
docs/install-images.md:195:ordering invariant: push the new `xpfd` to a temp path, run
docs/install-images.md:196:`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
docs/install-images.md:208:- Day-0 config rejected at first boot: `journalctl -u xpf-day0-config`
docs/install-images.md:213:  `xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2
docs/research/1924-signed-hosted-dist/plan.md:184:rollback is `xpfd upgrade`'s job (#1917). If apt-pin-to-old IS wanted, that is
docs/research/1924-signed-hosted-dist/plan.md:336:**r2 (resolves AGY-HIGH-2) — apt UPGRADE inherits #1917's postinst cut-over.**
docs/research/1924-signed-hosted-dist/plan.md:339:package's postinst, which on a STANDALONE node invokes `xpfd upgrade` — a
docs/research/1924-signed-hosted-dist/plan.md:342:postinst has a safety-net `systemctl is-active` restart). This is #1917's
docs/research/1924-signed-hosted-dist/plan.md:347:  existing postinst escape hatch) for operators who want stage-only + manual
docs/research/1924-signed-hosted-dist/plan.md:348:  `xpfd upgrade` at a chosen time.
docs/research/1924-signed-hosted-dist/plan.md:349:- For HA nodes (`/etc/xpf/node-id` present) the postinst is already STAGE-ONLY;
docs/research/1924-signed-hosted-dist/plan.md:350:  the repo upgrade does NOT cut — `xpfd upgrade --rolling` does. Doc restates
docs/research/1924-signed-hosted-dist/plan.md:352:- No `postinst` / `pkg/upgrade` code is in scope for #1924.
docs/research/1924-signed-hosted-dist/plan.md:477:  a VM image. Mitigation: install.sh PRINTS the warning and does NOT auto-start
docs/research/1924-signed-hosted-dist/plan.md:546:| apt UPGRADE inherits #1917 postinst cut-over (dataplane blip / HA) | AGY-HIGH-2 | §5.4: documented (`XPF_NO_POSTINST_CUT`, HA stage-only); no postinst code in #1924 scope. |
docs/research/1924-signed-hosted-dist/plan.md:553:AGY-HIGH-2 (postinst cut-over is #1917's reviewed mechanism) and the
scripts/image/incus-agent.service:5:# images:debian/13 VM on incus 6.21). The unit is NOT enabled: it is
scripts/image/incus-agent.service:21:ExecStartPre=/lib/systemd/incus-agent-setup
scripts/image/incus-agent.service:22:ExecStart=/run/incus_agent/incus-agent
scripts/image/incus-agent.service:23:Restart=on-failure
scripts/image/incus-agent.service:24:RestartSec=5s
scripts/image/xpf-day0-config.service:3:# Ordering-only coupling: Before=xpfd.service delays the daemon until
scripts/image/xpf-day0-config.service:7:# keep xpfd from starting. The script itself always exits 0;
scripts/image/xpf-day0-config.service:9:# malicious medium wedging mount), after which systemd kills the unit
scripts/image/xpf-day0-config.service:13:# loader regenerates them so sshd starts with per-instance keys.
scripts/image/xpf-day0-config.service:18:Before=xpfd.service ssh.service
scripts/image/xpf-day0-config.service:25:ExecStart=/usr/local/sbin/xpf-day0-config
scripts/image/xpf-day0-config.service:28:SyslogIdentifier=xpf-day0
scripts/image/xpf-day0-config.service:31:WantedBy=multi-user.target
scripts/image/incus-agent-setup:30:    # This will typically be true during restart in the case of a cdrom-based setup.
scripts/image/99-incus-agent.rules:5:SYMLINK=="virtio-ports/org.linuxcontainers.incus", TAG+="systemd", ENV{SYSTEMD_WANTS}+="incus-agent.service"
scripts/image/make_config_drive.py:13:Validation: if an xpfd binary is available (./xpfd or $XPFD), the config
scripts/image/make_config_drive.py:30:def find_xpfd():
scripts/image/make_config_drive.py:33:    for c in (os.environ.get("XPFD"), os.path.join(root, "xpfd"), shutil.which("xpfd")):
scripts/image/make_config_drive.py:55:        xpfd = find_xpfd()
scripts/image/make_config_drive.py:56:        if xpfd:
scripts/image/make_config_drive.py:57:            print(f"==> validating {config} with check-config ({xpfd})")
scripts/image/make_config_drive.py:59:            r = subprocess.run([xpfd, "check-config"] + nodearg + [config],
scripts/image/make_config_drive.py:65:            print("WARNING: no xpfd binary — skipping build-host validation "
scripts/image/make_config_drive.py:69:    stage = tempfile.mkdtemp(prefix="xpf-day0-")
scripts/image/bake.py:17:creates the /usr/local/sbin symlinks + enables the units via its postinst)
scripts/image/bake.py:53:    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
scripts/image/bake.py:57:    "net.core.bpf_jit_enable=1\n"
scripts/image/bake.py:194:        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
scripts/image/bake.py:196:        # enable xpfd`. The git-tracked, kernel-verified shim travels
scripts/image/bake.py:197:        # embedded inside the staged xpfd binary (#1864 contract preserved).
scripts/image/bake.py:199:        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
scripts/image/bake.py:200:        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
scripts/image/bake.py:202:        "--run-command", "chmod 0755 /usr/lib/systemd/incus-agent-setup",
scripts/image/bake.py:247:        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
scripts/image/bake.py:248:        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
scripts/image/bake.py:249:        "--run-command", "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
scripts/image/bake.py:250:        "--run-command", "systemctl enable frr chrony",
scripts/image/bake.py:254:        # present) from the local file. The postinst stages the binaries,
scripts/image/bake.py:255:        # creates the /usr/local/sbin symlinks, and enables xpfd +
scripts/image/bake.py:256:        # xpf-day0-config — so there is no separate `systemctl enable xpfd`
scripts/image/bake.py:257:        # here. systemd is not running under virt-customize, so the
scripts/image/bake.py:258:        # postinst's deb-systemd-invoke start is a harmless no-op (the units
scripts/image/bake.py:259:        # are enabled and start on the real first boot). The xpfd version
scripts/image/bake.py:268:        "--run-command", "/usr/local/sbin/xpfd version",
scripts/image/bake.py:310:            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
scripts/image/bake.py:324:        # the build-host kernel before baking it in (#1864). Verify the xpfd
scripts/image/bake.py:326:        # path), not ROOT/xpfd — under --skip-build those can diverge (a
scripts/image/bake.py:327:        # stale loose ROOT/xpfd next to a newer packaged binary), and the
scripts/image/bake.py:329:        staged_xpfd = os.path.join(work, "pregate", "usr", "local",
scripts/image/bake.py:330:                                   "share", "xpf", "staged", "xpfd")
scripts/image/bake.py:332:        if not os.access(staged_xpfd, os.X_OK):
scripts/image/bake.py:333:            die(f"package {xpf_deb} does not contain an executable staged xpfd")
scripts/image/bake.py:335:            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
scripts/image/bake.py:338:                               staged_xpfd, "verify-dataplane"]).returncode != 0:
scripts/image/bake.py:366:        run(["virt-sysprep", "-a", work_qcow, "--quiet", "--enable",
scripts/image/bake.py:370:             "/etc/xpf/.day0-config-applied /var/lib/systemd/random-seed "
scripts/image/bake.py:425:        info("deploy quickstarts: docs/install-images.md")
scripts/image/xpf-day0-config:7:# the xpf analog, run as a oneshot systemd unit ordered Before=xpfd:
scripts/image/xpf-day0-config:18:#   3. Validate with the REAL commit-check gate (`xpfd check-config`,
scripts/image/xpf-day0-config:21:#      is installed as /etc/xpf/xpf.conf; xpfd's normal
scripts/image/xpf-day0-config:25:#      bootstrap (xpfd brings up fxp0 via DHCP). This script NEVER
scripts/image/xpf-day0-config:27:#      ordering-only (Before=, no Requires=) with a start timeout.
scripts/image/xpf-day0-config:32:# `xpfd check-config`); node-id must be literally `0` or `1`; validation
scripts/image/xpf-day0-config:44:MNT=/run/xpf-day0
scripts/image/xpf-day0-config:45:XPFD=/usr/local/sbin/xpfd
scripts/image/xpf-day0-config:46:MAX_CONF_BYTES=$((4 * 1024 * 1024)) # keep in sync with xpfd check-config
scripts/image/xpf-day0-config:49:log()  { echo "xpf-day0: $*"; }
scripts/image/xpf-day0-config:50:warn() { echo "xpf-day0: WARNING: $*" >&2; }
scripts/image/xpf-day0-config:59:# boot regenerates them. This unit is Before=ssh.service so sshd starts
scripts/image/xpf-day0-config:71:# TimeoutStartSec and delay xpfd/sshd by the full backstop.
scripts/image/xpf-day0-config:108:	tmpconf=$(mktemp /run/xpf-day0-conf.XXXXXX) || {
scripts/image/xpf-day0-config:166:	# with -node-id and xpfd reads /etc/xpf/node-id before bootstrap. If this
scripts/image/xpf-day0-config:182:	log "day-0 config installed as $XPF_DIR/xpf.conf — xpfd will import and commit it at startup"
scripts/image/validate.py:7:  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
scripts/image/validate.py:8:     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
scripts/image/validate.py:87:        incus("start", name)
scripts/image/validate.py:119:    def wait_xpfd(self, name):
scripts/image/validate.py:120:        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
scripts/image/validate.py:122:                   40, 3, "xpfd not active after 120s")
scripts/image/validate.py:132:        self.wait_xpfd("xpf-image-a")
scripts/image/validate.py:147:        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
scripts/image/validate.py:163:                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
scripts/image/validate.py:172:            f.write("system {\n    host-name xpf-day0-b;\n}\n"
scripts/image/validate.py:179:        self.wait_xpfd("xpf-image-b")
scripts/image/validate.py:185:                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
scripts/image/validate.py:190:                                    '| grep -q "host-name xpf-day0-b"'),
scripts/image/validate.py:191:                   20, 3, "committed config does not show host-name xpf-day0-b")
scripts/image/validate.py:192:        if not guest_sh("xpf-image-b", '[ "$(hostname)" = xpf-day0-b ]'):
scripts/image/validate.py:195:        incus("restart", "xpf-image-b")
scripts/image/validate.py:197:        self.wait_xpfd("xpf-image-b")
scripts/image/validate.py:199:                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
scripts/image/validate.py:202:                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
scripts/image/validate.py:203:                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
scripts/image/validate.py:212:            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
scripts/image/validate.py:216:        self.wait_xpfd("xpf-image-c")
scripts/image/validate.py:218:                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
scripts/image/validate.py:225:        if not guest_sh("xpf-image-c", '[ "$(hostname)" != xpf-day0-c ]'):
debian/xpf.postinst:2:# xpf postinst (#1917 — increment A packaging + increment B cut-over hook).
debian/xpf.postinst:7:# (no previously configured version) we create those symlinks so xpfd
debian/xpf.postinst:9:# verified cut-over to the increment-B mechanism (`xpfd upgrade`):
debian/xpf.postinst:11:#  - STANDALONE node: the postinst invokes `xpfd upgrade` — the
debian/xpf.postinst:15:#    verify gate, flips atomically, and pins the unit ExecStart to the
debian/xpf.postinst:17:#  - CLUSTERED node (/etc/xpf/node-id present): STAGE-ONLY. The postinst
debian/xpf.postinst:18:#    does NOT cut — a clustered node is cut ONLY by `xpfd upgrade
debian/xpf.postinst:27:BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
debian/xpf.postinst:39:                # directory — a directory at /usr/local/sbin/xpfd would
debian/xpf.postinst:47:            # would let the running xpfd resolve a different-version helper,
debian/xpf.postinst:67:            #    The cut is driven ONLY by `xpfd upgrade --rolling` (operator
debian/xpf.postinst:73:            #    "live cluster" is a ROLLING-readiness check, not postinst
debian/xpf.postinst:82:            #    auto-cut with XPF_NO_POSTINST_CUT=1 and run `xpfd upgrade`
debian/xpf.postinst:86:                     "cut over with: xpfd upgrade --rolling" >&2
debian/xpf.postinst:89:                     "cut over with: xpfd upgrade" >&2
debian/xpf.postinst:99:                if ! "$STAGED/xpfd" upgrade; then
debian/xpf.postinst:105:                    # restarts. But a flip/daemon-reload error between STOP
debian/xpf.postinst:109:                    if ! systemctl is-active --quiet xpfd; then
debian/xpf.postinst:110:                        echo "xpf: unit not active after a failed cut-over; restarting" >&2
debian/xpf.postinst:111:                        systemctl start xpfd 2>/dev/null || \
debian/xpf.postinst:112:                            echo "xpf: WARNING could not restart xpfd; run: xpfd upgrade" >&2
debian/xpf.postinst:114:                    echo "xpf: inspect with 'journalctl -u xpfd' and re-run: xpfd upgrade" >&2
debian/xpf.postinst:124:        echo "postinst called with unknown argument \`$1'" >&2
debian/xpf.postrm:14:BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
debian/control:17: Go control plane (xpfd).
debian/control:19: This package ships the binary set (xpfd, xpf-userspace-dp, cli),
debian/control:20: the day-0 config-drive loader, and the systemd units. Binaries are
debian/control:24: and is intentionally not part of this package's postinst).
debian/control:26: The AF_XDP shim is embedded into the xpfd binary (go:embed), so no
debian/control:48: systemd-resolved,
debian/rules:5:# xpfd embeds the kernel-verified AF_XDP shim (#1864) and the helper
debian/rules:12:#   /usr/local/share/xpf/staged/{xpfd,xpf-userspace-dp,cli,xpf-day0-config}
debian/rules:17:#   The live /usr/local/sbin/{xpfd,cli,...} symlinks are created by
debian/rules:37:# Stage the systemd units into debian/ under the package-canonical
debian/rules:38:# names so dh_installsystemd finds them. The unit sources remain in
debian/rules:40:# same files); the package re-homes them at /lib/systemd/system.
debian/rules:42:# The package-owned xpfd.service gets an ExecStartPre verify-dataplane
debian/rules:45:# change or a skipped bake validation must never reach ExecStart with a
debian/rules:46:# verifier-failing shim. exit 3 = REJECT aborts the start. We inject it
debian/rules:47:# here (rather than editing test/incus/xpfd.service) so the gate ships in
debian/rules:49:# binary the gate runs is the live /usr/local/sbin/xpfd symlink.
debian/rules:52:	@# Match ExecStart tolerating leading whitespace and spaces around '='
debian/rules:53:	@# (systemd accepts those), then HARD-ASSERT the gate landed — a silent
debian/rules:56:	sed -E '/^[[:space:]]*ExecStart[[:space:]]*=/i ExecStartPre=/usr/local/sbin/xpfd verify-dataplane' \
debian/rules:57:	    test/incus/xpfd.service > debian/xpf.xpfd.service
debian/rules:58:	grep -q '^ExecStartPre=/usr/local/sbin/xpfd verify-dataplane$$' debian/xpf.xpfd.service || \
debian/rules:59:	    { echo "FATAL: ExecStartPre verify-dataplane injection failed (xpfd.service ExecStart line not matched)" >&2; exit 1; }
debian/rules:60:	cp scripts/image/xpf-day0-config.service debian/xpf.xpf-day0-config.service
debian/rules:68:	install -m 0755 xpfd              debian/xpf$(STAGED)/xpfd
debian/rules:71:	install -m 0755 scripts/image/xpf-day0-config \
debian/rules:72:	                                  debian/xpf$(STAGED)/xpf-day0-config
debian/rules:73:	install -d debian/xpf/etc/needrestart/conf.d
debian/rules:74:	install -m 0644 debian/xpf.needrestart \
debian/rules:75:	                debian/xpf/etc/needrestart/conf.d/xpf.conf
debian/rules:77:# Disable the auto-restart-on-upgrade block dh_installsystemd would
debian/rules:78:# otherwise append to postinst. A plain `apt upgrade xpf` must NOT
debian/rules:79:# cycle xpfd (a full dataplane gap); the verified cut-over is driven
debian/rules:81:# documented directive (--no-restart-on-upgrade is a deprecated alias).
debian/rules:82:# The units are still enabled on install via dh_installsystemd.
debian/rules:83:override_dh_installsystemd:
debian/rules:84:	dh_installsystemd --no-stop-on-upgrade --name=xpfd
debian/rules:85:	dh_installsystemd --no-stop-on-upgrade --name=xpf-day0-config
debian/rules:88:	rm -f debian/xpf.xpfd.service debian/xpf.xpf-day0-config.service
debian/rules:94:# maintainer scripts manage) because the appliance image, the systemd
debian/xpf.needrestart:1:# xpf (#1917 §6.3c): keep needrestart from auto-restarting xpfd.
debian/xpf.needrestart:3:# Ubuntu server installs needrestart by default; at the end of an apt
debian/xpf.needrestart:5:# auto-restarts their services. That would cut the dataplane mid-apt
debian/xpf.needrestart:6:# even though our packaging never stops xpfd on upgrade. Two defences:
debian/xpf.needrestart:8:#   1. The running xpfd binary lives under the non-dpkg runtime path
debian/xpf.needrestart:11:#      running binary is not deleted and needrestart has nothing to
debian/xpf.needrestart:13:#   2. Belt-and-braces: explicitly blacklist xpfd.service so even if a
debian/xpf.needrestart:14:#      future layout exposes a deleted-binary condition, needrestart
debian/xpf.needrestart:15:#      never restarts the dataplane. The verified cut-over is driven
debian/xpf.needrestart:17:#      needrestart.
debian/xpf.needrestart:18:$nrconf{override_rc}{qr(^xpfd\.service$)} = 0;
debian/xpf.needrestart:19:$nrconf{override_rc}{qr(^xpf-day0-config\.service$)} = 0;
debian/changelog:4:    Ships xpfd, xpf-userspace-dp, cli, the day-0 config-drive loader,
debian/changelog:5:    and the systemd units. Binaries install to a dpkg-static staging

exec
/bin/bash -lc "nl -ba debian/rules | sed -n '1,130p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
exec
/bin/bash -lc "nl -ba test/incus/xpfd.service | sed -n '1,100p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
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

 succeeded in 0ms:
     1	[Unit]
     2	Description=xpf Stateful Firewall Daemon
     3	After=network-online.target frr.service
     4	Wants=network-online.target
     5	
     6	[Service]
     7	Type=simple
     8	ExecStart=/usr/local/sbin/xpfd
     9	Restart=on-failure
    10	RestartSec=1
    11	TimeoutStopSec=20
    12	LimitMEMLOCK=infinity
    13	StandardOutput=journal
    14	StandardError=journal
    15	SyslogIdentifier=xpfd
    16	
    17	# #712 Option A retry (after #740 fix): measured on the 6-core loss
    18	# userspace lab with workers correctly pinned to CPUs 2-5 via
    19	# CPUAffinity=2 3 4 5 — no metric moved by the #712 thresholds
    20	# (rate ratio +2%, retrans +11%, per-flow CoV mean -0.6 pp, per-flow
    21	# CoV max +1.7 pp; all within run-to-run noise). The directive is
    22	# NOT shipped. See docs/cos-validation-notes.md §"CPU pinning retry
    23	# post-#740" for the dated measurement, docs/712-cpu-pinning-recipe.md
    24	# for the recipe (kept as design intent), and #739 for the kernel
    25	# cmdline (isolcpus/nohz_full) follow-up which is now the next lever
    26	# to try on this hardware.
    27	
    28	[Install]
    29	WantedBy=multi-user.target

exec
/bin/bash -lc "nl -ba scripts/image/xpf-day0-config.service | sed -n '1,80p'" in /home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist
 succeeded in 0ms:
     1	# xpf day-0 config-drive loader (#1879 Path C).
     2	#
     3	# Ordering-only coupling: Before=xpfd.service delays the daemon until
     4	# the probe finishes (so a valid day-0 config is in place before
     5	# bootstrap-from-file runs), but there is NO Requires= in either
     6	# direction — a failed or timed-out probe can never block the boot or
     7	# keep xpfd from starting. The script itself always exits 0;
     8	# TimeoutStartSec is the backstop against a pathological hang (e.g. a
     9	# malicious medium wedging mount), after which systemd kills the unit
    10	# and the boot proceeds to the factory bootstrap (fxp0 DHCP).
    11	#
    12	# Before=ssh.service: the sealed image ships without ssh host keys; the
    13	# loader regenerates them so sshd starts with per-instance keys.
    14	[Unit]
    15	Description=xpf day-0 config drive loader
    16	Documentation=https://github.com/psaab/xpf/blob/master/docs/install-images.md
    17	After=local-fs.target
    18	Before=xpfd.service ssh.service
    19	ConditionPathExists=!/etc/xpf/.day0-config-applied
    20	
    21	[Service]
    22	Type=oneshot
    23	RemainAfterExit=yes
    24	TimeoutStartSec=120
    25	ExecStart=/usr/local/sbin/xpf-day0-config
    26	StandardOutput=journal
    27	StandardError=journal
    28	SyslogIdentifier=xpf-day0
    29	
    30	[Install]
    31	WantedBy=multi-user.target

codex
Grounding note: `scripts/deploy/validate.py` does not exist in this worktree; the current validator is [scripts/image/validate.py](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/image/validate.py:1).

**R1 Check**
Your six r1 findings are mostly addressed in text, but two are only partial because the r2 additions introduce uncovered paths.

- Verify wrong bytes/path binding: r2 fixes the core algorithm: “computes its SHA256 and compares against the manifest entry” [plan.md:286](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:286). Partial: see Finding 1.
- Publish fail-closed: r2 adds a “PRECONDITION gate” and “nothing uploaded” [plan.md:358](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:358). Partial: see Finding 2.
- Retention/global SHA256SUMS: resolved by “per-version, version-named checksum manifest” [plan.md:250](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:250).
- Replay/freshness: r2 adds apt `Valid-Until` and signed `latest.json` [plan.md:382](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:382). Partial: see Finding 2.
- install.sh inline-vs-pin: resolved; r2 says “an authentic install.sh CONTAINS the apt archive key” [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:213).
- Out-of-band pubkey root: resolved; r2 says get the key via `git clone` and “NEVER from `XPF_DIST_BASE_URL`” [plan.md:222](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:222).

**Findings**
1. Major: `xpf-deploy.py` verification is specified against a path surface the deployer does not have. r2 says verification uses “the concrete `--qcow2` / `--metadata` argument paths” [plan.md:286](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:286), then says `xpf-deploy.py` verifies “before `incus image import`” [plan.md:296](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:296). Current `xpf-deploy.py` does not import Incus images; it launches an alias with `incus init ap["image"]` [xpf-deploy.py:300](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/deploy/xpf-deploy.py:300). Counter-example: an operator has a stale/tampered `xpf-appliance` Incus alias already imported; `xpf-deploy.py` has no qcow2/metadata path to hash and launches it anyway. The plan needs an explicit import/download mode or must stop claiming the existing deploy path verifies image bytes.

2. Major: the fail-closed publish gate omits the new freshness root. r2 adds “a signed, per-channel `dist/<channel>/latest.json`” [plan.md:386](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:386), but the publish gate only lists image manifests, apt `InRelease`, and `install.sh.minisig` [plan.md:360](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:360). Counter-example: `dist/stable/latest.json` is unsigned or stale, all per-version images and apt metadata verify, and `dist-publish` proceeds. That breaks the r2 anti-rollback path.

3. Major: r2 contradicts itself on the apt repo backend. It says the “Default recommendation” is “the flat signed repo” [plan.md:176](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:176) and §5.3 says “Default = the flat signed repo” [plan.md:302](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:302). Later it says “Use reprepro … rather than hand-rolled scanning” [plan.md:466](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:466) and the summary says “Apt: reprepro-built signed repo” [plan.md:517](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:517). Counter-example: OQ-1 is stateless GitHub Actions; an implementor follows §11/R3, chooses reprepro, loses `db/`, and regresses the stateless-CI finding r2 claims to fix.

4. Major: GitHub Releases is still presented as a valid full hosting target while the apt contract requires a directory tree. r2 says “GitHub Releases” can satisfy the base URL contract [plan.md:88](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:88), but install.sh writes `URIs: <XPF_DIST_BASE_URL>/apt` [plan.md:191](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:191), and r2 later admits GitHub Releases “CANNOT serve a `dists/`+`pool/` directory tree” [plan.md:315](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:315). Counter-example: user selects GitHub Releases for OQ-1; apt fetches `/apt/dists/stable/InRelease` and gets no valid repo. Split image/install and apt base URLs or remove GitHub Releases as a full target.

5. Major: install.sh overpromises “fresh Debian/Ubuntu host” while kernel/OS support is explicitly out of scope. r2 promises one-command `apt install xpf-appliance` on “a fresh Debian/Ubuntu host” [plan.md:84](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:84), but existing docs say the appliance image’s dependency closure includes “a >= 6.18 kernel” [install-images.md:4](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/install-images.md:4), while `debian/control` says kernel handling is “out of scope” [control:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:66). Counter-example: Debian 12 or Ubuntu 24.04 host runs install.sh; packages install, but the service’s verifier floor rejects the host kernel. The plan needs a preflight/scope restriction or must stop claiming fresh-host appliance bootstrap.

Nits: §6 still says byte-flip failure happens at `sha256sum -c` [plan.md:402](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:402), which conflicts with the new parsed-hash verifier; [plan.md:528](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:528) has a stray code fence.

PLAN-NEEDS-MAJOR — r2 fixes the named trust-root and per-file manifest problems in prose, but the plan is not implementation-ready: the deployer verification path cannot bind bytes for the current Incus alias flow, the new freshness pointer is not covered by fail-closed publish, the apt backend and GitHub Releases contracts contradict themselves, and install.sh claims a fresh-host bootstrap that the package/kernel contract does not support.
tokens used
115,268
Grounding note: `scripts/deploy/validate.py` does not exist in this worktree; the current validator is [scripts/image/validate.py](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/image/validate.py:1).

**R1 Check**
Your six r1 findings are mostly addressed in text, but two are only partial because the r2 additions introduce uncovered paths.

- Verify wrong bytes/path binding: r2 fixes the core algorithm: “computes its SHA256 and compares against the manifest entry” [plan.md:286](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:286). Partial: see Finding 1.
- Publish fail-closed: r2 adds a “PRECONDITION gate” and “nothing uploaded” [plan.md:358](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:358). Partial: see Finding 2.
- Retention/global SHA256SUMS: resolved by “per-version, version-named checksum manifest” [plan.md:250](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:250).
- Replay/freshness: r2 adds apt `Valid-Until` and signed `latest.json` [plan.md:382](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:382). Partial: see Finding 2.
- install.sh inline-vs-pin: resolved; r2 says “an authentic install.sh CONTAINS the apt archive key” [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:213).
- Out-of-band pubkey root: resolved; r2 says get the key via `git clone` and “NEVER from `XPF_DIST_BASE_URL`” [plan.md:222](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:222).

**Findings**
1. Major: `xpf-deploy.py` verification is specified against a path surface the deployer does not have. r2 says verification uses “the concrete `--qcow2` / `--metadata` argument paths” [plan.md:286](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:286), then says `xpf-deploy.py` verifies “before `incus image import`” [plan.md:296](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:296). Current `xpf-deploy.py` does not import Incus images; it launches an alias with `incus init ap["image"]` [xpf-deploy.py:300](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/scripts/deploy/xpf-deploy.py:300). Counter-example: an operator has a stale/tampered `xpf-appliance` Incus alias already imported; `xpf-deploy.py` has no qcow2/metadata path to hash and launches it anyway. The plan needs an explicit import/download mode or must stop claiming the existing deploy path verifies image bytes.

2. Major: the fail-closed publish gate omits the new freshness root. r2 adds “a signed, per-channel `dist/<channel>/latest.json`” [plan.md:386](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:386), but the publish gate only lists image manifests, apt `InRelease`, and `install.sh.minisig` [plan.md:360](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:360). Counter-example: `dist/stable/latest.json` is unsigned or stale, all per-version images and apt metadata verify, and `dist-publish` proceeds. That breaks the r2 anti-rollback path.

3. Major: r2 contradicts itself on the apt repo backend. It says the “Default recommendation” is “the flat signed repo” [plan.md:176](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:176) and §5.3 says “Default = the flat signed repo” [plan.md:302](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:302). Later it says “Use reprepro … rather than hand-rolled scanning” [plan.md:466](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:466) and the summary says “Apt: reprepro-built signed repo” [plan.md:517](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:517). Counter-example: OQ-1 is stateless GitHub Actions; an implementor follows §11/R3, chooses reprepro, loses `db/`, and regresses the stateless-CI finding r2 claims to fix.

4. Major: GitHub Releases is still presented as a valid full hosting target while the apt contract requires a directory tree. r2 says “GitHub Releases” can satisfy the base URL contract [plan.md:88](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:88), but install.sh writes `URIs: <XPF_DIST_BASE_URL>/apt` [plan.md:191](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:191), and r2 later admits GitHub Releases “CANNOT serve a `dists/`+`pool/` directory tree” [plan.md:315](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:315). Counter-example: user selects GitHub Releases for OQ-1; apt fetches `/apt/dists/stable/InRelease` and gets no valid repo. Split image/install and apt base URLs or remove GitHub Releases as a full target.

5. Major: install.sh overpromises “fresh Debian/Ubuntu host” while kernel/OS support is explicitly out of scope. r2 promises one-command `apt install xpf-appliance` on “a fresh Debian/Ubuntu host” [plan.md:84](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:84), but existing docs say the appliance image’s dependency closure includes “a >= 6.18 kernel” [install-images.md:4](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/install-images.md:4), while `debian/control` says kernel handling is “out of scope” [control:66](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/debian/control:66). Counter-example: Debian 12 or Ubuntu 24.04 host runs install.sh; packages install, but the service’s verifier floor rejects the host kernel. The plan needs a preflight/scope restriction or must stop claiming fresh-host appliance bootstrap.

Nits: §6 still says byte-flip failure happens at `sha256sum -c` [plan.md:402](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:402), which conflicts with the new parsed-hash verifier; [plan.md:528](/home/ps/git/bpfrx/.claude/worktrees/1924-research-signed-hosted-dist/docs/research/1924-signed-hosted-dist/plan.md:528) has a stray code fence.

PLAN-NEEDS-MAJOR — r2 fixes the named trust-root and per-file manifest problems in prose, but the plan is not implementation-ready: the deployer verification path cannot bind bytes for the current Incus alias flow, the new freshness pointer is not covered by fail-closed publish, the apt backend and GitHub Releases contracts contradict themselves, and install.sh claims a fresh-host bootstrap that the package/kernel contract does not support.
