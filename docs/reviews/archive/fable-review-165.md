# fable-review-165 — Day-0 Setup Coverage Campaign

**Focus:** day-0 setup, end to end — image bake (qcow2), libvirt + incus deploy,
day-0 config drive, first boot, signed distribution / install.sh, Go-side
bootstrap (interface naming, config import), bare-metal device-map, and the
boot-substrate units (grow-root, A/B UEFI kernel slots, day-0 loader).
Goal per operator directive: make day-0 "super easy" — every finding is a
remediation item toward that.

## 1. Base commit reviewed

`d70851156` — "Merge pull request #4145 from psaab/fix/3888-nat64-fail-scoped"
(tip of `origin/master` at review time).

Note on the mandated `git pull --rebase`: the primary checkout has a stale
unmerged index entry (`UU _Log.md`, leftover conflict markers), which makes
`git pull --rebase` refuse to run; resolving the operator's in-progress
conflict would exceed the permitted mutation. The review therefore ran against
a detached read-only worktree of freshly-fetched `origin/master` (107 commits
ahead of the local HEAD), which satisfies the intent (review current code, no
repo mutation). The worktree is removed after the campaign.

## 2. Output path

`/tmp/fable-review-165.md` (highest existing campaign number was 164;
`fable` already has a 164 file, so this campaign takes 165).

## 3. Duplicate suppression summary

Read for dedup: all `/tmp/codex-review-*.md` (001–163), `/tmp/agy-review-*.md`
(149–152 + earlier), `/tmp/fable-review-{161,163,164}.md`, plus repo docs
(`docs/install-images.md`, `docs/deploy-quickstart.md`, `docs/distribution.md`,
`docs/image-validation.md`, `docs/bare-metal-device-map.md`,
`examples/deploy/README.md`, `README.md`, `CLAUDE.md`) and the full GitHub
issue history around day-0 (`gh issue list/view` sweeps for day0, bake, image,
qcow2, libvirt, config drive, bootstrap, device-map, install, ZTP).

**Suppressed as prior campaign findings (fable-review-161):**
- F-092 sign-before-validate in bake.py (since FIXED on master via #4017).
- F-256 `--skip-build` manifest provenance (stale deb vs bake-time HEAD).
- F-257 Ubuntu base image SHA256SUMS fetched without GPG verification.
- F-216 device-map `deriveKernelName`/`pciAddrToEnp` name-shape gaps.
- F-227 `InstallCandidateKernel` dead `/lib/modules` stat.
- F-222 `FindExternallyManaged` only matches `Name=`-keyed `.network` files.
- F-247 `IfInfo::from_ifindex` `i8` portability.
- F-015 transfer-on-commit archives the stale day-0 `xpf.conf` (also #3867, fixed).
- F-093/F-090/F-091/F-149 (cluster deploy/test-infra/build provenance).
- fable-163 F6 / fable-164 M-5 (DHCPv4 `/0` mask on fxp0 bootstrap).

**Suppressed as known/deferred tracker items (not re-reported as novel):**
- #1924 signed-distribution go-live pending operator inputs (keys, URLs) —
  placeholder keys fail closed by design.
- #1926 baked image never proven to FORWARD on a real NIC venue (virtio is
  not a forwarding venue, #1963).
- #1925 Item 2 HA image-replace rehearsal + grown-disk lab validation.
- #1958 Slices B/C container substrate / platform-profile (deferred design).
- #1956 §9.6 no auto-fxp0 / no bootstrap DHCP in device-map mode (deliberate).
- #4056 secrets at 0644 in rollback/archive/rescue files (open issue).
- #2008 vSRX config-parity catalog.

Every finding below carries its own dedup note against this baseline.

## 4. Module checklist (18 modules)

| # | Module | Findings |
|---|--------|----------|
| 1 | `scripts/image/bake.py` (image bake pipeline) | MINE-1 (package closure); prior findings suppressed |
| 2 | `scripts/image/xpf-day0-config` + `.service` (day-0 loader) | GO-1, SUB-7 |
| 3 | `scripts/image/make_config_drive.py` | negative (clean); minor note in MINE-3 |
| 4 | `scripts/image/validate.py` (validation gate) | MINE-2 |
| 5 | `scripts/image/xpf-grow-root` (+unit, self-test) | SUB-5, SUB-8 |
| 6 | `scripts/image/xpf-uefi-slots`, `xpf-kernel-promote` (+units), `grub.d/09_xpf` | SUB-1..SUB-4, SUB-9, SUB-10 |
| 7 | `scripts/image/incus-agent-setup` (+unit/rules) | negative (verified inert under libvirt) |
| 8 | `scripts/deploy/xpf-deploy.py` (incus/libvirt deployer, fetch, rolls) | H-20..H-39, M-12, L-4..L-10 |
| 9 | `examples/deploy/*` (shipped definitions) | H-22, H-28, H-29, L-9 |
| 10 | `scripts/dist/*` (install.sh, publish.py, sign.py, build-apt-repo.sh, selftest.sh) | DIST-1..DIST-14 |
| 11 | `debian/` (control, rules, maintainer scripts — the install vehicle) | DIST-7, SUB-1, MINE-1 |
| 12 | `pkg/daemon/linksetup.go` (first-boot naming, bootstrap fxp0) | GO-2 |
| 13 | `pkg/daemon` bootstrap import path + `check-config` | GO-1, GO-3, GO-6, GO-7 |
| 14 | `pkg/daemon/device_map.go` + `pkg/devicemap` + doc | GO-3, GO-8 |
| 15 | `pkg/upgrade/runtime` (seed-runtime) | negative (clean) |
| 16 | `pkg/frr` reload dependency posture on the appliance | MINE-1 |
| 17 | Docs: install-images, deploy-quickstart, distribution, image-validation, bare-metal-device-map, examples README, README | GO-8, DIST-1, DIST-6; else clean |
| 18 | Makefile `image`/`deb`/`dist-*` targets | DIST-3, SUB-6, DIST-10 |

## 5. Module-by-module inspection log

1. **bake.py** — read in full (714 lines). The pipeline is heavily hardened
   (kernel hold with per-package verify, single-kernel assert, growpart
   assert, validate-before-sign via `finalize_artifacts`, cache re-verify).
   One novel defect: the runtime package closure omits `frr-pythontools`
   (MINE-1). Prior findings (base-image GPG, --skip-build provenance)
   suppressed.
2. **xpf-day0-config** — read in full (232 lines). Security posture is
   genuinely careful (ro/nosuid/nodev/noexec mount under timeout, copy-once
   then validate then install, node-id before stamp). Two defects: the
   `.configdb` guard is defeated by the daemon's eager DB-dir creation
   (GO-1, the campaign's top finding) and ssh host-key regen shares the
   config stamp's condition gate (SUB-7).
3. **make_config_drive.py** — read in full (104 lines). Clean: validates via
   real check-config when an xpfd binary is present, refuses bad configs,
   safe staging. (ISO carries `xpf.conf` 0644 by design; the installed copy
   is 0600 — noted under MINE-3's channel discussion, not a finding.)
4. **validate.py** — read in full (444 lines). Scenarios a–d are real and
   assert the right invariants (sshd -T posture, single kernel, grow
   idempotency, ESP intact). Gaps: incus-only (no libvirt/QEMU boot leg),
   no cluster node-id scenario, no reject-then-fix-then-reboot retry
   scenario — which is exactly why GO-1 shipped (MINE-2).
5. **xpf-grow-root** — reviewed + its self-test executed (35/35 pass).
   Stamp discipline and bus-agnostic device resolution are solid. Residual:
   stamps success on a growpart-CHANGED/kernel-not-resized partial (SUB-5);
   structurally unsupported layouts retry forever (SUB-8).
6. **UEFI slots / kernel promote / 09_xpf** — read in full; promote gate's Go
   fast path cross-checked (`pkg/upgrade/kernel_run.go`, `lock.go`). The
   .deb omits the OnFailure recovery unit (SUB-1); two NVRAM writers race
   (SUB-2); NVRAM wipe silently reseeds the old kernel slot (SUB-3);
   OnFailure trigger set wider than its loop-safety argument (SUB-4);
   20s timeout vs ~12-15 serial efibootmgr calls (SUB-9); `After=xpfd`
   readiness is exec-time not dataplane-ready (SUB-10). 09_xpf itself and
   BIOS fallback are clean.
7. **incus-agent loader** — verified inert outside incus: udev rule keys on
   the incus-specific virtio-port symlink; unit has no [Install]; libvirt
   guests unaffected. Negative result.
8. **xpf-deploy.py + examples** — read in full (1348 lines) + all six
   example YAMLs and both confs; pure functions and argparse behavior
   exercised by execution. Negative results worth recording: the
   config-drive contract (label, filenames, node-id) is consistent across
   all four tools; `sign.verify_image_artifact` fetch-verification core is
   sound; the lease machinery (flock, atomic write, holder-guarded release,
   per-element quoting) has no injection or format bug; no `shell=True`
   anywhere; the docs' position→name tables match `expected_name()` and
   `assignName()` exactly including node-1 FPC 7; the bare-YAML
   `xpf-deploy.py a.yaml b.yaml` shorthand in the quickstart is valid
   (verified against the command peeling). Findings H-20..H-39, M-12,
   L-4..L-10.
9. **scripts/dist** — read in full; `install.sh` dry-run executed, unit-file
   probe semantics verified live. Cryptographic core (sign.py) is strong,
   fail-closed, TOCTOU-aware. The day-0 promise breaks around it: DIST-1
   (one-liner cannot run), DIST-2 (channel bleed), DIST-3 (unsigned debs
   ride the publish tree), DIST-4 (auto-start seizes interfaces before the
   caveat prints), DIST-5..14.
10. **debian/** — maintainer scripts carefully reasoned, no new correctness
    bug found in them (they remain untested by any harness, DIST-10);
    metapackage misses `systemd-networkd` (DIST-7) and `frr-pythontools`
    (MINE-1); rules omits the promote-failed unit (SUB-1).
11. **linksetup.go** — bootstrap fxp0 `.network` (DHCP=yes, dual-stack) is
    fine. The positional rename loop lacks the collision discipline the
    device-map path has; `.link` OriginalName chain corrupts on enumeration
    shift (GO-2).
12. **bootstrap import path** — `CheckText` and the commit compile pipeline
    are the same function (verified negative for compile drift). Divergences
    found at the daemon-extras layer: device-map preflight not run at
    check-config/bootstrap (GO-3); HA empty-takeover naming (GO-4); dual
    node-identity SSOT (GO-5); bootstrap state invisible in-band (GO-6);
    misleading factory-boot WARN (GO-7).
13. **device-map** — startup decision + rollback-to-bootstrap well tested;
    doc bug: `commit check` documented as confirming a `commit confirmed`
    (GO-8).
14. **pkg/upgrade/runtime seed** — idempotent, crash-safe, tested. Negative.
15. **pkg/frr reload posture** — primary reload is `frr-reload.py`; fallback
    additive `vtysh -f`; degraded-retry ALSO requires frr-reload.py, so a
    box without frr-pythontools never converges stale-config removal
    (MINE-1 impact chain, verified at `pkg/frr/manager.go:641-661,824`).
16. **Docs** — deploy-quickstart's bare-YAML HA invocation verified valid
    (deployer defaults to `deploy`; negative result). distribution.md's
    Tier-A one-liner contradicts install.sh's hard requirement (DIST-1);
    runbook dead-ends at the placeholder gate (DIST-6); device-map doc
    confirm error (GO-8).
17. **Makefile** — `image`/`deb`/`dist-*` present; none of the image/dist
    self-tests are reachable from `make test` (SUB-6, DIST-10); `DEB_OUT`
    defaults inside the publish root (DIST-3).
18. **examples/deploy** — see DEP-*.

Confidence tiers below: **High** = directly evidenced in code read during this
run (and the top items re-verified line-by-line by the coordinating
reviewer); **Medium** = likely bug or incomplete behavior needing runtime
validation; **Low** = design smell / parity gap worth issue triage.

---

## 6. Findings — HIGH CONFIDENCE

### H-1. Day-0 config-drive retry is permanently dead: xpfd creates `.configdb` on every start and the loader reads bare existence as "already configured"

- **Title:** Eager `.configdb` directory creation defeats the day-0 loader's
  fix-and-reboot retry contract
- **Severity:** High
- **Confidence:** High (both sides verified line-by-line)
- **Evidence:** `scripts/image/xpf-day0-config:194-196`:
  ```bash
  if [ -e "$XPF_DIR/.configdb" ]; then
      log "configstore DB exists — system already configured, skipping day-0 probe"
      return 0
  ```
  vs the loader's own contract (`xpf-day0-config:35-38`): "a medium that
  fails validation does NOT write the stamp, so the operator can fix the
  config and reboot — the system is still unconfigured". But
  `pkg/configstore/db.go:36-51`:
  ```go
  // NewDB creates a DB rooted at the given directory.
  // The directory is created if it doesn't exist.
  func NewDB(dir string) (*DB, error) {
      ...
      if err := fsatomic.MkdirAllDurable(dir, 0700); err != nil {
          return nil, fmt.Errorf("create db dir: %w", err)
      }
  ```
  `NewDB` is called from `configstore.New` (`pkg/configstore/store.go:176`),
  called from `daemon.New` (`pkg/daemon/daemon.go:714`) — i.e. on **every**
  xpfd start, before any commit. `docs/install-images.md` §First-boot
  contract advertises: "A REJECTED medium does not stamp — fix the config
  and reboot to retry while the system is still factory-default."
- **Trace:**
  1. First boot with a config drive whose config has a typo. Loader
     correctly REJECTS, does not stamp (retriable by design).
  2. Boot proceeds; xpfd starts factory bootstrap; `daemon.New` →
     `configstore.New` → `NewDB` durably creates `/etc/xpf/.configdb`.
  3. Operator fixes the config, rebuilds the ISO, reboots — exactly what
     `docs/install-images.md` Recovery says to do.
  4. Loader hits `[ -e .configdb ]` → logs "system already configured"
     (false — the box is factory-default in bootstrap mode) → never probes
     the medium again. Same for "boot once to look around, then attach the
     drive and reboot."
- **Why it matters:** this kills the single most important day-0 recovery
  loop, with an actively misleading log line. The only escape is knowing to
  delete `.configdb` or hand-copy `xpf.conf` — the opposite of easy day-0.
  `validate.py` scenario C tests reject-within-one-boot only, so the bake
  gate structurally cannot catch it (see H-9/MINE-2).
- **Fix direction:** guard on the committed artifact, not the directory:
  test `/etc/xpf/.configdb/active.json` (or an explicit `EverCommitted`
  marker / `xpfd config-state` probe) in `xpf-day0-config`. Script-side fix
  is smallest and version-skew-safe. Add a validate.py scenario:
  reject → fix ISO → reboot → assert applied.
- **Labels:** bug, day-0, first-boot, image
- **Dedup note:** no prior campaign finding or issue touches the
  `.configdb`-existence guard; #1893 (nil-DB panic) and #1922 (boot classes)
  are adjacent but neither covers the loader's guard being invalidated by
  eager dir creation.

### H-2. The documented Tier-A one-liner install cannot succeed — `install.sh` hard-requires `XPF_APT_BASE_URL`, which the pipe never delivers

- **Title:** `curl … install.sh | sh` fails 100% as documented; no publish-time
  substitution point exists for the apt base URL
- **Severity:** High
- **Confidence:** High (dry-run executed: dies `XPF_APT_BASE_URL is required`)
- **Evidence:** `scripts/dist/install.sh:130-132`:
  ```sh
  write_source() {
      [ -n "${XPF_APT_BASE_URL:-}" ] || die "XPF_APT_BASE_URL is required \
  (the apt repo base URL — a dists/+pool/ directory host). Set it and re-run."
  ```
  vs `docs/distribution.md:124-126`:
  ```
  ### Install (Tier A — one-liner)
  curl -fsSL https://dl.example.com/xpf/install.sh | sh
  ```
  The release build substitutes the archive **key** into install.sh
  (`install.sh:26-30`, gated by `publish.py:196-200`) but there is no
  substitution marker or gate for the apt base URL.
- **Trace:**
  1. Operator runs the documented one-liner. `main` → `preflight` OK →
     `install_keyring` writes the keyring → `write_source` dies.
  2. `XPF_APT_BASE_URL=… curl … | sh` also fails — the env prefix binds to
     `curl`, not the `sh` right of the pipe.
  3. The documented line also omits `sudo`; a non-root run dies at the
     root check before that.
- **Why it matters:** this is the flagship "easy path" of the distribution
  story, and it is structurally incapable of one-command install — and it
  fails *after* mutating the host (keyring installed; see H-16).
- **Fix direction:** bake `XPF_APT_BASE_URL` + default channel into
  install.sh at publish time exactly like the key (`%%MARKER%%` +
  publish-gate refusal on unsubstituted marker); fix the doc one-liner to
  `curl -fsSL … | sudo sh`.
- **Labels:** bug, day-0, distribution, docs
- **Dedup note:** #1924 is open for "operator inputs" (keys + hosting URL) —
  but that issue covers *choosing* the URL, not the fact that the installer
  has no mechanism to receive it in a piped run and no publish gate for it;
  no prior campaign finding covers install.sh.

### H-3. The baked appliance cannot ever run `frr-reload.py`: `frr-pythontools` is missing from the image and the metapackage — FRR reload is permanently degraded, stale-config removal never converges

- **Title:** `RUNTIME_PACKAGES` and `xpf-appliance` Depends omit
  `frr-pythontools`, so every appliance FRR reload takes the additive
  `vtysh -f` fallback and the degraded-retry loop can never converge
- **Severity:** High
- **Confidence:** High (all four links verified line-by-line)
- **Evidence:** `scripts/image/bake.py:57-72` (`RUNTIME_PACKAGES` — has
  `"frr"`, no `frr-pythontools`); `debian/control:41` (metapackage Depends —
  `frr,` only). The daemon's primary reload is `frr-reload.py`
  (`pkg/frr/manager.go:641-644`) with an explicit missing-classifier:
  ```go
  if isFrrReloadPyMissing(perr) {
      m.warnPytoolsOnce(perr)
  ...
  slog.Warn("FRR config loaded via additive vtysh -f (degraded: stale-config removal deferred to retry)")
  ```
  and the retry that is supposed to converge stale-config removal ALSO
  requires the script (`manager.go:824`):
  ```go
  if err := m.executor().FrrReloadPy(rctx, m.frrConf); err != nil {
      nf := isFrrReloadPyMissing(err)
  ```
  Meanwhile the dev/test cluster installs it explicitly
  (`test/incus/cluster-setup.sh:452`: `... frr frr-pythontools ...`) — so
  every environment the routing stack is validated in HAS the tool, and the
  shipped appliance does NOT.
- **Trace:**
  1. Deploy the baked image; commit a config with static routes/BGP.
  2. First reload: `frr-reload.py` ENOENT → warn-once → additive `vtysh -f`
     applies desired lines; commit succeeds (degraded).
  3. Operator deletes a static route / BGP neighbor and commits: additive
     load cannot remove it; the degraded-retry loop re-execs the missing
     script forever — the stale route keeps forwarding/advertising until
     FRR is restarted by hand.
- **Why it matters:** on a router, "deleted route still active" is a
  correctness and security defect (traffic follows a route the operator
  removed), present on every image-based install from its first routing
  commit, and invisible except for one journald warning. It is also a
  test-environment divergence: the appliance's real reload path is the one
  combination never exercised.
- **Fix direction:** add `frr-pythontools` to `RUNTIME_PACKAGES` and the
  `xpf-appliance` Depends (the comment in bake.py already mandates keeping
  them in sync); add a bake-time assert (`test -x /usr/lib/frr/frr-reload.py`
  like the growpart assert) and a validate.py check.
- **Labels:** bug, day-0, image, routing, packaging
- **Dedup note:** no prior campaign finding or tracker issue mentions
  frr-pythontools or the appliance reload posture; #1880 (frr-reload.py
  direct-exec) and its tests explicitly model the missing-tool case as a
  *degraded* mode but nothing tracks that the shipped image is permanently
  in it.

### H-4. Apt channel isolation silently does not exist: one shared pool is re-indexed into whichever suite is rebuilt

- **Title:** `build-apt-repo.sh` pools all debs channel-agnostically and
  generates each suite's `Packages` by scanning the whole pool — edge
  builds become installable (signed) from stable
- **Severity:** High
- **Confidence:** High (verified: `POOL="$APT/pool/$COMPONENT/x/xpf"` has no
  suite component; `apt-ftparchive packages "pool/$COMPONENT"` at :117)
- **Evidence:** `scripts/dist/build-apt-repo.sh:62-64,110,117`:
  ```sh
  POOL="$APT/pool/$COMPONENT/x/xpf"
  DISTDIR="$APT/dists/$SUITE/$COMPONENT/binary-$ARCH"
  ...
  cp -f "$d" "$POOL/"
  ...
  ( cd "$APT" && apt-ftparchive packages "pool/$COMPONENT" > "dists/$SUITE/..." )
  ```
- **Trace:**
  1. Publish stable `xpf 0.0.5000`; later publish edge `0.0.5100` — same
     pool accumulates both.
  2. Next stable rebuild/re-sign scans the pool → stable's Packages lists
     `0.0.5100`; InRelease signs it; `publish.py gate_apt` verifies
     signatures per suite → passes (the bleed is signed and valid).
  3. Every stable host's `apt upgrade` pulls the edge build; the standalone
     postinst then auto-cuts the dataplane to it.
- **Why it matters:** the stable/edge split is the operator's only
  blast-radius control for the day-0/day-2 package path; it silently
  collapses in exactly the layout publish.py expects (both suites under one
  tree).
- **Fix direction:** per-suite pool (`pool/$SUITE/$COMPONENT/…`) or generate
  `Packages` from the `--debs` list; add a selftest building both suites in
  one tree asserting suite isolation.
- **Labels:** bug, distribution, security
- **Dedup note:** no prior finding or issue covers the apt tree layout;
  #1924's open scope is keys/hosting, not repo-builder logic.

### H-5. The "fail-closed" publish gate uploads unsigned executables: `dist/deb/*.deb` and any non-image file ride the image tree unchecked

- **Title:** `publish.py gate_images` sweeps only `.qcow2`/`.incus-metadata.tar.gz`
  suffixes while `make deb` drops unsigned debs inside the publish root
- **Severity:** High
- **Confidence:** High (verified `IMAGE_ARTIFACT_SUFFIXES` at publish.py:77,
  the `continue` at :177, and `DEB_OUT ?= $(CURDIR)/dist/deb` at Makefile:414)
- **Evidence:** `scripts/dist/publish.py:77`:
  ```python
  IMAGE_ARTIFACT_SUFFIXES = (".qcow2", ".incus-metadata.tar.gz")
  ```
  and :171-178: any file not ending in those suffixes is skipped by the
  orphan sweep; `dispatch()` then uploads the whole `dist` tree.
  `Makefile:414`: `DEB_OUT ?= $(CURDIR)/dist/deb`.
- **Trace:** `make deb` → unsigned `dist/deb/xpf_*.deb`; `make image` →
  signed image set; `make dist-publish` → gate passes; rsync/S3 shim
  publishes the unsigned debs (and any stray file) to the image URL.
- **Why it matters:** the module's stated contract ("refuses to publish …
  unless every artifact in the publish set is properly signed") is what an
  operator trusts; a user who fetches the conveniently-hosted deb installs
  bytes no signature covered.
- **Fix direction:** default-deny sweep — every file must be manifest-covered
  or on an explicit allowlist (`*.SHA256SUMS`, `*.minisig`, `install.sh`,
  `latest.json`, `xpf-image.pub`); stop defaulting `DEB_OUT` into the
  publish root.
- **Labels:** bug, distribution, security
- **Dedup note:** the orphan sweep itself was added for Codex-r2-1 (per the
  in-code comment) but its suffix-shaped scope and the DEB_OUT interaction
  are unreported anywhere.

### H-6. The `.deb` ships `xpf-kernel-promote.service` but not its `OnFailure=` recovery unit — hang recovery is a dangling reference on every deb-installed host

- **Title:** `debian/rules` never stages `xpf-kernel-promote-failed.service`
  though the promote unit references it and the rules comment promises the
  full A4 substrate in the deb
- **Severity:** High
- **Confidence:** High (verified: `grep promote debian/rules` shows only the
  main unit at :72,:139; `xpf-kernel-promote.service:18` has
  `OnFailure=xpf-kernel-promote-failed.service`; bake.py:375 installs the
  failed unit into the image only)
- **Evidence:** `scripts/image/xpf-kernel-promote.service:18`:
  ```
  OnFailure=xpf-kernel-promote-failed.service
  ```
  `debian/rules:71-72` stages only `xpf-uefi-slots.service` and
  `xpf-kernel-promote.service`.
- **Trace:** foreign-host `apt install xpf` → operator runs
  `xpfd upgrade kernel arm` → candidate trial boot hangs the gate →
  `TimeoutStartSec=120` fails the unit → systemd cannot find the OnFailure
  unit ("Unit not found") → **no recovery reboot**; the node sits on the
  unverified candidate held SECONDARY indefinitely — the exact r2 AGY
  Finding 3 scenario the unit exists to prevent.
- **Why it matters:** the deb-install substrate silently lacks the
  hang-recovery half of the LANE-1 channel; it only manifests during a hung
  kernel upgrade — the worst possible time.
- **Fix direction:** stage the failed unit in `debian/rules` (no
  `dh_installsystemd` enable needed — it correctly has no `[Install]`);
  add a bake↔deb unit-parity assert.
- **Labels:** bug, packaging, kernel-channel, HA
- **Dedup note:** #1930 and its AGY review rounds designed the OnFailure
  unit; no issue or prior finding covers its absence from the deb.

### H-7. Positional rename loop corrupts the `.link` `OriginalName=` chain on enumeration shift (no collision discipline, unlike device-map mode)

- **Title:** `enumerateAndRenameInterfaces` writes/overwrites `.link` files
  mid-loop and re-reads them via `recoverOriginalName`, so an added NIC at a
  lower PCI address scrambles the persistent rename database and part-renames
  interfaces for a boot
- **Severity:** Medium (bounded: converges on the second reboot; but the
  intervening boot can swap port↔zone bindings on a firewall)
- **Confidence:** High (code-trace verified; not executed)
- **Evidence:** `pkg/daemon/linksetup.go:82-106` — per-index
  `writeLinkFile(target, recoverOriginalName(nic.name))` then
  `renameInterface`, where `recoverOriginalName` (:242-273) reads the
  just-overwritten files of earlier iterations and `renameInterface` EEXIST
  failures are warn-and-continue. The device-map path explicitly solved
  this (phase-1 temp-rename collision break, originals captured before any
  write — `device_map.go:166-221`); positional mode never inherited it.
- **Trace:** prior boot A→fxp0, B→ge-0-0-0; add NIC C at a lower bus;
  reboot; enumeration is C,A,B. idx0 overwrites `10-xpf-fxp0.link` with
  C's original, rename C→fxp0 EEXIST (A holds it); idx1 recovers the WRONG
  original from the corrupted file and clobbers B's record; end state:
  three `.link` files claiming the same OriginalName, interfaces one slot
  off for this boot.
- **Why it matters:** adding a virtio NIC to a VM is routine day-0/day-1
  activity; the default (positional) mode should degrade predictably, not
  corrupt persistent naming state and shift security zones for a boot.
- **Fix direction:** two-pass the positional loop like
  `enumerateAndRenameMapped`: compute targets, snapshot ALL originals before
  any write, temp-rename occupants, then write `.link` files.
- **Labels:** bug, first-boot, interfaces
- **Dedup note:** fable-161 F-216 covered device-map *name derivation*
  shapes; the positional-loop collision/corruption is distinct and
  unreported; deploy-quickstart documents "an interface added between
  deploys changes order" but not the `.link`-corruption/EEXIST mechanics.

### H-8. Day-0 gate is weaker than an interactive commit: `check-config` and `bootstrapFromFile` skip the device-map strand-management preflight

- **Title:** a bare-metal day-0 config that would be REJECTED interactively
  (management-stranding device-map) passes check-config and commits at first
  boot, yielding a console-only box
- **Severity:** Medium
- **Confidence:** High
- **Evidence:** preflight only on interactive paths
  (`pkg/daemon/daemon_apply.go:196,367`
  `d.deviceMapCommitPreflight(cand, nil)`); the day-0 import is a raw store
  commit (`daemon_apply.go:56-76`: EnterConfigure → LoadOverride → Commit);
  `configstore.CheckText` (`pkg/configstore/check.go:26-36`) is
  parse+schema+compile only, while its own doc-comment claims it is "the
  exact gate sequence every operator commit goes through".
- **Trace:** operator fat-fingers the mgmt PCI BDF in `chassis device-map`
  on the day-0 drive → `xpfd check-config` on the target box PASSES →
  installed → `bootstrapFromFile` commits without preflight →
  `applyStartupNamingPolicy` leaves mgmt UNBOUND; §9.6 means no auto-fxp0
  fallback in device-map mode → console-only from the very first boot —
  the exact lockout `deviceMapCommitPreflight` exists to prevent.
- **Why it matters:** bare-metal day-0 is where a lockout is most expensive,
  and both check sites RUN ON THE TARGET HARDWARE (the NIC inventory is
  available) — the stronger check is feasible exactly where it matters.
- **Fix direction:** run `deviceMapStrandsManagement` (pure given
  `EnumeratePresentNICs()`) in `check-config` (hard FAIL) and in
  `bootstrapFromFile` (at minimum loud error); surface per-entry
  UNBOUND counts in check-config output.
- **Labels:** bug, day-0, bare-metal, device-map
- **Dedup note:** #1956 built the preflight for interactive commits and its
  §9.6 console-lifeline stance is deliberate and suppressed; the *gate
  asymmetry* (day-0 bypasses the preflight) is unreported.

### H-9. Image validation gate: no libvirt/QEMU leg, no cluster node-id scenario, no reject-fix-reboot retry scenario

- **Title:** `validate.py` proves first boot under incus only; the libvirt
  quickstart path, the `node-id` day-0 drive path, and the loader's
  advertised retry loop are never exercised by the bake gate
- **Severity:** Medium (test coverage)
- **Confidence:** High (scenarios a–d read in full; all use `incus init`)
- **Evidence:** `scripts/image/validate.py:131-147` (`launch()` is
  incus-only); scenarios a–d never pass `-n/--node-id` to
  `make_config_drive.build_config_drive` (:235-237, :272-274); scenario C
  ends at reject (no fix+reboot leg, :267-287). `docs/install-images.md`
  sells the same qcow2 for "libvirt/KVM, plain QEMU … boots UEFI or BIOS"
  and documents the retry contract the gate never tests.
- **Trace:** a bake regression breaking only the libvirt path (e.g. BIOS
  boot, virtio-scsi vs blk, cdrom day-0 attach semantics), or the node-id
  path, or the retry loop (H-1 — a shipped, real example) passes `all` and
  ships signed.
- **Why it matters:** libvirt is one of the two first-class deploy targets
  on day-0; the gate's blind spots map 1:1 onto the paths that only
  customers run. H-1 proves the retry blind spot is not hypothetical.
- **Fix direction:** add a QEMU-direct scenario (boot the qcow2 with
  `qemu-system-x86_64 -snapshot` + day0.iso cdrom, assert xpfd active +
  day-0 applied via serial/ssh), a node-id=1 drive scenario asserting em0/
  FPC-7 naming, and a scenario-C extension: fix ISO → reboot → applied.
- **Labels:** test-gap, day-0, image, libvirt
- **Dedup note:** #1926 (open, suppressed) covers *forwarding* proof on real
  NICs; the libvirt *boot/day-0* leg, node-id scenario, and retry scenario
  are not part of it and appear nowhere else.

### H-10. HA node with node-id but no config takes over ALL NICs with standalone names and never re-runs naming when the cluster config arrives

- **Title:** empty-config HA takeover uses `clusterMode=false`, so the
  control NIC becomes `ge-0-0-0` (not `em0`) and node-1 ports get FPC 0;
  the advertised recovery ("push config and commit") does not converge —
  only an undocumented daemon restart does
- **Severity:** Medium
- **Confidence:** High
- **Evidence:** `pkg/daemon/daemon_run.go:301-310` (EMPTY-takeover branch)
  then :337-341 derives `clusterMode`/`nodeID` only from the nil config;
  startup naming has exactly two call sites (boot :385; bootstrap-exit
  :1845 gated on `inBootstrap()`), and this path is NOT bootstrap.
- **Trace:** fresh replacement node 1 boots with `/etc/xpf/node-id`=1, no
  DB, no xpf.conf → all NICs named standalone → cluster config syncs and
  commits → config references `em0`/`ge-7-0-*` which don't exist → VRRP/
  fabric/heartbeat fail → stays wrong until an xpfd restart the error
  message never mentions.
- **Why it matters:** this IS the day-0 flow for the second chassis of an
  HA pair (config expected via peer sync).
- **Fix direction:** in the HA-guard branch, derive cluster naming from
  `nodeIDPresent` + file value (`clusterMode=true, nodeID=<file>`); or re-run
  `applyStartupNamingPolicy` on the first non-empty apply on this path; and
  fix the error text to name the restart requirement.
- **Labels:** bug, day-0, HA, interfaces
- **Dedup note:** no prior finding or issue; #1922's boot classes cover the
  predicate but not the naming-mode mismatch inside the EMPTY-takeover leg.

### H-11. Bootstrap/day-0 import failure is journald-only: no alarm, no `show` surface, no /health field

- **Title:** "why didn't my config apply" — the #1 day-0 support question —
  has no in-band answer; bootstrap cause is invisible to CLI/REST/gRPC
- **Severity:** Medium (UX with outage-shaped consequences)
- **Confidence:** High (`grep -rn bootstrap pkg/api pkg/grpcapi pkg/cli
  proto pkg/cmdtree` → no hits; import failure is a `slog.Warn`,
  `daemon_run.go:265-268`)
- **Trace:** preseeded `xpf.conf` fails to parse → one WARN in journald →
  box in bootstrap; operator SSHes in (fxp0 lifeline works), sees empty
  `show configuration`, nothing in `show system alarms` / `/health`; the
  first in-band hint is the commit-time bootstrap-gate refusal.
- **Why it matters:** day-0 failures land on the least-context operator;
  precedent exists (`/health` already carries CompileHealth and
  persist-degraded).
- **Fix direction:** record bootstrap cause
  (`no-config` / `import-failed:<err>` / `compile-failed`) at boot; surface
  as an active system alarm, a `/health` field, and a `show version` line.
- **Labels:** enhancement, day-0, observability
- **Dedup note:** #1922 shipped the bootstrap machinery; no issue tracks
  its operator visibility; no prior campaign finding.

### H-12. Dual node identity (`/etc/xpf/node-id` file vs `chassis cluster node` leaf) is never cross-checked, and the daemon's file parser is laxer than every other consumer

- **Title:** file drives `${node}` expansion + boot class; leaf drives FPC
  naming + heartbeat identity; nothing rejects a mismatch, and
  `fmt.Sscanf("%d")` accepts `1garbage` / any integer while check-config and
  the loader enforce `0|1`
- **Severity:** Medium
- **Confidence:** High (code-verified at `pkg/config/compiler_system.go:1205-1211`,
  `pkg/daemon/daemon.go:728-735`, `cmd/xpfd/main.go:167-170`,
  `xpf-day0-config:128-135`; unparseable file → stat-only `hasNodeIDFile()`
  still forces HA boot class while the store stays nodeID=-1 → `${node}`
  expands with the node-0 fallback, `store.go:339-348`)
- **Trace (day-0 shape):** day-0 medium carries `node-id`=1 + a config whose
  text says `chassis cluster node 0` (copied from node 0, forgot the leaf)
  → check-config -node-id 1 passes → boot: `${node}` groups expand as node 1
  while FPC naming and heartbeat identify as node 0 → two half-identities,
  node 0's per-node IPs duplicated on the wire, no diagnostic anywhere.
- **Fix direction:** single SSOT: at compile/commit-check, when store
  nodeID ≥ 0 and the leaf is present, reject on mismatch; harden the
  daemon's file parse to the same trimmed-`Atoi`-`0|1` contract; log loudly
  on an unparseable file instead of silently half-standalone.
- **Labels:** bug, HA, day-0, config
- **Dedup note:** unreported anywhere; distinct from #1944 (login parity)
  and #1922 (boot classes).

### H-13. `gate_latest` verifies only the target channel; other channels' `latest.json` publish unverified

- **Title:** publish uploads the whole dist tree but signature-gates only
  `--channel`'s freshness pointer
- **Severity:** Medium
- **Confidence:** High (`publish.py:213-217`; `latest.json` doesn't match
  `IMAGE_ARTIFACT_SUFFIXES`, so the orphan sweep skips it)
- **Trace:** stale/tampered/unsigned `dist/edge/latest.json` sits in the
  tree → `make dist-publish` (stable) gates stable only → edge pointer
  ships; `xpf-deploy.py fetch --channel edge` consumers resolve it.
- **Fix direction:** enumerate every `dist/*/latest.json` and gate each
  (mirror the per-suite InRelease posture of `gate_apt`).
- **Labels:** bug, distribution
- **Dedup note:** unreported; #1924's open scope is keys/hosting.

### H-14. Publisher runbook dead-ends: no tooling substitutes the real archive key into install.sh, the doc signs the placeholder, and install.sh presence is optional to the gate

- **Title:** following `docs/distribution.md` step 4 verbatim produces an
  installer publish.py refuses (or none at all, which passes)
- **Severity:** Medium
- **Confidence:** High (no substitution tooling exists anywhere in
  `scripts/`/Makefile; `publish.py:195` gates install.sh only
  `if os.path.isfile(installsh)`)
- **Trace:** release engineer follows the runbook → signs the
  placeholder-key installer → gate dies "still embeds the PLACEHOLDER
  archive key" → hand-edit + re-sign ceremony with an easy
  substitute-after-sign footgun; alternatively ship no install.sh → gate
  passes → Tier-A URL 404s.
- **Fix direction:** `make dist-installer` (or fold into publish.py):
  substitute key+URL → sign → gate asserts substitution AND presence
  (explicit `--no-installer` opt-out).
- **Labels:** enhancement, distribution, docs
- **Dedup note:** unreported; adjacent to but distinct from #1924's open
  operator inputs.

### H-15. No cross-check that the installer's embedded key, the packaged keyring, and the InRelease signer agree

- **Title:** three placeholder predicates, zero same-key predicates — a
  stale real-keyed install.sh publishes cleanly after rotation and bricks
  every new Tier-A install at `apt-get update`
- **Severity:** Medium
- **Confidence:** High (publish.py checks placeholder-ness at :196-200,
  :261-264, :309-315 independently; no fingerprint comparison anywhere)
- **Trace:** archive key rotates → keyring + XPF_GPG_KEY updated → stale
  `dist/install.sh` (old real key, valid minisig) passes all gates → new
  installs write the old keyring → apt signature failure fleet-wide for
  new installs.
- **Fix direction:** in `gate_apt`: extract install.sh's armored block,
  require fingerprint-set agreement with `xpf-archive-keyring.asc`
  (superset allowed during documented dual-sign) and that InRelease
  verifies against the installer's key.
- **Labels:** bug, distribution, security
- **Dedup note:** key *rotation* mechanics are documented
  (docs/distribution.md §Key rotation) but the publish-time agreement gate
  is absent and unreported.

### H-16. install.sh mutates the host before validating its inputs; `apt remove` leaves a dangling apt source that breaks `apt update` forever

- **Title:** keyring installed before URL/channel validation; the written
  `xpf.sources` is unowned by any package while its `Signed-By` keyring IS
  package payload — removal strands apt
- **Severity:** Low (two grouped hygiene defects)
- **Confidence:** High
- **Evidence:** `install.sh:180-187` ordering (preflight → install_keyring →
  write_source(validates) → do_install); keyring shipped by the package
  (`debian/rules:105-112`) vs `xpf.sources` written only by install.sh and
  never removed by `debian/xpf.postrm`.
- **Trace:** (a) typo'd `XPF_APT_BASE_URL` → dies after keyring write —
  half-configured host. (b) Tier-A install → later `apt remove xpf
  xpf-appliance` → dpkg deletes the keyring → `xpf.sources` still points at
  it → every `apt update` errors until an operator hand-deletes a file they
  never knew existed.
- **Fix direction:** hoist all validation to `main()` top; own the source
  file (ship it, or postrm-purge it with a we-wrote-it check mirroring
  `link_is_owned`).
- **Labels:** bug, distribution, packaging
- **Dedup note:** unreported.

### H-17. Every factory boot logs "failed to bootstrap config from file … no such file or directory" as a WARN

- **Title:** the expected fresh-boot path reads like a failure in journald
- **Severity:** Low
- **Confidence:** High (`daemon_apply.go:57-59` unconditional ReadFile;
  `daemon_run.go:267` warns on any error)
- **Trace:** factory boot, no `/etc/xpf/xpf.conf` → WARN. Operators triaging
  real day-0 failures (H-1/H-11) must first learn to ignore this line.
- **Fix direction:** `os.IsNotExist` → Info("no text config present");
  keep WARN for real read/parse/commit failures.
- **Labels:** cleanup, day-0, logging
- **Dedup note:** unreported.

### H-18. `docs/bare-metal-device-map.md` tells the operator `commit check` confirms a `commit confirmed` — it does not; following the doc rolls back a verified config

- **Title:** device-map quick-start step 3 conflates `commit check`
  (validation-only) with confirmation
- **Severity:** Low (doc, lockout-shaped consequence)
- **Confidence:** High (`pkg/configstore/store_commit.go:26-27,306-307`:
  `CommitCheck` never touches the confirm timer)
- **Trace:** console operator runs `commit confirmed 5`, verifies, runs
  `commit check` per the doc, walks away → auto-rollback of the good
  device-map at T+5m.
- **Fix direction:** doc fix: `commit` confirms; `commit check` validates.
- **Labels:** docs, bare-metal, day-0
- **Dedup note:** unreported; distinct from #1956's shipped design.

### H-19. Day-0/image/dist self-tests exist but are wired into nothing

- **Title:** `test-grow-root.sh` (35 asserts), `test_bake_sign_ordering.py`
  (6 tests), `scripts/dist/selftest.sh` all pass and all are unreachable
  from `make test` or any CI
- **Severity:** Medium (meta test-gap)
- **Confidence:** High (no `.github/workflows`; Makefile greps show
  `dist-selftest` is a manual target and the other two appear nowhere;
  `make test` = Go + Rust suites only, #4006)
- **Trace:** a regression re-introducing sign-before-validate (#4017) or
  breaking the grow-root stamp discipline (#2047's Codex MAJOR) merges
  green; the pinning tests still pass — locally, run by no one.
  Additional uncovered surface catalogued: publish.py `gate_apt`/`gate_latest`
  legs (positive AND negative), channel isolation (would have caught H-4),
  the reprepro branch, debian maintainer scripts (no install→upgrade→
  remove→purge roundtrip), `bootstrapFromFile` (its only "test" is a
  drift-prone re-implementation in `device_map_startup_test.go:11`),
  the positional rename loop (H-7 is unit-reproducible today with existing
  seams), and the day-0 shell script's guard/stamp logic (H-1 lives there).
- **Fix direction:** `make test-image-scripts` (sh -n + both image tests,
  <1s) folded into `make test`; extend dist selftest with a positive
  end-to-end gate pass + gate_apt/gate_latest/channel-isolation negatives;
  add a `bootstrapFromFile` daemon-level test and a bats-style self-test
  for xpf-day0-config's main() guards (repo precedent:
  `make test-deploy-lib`, `make test-cluster-lock-lib`).
- **Labels:** test-gap, day-0, image, distribution
- **Dedup note:** fable-161 F-091 ("make test never runs cargo suite") was
  fixed by #4006 and covered the Rust leg only; the image/dist/bootstrap
  test wiring is unreported.

### H-20. libvirt deploy boots VMs directly off the shared golden qcow2 — an HA pair attaches the SAME writable disk to both VMs

- **Title:** `deploy_libvirt` hardcodes
  `--disk path=/var/lib/libvirt/images/<image>.qcow2` with no per-VM clone;
  even a single deploy dirties the golden image (day-0 stamp, host keys,
  configstore DB baked into the master)
- **Severity:** High (data-corruption class + broken second deploy)
- **Confidence:** High (verified at `scripts/deploy/xpf-deploy.py:358-365`)
- **Evidence:**
  ```python
  def deploy_libvirt(ap, runner, start):
      ...
      argv = ["virt-install", "--name", name, ..., "--import",
              "--disk", f"path=/var/lib/libvirt/images/{ap['image']}.qcow2",
  ```
  Every YAML defaults `image: xpf-appliance` (`load_yaml_appliance`), so
  `deploy --hypervisor libvirt ha-fw0.yaml ha-fw1.yaml` attaches the same
  writable file to both domains. The incus path clones from the image
  store (`incus init`) — correct.
- **Trace:** (1) single deploy: `--import` boots and mutates the golden —
  `/etc/xpf/.day0-config-applied` + configstore land in the master, so the
  NEXT VM "from the image" comes up pre-configured with the previous VM's
  identity and silently skips its own config drive. (2) HA pair: two live
  VMs on one qcow2 → filesystem corruption, locking-config dependent.
- **Why it matters:** libvirt is advertised as first-class ("Both run the
  *same* qcow2", examples/deploy/README.md); the very first documented
  libvirt deploy poisons the golden image.
- **Fix direction:** per-VM linked clone
  (`qemu-img create -f qcow2 -b <golden> -F qcow2 <name>.qcow2`) or
  `cp --reflink=auto`; refuse a disk path already attached to a defined
  domain; make the image directory configurable (see also H-30).
- **Labels:** bug, day-0, libvirt, deployer
- **Dedup note:** unreported anywhere; #1906 shipped the libvirt path,
  no follow-up issue covers disk lifecycle.

### H-21. Every hypervisor-command failure in the deployer is a bare traceback with the actual error swallowed

- **Title:** `Runner.run` uses `check=True, capture_output=True` and nothing
  catches `CalledProcessError` — incus/virt-install's real message (missing
  bridge, existing instance, missing image alias) is never shown
- **Severity:** High (day-0 failure-mode multiplier)
- **Confidence:** High (verified at `xpf-deploy.py:282-290`)
- **Trace:** first-run with a missing bridge → `incus config device add`
  fails → operator sees
  `subprocess.CalledProcessError: ... exit status 1` and not
  `Error: ... no such network` — the single most common first-run failure
  is opaque, contradicting the tool's own "fails on your laptop" pitch.
- **Fix direction:** wrap and `die()` with command, rc, and captured
  stderr; catch at `deploy()` level.
- **Labels:** bug, deployer, UX
- **Dedup note:** unreported.

### H-22. Role validation ignores the guest's virtio-first tiebreaker — a virtio NIC listed after a hardware NIC silently swaps firewall zones

- **Title:** `validate_appliance` checks role-text vs list index only, but
  the guest sorts virtio before hardware
  (`pkg/daemon/linksetup.go:189-204`), so a mixed-order YAML passes
  validation and boots with LAN/WAN (trust/untrust) on swapped ports
- **Severity:** High (silent security miswiring)
- **Confidence:** High (both sides verified; all six shipped examples
  happen to put virtio first, so the hazard is latent, not active, in the
  shipped files)
- **Evidence:** `xpf-deploy.py:179-188` (index-only check) vs the guest's
  `sk = 0` for `virtio_net` + sort at `linksetup.go:189-204`.
- **Trace:** operator customizes an example: pos1 fxp0 bridge (virtio),
  pos2 ge-0/0/0 `pci:` VF, pos3 ge-0/0/1 bridge (virtio). Validation
  passes. In-guest both virtio NICs sort first: the pos-3 bridge becomes
  ge-0/0/0 (LAN) and the VF becomes ge-0/0/1 (WAN). Zones, policies, NAT
  land on swapped ports; nothing errors.
- **Why it matters:** this is exactly the class of failure the
  role/position check exists to prevent, the deployer HAS every interface's
  backing class, and the docs hand-wave it ("identical to pure position in
  every normal layout").
- **Fix direction:** classify backings virtio-class (`net`/`bridge`/
  `macvlan`) vs hardware-class (`sriov`/`pci`/`physical`) in
  `validate_appliance` and `die()` when a virtio-class interface follows a
  hardware-class one (or recompute and print the effective map). Add a
  `deploy --verify` post-launch acceptance step
  (`incus exec <n> -- cli -c "show interfaces terse"` diffed against
  declared roles) — the README currently asks the operator to invent this
  by hand.
- **Labels:** bug, day-0, deployer, security
- **Dedup note:** the virtio-first tiebreaker is documented
  (deploy-quickstart "60-second mental model") but no issue or finding
  covers the validator's blindness to it.

### H-23. `physical` backing is broken on libvirt: a netdev name is passed to `virt-install --hostdev`

- **Title:** `--hostdev enp8s0` is not a valid hostdev spec (PCI/USB
  address or node-device name required) — the documented backing cannot
  work on libvirt, and per H-21 the error is swallowed
- **Severity:** Medium (documented feature dead on one of two hypervisors)
- **Confidence:** High (`xpf-deploy.py:377-378`; the backing table in
  examples/deploy/README.md advertises `physical` → `--hostdev`)
- **Fix direction:** translate netdev → PCI address with the existing
  `pci_of()` helper, or reject `physical` under libvirt pointing at `pci:`.
- **Labels:** bug, libvirt, deployer
- **Dedup note:** unreported.

### H-24. `xpf-deploy.py` has zero test coverage — including the Python "mirror" of the Go mixed-base HA safety gate

- **Title:** 1348 lines (deploy, fetch/verify, kernel-roll, image-roll)
  imported/executed by nothing; `_gate_mixed_base`'s docstring leans on the
  GO side's tests ("EXACT Python mirror of upgrade.GateMixedBaseSwap
  (unit-tested in Go)") while nothing prevents the mirror from drifting
- **Severity:** High (coverage; the gate decides whether an HA image roll
  can preserve sessions)
- **Confidence:** High
- **Evidence:** repo-wide grep: only `scripts/image/test_bake_sign_ordering.py`
  exists under scripts/; no Makefile target touches the deployer (the
  `test-deploy-lib` selftest covers the DIFFERENT incus test-env stack).
  Untested-but-pure surface: `expected_name`/`validate_appliance` (the
  naming contract), `memory_mb`, `_ver_key` (see H-25 — an actual bug found
  by executing it), `_gate_mixed_base`, the manifest key round-trip, the
  `--nic` spec parser, dry-run command emission.
- **Fix direction:** `scripts/deploy/test_xpf_deploy.py` — pure functions +
  dry-run golden commands + `_gate_mixed_base` parity vectors shared with
  the Go test; wire into `make test` (repo precedent: `test-deploy-lib`,
  `test-cluster-lock-lib`). Fold into the same wiring work as H-19.
- **Labels:** test-gap, deployer, HA
- **Dedup note:** distinct from H-19's image/dist test wiring; unreported.

### H-25. Anti-rollback watermark mis-orders git-describe counts and rc numbers (reproduced by execution)

- **Title:** `_ver_key` compares pre-release suffixes as whole strings:
  `1.2.3-10-gabc` ranks OLDER than `1.2.3-9-gdef`, `rc10` below `rc9` —
  false "possible stale mirror / rollback" refusals train operators to pass
  `--allow-rollback`
- **Severity:** Medium
- **Confidence:** High (executed: both misorderings reproduced)
- **Evidence:** `xpf-deploy.py:485-493` — `pre_rank = (2, suffix)` string
  comparison, while `rel_key` numeric-splits the release part correctly.
- **Fix direction:** numeric-split the suffix
  (`re.split(r'(\d+)', suffix)` with int coercion).
- **Labels:** bug, distribution, deployer
- **Dedup note:** unreported.

### H-26. `--no-start` is silently ignored on libvirt, and both docs claim the tool "emits a command you run" when it actually executes it

- **Title:** `virt-install --import` defines AND boots; when `start` is
  False only a print is skipped — the README's own pinned-guest-PCI
  workflow (edit slots via `virsh edit` BEFORE first boot) is impossible
- **Severity:** Medium
- **Confidence:** High (`xpf-deploy.py:396-402` vs
  examples/deploy/README.md "emits a `virt-install` command you run" and
  deploy-quickstart.md "the tool emits a `virt-install` command")
- **Trace:** `deploy --hypervisor libvirt --no-start x.yaml` → VM boots,
  consumes its day-0 config with unpinned slots; combined with H-20 the
  boot also dirties the golden image.
- **Fix direction:** honor `--no-start` via
  `virt-install --print-xml | virsh define`; fix both docs.
- **Labels:** bug, libvirt, deployer, docs
- **Dedup note:** unreported.

### H-27. No preflight, no idempotency, no cleanup, no destroy verb — partial failures dead-end and re-runs fail

- **Title:** `deploy_incus` runs init → N× device add → start with no
  existence checks, no rollback of a half-created instance, and the tool
  has no `destroy` subcommand — attempt #2 requires hand-run
  `incus delete`
- **Severity:** Medium (day-0 robustness IS re-run safety)
- **Confidence:** High (`xpf-deploy.py:301-356`; subcommand list :1237-1238)
- **Trace:** HA deploy; fw0 succeeds, fw1's bridge missing → device add
  throws (traceback per H-21) → fw1 left init'd-with-some-devices →
  fix bridge, re-run → `incus init` fails "already exists".
- **Fix direction:** preflight every source (bridge/PF/VF/PCI/image
  alias/name-free — the helpers already exist in `cmd_inventory`) before
  any mutation; delete the partial instance on mid-deploy failure; add
  `destroy <yaml>`.
- **Labels:** enhancement, deployer, UX
- **Dedup note:** unreported.

### H-28. Quickstart "Standalone in two commands" fails on a fresh host: bridge prerequisites (and their DHCP-bearing form) are documented only for HA

- **Title:** `standalone.yaml` sources br-mgmt/br-lan/br-wan whose creation
  appears only in the HA section; a bare `ip link add` bridge also provides
  no DHCP, so even after creating them the "working NAT firewall" has no
  mgmt or WAN address
- **Severity:** Medium
- **Confidence:** High (docs/deploy-quickstart.md:43-48 vs :86-92)
- **Fix direction:** copy-pasteable `incus network create ...` block
  (NAT/DHCP-bearing for mgmt) in the standalone section; preflight (H-27)
  prints exactly that command when a source is missing.
- **Labels:** docs, day-0, deployer
- **Dedup note:** unreported.

### H-29. Day-0 credential gap: examples ship no `root-authentication`/`login`, so SSH is enabled but unusable — and vSRX would refuse to commit such a config

- **Title:** the image's factory posture is console-only root/empty
  password + sshd `prohibit-password`; `standalone.conf`/`ha-pair.conf`
  enable ssh host-inbound but carry no credentials and no doc states how to
  log in at all
- **Severity:** Medium (UX + parity; silent remote-unreachable mgmt plane)
- **Confidence:** High (bake.py:100-104 SSHD_DROPIN; both example confs
  grepped: no root-authentication/login stanza; schema supports both,
  #1944)
- **Trace:** deploy the example → `ssh root@fxp0` → pubkey-only, no keys →
  locked out of SSH until the operator independently discovers the console
  path; meanwhile the console accepts empty-password root — undisclosed in
  the deploy docs — on whatever bridge br-mgmt is.
- **vSRX parity:** vSRX refuses to commit without `root-authentication`;
  xpf's gate accepts it silently.
- **Fix direction:** commented `system root-authentication` stanza in both
  example confs; document the factory console posture in quickstart
  Troubleshooting; consider a check-config WARNING for
  ssh-enabled-but-credential-less configs (parity option: reject like
  vSRX under a strictness knob).
- **Labels:** vsrx-parity, day-0, docs, security
- **Dedup note:** #1944 added the `login user` encrypted-password support
  (closed); the examples/docs/commit-gate gap is unreported.

### H-30. `fetch` → libvirt gap: the verified qcow2 never reaches the hardcoded path deploy expects

- **Title:** `fetch --qcow2-only` leaves `out/xpf-<ver>.qcow2`;
  `deploy_libvirt` demands `/var/lib/libvirt/images/<alias>.qcow2`; no
  command, doc, or hint bridges the move/rename — the two halves of the
  libvirt story don't connect
- **Severity:** Medium
- **Confidence:** High (`xpf-deploy.py:569-573` vs :364)
- **Fix direction:** `fetch --qcow2-only --install-libvirt` (or print the
  exact `install` command); YAML-configurable image path; with H-20's
  per-VM clone this becomes "fetch verifies the golden, deploy clones it".
- **Labels:** bug, libvirt, deployer, distribution
- **Dedup note:** unreported.

### H-31. image-roll's mixed-base gate consumes an UNSIGNED manifest that `fetch` doesn't even download

- **Title:** the signed set is qcow2+metadata only
  (`bake.py:640-641 sign.write_manifest(sums, [qcow_out, meta_out])`);
  `xpf-<ver>.manifest` — the input to the session-survival decision — is
  neither signed nor fetched, so operators copy it out-of-band unverified
- **Severity:** Medium (integrity gap in an HA-availability decision)
- **Confidence:** High
- **Trace:** tampered/stale manifest claims protocol compat → roll proceeds
  into a genuinely incompatible mixed pair; the in-guest drain precheck is
  the only remaining backstop.
- **Fix direction:** add the `.manifest` to the signed manifest set in
  bake.py; teach `fetch` to download+verify it; image-roll notes
  verified-vs-unverified provenance.
- **Labels:** bug, distribution, HA, kernel-channel
- **Dedup note:** #1930 INC-3 designed the manifest gate; its signing/
  distribution is unreported. Distinct from suppressed F-256 (provenance
  fields under --skip-build).

### H-32. kernel-roll releases both leases on mid-roll failure while image-roll deliberately TTL-holds them — inconsistent never-both-down defense

- **Title:** `cmd_kernel_roll`'s `finally` always `_clear_lease`s both
  nodes (`xpf-deploy.py:892-894`); image-roll keeps leases on a half-rolled
  cluster precisely so another orchestrator cannot drain the healthy peer
  (its comment cites the "HIGH Codex never-both-down" review)
- **Severity:** Medium
- **Confidence:** High
- **Trace:** kernel-roll times out with node 0 still down mid-reboot →
  die() → leases released → a second orchestrator immediately drains the
  healthy peer while node 0 is down.
- **Fix direction:** port image-roll's `state_changed`/`completed` TTL-hold
  logic to kernel-roll.
- **Labels:** bug, HA, kernel-channel, deployer
- **Dedup note:** unreported; the image-roll side shows the reviewed-correct
  pattern, kernel-roll predates it.

### H-33. `--node0-id/--node1-id` are keyed to argument ORDER with defaults 0/1 — rolling the secondary first writes wrong node-ids into the leases

- **Title:** `node_ids = {nodes[0]: args.node0_id, nodes[1]: args.node1_id}`
  — `kernel-roll --node fw1 --node fw0` (the natural roll-secondary-first
  call) suppresses self-recovery on the WRONG node during each roll
- **Severity:** Medium
- **Confidence:** High (`xpf-deploy.py:741`, defaults at :1281-1284)
- **Fix direction:** read `/etc/xpf/node-id` from each node at start and
  drop the flags (or die on mismatch).
- **Labels:** bug, HA, deployer
- **Dedup note:** unreported.

### H-34. Config-drive builder is duplicated in the deployer instead of importing `make_config_drive.py` — and has already drifted

- **Title:** two implementations of the day-0 drive; `find_xpfd()` differs
  (repo-root search vs cwd search), so `deploy` run from
  `examples/deploy/` silently skips build-host validation that
  `make_config_drive.py` would have performed
- **Severity:** Medium (drift risk on the day-0 SSOT)
- **Confidence:** High (`xpf-deploy.py:213-263` vs
  `make_config_drive.py:30-46`, whose docstring says "Importable: …
  other tooling call build_config_drive()")
- **Fix direction:** import and call `make_config_drive.build_config_drive`
  (sys.path-insert like `cmd_fetch` already does for `sign`).
- **Labels:** refactor, deployer, day-0
- **Dedup note:** unreported.

### H-35. ssh-backend rolls break permanently after a node recreate: fresh host keys × `BatchMode=yes`

- **Title:** the image regenerates host keys at first boot;
  `_recreate_node_from_image` changes the node's key; `_node_exec`'s
  `BatchMode=yes` + default StrictHostKeyChecking then fails every
  subsequent exec — the poll loop reads it as "node never came back",
  dies at boot-deadline with leases TTL-held and the cluster half-rolled
- **Severity:** Medium
- **Confidence:** High (`xpf-deploy.py:636-639`, :1147-1157)
- **Fix direction:** scoped `-o StrictHostKeyChecking=accept-new -o
  UserKnownHostsFile=<roll-tmp>` (flag-gated), or require the recreate
  hook to refresh known_hosts and verify reachability with a clear
  ssh-specific error.
- **Labels:** bug, HA, deployer
- **Dedup note:** unreported.

### H-36. No per-subcommand help; `fetch`/`kernel-roll`/`image-roll` flags are documented nowhere outside the source

- **Title:** `main()` intercepts `-h` anywhere and prints the module
  docstring; all subparsers are `add_help=False` — `fetch -h` never shows
  `--channel/--allow-rollback/--qcow2-only`; neither quickstart nor
  examples README mentions fetch or the roll verbs at all (the Fleet
  section describes the image-replace upgrade by hand without pointing at
  `image-roll`)
- **Severity:** Medium (UX/docs)
- **Confidence:** High (`xpf-deploy.py:1217-1220`, :1244)
- **Fix direction:** let subparsers own `-h`; add "getting the image
  (fetch)" + roll-verb sections to the quickstart.
- **Labels:** docs, deployer, UX
- **Dedup note:** unreported.

### H-37. Quickstart prerequisites teach the UNVERIFIED import path, bypassing the #1924 signed-distribution posture

- **Title:** deploy-quickstart's first block is a raw
  `incus image import dist/...` hand-copy while distribution.md mandates
  "fetch + verify … instead of copying files by hand" — the day-0 front
  door contradicts the trust model
- **Severity:** Medium
- **Confidence:** High (docs/deploy-quickstart.md:35-41 vs
  docs/distribution.md:20-24)
- **Fix direction:** make `xpf-deploy.py fetch --version <ver>` the primary
  prerequisite; raw import as the "I built it myself" fallback.
- **Labels:** docs, distribution, day-0
- **Dedup note:** unreported; #1924's open item is keys/hosting, not this
  doc ordering.

### H-38. No root-disk-size knob in the deployer despite the image's 8 GiB floor + first-boot auto-grow feature

- **Title:** install-images.md documents `incus init ... -d root,size=40GiB`
  + #1925 auto-grow as the intended flow; the YAML schema cannot express a
  disk size (and libvirt's shared-disk design, H-20, can't either)
- **Severity:** Medium (ease-of-use; the 8 GiB default silently becomes
  the fleet standard)
- **Confidence:** High (`xpf-deploy.py:314-316`; no `disk:` key in
  README schema)
- **Fix direction:** `appliance.disk: 40GiB` → `-d root,size=` (incus) /
  `qemu-img resize` on the per-VM clone (libvirt).
- **Labels:** enhancement, deployer, day-0
- **Dedup note:** unreported; complements shipped #1925.

### H-39. `fetch`'s alias swap is non-atomic: the old GOOD alias is deleted before the new import can fail

- **Title:** unconditional `incus image delete <alias>` precedes the
  import; a failed import (disk full, corrupt download) leaves NO
  `xpf-appliance` alias and every subsequent deploy breaks
- **Severity:** Low-Medium
- **Confidence:** High (`xpf-deploy.py:575-583`)
- **Fix direction:** import under a temp alias then re-alias; delete old
  last.
- **Labels:** bug, deployer, distribution
- **Dedup note:** unreported.

---

## 7. Findings — MEDIUM CONFIDENCE

### M-1. One-command install auto-starts xpfd, which seizes and renames every interface — the lockout caveat prints only after the damage window

- **Title:** install.sh sequences the #1879 interface-takeover warning after
  `apt-get install`, and first start is unconditional on package install
- **Severity:** High (remote lockout on the "easy" path)
- **Confidence:** Medium-High (unit/dh_installsystemd first-install start
  semantics traced, not executed end-to-end)
- **Evidence:** `install.sh:153-178` (do_install then CAUTION text);
  `debian/rules:132-139` (`dh_installsystemd --no-stop-on-upgrade` still
  enables+starts on first install); bake.py:232-234 comment confirms
  postinst enables xpfd.
- **Trace:** operator SSHes to a remote Debian box → one-liner →
  postinst starts xpfd → `enumerateAndRenameInterfaces()` renames NICs by
  PCI order and downs unconfigured ones → if the mgmt NIC doesn't land as
  bootstrap fxp0 DHCP (static-addressed NIC, multi-NIC ordering), SSH dies
  mid-apt → the caveat scrolls into a dead terminal.
- **Why it matters:** the package path's day-0 promise becomes a remote
  lockout precisely when it's most convenient to trust it.
- **Fix direction:** print the caveat + confirm gate (or `XPF_ASSUME_YES=1`)
  BEFORE do_install; better: stage-not-start on first install (policy-rc.d
  window or `XPF_NO_AUTOSTART`) with explicit first-start after config
  seeding; or install.sh detects "SSH session + no day-0 config present"
  and requires opt-in.
- **Labels:** bug, day-0, distribution, safety
- **Dedup note:** the hazard is documented (docs/distribution.md CAUTION;
  #1958's reachability contract is the long-term design) — the novel defect
  is the SEQUENCING: tooling warns after acting and offers no opt-out.

### M-2. Two unserialized NVRAM writers: `xpf-uefi-slots` can race the promote gate and durably un-promote a just-promoted kernel

- **Title:** no ordering edge between xpf-uefi-slots.service and
  xpf-kernel-promote.service; uefi-slots' BootOrder read-modify-write can
  complete after `SetBootOrderFront(candID)`
- **Severity:** Medium
- **Confidence:** Medium (race window requires slow firmware NVRAM; both
  units verified concurrent-eligible in the same transaction)
- **Evidence:** `xpf-uefi-slots.service:8` (`After=local-fs.target` only);
  `xpf-uefi-slots:128-133,141,160,174` (PRE_FRONT snapshot → later ORDER
  re-read → `--bootorder` write); promote writes BootOrder at
  `pkg/upgrade/kernel_run.go:410`.
- **Trace:** candidate trial boot → both units start → uefi-slots mid-flight
  (~12-15 serial efibootmgr calls) when the gate PASSES and reorders →
  uefi-slots writes an order computed from the pre-promotion LED slot →
  next power cycle boots the old kernel while the journal says Promoted.
- **Fix direction:** one line: `Before=xpf-kernel-promote.service` in
  xpf-uefi-slots.service (slots runs once per boot, closing the window).
- **Labels:** bug, kernel-channel
- **Dedup note:** #1930's r2/r4/r5 review rounds hardened each script
  individually; the cross-unit ordering is unreported.

### M-3. NVRAM wipe after a promotion to slot B silently reseeds slot A — durable, undetected kernel rollback

- **Title:** the fresh-box BootOrder seed consults only NVRAM itself, never
  the on-disk promotion marker, so hypervisors without persistent EFI
  variables (or a firmware reset) resurrect the pre-upgrade kernel
- **Severity:** Medium
- **Confidence:** Medium (behavior on NVRAM-loss traced; not executed)
- **Evidence:** `xpf-uefi-slots:166-173` (no-led → seed `xpf-A` first);
  the promote path writes a durable marker (`kernel_run.go:418`
  `WritePromotionMarker`) that the seeder never reads.
- **Trace:** libvirt guest without per-VM NVRAM file → promote to B
  (ESP selector persists; BootOrder doesn't) → next boot: empty NVRAM →
  self-heal seeds A first → grub sources `xpf-A/xpf.selector` → old kernel
  forever; `xpfd upgrade kernel status` still says promoted.
- **Fix direction:** consult the promotion marker/journal before the
  fresh-box seed; seed the promoted slot first and log loudly; at minimum
  WARN that a recorded promotion could not be verified against NVRAM.
- **Labels:** bug, kernel-channel, libvirt
- **Dedup note:** #1930 r4 AGY covered NVRAM registration being first-boot
  (not offline-bake); the wipe-reseed rollback is unreported.

### M-4. `xpf-kernel-promote-failed` reboots on ANY unit failure — including non-gate failures on ordinary boots — with no state-based guard: infinite reboot loop surface

- **Title:** OnFailure trigger set is wider than the loop-safety argument
  (203/EXEC on a missing script, OOM-kill, wedged fs all reboot every boot)
- **Severity:** Medium
- **Confidence:** Medium (the fast-path no-op claim was verified true for
  the script; the unit-level failure modes are traced, not induced)
- **Evidence:** `xpf-kernel-promote.service:10-18` justifies loop-safety
  from the script's fast exit-0 no-op (verified: `kernel_run.go:334-344`
  + non-blocking lock); but a missing/non-executable
  `/usr/local/sbin/xpf-kernel-promote` fails the UNIT before the script's
  logic can exit 0.
- **Trace:** botched upgrade removes the script while the unit stays
  enabled → every boot: 203/EXEC → failed → OnFailure reboot → loop;
  console/single-user is the only escape.
- **Fix direction:** state-based condition on the failed unit
  (`ConditionPathExists=/var/lib/xpf/kernel-journal` — armed-candidate
  evidence) and/or `ExecCondition=test -x …` on the promote unit.
  StartLimit can't help across reboots.
- **Labels:** bug, kernel-channel, resilience
- **Dedup note:** the OnFailure unit itself was r2 AGY Finding 3's fix;
  its over-broad trigger is unreported.

### M-5. grow-root can stamp success with the space silently stranded (growpart table-write OK, kernel resize not applied)

- **Title:** the stamp asserts exit codes, not the invariant; a
  CHANGED-but-kernel-stale growpart + no-op resize2fs both exit 0 → stamped,
  never retried, operator got 8 GiB of a 200 GiB disk with all signals green
- **Severity:** Medium
- **Confidence:** Low-Medium (depends on growpart/kernel combination
  behavior for online partition resize notification failures)
- **Evidence:** `xpf-grow-root:144-168` — stamp on `gp_rc==0 && r2_rc==0`;
  no post-check of kernel partition size vs fs size.
- **Fix direction:** before stamping, compare
  `/sys/class/block/<part>/size` against the fs block count
  (`resize2fs -P` / statfs); >1-block delta → no stamp (retry converges
  after reboot).
- **Labels:** bug, image, first-boot
- **Dedup note:** #1925/#2047 built the stamp discipline; the
  partial-that-stamps case is unreported.

### M-6. `xpf-appliance` doesn't depend on `systemd-networkd`; install.sh's preflight warns with a false remedy

- **Title:** minimal Debian/Ubuntu hosts without the split networkd package
  install cleanly and boot an xpfd whose entire interface management is
  dead letter — while the preflight says "the xpf package pulls it in"
- **Severity:** Medium
- **Confidence:** Medium (Depends verified absent; distro packaging split
  varies by release)
- **Evidence:** `debian/control:39-61` (has `systemd-resolved`, no
  `systemd-networkd`); `install.sh:97-103` (warning text asserts the
  package pulls it in). The image path is fine (bake enables networkd).
- **Fix direction:** add `systemd-networkd` (appropriately versioned
  alternation) to Depends; make the preflight fatal-with-override,
  matching the kernel-floor posture.
- **Labels:** bug, packaging, distribution
- **Dedup note:** unreported.

### M-7. selftest.sh plants a fake `xpf-appliance_*.deb` in the real `dist/deb`, matching the repo builder's default glob

- **Title:** a SIGKILLed selftest leaves an empty, signed-over-able
  `xpf-appliance` package that the next `make dist-repo` pools and signs
- **Severity:** Medium
- **Confidence:** Medium (persistence requires an uncleaned abort; the glob
  match is verified)
- **Evidence:** `selftest.sh:154-158` (FAKEDEB in `$ROOT/dist/deb`, trap
  EXIT/INT/TERM only); `build-apt-repo.sh:58` default glob
  `xpf-appliance_*.deb` matches it.
- **Fix direction:** build the fake deb under `$WORK` (it's passed via
  `--debs` explicitly anyway); exclude `*.selftest.deb` in the default
  glob; publish-gate refusal on selftest-marked Maintainer.
- **Labels:** bug, distribution, test-infra
- **Dedup note:** unreported.

### M-8. Day-0 unit stamps ssh-host-key regeneration off forever if the first-boot regen failed

- **Title:** key regen and config install share one
  `ConditionPathExists=!/etc/xpf/.day0-config-applied` gate; a failed
  `ssh-keygen -A` on a successful config boot leaves the appliance with a
  valid config and no SSH path, permanently
- **Severity:** Low-Medium
- **Confidence:** Medium (failure requires ssh-keygen failing while
  check-config succeeds — narrow but real: ENOSPC window, ro-/etc corner)
- **Evidence:** `xpf-day0-config:61-66` (`|| warn` only);
  `xpf-day0-config.service:19` (stamp condition gates the whole unit);
  sealed image ships keyless (`bake.py:609`); Ubuntu's ssh.service does not
  self-generate keys.
- **Fix direction:** decouple — a tiny
  `ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key` oneshot
  `Before=ssh.service`, or `ExecStartPre=ssh-keygen -A` in an sshd drop-in.
- **Labels:** bug, day-0, image
- **Dedup note:** unreported.

### M-9. `xpf-uefi-slots` makes ~12-15 serial `efibootmgr` invocations under `TimeoutStartSec=20`

- **Title:** slow physical-firmware NVRAM trips the unit timeout mid-run on
  bare-metal day-0; `SuccessExitStatus=0` is a no-op that doesn't cover
  timeout kills despite the adjacent comment
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:** `xpf-uefi-slots.service:16,19`; call sites at
  `xpf-uefi-slots:46,86-87,127-130,139-140,153`.
- **Fix direction:** snapshot one `efibootmgr` read per phase (also removes
  TOCTOU windows in the dedup loop); raise to 60s; delete the misleading
  SuccessExitStatus line.
- **Labels:** bug, kernel-channel, bare-metal
- **Dedup note:** unreported.

### M-10. Promote gate treats `Type=simple` xpfd "exec'd" as "dataplane ready" — good kernels get reverted on slow-config boxes

- **Title:** `After=xpfd.service` releases at exec for Type=simple; the
  20s beacon deadline starts before config load/helper start on loaded
  production boxes → false REVERT of a healthy candidate kernel
- **Severity:** Low (fails safe — falls back to known-good; but makes
  LANE-1 flaky exactly where it targets)
- **Confidence:** Medium
- **Evidence:** `xpf-kernel-promote.service:8`; `test/incus/xpfd.service:7`
  `Type=simple`; beacon deadline `cmd/xpfd/upgrade_kernel.go:41`.
- **Fix direction:** `Type=notify` + `sd_notify(READY=1)` after dataplane
  load (right long-term fix), or beacon poll-with-patience gated on a
  "helper up" precondition.
- **Labels:** enhancement, kernel-channel, HA
- **Dedup note:** unreported.

### M-11. `run() { eval "$*"; }` in install.sh + unvalidated URL written into a root-owned apt source

- **Title:** latent injection/word-splitting pattern; a newline-bearing
  `XPF_APT_BASE_URL` injects arbitrary deb822 fields (e.g. `Trusted: yes`)
- **Severity:** Low (requires the operator to feed a hostile value to their
  own root shell; copy-paste culture makes hygiene cheap)
- **Confidence:** Medium (pattern verified; exploitability today low —
  every current `run` argument is a constant)
- **Evidence:** `install.sh:44-46`, `:135-143`.
- **Fix direction:** `"$@"` execution; validate URL shape
  (`https://` prefix, no whitespace/newlines).
- **Labels:** hardening, distribution
- **Dedup note:** unreported.

### M-12. `memory: 4096` means MiB on libvirt but BYTES on incus — the README-documented form breaks the default hypervisor

- **Title:** only the libvirt path normalizes through `memory_mb()`
  (verified by execution: `"4096"` → 4096 MB); the incus path passes the
  raw string to `limits.memory`, where a suffix-less integer is bytes
- **Severity:** Medium
- **Confidence:** Medium (incus bytes-interpretation semantics not
  executed end-to-end)
- **Evidence:** examples/deploy/README.md schema:
  `memory: 4GiB # 4GiB | 4096MiB | 4096 (MB)`; `xpf-deploy.py:315`
  (`limits.memory={ap['memory']}` raw).
- **Fix direction:** normalize both backends through `memory_mb()` (emit
  `f"{mb}MiB"` to incus) or reject suffix-less values.
- **Labels:** bug, deployer
- **Dedup note:** unreported.

---

## 8. Findings — LOW CONFIDENCE

### L-1. No public-cloud / NoCloud day-0 channel: the config drive is the only bootstrap input, and it requires hypervisor device attach

- **Title:** cloud-init is purged (deliberately) but nothing replaces its
  transport on clouds where you cannot attach an arbitrary ISO/volume —
  AWS/GCP/Azure imports of the qcow2 have no config channel at all
- **Severity:** Medium (parity/reach)
- **Confidence:** Low (design gap, not a bug; demand-dependent)
- **Evidence:** bake purges cloud-init (`bake.py:320-321`); the loader
  probes only labeled volumes + ISO9660 (`xpf-day0-config:72-77`); vSRX
  supports cloud-init user-data bootstrap on AWS/KVM per Juniper docs.
- **Why it matters:** "qcow2 + libvirt or incus" is covered today; the same
  artifact on a public cloud boots factory-default with console-only
  access — on clouds with no console. Even SMBIOS/OEM-string or
  NoCloud-seed support would close it without resurrecting cloud-init.
- **Fix direction:** teach xpf-day0-config two more read-only sources, in
  priority order after labeled volumes: (a) a NoCloud-style seed (volume
  labeled `cidata` carrying `user-data` that IS an xpf.conf, or an
  `xpf.conf` alongside), (b) SMBIOS type-11 OEM string / qemu fw_cfg
  pointing at an embedded config. All are passive reads; the validation
  gate stays the same commit-check.
- **Labels:** vsrx-parity, enhancement, day-0, cloud
- **Dedup note:** the issue-history sweep confirmed no tracker issue covers
  cloud-init/ZTP-style provisioning; the cloud-init PURGE is deliberate and
  documented (suppressed as such) — the missing replacement transport is the
  novel gap. (Independently re-derived by the deployer sweep: NoCloud
  support would also let virt-manager / incus `cloud-init.user-data` /
  OpenStack config-drive tooling provision xpf with zero custom tooling.)

### L-2. Structurally unsupported root layouts retry-fail the grow every boot forever

- **Title:** LVM/dm or non-ext4 roots hit the grow path's fail-no-stamp
  branch eternally — noise that trains operators to ignore the unit that
  M-5 needs them to notice
- **Severity:** Low
- **Confidence:** High on the fact, Low on it mattering (out-of-scope
  layouts per #1925 §9; nothing enforces the scope)
- **Evidence:** `xpf-grow-root:117-122,162-167`.
- **Fix direction:** distinguish structurally-unsupported (stamp with an
  `unsupported-layout` marker + one loud log) from transient (keep retry).
- **Labels:** cleanup, image
- **Dedup note:** unreported; #1925 declared LVM out of scope but not the
  retry semantics.

### L-3. Grouped minor distribution items

- **Severity:** Low. **Confidence:** High (facts) / Low (impact).
- (a) placeholder detection asymmetry: `sign.py:67-70` detects the image
  placeholder by FILENAME, the archive-key checks by CONTENT — a renamed
  placeholder yields a confusing signature-mismatch instead of a crisp
  refusal (still fail-safe).
- (b) `XPF_PUBLISH_CMD` is argv[0]-only (`publish.py:348`); `rsync -a` as a
  value crashes with a raw traceback; docs don't state single-executable.
- (c) reprepro branch of build-apt-repo.sh skips the deb-path charset guard
  the flat branch has (`:85-88` vs `:106-113`).
- (d) install.sh kernel parse dies on single-component versions
  (`6.18-rc1`).
- (e) `scripts/dist/README.md` files table omits selftest.sh.
- (f) no apt-pool↔Packages hash consistency check in the publish gate
  (availability-only; apt protects clients).
- **Fix direction:** content-based placeholder detection everywhere;
  `shlex.split` or documented single-executable for the shim; copy the
  charset guard; tolerate 2-component kernels; doc touch-ups.
- **Labels:** cleanup, distribution
- **Dedup note:** all unreported.

### L-4. Deployer YAML handling: silent key drops and no strict validation

- **Severity:** Low. **Confidence:** High (facts).
- `mac:` honored for net/bridge/macvlan/sriov/pci but silently discarded
  for `physical`; typo'd keys (`mac_address:`, `roles:`, `backing: SRIOV`)
  are silently ignored or die generically; unknown top-level keys dropped
  without warning; `appliance.name` is unvalidated and flows into the ISO
  path (`../x` escapes cwd) and instance names.
- **Fix direction:** whitelist keys and die on unknowns; die on
  `physical`+`mac`; `[A-Za-z0-9-]` name check.
- **Labels:** cleanup, deployer
- **Dedup note:** unreported.

### L-5. Deployer error-shape paper cuts: typo'd YAML path / missing curl are raw tracebacks; a typo'd subcommand misroutes into the deploy shorthand

- **Severity:** Low. **Confidence:** High.
- `load_yaml_appliance` open() unguarded → FileNotFoundError traceback;
  `fetsh --version 1` falls into the bare-YAML deploy shorthand and errors
  from the wrong parser; `cmd_fetch` assumes curl exists.
- **Fix direction:** die() wrappers; restrict the shorthand to args ending
  in `.yaml`/`.yml`.
- **Labels:** cleanup, deployer, UX
- **Dedup note:** unreported.

### L-6. Day-0 ISO lifecycle unmanaged

- **Severity:** Low. **Confidence:** High.
- `build_config_drive` writes `{name}-day0.iso` into cwd (silent
  overwrite); the incus/libvirt device references that path forever
  (moving it breaks the next VM start); concurrent same-name deploys race;
  `--dry-run` doesn't check the config file exists so a preview passes on
  a path that fails for real.
- **Fix direction:** stage ISOs under a stable dir
  (`/var/lib/xpf-deploy/`), detach on destroy (H-27), existence-check in
  dry-run.
- **Labels:** cleanup, deployer, day-0
- **Dedup note:** unreported.

### L-7. Global pre-parser quirks: abbreviation and option-stealing

- **Severity:** Low. **Confidence:** High (executed).
- `--dry` is consumed as `--dry-run` (allow_abbrev default); a stray
  `--image` on `kernel-roll` (meaningless there) is silently stolen by the
  globals. (`--image-url` is NOT swallowed — verified negative.)
- **Fix direction:** `allow_abbrev=False`; warn on irrelevant globals.
- **Labels:** cleanup, deployer
- **Dedup note:** unreported.

### L-8. `fetch` hygiene: `.tmp` droppings, unconditional re-download, repo-layout dependence

- **Severity:** Low. **Confidence:** High.
- Failed curl leaves `dst.tmp`; re-running re-downloads multi-GB artifacts
  that already verify locally; a copied-out `xpf-deploy.py` (natural for a
  "single Python tool") throws `ModuleNotFoundError: sign` because of the
  `scripts/dist` sys.path insert; minisign + real-pubkey prerequisites are
  not in the quickstart.
- **Fix direction:** clean tmp on failure; skip verified local files;
  guard the import with a die() explaining prerequisites.
- **Labels:** cleanup, deployer, distribution
- **Dedup note:** unreported.

### L-9. Deployer/docs cosmetic drift and gaps (grouped)

- **Severity:** Low. **Confidence:** High.
- examples/deploy/README.md "No shell scripts." vs image-roll's mandatory
  `--recreate-hook <script>` (and no example hook ships for the common
  incus case — the tool already contains all the logic a built-in incus
  recreate needs); `launch` cannot set `pool` (YAML-only asymmetry);
  virt-manager GUI flow undocumented (one paragraph would cover GUI
  shops); no doc states ZTP/phone-home is a non-goal.
- **Fix direction:** built-in incus recreate implementation (hook only for
  exotic backends); `launch --pool`; short virt-manager + non-goals
  paragraphs.
- **Labels:** docs, deployer
- **Dedup note:** unreported.

### L-10. No post-launch acceptance check (`deploy --verify`)

- **Severity:** Low (enhancement; closes the loop on H-22)
- **Confidence:** High that it's absent.
- Both docs end with "verify the realized map" by hand. The tool can do
  it: exec `cli -c "show interfaces terse"` in the guest, diff against
  declared roles, exit non-zero on mismatch.
- **Fix direction:** `deploy --verify` (incus exec / virsh console
  expect-lite or ssh once credentials exist per H-29).
- **Labels:** enhancement, deployer, day-0
- **Dedup note:** unreported; independently valuable beyond H-22's
  validator fix (catches host-side surprises the validator can't see).

---

## 9. Suggested issue split

Grouped so each issue is one reviewable PR-sized unit of work; titles are
suggestions. Ordered by triage priority.

1. **[bug][day-0] day-0 config-drive retry permanently disabled by eager
   `.configdb` creation** — H-1 (+ validate.py retry scenario from H-9).
2. **[bug][day-0][image] appliance image ships without frr-pythontools:
   FRR reload permanently degraded, stale-config removal never converges**
   — H-3 (+ bake assert + validate check).
3. **[bug][day-0][libvirt] deployer libvirt path: shared golden qcow2,
   dead `--no-start`, broken `physical` backing, fetch→path gap, no disk
   knob** — H-20, H-26, H-23, H-30, H-38 (one libvirt-correctness PR).
4. **[bug][security][deployer] validator blind to virtio-first tiebreaker
   (silent zone swap) + post-launch `--verify`** — H-22, L-10.
5. **[bug][distribution] install.sh one-liner cannot run as documented;
   publish-time URL substitution + gate; validate-then-mutate; uninstall
   story** — H-2, H-14, H-16, M-11.
6. **[bug][security][distribution] apt channel bleed via shared pool** — H-4.
7. **[bug][security][distribution] publish gate default-deny sweep
   (unsigned debs / latest.json / key-agreement)** — H-5, H-13, H-15, M-7.
8. **[bug][packaging] .deb parity: promote-failed unit missing;
   systemd-networkd dependency; frr-pythontools (with #2)** — H-6, M-6.
9. **[bug][kernel-channel] A/B substrate hardening: uefi-slots/promote
   ordering, NVRAM-wipe reseed vs promotion marker, OnFailure loop guard,
   slots timeout, Type=notify readiness** — M-2, M-3, M-4, M-9, M-10.
10. **[bug][day-0][interfaces] positional rename loop: two-pass collision
    safety + originals snapshot** — H-7.
11. **[bug][day-0][device-map] run strand-management preflight in
    check-config + bootstrapFromFile** — H-8.
12. **[bug][day-0][HA] empty-config HA takeover naming + node-identity
    SSOT (file vs leaf) + lax file parsing** — H-10, H-12.
13. **[enhancement][day-0][observability] bootstrap cause surfaced as
    alarm//health/show + factory-boot WARN fix** — H-11, H-17.
14. **[bug][HA][deployer] roll orchestration: kernel-roll lease TTL-hold,
    node-id order keying, ssh host-key handling, signed image-roll
    manifest** — H-32, H-33, H-35, H-31.
15. **[test-gap] wire the day-0/dist/deployer self-tests into `make test`
    + new coverage (validate.py libvirt/node-id/retry scenarios,
    bootstrapFromFile, rename loop, day0 script, channel isolation,
    maintainer-script roundtrip, deployer pure functions +
    `_gate_mixed_base` parity vectors)** — H-9, H-19, H-24, H-25 fix.
16. **[bug][day-0][image] grow-root: verify the invariant before stamping;
    unsupported-layout terminal state; ssh-hostkey regen decoupled from
    the day-0 stamp** — M-5, L-2, M-8.
17. **[enhancement][deployer][UX] preflight/idempotency/destroy;
    stderr surfacing; per-subcommand help; standalone bridge prereqs;
    memory normalization; fetch alias atomicity + hygiene; YAML strict
    keys; ISO lifecycle** — H-21, H-27, H-28, H-36, M-12, H-39, L-4..L-8.
18. **[vsrx-parity][day-0] credentials: example root-authentication,
    console-posture docs, check-config warning on credential-less ssh** —
    H-29.
19. **[vsrx-parity][cloud] NoCloud/SMBIOS day-0 transport for public-cloud
    and generic-tooling provisioning** — L-1.
20. **[docs] quickstart teaches unverified import; runbook installer step
    dead-ends; device-map `commit check` confirm error; drift batch** —
    H-37, H-14 (docs half), H-18, L-3(e), L-9.

## 10. Campaign summary

- **61 findings** total: 39 high-confidence (10 of them High-severity),
  12 medium-confidence (1 High-severity: M-1 install auto-start lockout),
  10 low-confidence/grouped — every one novel against 30+ prior review
  files and the full issue-tracker history.
- The day-0 SECURITY core (day-0 loader hardening, sign.py crypto,
  seed-runtime, lease machinery, boot-class fail-closed logic) repeatedly
  survived adversarial reading — the carefully-reviewed paths are genuinely
  good. The gaps cluster in the CONNECTIVE TISSUE: paths only customers
  run (libvirt, apt-on-foreign-host, fix-and-reboot retry), parity between
  the bake and the .deb, and tooling that acts before it validates.
- The three findings that most directly contradict the "day-0 super easy"
  goal: H-1 (the advertised retry loop is dead), H-2 (the advertised
  one-liner cannot run), H-20 (the advertised libvirt path corrupts its
  own golden image). All three have small, mechanical fixes.
- Inspection log proves module coverage for all 18 modules including the
  negative results (incus-agent inertness, 09_xpf, seed-runtime, compile
  pipeline parity, config-drive contract consistency, lease machinery).


