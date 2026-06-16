# Claude SMR hostile review — #1917 plan v1, round 1

**Verdict: PLAN-NEEDS-REVISION** (not KILL — the recommended composition is
sound; three blocking corrections + the framing needs sharpening).

I am reviewing as domain SMR (xpf dataplane/HA), Debian/systemd packaging, and
on-disk state-format compat. I verified the load-bearing claims against code.

## Verified-correct (the plan got these right)

- **xpfd cannot re-attach to a running helper — CONFIRMED.** process.go:24-86:
  the helper is `exec.Command` (line 76); `m.proc` is the `*exec.Cmd` held in
  xpfd process memory; a fresh xpfd starts `m.proc == nil`, and the bind path
  `stopLocked()`s any prior helper and spawns a new one, clearing XSKMAP entries
  (process.go:64-71) because they point to dead socket fds. There is **no PID
  file xpfd persists for re-attach** (grep: the only persisted state-file is the
  *Rust helper's* `--state-file`, written by `state_writer.rs`, not an xpfd
  re-attach handle). So **"zero-gap xpfd-only hot restart does NOT exist"** is
  correct, and the plan's down-scoping of the issue's stated acceptance
  ("standalone xpfd-only restart with ZERO dataplane gap") is the single most
  important correction this plan makes. Keep it front-and-center.

- **No config-DB version manifest — CONFIRMED.** db.go marshals
  `config.ConfigTree` to `active.json` with no version field; rollback slots are
  re-parsed text. The codex-review-010 manifest requirement is real and adopted
  correctly.

- **Protocol lockstep via `Depends: (= same version)`** correctly closes the
  *common* upgrade mismatch window and correctly leaves only the M-mech-2
  hot-reattach window open (protocol.go:11 / control.rs:22).

## Blocking corrections

1. **§6.1 ships a phantom artifact. The shim is EMBEDDED, not a file.**
   userspace_xdp_rust.go:11 is `//go:embed userspace_xdp_bpfel.o` — the verifier
   gate consumes the `.o` *compiled into the Go binary*, not a file at a runtime
   path. So an `xpf-dataplane` package that ships "the AF_XDP shim object… to a
   fixed path xpfd reads" ships **dead weight nobody loads**, and worse invites a
   drift hazard (a file `.o` diverging from the embedded one). **Fix:** the shim
   travels *inside* the xpfd binary; the `xpf-dataplane` package's only real
   artifact is `xpf-userspace-dp`. Either fold xpfd+helper into one package
   (they already `Depends: = same version`) or keep two packages but DROP the
   separate-`.o` claim. This also weakens open-question #6's framing — answer it
   in the plan: "embedded, so no file shipped."

2. **The held-kernel contradiction is real and the plan under-states it (RISK #2
   is necessary but the §5-Path-A pros oversell).** The operator's premise is
   "base OS self-updates via apt." But the verifier floor forces holding
   `linux-*`. So the component with the highest CVE surface (the kernel) is
   exactly the one apt does NOT update — Path A's headline value ("base CVEs flow
   automatically") is *false for the kernel*. The plan must say this in §5 Path A
   cons, not bury it in the risk table: **Path A delivers automatic base updates
   for everything EXCEPT the kernel, which is the part you most wanted automated.**
   A reviewer could reasonably escalate this to PLAN-KILL of the unqualified
   all-`.deb` framing. Mitigation to add: a `postinst`/`xpf-upgrade
   precheck-kernel` that re-runs `verify-dataplane` against a candidate kernel in
   a holding state before allowing the unhold — i.e. gate the kernel bump on a
   verify PASS rather than blanket-hold forever. That turns "hold the kernel" from
   a permanent contradiction into a "verify-gated kernel channel," which is a
   defensible answer to open-question #2.

3. **Config-DB manifest chicken-and-egg (open question #5) is currently
   under-specified and must be resolved IN the plan before PLAN-READY.** binary N
   never wrote a manifest and never reads the journal at boot. N+1 must
   distinguish "no manifest ⇒ legacy N-written state, parse it" from "no manifest
   ⇒ truncation/corruption." The plan adopts the manifest but doesn't say how the
   *first* N→N+1 transition is safe. **Fix:** specify that absence-of-manifest is
   treated as schema-version-0 (legacy, parse-and-then-write-a-manifest-on-first-
   successful-load), and that corruption is caught by the existing
   parse/unmarshal error (a truncated active.json fails `json.Unmarshal`
   independent of the manifest). The manifest's job is forward-gating (N reading
   N+1 state), not backward detection. State that explicitly.

## Non-blocking but should land

- **§6.4 standalone gap honesty (open question #3):** the 3s NAPI bootstrap
  window (process.go:108-112) is a *floor*, and the full helper respawn + XSKMAP
  repopulate + session re-sync is plausibly several seconds of total dataplane
  loss on a standalone box. The plan already flags this; it should commit to
  *measuring* it in the test plan (it does) and to the honest conclusion: if the
  measured standalone gap is multi-second, then "in-place" standalone is only
  marginally better than image-replace for anything but mgmt-plane continuity, and
  the issue's "zero dataplane gap" standalone acceptance is **unmeetable** without
  M-mech-2. Say that as a conclusion, not just a test.

- **Open question #1 (is #1917 a dup of #1923 + a new HA issue?):** the plan's
  reconciliation (#1917 = mechanism + workflow + HA-rolling, consuming #1923,
  deferring to #1924, depending on #1922) is the right answer. I'd make it a
  recommendation in the issue comment: **re-scope #1917 to the
  mechanism+HA-rolling umbrella; the packaging is #1923.** Don't leave it as a
  parallel fourth effort.

- **Open question #7 (auto-rollback mid-rolling-HA):** I agree this is dangerous.
  Recommend the plan state a hard rule: **auto-rollback is standalone-only; in
  HA, rollback is operator-driven** (a node that fails post-cut health stays
  drained/secondary and alerts, rather than auto-reverting into a version-split
  cluster). Add to §8 invariants + RISK table.

## Bottom line

The recommended composition (A-packaging + B-mechanism, C-for-kernels) is
correct and well-reasoned, and the plan's headline finding (no zero-gap hot
restart today) is verified and valuable. But it ships a phantom shim file,
under-states the kernel contradiction, and leaves the manifest first-upgrade
case under-specified. Fix those three and resolve open-questions #2/#3/#5/#7 into
stated conclusions, and this is PLAN-READY.
