# Claude SMR confirmation — #1917 plan v4, round 3

**Verdict: PLAN-READY.**

Round-2 Codex caught a genuine correctness defect that my own round-2 SMR pass
missed (I had given PLAN-READY prematurely). I empirically verified both the
defect and the v4 fix.

## The defect (round-2 Codex blocker #1) was real — verified empirically

`config.ConfigTree` has exactly one field, `Children []*Node` (ast.go:99) — no
version field. A naive object envelope `{ "manifest":..., "tree":... }` is unsafe
because Go's `json.Unmarshal` ignores unknown object fields. I ran the three
encodings against a `ConfigTree`-shaped struct:

- `# hdr\n{...}` (magic header) → `invalid character '#'` — **fails closed ✓**
- `[manifest, tree]` (top-level array) → `cannot unmarshal array into Go value` —
  **fails closed ✓**
- `{ "manifest":..., "tree":... }` (naive object) → **err `<nil>`, empty
  children** — the silent empty-load defect. **UNSAFE.**

So Codex was right, my r2 was wrong, and the v4 fix (mandate an old-reader-
REJECTING encoding + a legacy-reader test proving N errors not empty-loads) is
the correct resolution, now empirically grounded.

## The other two round-2 Codex blockers — resolved

- **Single install form (blocker #2):** v4 §6.3 deletes the `/usr/local/sbin`
  live-overwrite alternative entirely; the only form is versioned dir + symlink
  flip + absolute-path staged launch. This closes the old-xpfd-respawns-new-helper
  window (`findBinary`, process.go:168). §6.1 ships `xpf-upgrade` in the versioned
  dir so the staged orchestrator is reachable by absolute path.
- **Kernel watchdog (blocker #3):** v4 §6.7 specifies a HW/softdog watchdog armed
  before `grub-reboot`, disarmed only after verify+health, GRUB default unchanged;
  and honestly states the no-watchdog bound (GRUB default preserved, early-boot
  hang needs external recovery). The "never brick" claim is now conditioned on the
  watchdog — honest.
- **dh flag:** v4 uses `--no-stop-on-upgrade` (not the deprecated
  `--no-restart-on-upgrade` alias) + pins debhelper-compat.

## Convergence summary

- Round-1: Codex / Claude-SMR / AGY all PLAN-NEEDS-REVISION (no KILL); composed
  A(packaging)+B(mechanism)+C(kernel) endorsed by all three.
- Round-2: Codex 3 blockers (fixed in v4), SMR premature-READY (corrected here),
  AGY 4 round-1 blockers all incorporated.
- Round-3: all round-2 Codex blockers verified resolved; the critical one
  empirically proven.

Recommend PLAN-READY pending round-3 Codex + AGY concurrence. This is research
only — STOP at PLAN-READY; the operator approves `/engineer 1917`.
