# Triage Result: ps-review-040-A4-b1

- **Subsystem:** A4 — `pkg/configstore` (durable storage, encryption envelope, commit/confirm rollback, history/archival)
- **Review base commit:** `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc`
- **Triaged against:** `origin/master` = `95b33d49634d56086269a62a92e213dae7926f88`
- **base == master?** No — base is an ancestor of master (`git merge-base --is-ancestor` = YES, base is behind). Cited line numbers land within a few lines of the master copies; all three cited code regions verified verbatim on master.
- **Repo:** real `bpfrx` (all cited symbols exist in `pkg/configstore/*.go` on origin/master — NOT the avacado-xpf fork).
- **Outcome counts:** 3 findings → **1 NOT-MATERIAL** (F1) + **2 GENUINE-RESIDUAL** (F2 INFO/cosmetic, F3 LOW). 0 already-fixed, 0 confabulated, 0 dup.
- The report's 39 NEGATIVE-RESULT module sweeps are consistent with the ps-038 finding that A4/configstore is well-hardened; not re-audited line-by-line (out of scope — only the 3 detailed findings triaged).

---

## Finding 1 — LoadSet/LoadMerge partial mutation on line error → **NOT-MATERIAL**

**Symbol exists?** Yes. `pkg/configstore/store_command.go` on master: `LoadSet` (func at line ~390, loop 402-419 verbatim as quoted) and `LoadMerge` flat branch (283-293) both call `applyEditLine(s.candidate, ...)` in a loop and `return` mid-loop on error. `LoadOverride` (220-243) parses whole into `tree` then swaps. The finding's read of the code is accurate.

**Already fixed?** No. No atomicity/clone guard added in the #4517-#4685 range (git log of `store_command.go` shows only `#4476` idle-lease + `#4587` annotate + merges). No test asserts atomicity.

**Why NOT-MATERIAL (severity Medium is overstated → effectively INFO):**
1. **Candidate is staging, not active.** The mutation lands on `s.candidate`, the operator's scratch tree. The canonical `s.active` and on-disk config are untouched. A dirty candidate cannot corrupt the running config — only `Commit` promotes it, and the operator reviews with `show | compare` first.
2. **Lock held throughout.** `s.mu.Lock()` + `defer s.mu.Unlock()` span the whole loop, so no concurrent reader/writer ever observes a torn half-state *during* execution. The only "residual" is post-return state in the caller's own session.
3. **Clear, line-numbered error is returned** (`line %d: %q: %w`), and `LoadSet` returns the successful `count`. The operator/orchestrator is explicitly told which line failed and how many applied — this is actionable, not silent.
4. **This is Junos `load set` / `load merge` semantics.** In Junos, a `load set` (or `load merge terminal`) that errors mid-stream leaves the earlier commands applied to the candidate; it does NOT roll back the whole load. The operator inspects with `show | compare` and either fixes-and-reloads or `rollback 0`. So the behavior is the intended vSRX-parity behavior, not a defect. Wrapping in a clone-and-swap would actually *diverge* from Junos.
5. **Recovery is trivial and idempotent:** `rollback 0` (or exiting/re-entering config mode, which re-clones active→candidate) discards the partial state. A retrying orchestrator that re-enters config mode starts fresh.

No security, crash, or active-config-corruption impact. Real code observation, below the materiality bar. Not listed as a genuine residual.

---

## Finding 2 — Concurrent auto-archive goroutines race in rotateArchives → **GENUINE-RESIDUAL (INFO / cosmetic)**

**Symbol exists?** Yes, verified on master:
- `pkg/configstore/store_commit.go:152` spawns `go func() { if err := writeArchive(dir, max, data, ts, seq); ... }()` at the tail of `CommitWithDescription`, off-lock (data/ts/seq captured under lock first — the #3441 H4 fix).
- `writeArchive` (store_persist.go:419) calls `rotateArchives(archiveDir, maxArchives)` at 446.
- `rotateArchives` (464-491) does `os.ReadDir` → sort → `for i ... os.Remove(path)`; on ANY remove error (including ENOENT) it logs `slog.Warn("failed to remove old archive", ...)`. No serialization, no `os.IsNotExist` guard. Matches the finding verbatim.

**Reachable?** Yes. Commits serialize on `s.mu`, but each commit spawns its OWN detached `writeArchive` goroutine that runs *after* the lock releases. Two rapid back-to-back commits (scripted/orchestrated) → goroutines GA and GB run concurrently → both `ReadDir` the same archive dir → both target the same oldest-beyond-max files → one `os.Remove` wins, the loser gets ENOENT → spurious warning.

**Already fixed?** No. `#4621` (`daemon: stage config archive via fsatomic.WriteFileAtomic`) touched the daemon staging path, not this in-store rotation race. `rotateArchives` on master still warns on ENOENT.

**Why INFO / cosmetic (not higher):**
- **No data loss.** Archive filenames are unique (`config-<ts>.<seq>.conf`, #3441 H4 seq tiebreak), written atomically. The "keep" set is the newest `maxArchives`, which only grows as new archives arrive; the "delete" set is strictly the oldest-beyond-max. A race can only double-delete a file that was *already* destined for deletion — it can never delete a file that should be kept. Rotation remains functionally correct.
- **Only impact:** a misleading `failed to remove old archive: ... no such file or directory` warning in journald, which reads as a real fault when it is benign. That is genuine (if trivial) operator-noise, hence a real residual rather than NOT-MATERIAL, but there is no correctness or availability consequence.

**Fix (trivial):** in `rotateArchives`, wrap the remove error in `if err := os.Remove(path); err != nil && !os.IsNotExist(err) { slog.Warn(...) }` (mirrors the existing #3441 L3 ENOENT-tolerant pattern already used in `cleanupRollbackFiles`). Optionally guard the whole `writeArchive`/rotate with a per-store archive mutex, but the ENOENT guard alone removes the noise. **Lane: go.**

---

## Finding 3 — loadRollbackHistory logs raw ParseError (may embed secret token) → **GENUINE-RESIDUAL (LOW)**

**Symbol exists?** Yes, verified verbatim on master, `pkg/configstore/store_commit.go:805`:
```go
if len(errs) > 0 {
    slog.Warn("skipping corrupt rollback file", "path", path, "err", errs[0])
    continue
}
```
`errs[0]` is a `config.ParseError` whose `Error()` = `"line %d, column %d: %s"` embedding `ParseError.Message` (`pkg/config/parser.go:6-14`). Several `addError` call sites populate `Message` from raw token text (e.g. `parser.go:149` `p.addError(tok.Line, tok.Column, tok.Value)`), so `Message` can carry the offending token verbatim. slog renders `errs[0]` via its `Error()` string. Rollback files (`xpf.conf.N`) hold the full committed config TEXT with cleartext secrets (IKE PSK, auth-keys, SNMP community) at 0600 (see the loader's own 720-724 comment). The finding's read is accurate.

**Already fixed?** No. Still `errs[0]` raw on master; no line/column-only rewrite for this loader.

**Real + material — this is a genuine gap in an invariant the project actively enforces:**
- The project established a "never echo a ParseError (which embeds a secret token) on parse failure" invariant in **#4099** for the sibling path `LoadRescueConfigRedacted` (store_persist.go:545-585). That fix deliberately returns *position-only* (`"parse failed at line %d, column %d"`, `perrs[0].Line/.Column`) and its test (`rescue_redaction_leak_4099_test.go`) pins the RED-on-revert: `ParseError.Error()` embeds `ParseError.Message` populated from the tampered file content. `loadRollbackHistory` is the same class of loader (parses saved config TEXT bearing cleartext secrets) but was **missed** — it still forwards the raw error.

**Why LOW (not the MED/HIGH that #4099-class might suggest):**
- **Weaker sink than #4099.** #4099 returns the error to a **VIEW-only CLI caller** (a genuinely lower-privileged login class crossing a privilege boundary). Here the leak goes to `slog.Warn` → journald, a **root/adm/systemd-journal-readable** system log — not a per-request low-priv caller. The wider-blast-radius scenario requires off-box log forwarding (syslog/SIEM) to be configured.
- **Requires a corrupt/tampered rollback file.** Daemon-authored files are always well-formed (`SaveRescue`/rollback writes render a valid tree via `Format()`), so a parse error implies on-disk corruption or manual tampering — and the party who can write/corrupt a 0600 root-owned file can already read the plaintext secret directly.
- **Leak is conditional on WHERE corruption lands** — the token echoed is only a secret if the malformed token happens to be/adjoin the PSK/community leaf.

Still a legitimate defense-in-depth residual: the project treats exactly this leak class as worth closing (#4099/#4051/#4060), and this is an un-addressed sibling.

**Fix:** log position only, matching #4099:
```go
slog.Warn("skipping corrupt rollback file", "path", path, "line", errs[0].Line, "column", errs[0].Column)
```
**Lane: go.**

---

## Summary

- **F1** — NOT-MATERIAL: candidate-only staging, lock held, clear line-numbered error, matches Junos `load set` incremental-apply semantics; recoverable via `rollback 0`. Medium is overstated.
- **F2** — GENUINE-RESIDUAL, INFO/cosmetic: real reachable two-goroutine archive-rotation race, but impact is a spurious ENOENT warning only; no data loss (rotation stays correct). One-line `os.IsNotExist` guard.
- **F3** — GENUINE-RESIDUAL, LOW: real secret-leak-to-log consistency gap vs the #4099 redaction-on-parse-failure invariant; bounded by privileged journald sink + requires corrupt/tampered file. Position-only log fix.
