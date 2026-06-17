# Claude SMR hostile plan review — #1916 r3 (final)

**Verdict: PLAN-READY.**

r3 resolves my r2 M1 and folds in all of Codex's and AGY's r2 findings
without introducing a new contradiction. I re-attacked the new r3 material
and found nothing blocking.

---

## My r2 M1 — RESOLVED

cert is now **DurableState** consistently across §1 item 2, §2.A table,
§4 D6, §5 D5 step 4 (`WriteFileDurable(certPath, ...)`), §7 risk table,
and §8 docs. The non-loopback bind premise is cited to
`daemon_run.go:1093-1099`. The r2 "loopback / drop the harm" reasoning is
retained only inside the §12 *r1→r2 historical changelog* (accurate as a
record of what r2 said) — not as a live claim. Correct.

## Cross-checks on the other reviewers' r2 findings (all folded in)

- **Codex HIGH#1 (strict unlink)**: D5 step 2 now "ignore ONLY
  `os.IsNotExist`; on ANY other remove error OR `SyncDir` error, abort to
  step 5 (do NOT write)." This *proves* the {neither} start. Tests added
  (remove-failure, dir-sync-failure). Resolved.
- **Codex HIGH#2 (/etc/timezone + count)**: now in §2.B at line 111; count
  corrected to "36 real calls, 4 comment hits incl. `frr/manager.go:502`."
  Resolved.
- **Codex MED#1 (caller wiring)**: D5 step 5 + Step 1 — persistence
  failure returns the in-memory cert with NIL error so the existing
  `else`-branch at `server.go:264-277` still installs `httpsServer`;
  server-level test asserts `httpsServer != nil` on disk failure.
  Coherent. Resolved.
- **Codex MED#2 / AGY #6b (receiver-aware keying)**: D1 + Step 6 extend
  the AST keyer to `relpath::RecvType.MethodName` (strip leading `*`),
  with the concrete allowlist forms and a keyer unit test. Closes the
  same-package same-name hole. Resolved.
- **Codex LOW (WithOwner precedence)**: Step 0 — explicit `WithOwner` wins
  ownership, `WithPreserveExisting` may keep mode; precedence unit test.
  Resolved.
- **AGY #3 (timezone early-return loophole)**: Step 2b — early-return
  guard now requires BOTH `/etc/localtime` target AND `/etc/timezone`
  content to match before skipping. This is the correct fix for the
  crash-between-symlink-and-file stale-forever case. Resolved.
- **AGY #6a (cgo-free uid/gid)**: Step 0b — extend `lookupUID` →
  `lookupUIDGID` parsing `/etc/passwd` (uid field 2, gid field 3); no
  `os/user`. Consistent with the verified codebase convention
  (`login_password.go:115-137` "cgo-free"). Resolved.

## New-material re-attack (r3 changes) — no blockers

- **cert=DurableState cost**: one extra fsync on the cert regen path. That
  path runs only when `tls.LoadX509KeyPair` fails (first boot or after a
  lost pair) — operator/boot-paced, not per-apply. Within the project's
  "fsync on operator-paced paths only" rule. Fine.
- **D5 both-files-durable interaction with the strict-remove**: after the
  strict remove+SyncDir, key durable, cert durable — the only crash states
  remain {neither}, {key-only}, {both-matching}. With BOTH durable, a
  crash after the key write self-heals on the next *successful* regen (or
  stays key-only → `LoadX509KeyPair` errors on the missing cert → regen).
  No mismatch. The argument is unchanged from r2 and still holds; making
  the cert durable does not weaken it. Good.
- **lookupUIDGID GID source**: `/etc/passwd` field 3 (0-indexed [3]) IS
  the primary GID. The plan's "field 3" matches `name:x:UID:GID:...`.
  Correct. (Impl note for /engineer: the user's primary group must exist;
  it does for a `useradd -m` user. Not a plan blocker.)
- **No new contradiction introduced**: cert class, timezone class, sshd
  class are each stated once-consistently. Inventory count is internally
  consistent (36 real). §10 correctly states no open design questions
  remain, flagging only the D6 reversal for Codex/AGY ack.

## Verdict

PLAN-READY. The design is correct, the inventory is exhaustive and
receiver-keyed, the TLS path is crash-safe and non-silent, ownership is
fixed at the right layer (temp-fd chown before rename, cgo-free uid/gid),
and validation includes the failover gate the touched RETH files require.
Recommended path: ship the recommended option set (Path A receiver-aware
canary + D5 strict + D6 cert-durable + D7-a WithOwner + D8 failover) at
`/engineer 1916`.
