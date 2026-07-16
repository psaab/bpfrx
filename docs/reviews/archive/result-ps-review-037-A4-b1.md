# Triage result — ps-review-037-A4-b1 (A4: Go configstore, persistence & crypto-at-rest)

- **Subsystem:** Go configstore / persistence / crypto-at-rest — `pkg/configstore/*`,
  `pkg/config/{ast_redact,secret}.go`, `pkg/fsatomic/fsatomic.go`,
  `pkg/grpcapi/server_diag.go` (zeroize path).
- **Base:** d4506d445 (Merge #4571). Current origin/master: 32d96607a.
  The 4 intervening commits (#4572 workers-clamp, #4567 UDP-frag-flood) touch
  `pkg/dataplane/userspace` + `userspace-dp/src/screen` ONLY — nothing in A4's
  scope. **base == master for this subsystem; no stale-base false-opens.**
- **All cited symbols exist on origin/master** (no confabulation). Verified:
  `performZeroizeWipe` (server_diag.go:755), `store.New`/`.configdb`
  (store.go:195), `DB.activePath`/`masterKeyPath` (db.go:71 / crypto.go:34),
  `maybeEncryptTreeJSON`/`maybeDecryptTreeJSON`/`unmarshalEnvelope`/
  `masterPasswordPRF` (crypto.go), journal `OpenFile ... 0644` (journal.go:180),
  `confirmTimer`/`AfterFunc` (store_commit.go:269), `Load` (store_persist.go:19),
  `WriteFileDurable`/`MkdirAllDurable` (fsatomic.go:128/159), envelope helpers
  (envelope.go), `file_perms_4056_test.go`, schema `master-password` /
  `pseudorandom-function` (schema_system.go:113-114).

## Outcome counts
- GENUINE-RESIDUAL (novel): **6** (1 HIGH, 1 MEDIUM, 4 LOW/INFO) — note A4-04 is
  the same root cause + same fix as A4-01, so effectively **5 distinct fixes**.
- NEGATIVE (clean, well-reasoned): 2 (A4-08, A4-09).
- CONFABULATED: 0. DUP: 0 (A4-02/04/07 are *partial* overlaps, still novel residuals).

No A2-pattern (HIGH refuted by an upstream guard) and no #4572-pattern (headline
exploit already neutralized) here — the headline A4-01 traces cleanly to a
reachable factory-reset leak with no upstream mitigation.

---

## Per-finding dispositions

### A4-01 — GENUINE-RESIDUAL — HIGH — zeroize does NOT wipe `.configdb` (active.json + master.key survive factory reset)
**Disposition: GENUINE, NOVEL, reachable. This is the real finding of the batch.**

Traced end-to-end on master:
- `performZeroizeWipe` (server_diag.go:755-772) removes only top-level
  `/etc/xpf/*.conf` + `rollback*` files, `/sys/fs/bpf/xpf`, and `10-xpf-*`
  networkd files. It NEVER touches `/etc/xpf/.configdb/` (dot-prefixed dir; the
  `HasSuffix(".conf")` / `HasPrefix("rollback")` filters skip it) nor
  `/etc/xpf/.config.journal`.
- `store.New` (store.go:195) makes `.configdb` the *sole* persistence backend
  ("no file-only fallback exists"). The active config lives at
  `.configdb/active.json` (db.go:71-72), the AES key at `.configdb/master.key`
  (crypto.go:34-36), rollback slots at `.configdb/rollback.N.json`.
- `Store.Load` (store_persist.go:19-45) reads `.configdb/active.json`
  (`ReadActiveMeta`) → sets `everCommitted=true` for a committed DB → the daemon
  boots the OLD tenant config.
- **Decisive negative check:** `git grep RemoveAll` over `pkg/` finds NO removal
  of `.configdb`/`.config.journal`/`/etc/xpf` anywhere except the BPF-pin dir.
  `pkg/daemon` boot has no zeroize marker / no post-reboot `.configdb` wipe. So
  nothing neutralizes this downstream — the surviving config + key are reloaded.

Impact: `request system zeroize` reports "Configuration erased. Reboot to
complete factory reset." yet the box reboots with the previous tenant's full
firewall policy, NAT, IKE PSKs, WG private keys, SNMP communities, AND the
master.key that decrypts them. RMA/resale/multi-tenant hand-off leaks the prior
tenant's secrets and policy. **HIGH is justified** (security-boundary violation
+ operator explicitly requested a wipe + secrets at rest).

Dedup: **NOT** covered. #4108 (CLOSED) is zeroize *RBAC* (operator class can
invoke it) + zeroize *audit-journal* wiring (F8) — the journal survival there is
*intentional* (attribution). No issue covers `.configdb`/`master.key` survival.
`gh issue --search "configdb"/"factory reset"` returns nothing on point.

Fix: extend `performZeroizeWipe` with `os.RemoveAll("/etc/xpf/.configdb")`
(remove `master.key` FIRST — key-before-ciphertext so a power cut mid-wipe fails
closed) and decide the `.config.journal` policy explicitly (keep for attribution
is defensible but must be documented, since it is NOT a full wipe).

### A4-04 — GENUINE — MEDIUM — master.key co-located with ciphertext, survives zeroize
**Disposition: GENUINE but SAME ROOT CAUSE + SAME FIX as A4-01.** master.key is
`filepath.Join(db.dir, "master.key")` = `.configdb/master.key` (crypto.go:34),
written 0600 via `WriteFileDurable` (crypto.go:248), and `performZeroizeWipe`
never touches it — identical to A4-01. The "co-located key defeats disk-theft
protection" observation is valid design commentary (encryption protects against
accidental `active.json` exposure, not a stolen disk), and the zeroize-must-
delete-key requirement is real. Fold into the single A4-01 fix (RemoveAll
`.configdb`, key first). Distinct from **#4549** (in-memory PSK zeroize / a
`[u8;32] Clone` not `Zeroizing`) — that is RAM hygiene, this is on-disk erasure.
Not a separate PR; track as the master.key facet of A4-01.

### A4-03 — GENUINE-RESIDUAL — MEDIUM — commit-confirmed timer is in-memory only; crash loses the auto-rollback
**Disposition: GENUINE, NOVEL.** Confirmed: `confirmTimer = time.AfterFunc(...)`
(store_commit.go:267-271) is a process-lifetime timer; the confirm state is only
`confirmGen`/`confirmTimer`/`confirmPrevCfg` in memory. `git grep` finds NO
`confirm.json`/`commit_confirmed.json`/persisted deadline anywhere in
`pkg/configstore`. `Store.Load` (store_persist.go:19-90) recovers only
`everCommitted`/`persistMarkerCommitted` — it never re-arms a pending confirm
timer. A `commit confirmed N` writes `committed=1` to `active.json`
(store_commit.go:86-91), so after a crash the unconfirmed, potentially
management-stranding config reloads as permanent and the rollback window is gone.
Junos persists the confirm deadline; xpf does not.

Severity MEDIUM is reasonable but **bounded**: requires the narrow window of
(operator using `commit confirmed`) ∧ (daemon crash within the N-minute window)
∧ (the pending config strands management). Not always-on, but the whole point of
`commit confirmed` is the remote-change safety hatch, so losing it silently is a
real reliability defect. Dedup: NOT #4378 (that is commit-confirmed *demotion* /
plain-commit confirmation, not crash-recovery of the timer). NOVEL.

Fix: persist a durable `commit_confirmed.json` (deadline + prev-tree or its hash)
next to `active.json`; on `Load`, re-arm for the remaining time, or immediately
roll back if the deadline already passed — OR document it explicitly as
best-effort in-memory.

### A4-02 — GENUINE-RESIDUAL — LOW (reviewer said MEDIUM; I downgrade) — journal file is 0644
**Disposition: GENUINE gap, but severity is LOW/defense-in-depth, not MEDIUM.**
journal.go:180 confirmed `os.OpenFile(j.path, ..., 0644)`. The #4056 sweep test
(`file_perms_4056_test.go`) asserts 0600 on active.json / rollback slots / rescue
/ archive and 0700 on `.configdb` — it does **NOT** cover `.config.journal`, so
the journal is a genuine miss of that sweep. **But** `Detail` today is only the
operator commit comment + fixed strings (`persist_error`, `system_action`, etc.)
and `ConfigHash` is a non-reversible SHA256 — v2 already removed the fat
secret-bearing v1 payload (journal.go:1-11). The reviewer's own refutation
concedes "direct secret leak … is LOW severity today." So this is a
belt-and-suspenders hardening residual (0644 outlier + latent risk if a future
change logs a secret-adjacent string), correctly LOW. Partial-overlap with
**#4056** (same principle, journal was the one artifact the sweep missed).

Fix: open the journal 0600 + `os.Chmod(path, 0600)` upgrade for pre-#4056 files.

### A4-07 — GENUINE-RESIDUAL — LOW/INFO — master-password PRF typo silently disables encryption
**Disposition: GENUINE — and my verification makes it FIRMER than the reviewer's
hedged INFO ("need to verify whether the compiler rejects the typo").** I
verified: `masterPasswordPRF` (crypto.go:38-54) reads the raw AST child
`pseudorandom-function`; a mis-spelled leaf yields `nil` → `""` →
`maybeEncryptTreeJSON` returns plaintext. The open question was whether strict
commit rejects the typo. It does NOT: `master-password`/`pseudorandom-function`
are modeled (schema_system.go:113-114) but the `system` subtree is **open-world**
(no `closedWorld` anywhere in schema_system.go), and schema_walk.go:304-317
returns `nil` (silently accepts) for an unknown keyword outside a closed-world
subtree. So `set system master-password pseudo-random-function hmac-sha2-256`
commits clean and boots with encryption OFF despite operator intent.

This is a specific instance of the **known deferred X-1 open-world-schema class**
(fable-167 X-1; warn-only validation tracked around **#4515**) — silent accept of
an unmodeled/typo leaf. Real footgun (silent encryption bypass) but narrow
(operator must mis-type the exact leaf), hence LOW. Fix: make the leaf recognized
+ reject unknown children under `master-password` (local closed-world), or read
the compiled typed field instead of the raw AST. Partial-dup of the X-1/#4515
class; the concrete crypto instance is worth filing.

### A4-05 — GENUINE-RESIDUAL — LOW (hardening, non-exploitable) — GCM AAD not bound to envelope header
**Disposition: GENUINE hardening nit, NOT a vulnerability.** Confirmed
`gcm.Seal(nil, nonce, data, nil)` / `gcm.Open(nil, nonce, ciphertext, nil)`
(crypto.go:104 / 147) — nil AAD. The reviewer's own trace establishes it is not
exploitable: the derived key binds PRF+salt via HKDF (crypto.go:198-207), so a
header field swap changes the derived key → GCM auth fails → `Load` returns
`ErrConfigDBUnreadable` (fail-closed), not a silent substitution. Nonce is 12
random bytes per encrypt (crypto.go:94) → no reuse. Valid best-practice hardening
(bind Format/PRF/Salt as AAD for a specific error) but zero current impact. NEW,
LOW.

### A4-06 — GENUINE-RESIDUAL — LOW (root-only, defense-in-depth) — unmarshalEnvelope silent plaintext downgrade
**Disposition: GENUINE but marginal.** Confirmed unmarshalEnvelope
(crypto.go:159-172) returns `(zero,false,nil)` for non-envelope JSON → treated as
plaintext passthrough (correct for legacy pre-envelope DBs). The attack — replace
the encrypted `active.json` with plaintext to strip encryption — requires write
to `/etc/xpf/.configdb/active.json`, which is 0600 root-owned inside a 0700 dir.
As the reviewer concedes, that is root, "who can already do worse" — no privilege
escalation. Defense-in-depth only: when `master.key` exists, warn/reject a
plaintext active.json unless the tree intentionally dropped `master-password`.
NEW, LOW.

### A4-08 — NEGATIVE (accepted) — envelope compat / MkdirAllDurable / fsatomic / persist-before-promote
**Disposition: NEGATIVE, sound.** Spot-verified the cited clean symbols exist and
behave as described: `WriteFileDurable` (fsatomic.go:128), `MkdirAllDurable`
(fsatomic.go:159), `WithPreserveExisting`/`WithOwner` precedence
(fsatomic.go:68-88), persist-before-promote #1799 Option A in
`CommitWithDescription` (store_commit.go:86-92, "persist BEFORE promote"),
envelope helpers `hasEnvelope`/`buildEnvelopeHeaderLine`/`sanitizeEnvelopeToken`
+ min-reader fail-closed (envelope.go:79/152/160/178). Reviewer clearing ground,
not confabulating a clean bill.

### A4-09 — NEGATIVE (accepted) — journal rotation / torn-tail / size bounds
**Disposition: NEGATIVE, sound.** journal.go v2 rewrite (#1896) with bounded
reverse tail scan is real (journal.go header + OpenFile at :180 confirmed);
`MaxConfigSize` guard exists in store.go. Reviewer's clean bill is consistent
with the code; no re-open.

---

## Notes for the parent
- A4-01 (HIGH) + A4-04 (its master.key facet) = **one fix**: `performZeroizeWipe`
  must `RemoveAll` `/etc/xpf/.configdb` (key-first) and decide `.config.journal`
  policy. Strongest, most actionable finding of the batch — a genuine
  factory-reset secret-leak with no upstream mitigation.
- A4-03 (MEDIUM) is a legitimate durability gap (commit-confirmed = in-memory).
- A4-02 / A4-05 / A4-06 / A4-07 are LOW hardening/defense-in-depth residuals
  (I downgraded A4-02 from the reviewer's MEDIUM per its own refutation; I
  upgraded confidence on A4-07 after confirming the open-world schema accepts the
  typo). A4-07 is a concrete instance of the deferred X-1 / #4515 class.
- No confabulation, no A2/#4572 false-HIGH pattern in this batch.
