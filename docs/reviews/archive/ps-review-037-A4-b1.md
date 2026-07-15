# A4 — Go configstore, persistence & crypto-at-rest — deep review — d4506d445 (master HEAD)

Base: d4506d4450e23f9a3fc572206b3c82f6b6c99029 — Merge PR #4571 (fix/4570-ra-configequal)

## 1. Scope

pkg/configstore/{store.go, db.go, crypto.go, envelope.go, store_persist.go, store_commit.go, store_lock.go, store_command.go, store_format.go, history.go, dataplane_retire.go, journal/journal.go}
pkg/config/{ast_redact.go, secret.go}
pkg/fsatomic/fsatomic.go
pkg/grpcapi/server_diag.go (zeroize path — cross-cutting)

## 2. Dedup

Checked: /tmp/ps-review-018..036, /tmp/ps-review-036.md, gh issue list (open 30, closed 250+), /tmp/all_findings.txt (274), _Log.md.

CLOSED (do NOT re-report):
- #4562 navigatePath, #4556 cli/api LOW, #4555 XDP EH, #4549 LOW batch (VRRP hop-limit/HA IPv4-only/PSK zeroize/same-node-id), #4548 VRRP flap, #4547 ipsec DNS, #4546 WG, #4544 host-inbound dup, #4543 screen TLV, #4541 writeJSON, #4540 monitor keyword, #4539 session cache, #4535 three-color, #4534 PBR, #4526 DHCP, #4525 RA, #4524 monitor injection, #4521 NAT pool, #4519 nptv6, #4518 nat64 allocator, #4517 EH, #4514 policer, #4487/#4453/#4400 RST/FIN, #4399/#4438 NAT 1:N, #4393, #4392, #4388 HA NAT, #4384, #4378 commit-confirmed rollback, #4377 session limit, #4376 VRRP tie-break, #4365 global-policy scope, #4362 cookie_gen, #4360 BulkSync re-drive, #4348 quoted inactive, etc.

OPEN (do NOT re-report unless new trace):
- #4559 deterministic NAT (advisory only), #4555 XDP EH, #4549 LOW batch, #4548 VRRP flap, #4547, #4546, #4544, #4543, #4539, #4533 icmp_embed, #4515 warn-only, #4512 NAT64 HA-sync, #2387 bare 5-tuple (P0), #4146, #3226, #2852, #2562, #4478, #4455, #4313, #4498, etc.

## 3. Findings

---

### Finding A4-01 — HIGH — zeroize does NOT wipe .configdb (active.json + master.key survive factory reset)

**Severity:** HIGH
**Confidence:** HIGH
**Labels:** zeroize, persistence, factory-reset, secret-leak

**Evidence:**

`pkg/grpcapi/server_diag.go:755-773`:
```go
var performZeroizeWipe = func() {
    configDir := "/etc/xpf"
    files, _ := os.ReadDir(configDir)
    for _, f := range files {
        if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
            os.Remove(configDir + "/" + f.Name())
        }
    }
```

`pkg/configstore/db.go:70-72`:
```go
func (db *DB) activePath() string {
    return filepath.Join(db.dir, "active.json")
}
```
`pkg/configstore/store.go:196`:
```go
dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
```
So active config lives at `/etc/xpf/.configdb/active.json` (dotfile dir, not `*.conf`). The zeroize glob `*.conf` + `rollback*` never matches `.configdb/` (dot-prefixed directory, and `active.json` is not `*.conf`). After `request system zeroize`, `active.json` (cleartext or AES-GCM envelope + master.key at 0600) survives on disk.

**Trace:**
1. Operator runs `request system zeroize` (factory reset) via CLI/gRPC.
2. `performZeroizeWipe` removes `/etc/xpf/*.conf` and `rollback*` — does NOT touch `/etc/xpf/.configdb/` (dotdir).
3. On next boot, `Store.Load()` in `pkg/configstore/store_persist.go:23` calls `s.db.ReadActiveMeta()` which reads `/etc/xpf/.configdb/active.json` — the old config with all secrets (IKE PSKs, WG private keys, SNMP communities) is re-loaded.
4. The factory-reset box boots with the old firewall policy, not empty — traffic filtering, NAT, IPsec from the previous tenant persist. The journal `.config.journal` also survives (intentionally, per `#4108 F8`), but `.configdb/` survival is NOT intentional.

**Refutation attempt:**
- Could `.configdb` be removed via `os.RemoveAll` or via `xpf.conf` being the canonical file? No — `New()` in `store.go:195-200` creates `.configdb` as the sole persistence backend; `/etc/xpf/xpf.conf` is the operator-supplied bootstrap text that gets parsed and persisted into `.configdb/active.json`. Once committed, the filePath (`xpf.conf`) is not the SSOT. The DB dir is a dotfile dir that the zeroize `ReadDir` does skip (Go's `os.ReadDir` DOES return dotfiles — but the filter `strings.HasSuffix(f.Name(), ".conf")` does not match `.configdb` which is a directory, and `strings.HasPrefix(f.Name(), "rollback")` does not match either). The directory itself is never removed.
- Could the daemon delete `.configdb` on next boot after detecting zeroize? No — `BootClassify` in `pkg/daemon/bootstrap.go` never checks for a zeroize marker.

**HPC:** Pass — active.json write is durable (temp+fsync+rename+dir-fsync), so the surviving file is consistent.

**Why it matters:** A factory reset that leaves the active config + master.key intact is a data-leak and a security boundary violation. A resold / RMA'd appliance, or a multi-tenant hand-off, retains the previous tenant's firewall policy, VPN PSKs, and management credentials. The operator explicitly requested a wipe.

**Fix direction:**
- Extend `performZeroizeWipe` to `os.RemoveAll("/etc/xpf/.configdb")` and `os.Remove("/etc/xpf/.config.journal")` (or at minimum `.configdb/active.json`, `.configdb/master.key`, `.configdb/rollback.*.json`, candidates). The journal should be removed on zeroize (it is audit trail, but a factory reset should wipe it — current code in `store_commit.go:570` intentionally keeps journal on zeroize, citing attribution, which is reasonable but must be documented as NOT a full wipe if kept).

**Dedup:** NEW — prior reviews mention zeroize only for audit-trail survival (#4108 F8, intentional), not for `.configdb` survival.

---

### Finding A4-02 — MEDIUM — journal file is 0644 world-readable and carries commit comments that may contain secrets

**Severity:** MEDIUM
**Confidence:** MEDIUM
**Labels:** journal, file-perms, secret-leak

**Evidence:**

`pkg/configstore/journal/journal.go:180`:
```go
f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
```

`pkg/configstore/store_commit.go:125-128`:
```go
s.journalLog(&JournalEntry{
    Action:     "commit",
    Detail:     description, // operator-supplied commit comment
```

`pkg/configstore/store_persist.go:199-201`:
```go
Detail: fmt.Sprintf("%s: write active config failed: %v", action, err),
```

**Trace:**
- The journal is append-only JSONL at `/etc/xpf/.config.journal`. The `Detail` field on a commit entry is the operator's free-text commit comment (`commit confirmed "add IKE PSK for ..."`) — an operator could inadvertently type a secret into the comment, which then persists world-readable. More concretely, `persist_error` Detail includes the raw `err` from `WriteActive`, which on decrypt failure (`crypto.go:120` `"encrypted config but master key unavailable"`) does not leak key material, but the general pattern of echoing errors into a 0644 file is fragile.
- The v1 journal used to store full compiled configs (including secrets) in 0644 (noted in `journal.go:8`). v2 fixed that by storing only hash+detail, but the file mode was never tightened to 0600.

**Refutation attempt:** The journal's `Detail` is today commit comments + fixed strings (`"persist_error"`, `"rollback_persist_error"`, `"system_action"` + action name). None of these are secret leaves today. The `ConfigHash` is a SHA256 hex, not reversible. So direct secret leak via journal is LOW severity today, but the 0644 mode violates the `#4056` principle (all config-bearing files are 0600) and is a latent defect: any future addition that logs a secret-adjacent string into Detail would be world-readable.

**Why it matters:** Defense-in-depth: every other config-bearing artifact (`active.json`, `rollback.*`, `archive/*`, `rescue.conf`, `master.key`) is 0600 per `#4056`. The journal is the outlier. On a multi-user dev box or a compromised low-privilege process, 0644 allows enumeration of commit history + comments.

**Fix direction:** `os.OpenFile(j.path, O_APPEND|O_CREATE|O_RDWR, 0600)` and `os.Chmod(j.path, 0600)` on open (upgrade path from pre-#4056 0644).

**Dedup:** Partially covered by `#4056` (file-perms sweep) but journal was missed — the sweep in `file_perms_4056_test.go` asserts `.configdb` 0700 and DB files 0600, not journal.

---

### Finding A4-03 — MEDIUM — commit-confirmed timer is in-memory only; daemon crash/restart loses the auto-rollback

**Severity:** MEDIUM
**Confidence:** HIGH
**Labels:** commit-confirmed, durability, rollback, crash-recovery

**Evidence:**

`pkg/configstore/store_commit.go:267-271`:
```go
s.confirmGen++
gen := s.confirmGen
s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
    s.fireConfirmTimer(gen)
})
```

`pkg/configstore/store_persist.go:19-50` — `Load()` never recovers a pending confirm timer; it only sets `everCommitted`.

No file `confirm.json`, no `commit_confirmed` marker in `.configdb`, no `Load` recovery.

**Trace:**
1. Operator commits with `commit confirmed 10` — a potentially management-stranding change (interface takeover).
2. Daemon persists the new active config to `/etc/xpf/.configdb/active.json` (committed=1).
3. Daemon arms an in-memory `time.AfterFunc(10min)` to auto-rollback.
4. Daemon crashes (OOM, panic, power) 30s later — before operator confirms.
5. Daemon restarts, `Store.Load()` reads `active.json` (the unconfirmed config) as the active config. No timer is re-armed.
6. The unconfirmed, management-stranding config is now permanent — the safety net (`commit confirmed` auto-rollback) is lost. Junos persists the confirm deadline to disk and recovers it on restart; xpf does not.

**Refutation attempt:** Could the daemon's `#1922` bootstrap gate (never-committed marker) help? No — `commit confirmed` writes `committed=1` (a real commit) per `store_commit.go:229`. The never-committed marker only applies to first-commit rollback (`confirmPrevCfg==nil`). A non-first commit-confirmed writes `committed=1`, so restart loads it as committed and `everCommitted=true`.

**Why it matters:** `commit confirmed` is the safety hatch for remote changes that may cut management. Losing the timer on crash makes the hatch unreliable — the operator's 10-minute window disappears, and a stranded node stays stranded.

**Fix direction:** Persist a `commit_confirmed.json` (deadline + prev-tree hash or full prev tree) alongside `active.json`, fsynced durably. On `Load()`, if a confirm marker exists and its deadline is in the future, re-arm the timer for the remaining duration; if deadline already passed, immediately rollback. Alternatively, document as "best-effort, timer is in-memory only" and require operators to use `commit confirmed` only when management is reachable.

**Dedup:** NEW — prior reviews (#4378) cover commit-confirmed demotion and plain-commit confirmation, not crash-recovery of the timer.

---

### Finding A4-04 — MEDIUM — master.key is never zeroized and survives alongside active.json; on a stolen disk it decrypts the config

**Severity:** MEDIUM
**Confidence:** HIGH
**Labels:** crypto-at-rest, master-key, zeroize, disk-theft

**Evidence:**

`pkg/configstore/crypto.go:248`:
```go
if err := fsatomic.WriteFileDurable(path, key, 0600); err != nil {
```

`pkg/grpcapi/server_diag.go:755-773` — `performZeroizeWipe` never touches `.configdb/master.key`.

Zeroize leaves both `active.json` (AES-GCM ciphertext) and `master.key` (32-byte raw key) on disk. An attacker with physical disk access reads both and decrypts the config offline.

**Trace:**
- The threat model for `master-password` is "config at rest is encrypted, key is separate". But if both live in the same `.configdb/` directory on the same disk, stealing the disk yields both. The key is 0600, but once the disk is removed, file perms are irrelevant.
- Zeroize is the erasure path that should destroy key material first. It currently destroys neither.

**Refutation attempt:** Is `master.key` supposed to be TPM-sealed or stored elsewhere? No — `crypto.go:34-36` `masterKeyPath()` returns `filepath.Join(db.dir, "master.key")` (`/etc/xpf/.configdb/master.key`). It is co-located with the ciphertext by design. The encryption is then only useful against accidental `active.json` exposure (e.g. backup, log) — not against disk theft. This is a deliberate design choice, but it must be documented, and zeroize must still delete the key.

**Why it matters:** If the operator believes `master-password` protects config at rest against disk theft, they are mistaken — the key and ciphertext are co-located and both survive zeroize.

**Fix direction:**
- Zeroize must `shred`/`remove` `master.key` BEFORE removing `active.json` (key first, so a power cut mid-zeroize leaves ciphertext without its key — fail-closed, not fail-open). Document that master-password encryption is NOT disk-theft protection without TPM / external KMS.

**Dedup:** Partially covered by `#4549 LOW batch` (PSK zeroize) which is about zeroizing PSKs in memory, not on-disk master.key. NEW for on-disk zeroize.

---

### Finding A4-05 — LOW — AES-GCM nonce is random per-encrypt but envelope does not bind AAD; config substitution across versions is possible

**Severity:** LOW
**Confidence:** MEDIUM
**Labels:** crypto, AES-GCM, AAD, envelope

**Evidence:**

`pkg/configstore/crypto.go:94-104`:
```go
nonce := make([]byte, gcm.NonceSize())
if _, err := rand.Read(nonce); err != nil { ... }
env := encryptedTreeEnvelope{
    Format: encryptedTreeFormat,
    PRF:    prf,
    Salt:   base64.StdEncoding.EncodeToString(salt),
    Nonce:  base64.StdEncoding.EncodeToString(nonce),
    Data:   base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, nil)),
}
```

`crypto.go:147`:
```go
plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
```

Both `Seal` and `Open` pass `nil` AAD — no binding to envelope header fields (PRF, Salt, Format, committed marker).

**Trace:**
- An attacker who can replace `.configdb/active.json` on disk (e.g. via a backup restore) could swap the envelope header's `PRF` from `hmac-sha2-256` to `hmac-sha1` (or `Salt`) while keeping the same GCM ciphertext+nonce? No — GCM auth would fail if ciphertext is mutated, but the header fields are NOT covered by the tag, so a header swap that still yields the same derived key would decrypt successfully. Since the key derivation uses PRF + salt, a header swap that changes PRF/salt would normally derive a different key and fail GCM auth — but the failure mode is a generic "decrypt config tree" error (`Load` → `ErrConfigDBUnreadable` → fail-closed), not a silent config substitution. So the practical impact is LOW.
- However, if the same key material + same salt + same nonce were ever reused across two different envelope versions (e.g. a rollback file vs active), GCM nonce reuse would be catastrophic. The per-encrypt random nonce (12 bytes) makes collision negligible.

**Why it matters:** Best practice for AES-GCM envelope is to pass the header as AAD so any header mutation is detected as auth failure with a specific error, not a generic decrypt failure. Not a vulnerability today, but a hardening gap.

**Fix direction:** `gcm.Seal(nil, nonce, plaintext, []byte(env.Format+env.PRF+env.Salt))` and same on `Open`, or include `committed` marker in AAD.

**Dedup:** NEW — no prior review mentions GCM AAD.

---

### Finding A4-06 — LOW — `unmarshalEnvelope` silently treats any non-matching JSON as "not encrypted" (passthrough)

**Severity:** LOW
**Confidence:** MEDIUM
**Labels:** crypto, envelope, parsing, downgrade

**Evidence:**

`pkg/configstore/crypto.go:159-172`:
```go
func unmarshalEnvelope(data []byte) (encryptedTreeEnvelope, bool, error) {
    var env alias
    if err := json.Unmarshal(data, &env); err != nil {
        return encryptedTreeEnvelope{}, false, nil // not JSON → not encrypted, passthrough
    }
    if env.Format != encryptedTreeFormat {
        return encryptedTreeEnvelope{}, false, nil // wrong format → not encrypted
    }
    if env.PRF == "" || env.Salt == "" || env.Nonce == "" || env.Data == "" {
        return encryptedTreeEnvelope{}, false, fmt.Errorf("invalid encrypted config envelope")
    }
```

**Trace:**
- `maybeDecryptTreeJSON` calls `unmarshalEnvelope`. If `data` is valid JSON but does NOT have `format=="xpf-master-password-v1"`, it returns `(zero, false, nil)` — treated as "not encrypted, return raw JSON". This is correct for legacy plaintext configs (pre-envelope), but it also means a corrupted encrypted envelope (e.g. truncated JSON that still parses as `{"format":"x","prf":"..."}` with wrong format) would be treated as plaintext and then `json.Unmarshal` into `ConfigTree` — which would fail as `ErrConfigDBUnreadable`, not as a decrypt error. Not a secret leak, but confusing diagnostics.
- More importantly, if an attacker replaces the encrypted envelope with a valid plaintext `ConfigTree` JSON (no envelope fields), `unmarshalEnvelope` returns `false` and the plaintext is loaded as the active config — a downgrade attack that removes encryption. The attacker needs write access to `/etc/xpf/.configdb/active.json` (0600 root-owned, 0700 dir), so this requires root — not a privilege escalation.

**Why it matters:** The encryption is at-rest only; any root-level attacker who can write `.configdb/active.json` can already do worse. But the silent downgrade from encrypted to plaintext on file replacement is worth a warning.

**Fix direction:** When a master.key exists on disk (i.e. encryption was previously enabled), `maybeDecryptTreeJSON` should reject a plaintext-looking `active.json` unless the tree explicitly has no `master-password` leaf (i.e. encryption was intentionally disabled via config change). Log a warning on downgrade.

**Dedup:** NEW.

---

### Finding A4-07 — INFO — `masterPasswordPRF` reads PRF from config tree via raw AST, not compiled config; a typo in `pseudorandom-function` is silently ignored (defaults to no encryption)

**Severity:** INFO (feature gap)
**Confidence:** LOW
**Labels:** crypto, config-parse, silent-failure

**Evidence:**

`pkg/configstore/crypto.go:38-55`:
```go
func masterPasswordPRF(tree *config.ConfigTree) string {
    sys := tree.FindChild("system")
    if sys == nil { return "" }
    mp := sys.FindChild("master-password")
    if mp == nil { return "" }
    prf := mp.FindChild("pseudorandom-function")
    if prf == nil { return "" }
    return nodeValue(prf)
}
```

**Trace:**
- If operator types `set system master-password pseudo-random-function hmac-sha2-256` (typo: `pseudo` vs `pseudorandom`), the AST node is `pseudo-random-function`, not `pseudorandom-function` — `FindChild` returns nil, `masterPasswordPRF` returns `""`, `maybeEncryptTreeJSON` returns plaintext (`data, nil`). The config compiles (the typo leaf is ignored by the compiler's strict schema? Or it fails commit-check? Need to verify). If the compiler accepts unknown leaves leniently (it does on tolerant Load), the config boots with NO encryption despite operator intent.
- The strict commit path (`compileTreeStrict` → `schemaValidateExpandedTreeForNode`) would reject an unknown leaf? The schema validator should reject `pseudo-random-function` as unknown. So on strict commit it would fail. But on `SyncApply` (lenient path) it would be warned and then encryption would be skipped.

**Why it matters:** Silent encryption bypass due to typo — the operator thinks encryption is enabled, but `active.json` is plaintext.

**Fix direction:** Make `masterPasswordPRF` use the compiled config's typed field (`compiled.System.MasterPassword.PRF`) when available, or add a schema entry for `pseudorandom-function` so a typo is rejected.

**Dedup:** NEW — `#4515` tracks warn-only validation gaps, but not this specific one.

---

### Finding A4-08 — NEGATIVE — envelope compat, MkdirAllDurable, fsatomic durability, persist-before-promote

**Status:** NEGATIVE — no finding.

- **Envelope compat** (`envelope.go`): `hasEnvelope`/`stripEnvelope`/`buildEnvelopeHeaderLine` correctly implements the `#1917` floor — old reader fails closed on `#` header (json.Unmarshal rejects), new reader defaults `committed=true` on legacy DB (migration rule C3), `min-reader` gate fails closed on too-new DB. `sanitizeEnvelopeToken` removes whitespace/newline from writer version to prevent header injection. Correct.
- **MkdirAllDurable** (`fsatomic.go:159-191`): Records pre-existing ancestors, creates via `MkdirAll`, then fsyncs new levels + parent. Correct — the Codex High on PR #1900 (directory entry durability) is fixed.
- **fsatomic.WriteFileDurable** (`fsatomic.go:232-321`): Temp+write+fchmod+fchown+fsync+close+rename+dir-fsync, with cleanup on failure. Correct. `WithPreserveExisting` and `WithOwner` are used correctly for authorized_keys, not for configstore (which always uses 0600, not preserve).
- **Persist-before-promote** (`store_commit.go:86-92`): `CommitWithDescription` writes active to disk BEFORE promoting in-memory. On persist failure, nothing mutated — correct (#1799 Option A). `CommitConfirmed` same ordering. `SyncApply` and `PromoteRollback` use Option B (degrade-not-fail) with retry goroutine — correct per #1799.
- **Rollback file durability** (`store_commit.go:648-697`): Slot 1 durable, slots 2..N atomic, trailing `SyncDir`, `cleanupRollbackFiles` stops only on `IsNotExist`, `loadRollbackHistory` continues on non-IsNotExist errors. Correct (#3441 L1/L2/L3).

---

### Finding A4-09 — NEGATIVE — journal rotation, torn-tail recovery, size bounds

**Status:** NEGATIVE — no finding.

- **Journal rotation** (`journal/journal.go:219-236`): `maybeRotateLocked` shifts segments `.1→.2`, `.2→.3`, etc., then current→`.1`. Crash mid-rotation can leave gap — `Tail` tolerates gaps (skips IsNotExist). Correct.
- **Torn-tail** (`journal.go:186-196`): Reads last byte via `ReadAt`, prepends `\n` if no newline — confines damage to one record. Correct.
- **Tail reverse scan** (`journal.go:316-388`): `maxTailLineBytes` cap, `skipping` state, `pending` assembly — prevents buffering whole file on corrupt newline-free segment. Correct (#1896).
- **Size bounds** (`store.go:48-57`): `MaxConfigSize=16MiB` enforced on `LoadOverride`, `LoadMerge`, `LoadSet`, `SyncApply`, `CheckText`. Correct (H-2).

---

## 4. Summary

| # | Title | Severity | Confidence | Status |
|---|-------|----------|------------|--------|
| A4-01 | zeroize does NOT wipe .configdb (active.json + master.key survive) | HIGH | HIGH | NEW |
| A4-02 | journal 0644 world-readable | MEDIUM | MEDIUM | NEW (partial #4056) |
| A4-03 | commit-confirmed timer lost on daemon crash | MEDIUM | HIGH | NEW |
| A4-04 | master.key co-located with ciphertext, survives zeroize | MEDIUM | HIGH | NEW (partial #4549) |
| A4-05 | GCM AAD not bound to envelope header | LOW | MEDIUM | NEW |
| A4-06 | unmarshalEnvelope silent plaintext downgrade | LOW | MEDIUM | NEW |
| A4-07 | masterPasswordPRF typo silently disables encryption | INFO | LOW | NEW |
| A4-08 | NEGATIVE — envelope/MkdirAllDurable/fsatomic/persist-before-promote | — | — | NEGATIVE |
| A4-09 | NEGATIVE — journal rotation/torn-tail/size bounds | — | — | NEGATIVE |

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
