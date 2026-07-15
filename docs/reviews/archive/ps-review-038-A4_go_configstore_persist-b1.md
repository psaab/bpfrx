# A4_go_configstore_persist batch 1/1 — paladin-038 review

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A4_go_configstore_persist
Batch: 11/11 (44 files)

## Batch file list

- pkg/configstore/activate_test.go
- pkg/configstore/check.go
- pkg/configstore/check_test.go
- pkg/configstore/cluster_readonly_3893_test.go
- pkg/configstore/commit_confirm_demote_4378_test.go
- pkg/configstore/commit_confirm_pending_edit_4000_test.go
- pkg/configstore/commit_confirmed_3861_test.go
- pkg/configstore/config_size_ceiling_hb164_test.go
- pkg/configstore/crypto.go
- pkg/configstore/dataplane_retire.go
- pkg/configstore/dataplane_retire_test.go
- pkg/configstore/db.go
- pkg/configstore/db_test.go
- pkg/configstore/durability_3441_test.go
- pkg/configstore/envelope.go
- pkg/configstore/envelope_test.go
- pkg/configstore/equal_flow_worker_cap_test.go
- pkg/configstore/file_perms_4056_test.go
- pkg/configstore/freetext_store_test.go
- pkg/configstore/history.go
- pkg/configstore/inactive_test.go
- pkg/configstore/journal/journal.go
- pkg/configstore/journal/journal_test.go
- pkg/configstore/journal_compat_test.go
- pkg/configstore/load_compile_fail_test.go
- pkg/configstore/marker_test.go
- pkg/configstore/nodeid_lenient_test.go
- pkg/configstore/persist_failure_test.go
- pkg/configstore/ra_interval_4525_test.go
- pkg/configstore/redaction_placeholder_4060_test.go
- pkg/configstore/rescue_redaction_leak_4099_test.go
- pkg/configstore/store.go
- pkg/configstore/store_command.go
- pkg/configstore/store_commit.go
- pkg/configstore/store_format.go
- pkg/configstore/store_lock.go
- pkg/configstore/store_lock_3979_test.go
- pkg/configstore/store_lock_lease_4476_test.go
- pkg/configstore/store_new_test.go
- pkg/configstore/store_persist.go
- pkg/configstore/store_test.go
- pkg/configstore/system_action_journal_4108_test.go
- pkg/configstore/test_seams.go
- pkg/configstore/typed_leaf_lenient_test.go

## Module-by-module log

- **pkg/configstore/db.go**: Reviewed NewDB, ReadActiveMeta, WriteActiveMarker, readTreeMeta, writeTreeMarked. Verified temp+fsync+rename+dirfsync via fsatomic.WriteFileDurable, envelope strip before decrypt, committed marker handling, 0600/0700 enforcement on create. Found two gaps: (1) existing-file perm upgrade not retroactive (Finding F-003), (2) temp sweep only covers .configdb not parent (Finding F-004). Otherwise durability ordering correct.

- **pkg/configstore/store_persist.go**: Reviewed Load, Save, writeActive, writeActiveMarker, journalLog, persist retry loop, ArchiveConfig, writeArchive, rotateArchives, rescue, degraded flags. Verified persist-before-promote (Option A), degrade-not-fail (Option B), committed=0 handling, first-commit rollback marker seeding, archive seq unique. Found: archiveDir MkdirAll 0700 but no chmod-fix on existing dir (part of F-003). Retry loop holds mu during write — same as normal commit, not new. Negative otherwise.

- **pkg/configstore/store_commit.go**: Reviewed CommitCheck, CommitWithDescription, CommitConfirmed, clearPendingConfirmLocked, ConfirmCommit, ConfirmPendingOnDemotion, fireConfirmTimer, PromoteRollback, performAutoRollback, Rollback, saveRollbackFiles, cleanupRollbackFiles, loadRollbackHistory. Verified confirmGen staleness guard, nested confirmed preserve, plain-commit confirms pending, SyncApply confirms, degraded handling, rollback file durability split (slot1 durable + trailing SyncDir). No new truncation. Negative otherwise.

- **pkg/configstore/store.go**: Reviewed New, SetConfigDBWriterVersion, SetClusterReadOnly, compileTreeStrict, crossCheckNodeID, crossCheckRAIntervals, compileTreeLenient, schemaValidateExpandedTreeForNode, SyncApply. Verified strict vs lenient doctrine, RA interval integer math (Min*4 > Max*3) fits in int64, nodeID mismatch warn-not-reject on lenient, retired dataplane rewrite. No integer truncation to narrower type. Negative.

- **pkg/configstore/store_lock.go**: Reviewed ensureWritableLocked, lease TTL, touch, reclaimStaleLockLocked, EnterConfigureSession, EnterConfigureExclusive, ExitConfigureSession, ForceExitConfigure, ConfigHolder. Verified #3893 read-only gate on every mutating op, #3979 exclusive-holder fix, #4476 stale lease reclaim. EnterConfigureExclusive same-session re-entry not allowed but not a security gap. Negative.

- **pkg/configstore/store_command.go**: Reviewed Set, Delete, DeactivateFromInput, ActivateFromInput, Copy, Rename, Insert, Annotate, LoadOverride, LoadMerge, LoadSet, applyEditLine, hasFlatVerb. Verified MaxConfigSize gate, flat-verb fail-closed (#3442), deactivate/activate round-trip (#2008). Found **Annotate multi-key walk broken** (Finding F-001) — naive Keys-contains search fails for named containers (zones, policies).

- **pkg/configstore/store_format.go**: Reviewed Show* family and Show*Redacted family, forDisplay via RedactedClone, commit diff, rollback show. Verified redacted clones for REST/gRPC display, cleartext siblings preserved for HA sync/persist. No secret leak in this layer. Negative.

- **pkg/configstore/check.go**: Verified CheckText size gate + strict compile, thin wrapper over compileTreeStrict. Negative.

- **pkg/configstore/crypto.go**: Reviewed masterPasswordPRF, nodeValue, maybeEncryptTreeJSON, maybeDecryptTreeJSON, deriveEncryptionKey, deriveEncryptionKeyFromSalt, prfHash, readMasterKey, readOrCreateMasterKey. Verified AES-GCM with random salt (16B) + nonce per write, HKDF with prf agility, master.key WriteFileDurable ordering, 0600. Found: (F-005) keys not zeroized, (F-006) master.key orphan after master-password removal, (F-003) existing master.key perm not fixed.

- **pkg/configstore/envelope.go**: Reviewed hasEnvelope, buildEnvelopeHeaderLine, sanitizeEnvelopeToken, wrapEnvelope, stripEnvelope, parseEnvelopeHeader, min-reader/format gates, committed default true migration C3. Verified '#' makes old reader fail closed, forward-compat unknown fields, writer sanitized for newline/space. No injection via '=' (Cut on first '=', value kept as opaque). Negative.

- **pkg/configstore/history.go**: Simple ring buffer, accessed under Store.mu. Correct head arithmetic. Negative.

- **pkg/configstore/journal/journal.go**: Reviewed Journal struct, New clamping, Log with torn-tail self-heal, maybeRotateLocked, Tail bounded reverse scan, tailScan chunk handling, skip-mode over-cap, parseLine, rotation gap tolerance. Verified durability (file Sync + dir Sync on create/rotate), bounded read O(limit). Found (F-002) journal files created 0644 world-readable, legacy fat entries leak secrets.

- **pkg/configstore/dataplane_retire.go**: Reviewed rewriteRetiredDataplaneType, systemBlocksOf, groupsBlocksOf, systemBlocksOfNode, rewriteRetiredLeavesIn, isRetiredDataplaneLeaf. Verified split-stanza handling, groups second pass, split groups, LoadCaller vs SyncCaller remediation messages. Negative.

- **pkg/configstore/test files (non-prod)**: activate_test, check_test, cluster_readonly_3893_test, commit_confirm_demote_4378_test, commit_confirm_pending_edit_4000_test, commit_confirmed_3861_test, config_size_ceiling_hb164_test, dataplane_retire_test, db_test, durability_3441_test, envelope_test, equal_flow_worker_cap_test, file_perms_4056_test, freetext_store_test, inactive_test, journal_compat_test, load_compile_fail_test, marker_test, nodeid_lenient_test, persist_failure_test, ra_interval_4525_test, redaction_placeholder_4060_test, rescue_redaction_leak_4099_test, store_lock_3979_test, store_lock_lease_4476_test, store_new_test, system_action_journal_4108_test, typed_leaf_lenient_test, journal/journal_test, store_test — all reviewed for coverage gaps. No production bugs, but they expose missing permission tests for journal and temp-leak not asserted. Coverage gaps noted in Findings.

## Findings

---

### F-001: Annotate path walk fails on named containers (zones, policies, interfaces with unit)

Title: Annotate fails to find named security-zone / policy / interface nodes due to naive Keys-contains walk

Severity: Medium

Confidence: High

Evidence: pkg/configstore/store_command.go:199-220

```go
children := s.candidate.Children
var target *config.Node
for _, key := range path {
    found := false
    for _, child := range children {
        for _, k := range child.Keys {
            if k == key {
                target = child
                children = child.Children
                found = true
                break
            }
        }
        if found {
            break
        }
    }
    if !found {
        return fmt.Errorf("path not found: %s", strings.Join(path, " "))
    }
}
```

Trace:
1. Operator runs `annotate security zones security-zone trust description "test"` — path = ["security","zones","security-zone","trust"]
2. Annotate iterates path token "security" — finds Node Keys=["security"] — ok, descends.
3. Token "zones" — finds Node Keys=["zones"] — ok.
4. Token "security-zone" — scans children of zones: two nodes exist, Keys=["security-zone","trust"] and Keys=["security-zone","untrust"]. Loop `for _, k := range child.Keys { if k == key }` matches first child's Keys[0]=="security-zone" — picks "trust" zone regardless of next token, descends into trust's children.
5. Token "trust" — searches inside trust zone's children for a key "trust" — not found (trust zone contains "interfaces", "host-inbound-traffic", etc.). Returns "path not found" error.
6. Correct behavior would require matching multi-key nodes as a whole: Keys[0]=="security-zone" && Keys[1]=="trust" consumed as two path tokens, or at least matching second token against same node's Keys[1]. SetPath/DeletePath handle this; Annotate re-implements its own walk and does not.
7. Same failure for `security policies from-zone trust to-zone untrust policy foo`, `interfaces ge-0-0-0 unit 0`, etc.

HPC/invariant check: N/A — correctness bug in config-edit verb, not hot path.

Why it matters: `annotate` is the Junos-style comment verb for documentation/compliance. It is broken for any named container — the most common use (zone descriptions, policy comments). Operators get spurious "path not found" and cannot annotate zones/policies. The bug is silent for top-level leaves (system host-name) so tests pass, but fails for real firewall configs.

Fix direction: Replace the hand-rolled walk with the same navigation used by the tree's other verbs: call `candidate.FindNode(path)` or `Navigate` helper that understands multi-key nodes, or reuse `SetPath`/`DeletePath` path resolution. At minimum, consume two Keys at once when a node has len(Keys)==2, or change the loop to check `child.Keys[0]==key` and, if len>1, also match next path token against Keys[1:]. Add a test with two zones and annotate on the second.

Labels: correctness, cli

Dedup note: Not in dedup index. Dedup lists config warn-only validation (#4515), NAT issues, screen, CoS, etc., but no annotate bug. #3441/#4056 permission issues unrelated. This is a distinct code path.

---

### F-002: Journal files created world-readable (0644) — legacy fat entries contain cleartext secrets

Title: journal/journal.go creates .config.journal and rotated segments 0644, leaking secrets via legacy payloads and commit comments

Severity: Medium

Confidence: High

Evidence: pkg/configstore/journal/journal.go:180

```go
f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
```

Evidence: pkg/configstore/journal/journal.go:115-136 New clamping but no mode fix, and Log path uses 0644 even though v1 legacy lines carry full compiled config (including IKE PSK, SNMP community) — see journal_compat_test.go writeLegacyJournal.

Trace:
1. Daemon runs pre-#1896 (or pre-#4056) and writes v1 journal entries: `{"action":"commit","detail":"add ike","before":{...},"after":{"...pre-shared-key":"SUPERSECRET"...}}` with 0644 perms. This is world-readable.
2. Upgrade to current build: New() creates Journal with same path, Log rotates when size threshold hit — `j.maybeRotateLocked` renames current to .1 (rename preserves 0644), then creates new current with 0644.
3. Even after upgrade, `.config.journal`, `.config.journal.1`, `.config.journal.2` remain 0644. Any local unprivileged user can `cat /etc/xpf/.config.journal` and recover historic secrets from fat entries.
4. v2 entries themselves are compact (no config payload) but Detail is operator commit comment — if operator types secret in comment, it is also world-readable.
5. file_perms_4056_test pins 0600 for active.json, rollback slots, rescue.conf, archive dir/file, .configdb dir, but never checks .config.journal.

HPC/invariant check: Journal is DurableState-adjacent (audit trail) — should be owner-only per #4056 threat model: "every file that may carry a cleartext secret when master-password is not set" — legacy journal qualifies.

Why it matters: Secret leak to any local user (including compromised least-privileged service) — IKE PSK, SNMP community, auth keys from historic commits remain readable after upgrade. Violates #4056 intent.

Fix direction: Change OpenFile mode 0644 -> 0600. On New(), if journal file exists with 0644, chmod to 0600 (retroactive). For rotated segments, ensure they are created with 0600 (they are created via rename of current, which is already 0600 after fix, so ok). Add file_perms test: `TestJournalOwnerOnly_4056` similar to existing perms tests — create store, commit secret, LogSystemAction, assert `.config.journal` mode 0600 and not containing cleartext secret (or containing only hash).

Labels: security, secret-leak, permissions

Dedup note: Dedup open #4056 is closed? Actually file_perms_4056_test exists but dedup lists #4056 closed? No, dedup index lists open issues #4572..#4146 and closed issues #4570..#4220. #4056 is not listed — it was a fix, not a dedup entry. #4549 mentions PSK zeroize but not journal perms. #4484 opus-172 LOW batch mentions "secret-Debug" but not journal file perms. So distinct.

---

### F-003: Upgrade leaves pre-#4056 files world-readable — permission hardening not retroactive

Title: NewDB chmods only directory, not existing active.json/master.key/rollback/rescue/archive files; upgrade from pre-#4056 keeps secrets 0644

Severity: Medium

Confidence: High

Evidence: pkg/configstore/db.go:49-57

```go
if err := fsatomic.MkdirAllDurable(dir, 0700); err != nil {
    return nil, fmt.Errorf("create db dir: %w", err)
}
// MkdirAllDurable does not chmod an already-existing directory, so an
// upgrade from a pre-#4056 build inherits the old 0755. Enforce 0700
// here — the daemon owns the dir, so this is idempotent and cheap.
if err := os.Chmod(dir, 0700); err != nil {
    return nil, fmt.Errorf("restrict db dir perms: %w", err)
}
```

Evidence: pkg/configstore/crypto.go:227-236 readOrCreateMasterKey reads existing file without chmod

```go
if data, err := os.ReadFile(path); err == nil {
    if len(data) != 32 {
        return nil, fmt.Errorf("invalid master key length in %s", path)
    }
    return data, nil
}
```

Evidence: pkg/configstore/store_persist.go:310-318 ArchiveConfig MkdirAll 0700 but no chmod fix

```go
if err := os.MkdirAll(archiveDir, 0700); err != nil {
    return fmt.Errorf("create archive dir: %w", err)
}
```

Trace:
1. User runs pre-#4056 build: .configdb/active.json created 0644, .configdb/master.key 0600? (actually pre-#4056 used 0644 for active.json, 0644 for master.key? — crypto.go used WriteFileDurable with 0600 already, but old builds may have used 0644). Rollback files xpf.conf.1 created 0644, rescue.conf 0644, archive dir 0755 + files 0644.
2. Upgrade to current build: NewDB called, MkdirAllDurable creates .configdb if missing, then Chmod dir 0700 — fixes dir. But does NOT Chmod active.json from 0644 to 0600, nor master.key, nor candidate.json, nor rollback.*.json. Those remain 0644 world-readable.
3. Daemon loads active.json (reads fine), ActiveConfig available, but secrets remain world-readable until next commit (which rewrites active.json 0600 via WriteFileDurable). If operator never commits post-upgrade, secrets stay exposed indefinitely.
4. Similarly, master.key readOrCreateMasterKey returns existing 0644 file without fixing perms. Archive dir remains 0755, archive files remain 0644.
5. file_perms_4056_test only tests the happy path (fresh store + commit -> 0600) but never tests upgrade from 0644 files.

Why it matters: Defense-in-depth failure — #4056 intended to make all secret-bearing files owner-only, but upgrade does not retroactively fix existing files, leaving a window (potentially forever) where secrets are world-readable. Violates #4056 security goal.

Fix direction: In NewDB, after Chmod dir, glob existing files (`active.json`, `candidate.json`, `rollback.*.json`, `master.key`) and Chmod each to 0600 if perms != 0600 (best-effort, log warn on failure). In readOrCreateMasterKey, after successful read, if file mode != 0600, Chmod to 0600. In Store.New or Load, also Chmod rollback files and rescue.conf to 0600. In writeArchive, after MkdirAll, Chmod dir to 0700 even if exists, and ensure new files are 0600 (already). Add upgrade test: create files 0644, call NewDB, assert they become 0600.

Labels: security, permissions, upgrade

Dedup note: Not in dedup. #4056 is the original fix, not listed as open/closed dedup entry. #4484 LOW batch mentions "secret-Debug" but not perm retroactive. Distinct from F-002 (journal) — this is about config DB files, not journal.

---

### F-004: Stale temp files in parent directory not cleaned — rollback/rescue/archive temp leak

Title: NewDB only sweeps .configdb/.*.tmp-*, parent dir temp files from rollback/rescue/archive writes accumulate

Severity: Low

Confidence: High

Evidence: pkg/configstore/db.go:62-66

```go
if stale, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*")); err == nil {
    for _, p := range stale {
        _ = os.Remove(p)
    }
}
return &DB{dir: dir}, nil
```

Evidence: pkg/configstore/store_commit.go:658-670 saveRollbackFiles writes parent dir files

```go
path := s.rollbackPath(i + 1)
...
if i == 0 {
    err = rbWriteFileDurable(path, []byte(data), 0600)
} else {
    err = rbWriteFileAtomic(path, []byte(data), 0600)
}
```

Trace:
1. saveRollbackFiles writes `xpf.conf.1` via WriteFileDurable which creates temp `.xpf.conf.1.tmp-XXXX` in same dir (parent of .configdb, i.e., /etc/xpf). If daemon crashes between CreateTemp and rename, temp remains.
2. SaveRescueConfig writes `rescue.conf` similarly in parent dir, same leak.
3. ArchiveConfig writes in archiveDir, temp pattern `.config-*.tmp-*`, also not swept.
4. NewDB only globs `dir` (i.e., `.configdb/.*.tmp-*`), not parent dir or archive dir. So leaked temps in parent/archive accumulate forever.
5. fsatomic.WriteFileDurable cleans temp on error path (defer Remove) but not on crash (SIGKILL, power loss). Those are exactly the cases NewDB sweep is meant to handle — but it misses the other directories.

Why it matters: Resource leak, disk space exhaustion on long-lived firewalls with many crashes/power events. Also clutter and potential confusion for operators listing /etc/xpf. Not a crash-consistency issue (temps are not used), but violates durability plan's sweep guarantee.

Fix direction: In New() or Store.Load(), sweep parent dir `.*.tmp-*` and `*.tmp-*` for rollback/rescue patterns, and archive dir if configured. Or make NewDB accept additional sweep dirs, or make writeArchive use same durable sweep on startup. Simplest: after NewDB, in Store.New, glob `filepath.Join(filepath.Dir(filePath), ".*.tmp-*")` and remove. Also sweep archive dir on ArchiveConfig init. Add test injecting fake temp files and asserting cleanup.

Labels: resource-leak, durability

Dedup note: Not in dedup. Dedup lists persistence/durability issues (#1799, #1894) but not this sweep omission. Distinct from #4572 etc.

---

### F-005: Master key and derived encryption keys not zeroized — secret material remains in heap/GC

Title: crypto.go retains master key (32B), HKDF output, AES key, GCM state in Go heap after encrypt/decrypt

Severity: Low

Confidence: Medium

Evidence: pkg/configstore/crypto.go:213-252

```go
func (db *DB) readMasterKey() ([]byte, error) {
    path := db.masterKeyPath()
    data, err := os.ReadFile(path)
    ...
    return data, nil
}
func (db *DB) readOrCreateMasterKey() ([]byte, error) {
    ...
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, fmt.Errorf("generate master key: %w", err)
    }
    if err := fsatomic.WriteFileDurable(path, key, 0600); err != nil {
        return nil, fmt.Errorf("persist master key: %w", err)
    }
    return key, nil
}
```

Evidence: pkg/configstore/crypto.go:70-107 maybeEncrypt/maybeDecrypt keep `key` slice alive until GC, no memzero

```go
keyMaterial, err := db.readOrCreateMasterKey()
...
key, salt, err := deriveEncryptionKey(keyMaterial, prf)
...
block, err := aes.NewCipher(key)
...
// key never zeroed
```

Trace:
1. Daemon boots, reads active.json encrypted: readMasterKey loads 32B master key into slice, deriveEncryptionKeyFromSalt HKDFs to 32B AES key, creates AES-GCM, decrypts, returns plaintext. Function returns, but `keyMaterial`, `key`, `salt` slices remain referenced by stack frames until GC, and Go's GC does not zero memory on free.
2. An attacker with memory dump (core file, /proc/*/mem, cold-boot) can recover master key and thus decrypt all future active.json snapshots (which are stored encrypted at rest but key is in heap).
3. Standard Go mitigation is to zeroize sensitive slices via `for i:=range key { key[i]=0 }` or using `memguard` or `crypto/subtle`. The codebase already zeroes PSK elsewhere (#4549) but not here.

HPC/invariant check: Not hot path — decrypt only on boot, SyncApply, Load. Zeroize cost negligible.

Why it matters: Defense-in-depth for master password feature. Master key is the root secret — compromise allows offline decryption of all config backups, rollback files (which are plaintext anyway, but active.json encrypted). Goes against stated threat model: "master.key plus the active/candidate/rollback config DB — every file that may carry a cleartext secret when master-password is not set" — master.key itself is the most sensitive file, and its in-memory copy should be minimized.

Fix direction: After use, zeroize `keyMaterial`, `key` slices via `clear(key)` or loop. Consider using `runtime.KeepAlive` to avoid compiler optimizing away zeroing (use `for i:=range b { b[i]=0 }` and then `runtime.KeepAlive(b)`). Or use `memset` via `crypto/subtle`. Do same for `salt`? Salt is not secret (stored in envelope), but key is. Also zeroize derived key in maybeDecrypt. Document that Go GC may still have copies, but best-effort zeroize reduces window.

Labels: security, crypto, secret-zeroize

Dedup note: Dedup #4549 mentions "PSK zeroize" for IPsec PSK, but not master key. #4056 is file perms, not memory zeroize. Distinct.

---

### F-006: Master.key orphan after master-password removal — key material lingers on disk

Title: Removing `system master-password` does not delete .configdb/master.key, leaving key material on disk after operator intended to disable encryption

Severity: Low

Confidence: Medium

Evidence: pkg/configstore/crypto.go:70-74

```go
func (db *DB) maybeEncryptTreeJSON(data []byte, tree *config.ConfigTree) ([]byte, error) {
    prf := masterPasswordPRF(tree)
    if prf == "" {
        return data, nil
    }
```

Evidence: pkg/configstore/db.go:34-68 NewDB does not clean master.key on plaintext write

Trace:
1. Operator configures `set system master-password pseudorandom-function hmac-sha2-512` and commits. maybeEncryptTreeJSON generates master.key (32B random), encrypts active.json, writes master.key 0600 durable, then active.json encrypted. Good.
2. Operator later runs `delete system master-password` and commits. maybeEncryptTreeJSON sees prf=="", returns plaintext data unchanged, writes active.json plaintext (with envelope). It does NOT delete master.key.
3. master.key remains on disk 0600, containing the key that can decrypt old encrypted rollback files, old archives, and the previous active.json version that may still be recoverable from disk (e.g., via filesystem snapshots, backups, or journal). Operator expectation after removing master-password is that no key material remains.
4. Similarly, if operator changes PRF, master.key is reused (correct), but old derived keys remain valid for old salt — old files still decryptable with same master.key.

Why it matters: Violates expectation of "disable encryption" — key material lingers. If firewall is decommissioned or repurposed, master.key could be recovered from disk and used to decrypt old config backups that contain PSKs. Should be documented or cleaned.

Fix direction: On transition from encrypted to plaintext (prf == "" but master.key exists), either delete master.key (and warn), or keep but document that master.key lingers and must be manually removed if operator wants to fully purge. Safer: delete after successful plaintext commit, or provide CLI `request system master-password delete` that securely deletes. At minimum, log warning when writing plaintext while master.key exists: "master.key remains on disk; remove manually if no longer needed". Add test: commit with prf, then commit without prf, assert master.key still exists (document current) or assert deleted (if fix).

Labels: security, crypto, usability

Dedup note: Not in dedup. #4549 is PSK zeroize, #4056 file perms, not this. #1894 durability.

---

## Negative results (required)

- **pkg/configstore/check.go / check_test.go**: CheckText correctly gates size, parses, compiles strict, rejects retired dataplane, handles ${node} expansion. No truncation, no secret leak. Invariant held.

- **pkg/configstore/db.go durability ordering**: Verified WriteFileDurable temp+fsync+rename+dirfsync ordering, master.key durable before active.json (structural ordering via readOrCreateMasterKey inside encrypt before writeTree). No torn write, no overwrite of active.json on failed persist (Option A). Negative aside from F-003/F-004.

- **pkg/configstore/envelope.go compatibility**: Verified '#' makes old reader fail closed, min-reader gate, committed defaults true (C3), writer sanitization prevents newline injection. No truncation, no secret leak. Negative.

- **pkg/configstore/journal/journal.go crash consistency**: Verified torn-tail self-heal (prepend newline), rotation gap tolerance, bounded reverse scan, skip-mode over-cap line discard, maxTailLineBytes cap checked on every pending update. No integer overflow (size int64, readChunk 64K, n int64 -> make with int safe). Negative aside from F-002.

- **pkg/configstore/store_lock.go concurrency**: Verified RWMutex usage, reclaimStaleLockLocked only fires after TTL, active holder not stolen, exclusiveHolder cleared on reclaim, same-session re-entry refreshes lease. No deadlock, no TOCTOU beyond acceptable single-node daemon.

- **pkg/configstore/store_commit.go commit-confirmed timers**: Verified confirmGen bump prevents stale Timer.Stop lost race, nested confirmed preserves original rollback target, plain commit confirms pending, SyncApply confirms, demotion confirms. No double-free, no timer leak.

- **pkg/configstore/store_persist.go degrade-and-retry**: Verified persistDegraded flag, singleton retry guard, backoff doubling capped 60s, persistMarkerCommitted seeding from on-disk committed=0 (prevents never-committed -> committed=1 heal bug). No overflow (time.Duration 1s..60s), no stale tree write (re-reads s.active under lock).

- **pkg/configstore/crypto.go AES-GCM nonce handling**: Verified nonce generated via crypto/rand 12B per write, fresh salt 16B per encrypt, never reuse nonce with same key (new salt+new nonce each commit). GCM Seal/Open correct, HKDF with prfHash lowercasing, supported PRFs enumerated. No nonce reuse, no IV reuse. Negative aside from zeroize.

- **pkg/configstore/history.go**: Ring buffer math correct: `idx := (head-1-n+maxSize)%maxSize` handles wraparound, Push overwrites oldest. No overflow, no out-of-bounds.

- **Integer truncation**: Searched all 44 files for casts from Go int to narrower Go types (uint16/uint8) or Rust u16 — none found in this batch. Config values flow through compiler in pkg/config, not here. Archive seq uint64 -> %d formatting safe. Envelope version ints small (1). Journal size int64 -> int conversion for make() bounded by readChunk (64K) safe. No truncation bug in this area. Negative.

- **Secret redaction**: Verified LoadRescueConfigRedacted fails closed with generic line/col error (no token leak), Show*Redacted uses RedactedClone, forDisplay clones, ShowCompareRedacted masks both sides. No secret in logs (slog.Warn/Error only logs paths, err, issue tags, not config values). Negative aside from F-002/F-003.

- **Feature completeness vs vSRX**: This batch is persistence layer, not dataplane policy. No vSRX parity gap introduced. CLI `annotate`, `copy`, `rename`, `insert` verbs are implemented; `annotate` bug (F-001) is the only parity gap vs Junos (Junos annotate works on named zones). Not a missing feature, a bug.

- **Performance/latency**: All durability paths use fsync only for DurableState (active.json, master.key, rollback slot1, rescue), not for archive/rollback slots 2..N (atomic). This matches engineering-style Persistence classes. No hot-path allocation, no per-packet work. Negative.

- **Test coverage gaps noted**: file_perms_4056_test does not cover journal perms (F-002) or upgrade perm retroaction (F-003); durability_3441_test does not cover parent-dir temp sweep (F-004); crypto tests do not assert zeroize or master.key deletion on disable. These are coverage gaps but not production bugs themselves.

## Summary

Reviewed 44 files in A4_go_configstore_persist. Found 6 findings: 1 Medium correctness (Annotate multi-key), 2 Medium security (journal world-readable, upgrade perm retroaction), 3 Low (temp leak, zeroize, master.key orphan). Verified envelope fail-closed, AES-GCM nonce/salt uniqueness, commit/rollback timers, torn-tail recovery, rollback file durability split, integer truncation none, secret redaction in rescue path.

All findings checked against dedup open (#4572..#4146) and closed (#4570..#4220) — none duplicate.

