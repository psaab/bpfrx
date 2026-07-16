# Triage result — ps-review-038-A4_go_configstore_persist-b1

- **Subsystem**: A4_go_configstore_persist (`pkg/configstore/*`, `pkg/configstore/journal/`)
- **Review base**: d4506d4450e23f9a3fc572206b3c82f6b6c99029 (per header)
- **Triage base == current origin/master**: `57d24d9aed4b64680831a1765a128921e79c00f7`
- **Real bpfrx (not avacado)**: yes — every cited symbol (`Store.Annotate`, `journal.Log`, `NewDB`, `readOrCreateMasterKey`, `saveRollbackFiles`, `writeArchive`) exists on master; line numbers match within a few lines.
- **Outcome counts**: 6 findings → **2 GENUINE-RESIDUAL** (1 LOW-MED, 1 LOW), **2 DELIBERATE**, **2 NOT-MATERIAL**. 0 confabulated, 0 dup, 0 already-fixed-elsewhere.

---

## F-001 — Annotate path walk fails on named/multi-key containers → **GENUINE-RESIDUAL (LOW-MED, lane=go)**

**Symbol exists.** `git show origin/master:pkg/configstore/store_command.go` — `Store.Annotate` at line 179; the hand-rolled walk is lines ~199-220, verbatim as quoted.

**Confirmed reachable & broken.** The walk is:
```
for _, key := range path {
    for _, child := range children {
        for _, k := range child.Keys { if k == key { target=child; children=child.Children; ... } }
    }
    if !found { return "path not found" }
}
```
It consumes exactly **one** path token per node but matches against *any* key in a node's `Keys`. Named containers are stored as **multi-key** nodes — this is a documented invariant:
- CLAUDE.md: `family inet { dhcp; }` → `Node{Keys:["family","inet"]}`.
- `pkg/config/ast.go:navigatePath` (lines 173-197) exists precisely to consume multi-key nodes (`n.Keys[0]==keyword && n.Keys[1]==path[i+1]`, then consumes further key/value pairs). Its existence is direct proof named containers pack all identifiers into one node's `Keys`.

Trace for `annotate security zones security-zone trust description "x"` (path `["security","zones","security-zone","trust",...]`): token `security-zone` matches `Keys[0]` of node `Keys=["security-zone","trust"]`, descends into that zone's children; next token `trust` finds no child keyed `trust` → returns `path not found`. Same failure for `from-zone X to-zone Y policy Z`, `interfaces ge-0-0-0 unit 0`, and even `family inet`. Annotate works **only** for a chain of pure single-key nodes (e.g. `annotate system "..."`).

**Fails safe** — returns an error, no tree corruption. Both callers pass raw token slices (`pkg/cli/cli_dispatch.go:375` `append(GetEditPath(), Fields(pathStr)...)`; `pkg/api/config.go:359`), so no upstream normalization rescues it.

**Not covered by tests.** `store_test.go:TestAnnotate` only exercises `Annotate([]string{"system"}, ...)` (single-key top container) and the negative `nonexistent` case — the multi-key path is untested, which is why the bug survives. `TestAnnotateRejectsCommentDelimiter` also only uses `["system"]`.

**Dedup — novel.** `gh issue list --search annotate` and `git log --grep annotat` return only **#3900** (annotation `*/` comment-injection — a different bug in the same verb) and the Sprint-21 add. Not in the #4517-#4581 backlog (EH/screens/VRRP/WG/IPsec/PBR/CGNAT/etc. — no config-edit-verb entry). No open/closed issue for the multi-key walk.

**Severity reasoning (LOW-MED, below the review's Medium).** Exploitability: none — no attacker angle, no data path; a config-mode operator gets a spurious error. Blast radius: `annotate` is broken for essentially every useful target (zones, policies, interface units, `family inet`) — real Junos-parity/usability gap. Bounds: fails closed with a clear message, zero corruption, purely a documentation/comment verb; the config itself and commit path are unaffected. Not higher because there is no security or integrity impact and it fails safe; not lower because it's a real, always-reproducible functional break of a shipped CLI verb, not a corner case. **Fix**: replace the hand-rolled walk with `config.navigatePath` (or reuse `SetPath`/`DeletePath` resolution) so multi-key nodes are consumed as units; add a two-zone annotate test.

---

## F-002 — Journal files created 0644 world-readable → **DELIBERATE**

**Symbol exists.** `journal/journal.go:180` opens with mode `0644` (confirmed). Legacy fat v1 entries are real history (`#1896` rewrite deleted the fat payload).

**Refuted as a residual — documented design decision.** `pkg/configstore/README.md` lines 40-42 explicitly state: *"The v2 audit journal (`.config.journal`) stays 0644 by [design] … does not carry config content or secret values (#1896)."* The v2 `Entry` is metadata-only (`{v, timestamp, action, detail, config_hash}` — `journal.go` Entry doc, README 436-460). The `#4056` file-perms hardening (commit 848f54893) deliberately hardened `active.json`, rollback slots, rescue.conf, archive dir/file, `.configdb`, `master.key` to 0600 and **left the journal 0644 on purpose** because it carries no secret payload.

The two claimed secret vectors don't hold up:
- **Legacy v1 fat entries**: only exist if a box ran a *pre-#1896* build (which pre-dates #4056 entirely), wrote fat entries, then upgraded — and the file is never rewritten. The README head-comment already acknowledges this exact artifact ("the compiled payload (including secrets) sat in a 0644 file forever"). It is a documented historical residual of the deleted v1 format, not a new exposure; the go-forward design is metadata-only by intent.
- **`Detail` = commit comment**: operator-typed audit text. Commit comments are non-secret audit metadata in Junos (visible to any operator via `show system commit`); typing a secret into a commit comment is operator error, not a store defect.

Classification DELIBERATE (not GENUINE): the reviewer's proposed remedy (0600 the journal) directly contradicts an explicit, documented threat-model decision. No action.

---

## F-003 — Upgrade leaves pre-#4056 files world-readable (chmod only dir) → **NOT-MATERIAL / DELIBERATE**

**Symbols exist.** `db.go:49-57` eagerly `os.Chmod(dir, 0700)` at NewDB (the finding quotes it); `crypto.go readOrCreateMasterKey` and `store_persist.go writeArchive MkdirAll 0700` confirmed — none re-chmod existing *files*.

**Refuted / neutralized.**
1. **Documented lazy fix.** `pkg/configstore/README.md` lines 26-28: *"the atomic write re-creates the inode on every write, so an existing 0644 file from a pre-#4056 build is re-created 0600 on the next commit."* Lazy perm-fix-on-next-write is the intended behavior, not an oversight.
2. **`.configdb` files are already protected eagerly.** NewDB does `os.Chmod(dir, 0700)` at every boot (db.go:56). `active.json`, `candidate.json`, `master.key`, `rollback.N.json` all live *inside* `.configdb`. A 0700 directory denies non-owner traversal, so even a 0644 file inside is unreadable by a non-owner. The entire threat #4056 defends (non-root local user) is closed for those files at boot, independent of the file mode.
3. **Residual window is tiny and low-value.** Only the *parent-dir* text slots (`xpf.conf.N`, `rescue.conf`) and archive files could be 0644 in the window between upgrade and next commit — and each is fixed on the first commit. Archives are additionally created under a 0700 dir.

Severity reasoning: defense-in-depth only, narrow window, documented lazy behavior, and the sensitive `.configdb` set is already neutralized by the eager 0700 dir chmod. Not a genuine reachable secret leak. NOT-MATERIAL (leaning DELIBERATE per README). No action; if anything an eager glob-chmod is a nicety, not a fix for a live exposure.

---

## F-004 — Parent-dir / archive-dir crash-leaked temps never swept → **GENUINE-RESIDUAL (LOW, lane=go)**

**Symbols exist & confirmed.** `db.go NewDB` (lines 48-52) is the *only* temp sweep in the whole package — `filepath.Glob(filepath.Join(dir, ".*.tmp-*"))` where `dir` == `.configdb`. Verified there is no other `.tmp-`/`Glob` sweep anywhere in `pkg/configstore/*.go`.

The leaking writers live in **other** directories:
- `store_commit.go rollbackPath` (632-633) = `filepath.Dir(s.filePath)` — the **parent** dir (`/etc/xpf`), not `.configdb`. `saveRollbackFiles` writes via `rbWriteFileDurable`/`rbWriteFileAtomic` (= `fsatomic.WriteFileDurable/Atomic`), which `CreateTemp` a `.<base>.tmp-<rand>` in that parent dir.
- `store_persist.go rescuePath` (385-386) = parent dir; `SaveRescueConfig` same writer.
- `writeArchive` (310-337) writes into the operator `archiveDir`.

`fsatomic` only `defer`-removes its temp on an **error return** (fsatomic.go:271-274); a hard crash (SIGKILL / power loss) between `CreateTemp` and `rename` orphans the temp. NewDB's sweep never looks at the parent dir or archive dir, so `.xpf.conf.1.tmp-*`, `.rescue.conf.tmp-*`, `.config-*.tmp-*` accumulate across crashes forever (each crash mints a new random suffix; old orphans are never reclaimed).

**Dedup — novel for this subsystem.** The temp-orphan-on-crash issues in the backlog (#2714, #2957, #3009, #2147) are all **userspace-dp `state_writer`**, a different code path. #1894 is the durability work that *added* the `.configdb`-only sweep. No configstore parent-dir/archive sweep issue exists. This is the configstore twin of the already-fixed state_writer class.

**Severity reasoning (LOW).** Exploitability: none. Blast radius: disk clutter of tiny hidden files in `/etc/xpf` and the archive dir; the temps are never read (dead weight — no correctness/crash-consistency impact, the durable rename semantics are intact). Bounds: only leaks on a hard crash inside the small create→rename window of a per-commit parent-dir write, so accumulation is slow (a handful over a firewall's lifetime). Not higher because there's no security/correctness effect and it's crash-only; not INFO because it's a real unbounded (if slow) resource leak that the package's own sweep was meant to prevent, and the exact class was deemed worth fixing on the userspace-dp side. **Fix**: extend NewDB (or Store.New) to also glob-remove `.*.tmp-*` in `filepath.Dir(filePath)` and, when configured, the archive dir; add a test that plants fake temps and asserts cleanup.

---

## F-005 — Master key / derived keys not zeroized in memory → **NOT-MATERIAL**

**Symbols exist.** `crypto.go readMasterKey`/`readOrCreateMasterKey`/`maybeEncryptTreeJSON`/`deriveEncryptionKey` confirmed; none zeroize.

**Refuted by the documented threat model.** `pkg/configstore/README.md` lines 44-72: 0600+0700 defends only against **non-root local users**; it explicitly does **not** defend against root compromise or physical/disk theft, and states *"An attacker who can read `xpf.conf.N` can equally read `master.key` one directory over and decrypt — so on-box encryption is theater against the root/disk-theft threat, not defense."* The only actor who can read process memory (core dump, `/proc/pid/mem`, cold-boot) already has root and can read `master.key` directly off the 0600 disk file. So zeroizing the in-memory copy closes no threat that the on-disk key doesn't already hand over. Non-root actors are already blocked by 0600+0700. The reviewer graded it Low / Medium-confidence himself.

Not comparable to #4549/#4576 PSK zeroize (that hardens a *different* secret with a different lifecycle). NOT-MATERIAL per documented reasoning. No action.

---

## F-006 — master.key orphan after `delete system master-password` → **NOT-MATERIAL**

**Symbol exists.** `maybeEncryptTreeJSON` returns plaintext when `prf==""` (crypto.go:70-74) and does not delete `master.key`; confirmed.

**Refuted by the same threat model.** `master.key` sits in the 0700 `.configdb`, readable only by the daemon owner (root). Only the JSON DB body is AES-GCM encrypted; text rollback slots/archives/rescue are cleartext-at-rest 0600 (README 70-72). After disabling master-password the surviving key could only decrypt old *encrypted `.configdb/rollback.N.json`* copies — all inside the 0700 dir, i.e. root-only, and the README already establishes on-box key material is theater against the root/disk-theft threat, not a defended surface. Leaving the key is a housekeeping/usability wart (decommission hygiene), not a reachable secret exposure. The reviewer graded it Low / Medium-confidence and framed it as "should be documented." NOT-MATERIAL; at most a docs/usability nicety, not a security residual. No action.

---

## Genuine residuals to file

1. **F-001** (LOW-MED, go): `Store.Annotate` hand-rolled walk breaks on every multi-key/named container (`security-zone`, `from-zone/to-zone`, `unit N`, `family inet`) → spurious `path not found`; fails safe. Fix: use `config.navigatePath`. Untested path (`TestAnnotate` only covers `["system"]`).
2. **F-004** (LOW, go): configstore temp sweep only covers `.configdb`; crash-leaked `.<base>.tmp-*` orphans for parent-dir rollback text slots (`xpf.conf.N`), `rescue.conf`, and archive files are never reclaimed. Fix: extend the NewDB/Store.New sweep to the parent + archive dirs (configstore twin of the fixed #2714/#2957 state_writer class).

All other findings are DELIBERATE (F-002, and F-003-leaning) or NOT-MATERIAL (F-003, F-005, F-006) against the documented `#4056` threat model in `pkg/configstore/README.md`.
