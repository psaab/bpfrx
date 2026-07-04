# System login & authentication

This is the operator contract for `system login user` and
`system root-authentication` password handling. It documents how a
configured login password reaches the OS account database, the
commit-time validation of the hash, and the declarative reconciliation
behaviour when a password directive is removed. (#1944)

## Per-user console login password

```
set system login user <name> class operator
set system login user <name> authentication encrypted-password "<crypt-hash>"
```

On commit, xpf:

1. Creates the OS account (`useradd`) if it does not already exist.
2. Writes `<crypt-hash>` to `/etc/shadow` for `<name>` via
   `chpasswd -e` (the same idiom `root-authentication` uses), so the
   operator can log in on the **serial console** (and via SSH password
   if `sshd` permits). Without this, a freshly created account has a
   locked password field and cannot log in on the console at all — only
   SSH-key login (`authentication ssh-ed25519 …`) worked previously.

The password directive takes a **pre-computed crypt(3) hash**, never
plaintext — exactly like `root-authentication encrypted-password`. xpf
does not hash plaintext for you.

## Login class (RBAC) and commit-time validation (#2008 H6)

```
set system login user <name> class <class>
```

The `class` value is **enum-validated at commit** against the set of
system-defined Junos login classes xpf supports. An unrecognized class
(e.g. `superuser`, `admin`) is hard-rejected by the `#1319` typed-leaf
gate, closing the previous commit-accepts-any-string hole. The accepted
classes are:

| Class | Permissions |
|---|---|
| `super-user` | everything (incl. destructive maintenance) |
| `operator` | view, clear, control (request/test) — **not** maintenance |
| `read-only` | view only |
| `config-viewer` | view only (can display config; cannot enter `configure` to modify) |
| `unauthorized` | nothing |

`super-user` is the only class that holds the destructive **maintenance**
permission (`PermMaint`), which it reaches through `PermAll`. `operator` has
`control` (so it can run benign `request`/`test` commands) but **not**
maintenance, mirroring Junos where the predefined `operator` class lacks the
`maintenance` permission and therefore cannot reboot or zeroize the box (#4108).

RBAC is enforced at runtime by `checkPermission` (`pkg/cli/permissions.go`),
invoked by the dispatch layer before each top-level command. The accepted
enum is **derived from** `LoginClassPermissions`
(`config.ValidLoginClasses()`), so the commit-time validator and the
runtime RBAC table can never drift apart: adding a class in one place
without the other is impossible. An empty/unset class keeps the legacy
allow-everything behavior (no class configured = no RBAC restriction).

### Command-to-permission mapping

Gating is on the resolved **top-level** command word:

| Command | Required permission |
|---|---|
| `show`, `ping`, `traceroute`, `monitor` | view |
| `clear` | clear |
| `request`, `test` | control |
| `request system {reboot,halt,power-off,zeroize}`, `request chassis cluster failover` | **maintenance** (super-user only) |
| `configure` | config |
| anything else | super-user (all) |

**Privileged-subcommand exception — destructive maintenance (#4108 F21).**
Most `request` verbs are `control`-level, but the four `request system` verbs
that take the box down or wipe it — `reboot`, `halt`, `power-off`, `zeroize` —
and `request chassis cluster failover` are gated at the super-user-only
**maintenance** (`PermMaint`) level. On Junos the predefined `operator` class
has no `maintenance` permission and so cannot reboot/zeroize; xpf matches that:
`operator` (which holds `control`) is **denied** these verbs, while its benign
`request` commands (`request security …`, `request system software`,
`request system dynamic-dns`, rescue-config save, etc.) stay `control` and
remain available. The exception lives in `requiredPermission` →
`requestSubcommandIsMaintenance` (`pkg/cli/permissions.go`) and resolves the
subcommand with the same prefix matcher the dispatcher uses, so an abbreviated
`request system zero` or `request sys reboot` is gated identically to the
fully-spelled form and cannot bypass the gate. `super-user` reaches these verbs
through `PermAll`, so `PermMaint` need not appear in its permission list.

**Privileged-subcommand exception — `monitor traffic` (#4067).** Almost
every command is gated on the top-level word alone, but `monitor traffic`
spawns a **root `tcpdump` live packet capture** on a data interface, so it
is gated at the **control** level (the same bucket as the `request` /
shell-out family) instead of the plain `view` level the rest of `monitor`
(interface stats, security-flow trace) uses. A `read-only` / `config-viewer`
class — intended only to VIEW config and status — is therefore **denied**
`monitor traffic`; `operator` and `super-user` are allowed. This mirrors
Junos, which gates `monitor traffic` behind the maintenance permission, not
plain read-only. The exception lives in `requiredPermission`
(`pkg/cli/permissions.go`) and resolves the subcommand with the same prefix
matcher the dispatcher uses, so an abbreviated `monitor tr` is gated
identically to the fully-spelled form and cannot bypass the gate. Other
`monitor` subcommands and read-only `show` commands are unaffected.

**Secret redaction in `show configuration` (#4099).** The on-box interactive
CLI config-render show paths — `show configuration` (hierarchical / `| display
set` / `| display json` / `| display xml` / `| display inheritance`, including
path-scoped subtrees), `show system rollback <N> [| display set | compare]`,
`show system login` / `internet-options` / `root-authentication`, `show system
configuration rescue`, and the config-mode `show` / `show | compare` — mask
secret leaves (IKE pre-shared-keys, SNMP communities, BGP/OSPF
authentication-keys, WireGuard private keys, encrypted passwords, DDNS
tokens/keys) with `##SECRET-DATA##` for **every login class except
`super-user`**. This mirrors Junos (which never renders a cleartext secret in
`show configuration` for any class) and the always-redacted REST/gRPC
`ShowConfig` path (#4051): a VIEW-only `read-only`, `config-viewer`, or
`operator` login can no longer harvest cleartext firewall secrets through the
console. The redaction predicate is `CLI.showConfigRedacted()`
(`pkg/cli/permissions.go`): it routes rendering through the `*Redacted`
configstore methods (the same `RedactedClone` renderers REST/gRPC use) for any
class **without** `PermAll`.

`super-user` still reads cleartext — it is the console root that already has
direct config-DB filesystem access, so masking it would only obstruct the
operator copying a secret while providing no protection (the deliberate #4057
allowance). An **unset/empty** class (no `system login` configured — the legacy
no-RBAC allow-everything mode) is likewise treated as privileged and reads
cleartext, so a deployment with no login classes is bit-identical to before the
change. An **unknown** class fails **closed** (redacted). Config mode requires
`PermConfig` (super-user only today), so the config-mode candidate show paths
render cleartext in practice; they are wired through the same gate as
defense-in-depth should a lower class ever gain config-view access. The raw
`rescue.conf` text (a full cleartext-secret config dump, #4056) is reparsed +
redacted before display and fails **closed** — a parse error returns an error
rather than the cleartext bytes.

### Generating a hash

```
openssl passwd -6                       # prompts; emits a $6$ sha512crypt hash
mkpasswd -m sha512crypt                  # same, from the whois package
openssl passwd -6 -salt "$(head -c12 /dev/urandom | base64 | tr -d '+/=')"
```

Paste the resulting `$6$…` string into `encrypted-password`. yescrypt
(`$y$…`) and bcrypt (`$2b$…`) hashes are also accepted.

## Accepted hash formats (commit-check)

The value is validated at commit time by a shared validator
(`ValidateCryptHash`, used for both per-user and root authentication).

**Accepted:**

- A modular crypt(3) hash `$<id>$<salt>$<checksum>` with a non-empty
  salt and a non-empty final checksum, where `<id>` is one of
  `1, 2a, 2b, 2y, 5, 6, 7, y, gy`. Parameter fields are allowed
  (e.g. `$6$rounds=656000$salt$hash`, `$y$j9T$salt$hash`).
- An optional leading `!` or `!!` (the locked-but-restorable form),
  e.g. `!$6$salt$hash`.
- A bare lock sentinel: `*`, `!`, or `!!`. This is the intentional Unix
  way to lock an account, and the **only** way to lock root via config
  (`set system root-authentication encrypted-password "*"`).

**Rejected at commit:**

- **Plaintext** — pasting a cleartext password is hard-rejected. This is
  absolute: even a 13-character alphanumeric string (which a legacy DES
  crypt would resemble) is rejected, because xpf does not accept legacy
  DES hashes.
- An empty value, an unknown `$<id>$`, an empty salt, an empty checksum
  (`$6$salt$`), or a value containing `:` or a control character.

### Strict vs lenient paths

- **Operator commit / commit-check**: a bad value **hard-fails** the
  commit (the `#1319` typed-leaf gate). The plaintext footgun is closed
  at the entry point.
- **Boot / peer-sync**: an already-persisted or peer-synced value that
  fails validation is **downgraded to a warning** rather than failing
  boot, so a bad stored value can never brick the daemon.

## Removing the directive locks the account (declarative)

When you remove `authentication encrypted-password` from a user that xpf
provisioned, on the next commit xpf **locks** that account's password
(`<user>:!` via `chpasswd -e`) instead of leaving the old hash in
`/etc/shadow`. Removing the directive therefore disables password login
rather than orphaning a live credential. Re-adding the directive
restores the password.

This password reconciliation is **declarative**. SSH keys
(`authorized_keys`) remain additive and independent of the password — a
live password is a higher-severity orphan than a stale key. The
super-user sudo grant (`/etc/sudoers.d/xpf-<name>`) is **also
declarative** and reconciled on every apply (see below): a class
downgrade or user removal revokes it (#3889).

## Super-user sudo grants are reconciled and revoked (#3889)

A login user with `class super-user` is granted passwordless root via a
NOPASSWD drop-in `/etc/sudoers.d/xpf-<name>`. That grant is reconciled
against the **current** config on every commit by `reconcileSudoers`
(`pkg/daemon/daemon_system.go`), mirroring the networkd/rsyslog
stale-file reconcilers:

1. Write `xpf-<name>` for each user that is a super-user **now**.
2. Sweep `/etc/sudoers.d/xpf-*` and **REMOVE** any drop-in whose user is
   no longer a super-user. This covers both a **class downgrade**
   (`super-user` → `operator`/`read-only`) and a **user removal** from
   the config — in either case the passwordless-root grant is revoked on
   the next apply. Before #3889 the write had no removal branch, so a
   demoted or deleted admin kept passwordless root forever.

Only files with the `xpf-` prefix are written, kept, or removed; any
operator-authored file in `/etc/sudoers.d` is left untouched. The
reconcile runs **unconditionally** — even when `system login` has no
users (the "all users removed" case), so stale grants are still swept.
Writes are **DurableState** (`fsatomic.WriteFileDurable`, `0440`) and
the generated file is validated with `visudo -cf` (best-effort, root
only) before being trusted; a rejected drop-in is removed rather than
left as a lockout landmine, because a single malformed file in
`/etc/sudoers.d` breaks **all** sudo invocations. `root` is never
granted an xpf-managed drop-in.

### Scope — only xpf-managed accounts

The lock-on-removal applies **only to the exact account xpf
provisioned**, never root, and never to accounts absent from config
(xpf does not deprovision/`userdel` accounts). Provenance is tracked by
a per-user marker file under `/var/lib/xpf/provisioned-users/<name>`
whose content is the account's numeric **UID** at the time xpf wrote
its password (written on both `useradd` and a successful
`encrypted-password` apply).

- **Leave then rejoin the same account**: the UID is unchanged, so the
  marker matches and the lock fires — the old password is revoked.
- **`userdel` + out-of-band recreate with a new UID**: the marker's UID
  no longer matches, so xpf leaves the out-of-band account untouched
  (and opportunistically removes the stale marker).
- **Edge case**: if an out-of-band recreate happens to reuse the *exact
  same name and UID* xpf recorded, xpf treats it as the original managed
  account and may lock it. Re-add `encrypted-password` to restore.

A transient `/etc/shadow` read error never causes a lock (the lock
decision fails closed on a read error), so a read hiccup can never lock
out an operator.

## Idempotency

The password apply reads `/etc/shadow` directly and skips `chpasswd`
when the on-disk hash already equals the configured hash, so an
unchanged re-commit does not churn the account. It fails **open** toward
applying (any read error / missing entry / mismatch → apply), so a first
commit never silently skips the password.

## #1916 interaction (file-atomic writes)

The password path is a `chpasswd` **process** invocation (which performs
its own `lckpwdf`-protected shadow update), not a direct file write, so
the #1916 fsatomic file-write wrapper does not apply to it.

The sudoers drop-in (now written by `reconcileSudoers`, #3889) and the
`authorized_keys` write in `applySystemLogin` ARE direct file writes and
were migrated to **DurableState** in #1916
(`fsatomic.WriteFileDurable`): a torn sudoers file is a management-access
hazard, and SSH keys must survive a power cut. The
`authorized_keys` writes additionally use `fsatomic.WithOwner(uid, gid)`
(owner resolved cgo-free via `lookupUIDGID`) so the file is installed
already-correctly-owned — a plain durable write would replace the inode
with a root-owned temp, and a crash before the post-rename `chown` would
leave root-owned `0600` keys that sshd refuses (EACCES → lockout). If the
owner cannot be resolved the write is SKIPPED (retried next apply) rather
than degrading to that unsafe root-owned path. The enclosing `.ssh`
directory is created with `fsatomic.MkdirAllDurable` so the directory
entry itself also survives a power cut. The provisioned-users marker
(`markProvisioned`) is likewise DurableState.
