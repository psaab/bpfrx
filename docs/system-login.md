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

The `class` value is **validated at commit** against the set of
system-defined Junos login classes xpf supports **UNION any custom
`system login class <name>` defined in the same candidate tree** (#4304 S-2,
see below). An unrecognized class that is neither built-in nor defined
(e.g. `superuser`, `admin` with no matching `class` definition) is still
hard-rejected by the `#1319` typed-leaf gate, closing the previous
commit-accepts-any-string hole. The system-defined classes are:

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

### Custom login classes (accept-with-advisory, #4304 S-2)

Real vSRX configs define their own RBAC classes:

```
set system login class noc-admin permissions all
set system login class noc-admin idle-timeout 30
set system login user bob class noc-admin
```

Before #4304 the `class` leaf was a **fixed enum** over the built-ins only, so
`class noc-admin` was **hard-rejected at commit** — which blocked the WHOLE
config from committing. xpf now **recognizes** the custom `login class <name>`
definition (`permissions`, `idle-timeout`, `allow-commands`, `deny-commands`,
`allow-configuration`, `deny-configuration`), feeds the defined names into the
`class` validator (a tree-aware cross-reference, `validateLoginClassRef`), and
maps the Junos `permissions` token set onto xpf's coarse permission model at
compile (`LoginClass.MappedPermissions`, consulted at runtime by
`resolveClassPerms`).

Because xpf's runtime RBAC is **coarse** (view/clear/control/config/maintenance/
all) it cannot faithfully represent every fine-grained Junos permission or the
per-command allow/deny regexes. The mapping is therefore
**accept-with-advisory** — the commit succeeds and the compiler emits a
per-class advisory (`show system commit` / warnings) describing exactly what
maps and what does not:

- `all` / `super-user` → `super-user` (PermAll); `maintenance` → maintenance;
  `clear` → clear; `control` / `reset` → control; `configure` → configure;
  `view` / `view-configuration` → view.
- **No privilege escalation** — the mapping never grants more than the Junos
  token permits. Two Junos tokens are deceptive and are folded conservatively:
  `reset` permits restarting software *daemons* (`restart <process>`), **not**
  rebooting/halting/zeroizing the box, so it maps to **control**, never
  `maintenance` (the destructive box verbs). `rollback` permits reverting to a
  prior commit only, not arbitrary `set`/`delete`, so it folds to the
  **view-only floor**, never `configure`.
- **Every other** recognized token (a subsystem read like `network` /
  `interface` / `routing` / `firewall`, a `*-control` write token, `shell`,
  `secret`, …) folds **down** to a **view-only floor**. Under-granting is
  deliberate: the coarse model must never silently grant config / control /
  maintenance from a narrow subsystem token.
- `allow-commands` / `allow-configuration` / `idle-timeout` are **recognized
  but NOT enforced** by the coarse gate (dropping a whitelist extension or a
  session-lifetime knob cannot make the class more permissive); the advisory
  names them.
- **`deny-commands` / `deny-configuration` are blacklists** — because xpf does
  not enforce them, the denied verbs stay **allowed**, so the class is **more
  permissive than the Junos config**, not merely "unenforced". The advisory
  states this explicitly as a `WARNING` so the operator knows the security
  posture is weaker. Full per-command deny enforcement is a follow-up.

An undefined class (referenced by a user but never defined, and not a built-in)
still **fails closed** at commit.

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

**Audit trail (#4108 F8).** When one of these destructive verbs runs, the gRPC
`SystemAction` handler writes a fsynced `system_action` entry (verb + timestamp)
to the configstore audit journal (`.config.journal`) **before** executing, so an
attributable record is durable on disk before the action runs (the `journald`
line is not). For `reboot`/`halt`/`power-off` the record persists across the
reboot. For `zeroize`, the wipe now **deliberately removes `.config.journal`**
(#4576 — a completed factory reset must not hand its audit log, commit history,
or comments to the next tenant); the durable cross-wipe trail is therefore the
pre-execution fsync (an *interrupted* wipe still leaves the record on disk) plus
any remote syslog collector. See the configstore README "Audit journal" section
for the record format.

**Factory-reset erasure (#4576).** `zeroize` erases the xpf configuration
**state** so the prior tenant's committed config + secrets are not reloaded on
the next boot (RMA / resale / re-tenant). The wipe removes the `.configdb` SSOT
(`active.json`, `candidate.json`, `rollback.N.json`) and **`master.key` first**
(so an interrupted wipe cannot leave AES-GCM ciphertext behind next to the key
that decrypts it), the numbered text rollback slots `<config>.N` (full config
text with cleartext secret leaves — reloaded at boot by `loadRollbackHistory`),
the top-level `.conf` files (live config + `rescue.conf`), `.config.journal`
(+ rotated segments), and the self-signed REST-API TLS pair under `tls/`
(`tls/key.pem` — the device-generated localhost HTTPS private key — and
`tls/cert.pem`, #4599; xpf-generated, not tenant config, and regenerated on
absence by `generateSelfSignedCertAt` on the next boot). A wipe that cannot
fully erase this state returns an error rather than reporting a clean factory
reset.

**Rendered service-config erasure (#4585).** The wipe erases that
SSOT/rollback/journal state directly, but the prior tenant's secrets are ALSO
rendered into service configs xpfd writes **outside** `/etc/xpf`. `zeroize` now
erases those at wipe time too (`zeroizeRenderedConfigs`, same key-first /
error-surfacing discipline):

- **`/etc/frr/frr.conf`** — mode **0644 world-readable**; the `! BEGIN/END BPFRX
  MANAGED CONFIG` section carries BGP-MD5 / OSPF / IS-IS authentication keys.
  Only that section is stripped (`frr.StripManagedSectionFile`, disk-only — no
  FRR reload); operator content outside the markers is preserved and a purely
  operator-managed `frr.conf` is left untouched.
- **`/etc/swanctl/conf.d/xpf.conf`** — the IKE PSKs live in this single
  xpf-owned snippet; it is removed outright.
- **`/etc/kea/kea-dhcp{4,6}.conf`** — xpf owns these whole files; removed outright.

This must be done by the wipe itself, not deferred to the reconcile on the
completing reboot: a post-zeroize boot has **no committed config**, so the
daemon enters **#1922 bootstrap mode** (or, on an HA node, a normal boot with a
`nil` active config) and **SKIPS** the boot-time `applyConfig` that would
otherwise reconcile FRR/IPsec/Kea to empty (bootstrap suppresses the apply, and
the normal-boot apply is gated on `ActiveConfig() != nil`). Without the direct
wipe the rendered secrets would be a **persistent** residual across the reboot —
a re-tenanted device would keep the prior tenant's routing-auth keys in a
world-readable file — not the transient one earlier notes assumed. FRR /
strongSwan / Kea regenerate their configs from the now-empty xpf config on the
next `commit`, and the daemon still boots cleanly (bootstrap does not touch
those services). A failure to erase any of them surfaces as an error rather than
a clean factory-reset report.

**Provisioned login-account teardown (#4598).** The two erasures above remove
config + rendered-config secrets, but the OS **login accounts** xpf provisioned
also live **outside** `/etc/xpf` and **survive** the wipe — and they are the
*biggest* re-tenant leak because they grant **interactive login + sudo**, not
just a config-secret read:

- **`/etc/shadow` password hashes** (`reconcileUserPassword`),
- **SSH `authorized_keys`** under `/home/<user>/.ssh` (`applySystemLogin`),
- **`/etc/sudoers.d/xpf-<user>`** NOPASSWD grants (`reconcileSudoers`).

They persist for the same reason the rendered configs do: `applySystemLogin`
runs only inside the boot-time `applyConfig`, which a post-zeroize boot **SKIPS**
(bootstrap / `nil` active config), and even a full reconcile early-returns on an
empty config and never `userdel`s. So `zeroize` now tears them down at wipe time
too (`zeroizeLoginAccounts`, same error-surfacing discipline):

- **Sudoers.** The entire `/etc/sudoers.d/xpf-*` namespace is removed
  unconditionally (nothing is desired at factory reset), so no passwordless-root
  grant survives even if a marker is missing. Operator-authored drop-ins without
  the `xpf-` prefix are **left untouched**.
- **Users.** A `userdel -r` (removes the `/etc/shadow` + `/etc/passwd` entry and
  the home tree, incl. `authorized_keys`) fires **only** for an account that has
  a **provenance marker** in `/var/lib/xpf/provisioned-users/<user>` **and** whose
  current `/etc/passwd` UID still equals the marker's recorded UID — the same
  UID-keyed ownership marker used for the declarative D2 lock (#1944 §5.4).
  `authorized_keys` is removed *before* `userdel` so the SSH-key vector dies even
  if `userdel` fails; on a `userdel` failure the marker is **retained** so a
  retried `zeroize` re-attempts, and the failure is surfaced (the device is not
  reported safe to re-tenant while a live account remains).

**Never-touch safety invariant.** The teardown must never nuke a non-xpf account
or strand access:

- An **operator's own account** (created out of band, no xpf marker) is never
  iterated — its keys, sudoers, and login stay intact.
- **`root` and system accounts** have no marker and are never touched — the
  console/root lifeline survives the wipe (critical on bare metal).
- An **out-of-band `userdel`+recreate** with a different UID (marker UID ≠ live
  UID) is left alone — the current owner is someone else, exactly the #1944
  leave-then-rejoin-vs-recreate distinction.

**Privileged-subcommand exception — `monitor traffic` (#4067).** Almost
every command is gated on the top-level word alone, but `monitor traffic`
spawns a **root `tcpdump` live packet capture** on a data interface, so it
is gated at the **control** level (the same bucket as the `request` /
shell-out family) instead of the plain `view` level the rest of `monitor`
(interface stats, terminal-only `packet-drop`) uses. A `read-only` /
`config-viewer` class — intended only to VIEW config and status — is
therefore **denied** `monitor traffic`; `operator` and `super-user` are
allowed. This mirrors Junos, which gates `monitor traffic` behind the
maintenance permission, not plain read-only. The exception lives in
`requiredPermission` (`pkg/cli/permissions.go`) and resolves the subcommand
with the same prefix matcher the dispatcher uses, so an abbreviated `monitor
tr` is gated identically to the fully-spelled form and cannot bypass the
gate. Other `monitor` subcommands and read-only `show` commands are
unaffected.

**Privileged-subcommand exception — `monitor security flow {file,start}`
(#5038).** The file-backed flow trace makes the **root daemon create, append
to, and rotate a file on disk** (`openTraceFile` / `rotateTraceFile`,
`pkg/cli/monitor.go`). At `view` level a `read-only` class could point that
write at, and rotate-rename, an arbitrary existing regular inode — corrupting
or displacing a privileged log. `monitor security flow file <name>` and
`monitor security flow start` are therefore gated at the **control** level
too (same `requiredPermission` prefix-resolved gate as `monitor traffic`), so
a view-only class cannot trigger the root write at all. The status form (bare
`monitor security flow`), `filter` (in-memory), `stop`, and the terminal-only
`monitor security packet-drop` stay `view`. Defense in depth: traces are also
confined to a dedicated root-owned (0700) directory `/var/log/xpf-flow-trace`
rather than the shared `/var/log`, so even a control-level operator's trace
filename can never resolve onto — or rotate/rename — a system-log inode such
as `/var/log/auth.log`.

**Filter option-injection hardening — `monitor traffic ... matching` (#4524).**
The `matching <filter>` clause greedily consumes every token up to the next
grammar keyword and passes them to the root `tcpdump` capture. Without an
end-of-options guard a filter such as `matching -w /etc/cron.d/x` or
`matching -z <cmd>` reaches tcpdump as the `-w` (arbitrary file write) or `-z`
(post-rotate command execution) **option** under glibc getopt argv
permutation — escalating a control-level capture privilege to root
file-write / command-exec, and violating the capture-only contract even for
`super-user`. `buildMonitorTrafficArgv` (`pkg/cli/cli_request.go`) now inserts
an explicit `--` end-of-options separator before the filter tokens (mirroring
the diagcmd ping/traceroute #2084 treatment), so getopt stops scanning for
options and every filter token is parsed as part of the pcap filter
**expression** — an injected `-w`/`-z` becomes a filter operand that libpcap
rejects at compile time rather than a tcpdump option. A defense-in-depth
`validateMonitorFilter` check additionally rejects any option-looking filter
token (a term beginning with `-`, other than a bare `-`) up front with a clear
error. Legitimate pcap filters (`host 10.0.0.1 and port 22`, `tcp port 80`,
`not arp`) are unaffected.

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

**SNMP community masking in status commands (#4111).** The #4099 redaction
above covers the config-render surfaces (they route through the `RedactedClone`
renderers). Two **operational status** commands, however, format the typed
active config directly and so bypassed that path: `show system services`
(`showSystemServices`, `pkg/cli/cli_show_system.go`) printed `Community: <name>
(<auth>)`, and `show snmp` (`showSNMP`, `pkg/cli/show_services_snmp.go`) printed
`  <name>: <auth>`. Both are PermView `show` commands reachable by
`read-only` / `config-viewer` / `operator`, so the SNMP community string — a
read/write credential — leaked in cleartext to view-only classes. They now
reuse the same `CLI.showConfigRedacted()` predicate: for any class without
`PermAll` the community **name** is masked to `##SECRET-DATA##` while the
authorization **mode** (`read-only` / `read-write`) stays visible; `super-user`
and the unset/legacy class still read the cleartext name (parity with the #4099
config-render decision above). The TSIG key already showed `(secret redacted)`
and SNMPv3 renders auth/priv protocol names only, so the community name was the
last cleartext SNMP secret on these two surfaces.

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

## Removing a login user revokes its host credentials (#5128)

Deleting a whole `system login user` from config — not just its
`encrypted-password` directive — revokes that account's host access on
the next commit. Before #5128 only the sudo grant was swept
(`reconcileSudoers`); the account, its password, and its
`authorized_keys` all survived, so a deprovisioned operator could still
SSH in by password or key. `reconcileAbsentLoginUsers`
(`pkg/daemon/login_password.go`) closes that gap and, like
`reconcileSudoers`, runs **unconditionally** on every apply (including
the "all users removed" case):

1. Enumerate `/var/lib/xpf/provisioned-users/` — the accounts xpf
   actually provisioned (the UID-keyed provenance markers, #1944 §5.4).
2. For each marked username **no longer present** in
   `system login { user ... }`, and **only** while the marker's recorded
   UID still equals the account's current `/etc/passwd` UID
   (`xpfProvisioned`): **lock** the password (`<user>:!` via
   `chpasswd -e`, idempotent — skipped if already locked) and **remove**
   the xpf-managed `/home/<user>/.ssh/authorized_keys`, then drop the
   provenance marker so xpf forgets the account.

The path is scoped and fail-closed:

- An **out-of-band account** (no marker) is never enumerated, so it is
  never touched.
- A marker whose UID no longer matches the live account (deleted +
  recreated out of band with a different UID) is treated as **not ours**:
  the account is left intact and only the stale marker is cleaned.
- On a `/etc/shadow` read error, a `chpasswd` failure, or an
  `authorized_keys` removal failure, the marker is **retained** so the
  next apply retries — a credential is never forgotten while it may still
  be live.
- `root` is never deprovisioned.

Unlike the `zeroize` teardown (#4598), which `userdel -r`s the whole
account, ordinary removal only **locks** the password and removes the
managed key file. That fully revokes login (password and key) while
being reversible: re-adding the user to config recreates the account and
re-provisions it. Note the distinction from the section above: removing
just the **`encrypted-password` directive** (user still present) locks
the password but leaves `authorized_keys`; removing the **whole user**
revokes both.

### Emptying a retained user's SSH keys revokes the key file (#5106)

`reconcileAbsentLoginUsers` only fires for a user that has been **removed**
from config. A user that is **retained** but has had its **last**
`authentication ssh-rsa`/key removed (key list now empty) was NOT covered:
`applySystemLogin` wrote `authorized_keys` only inside `if len(user.SSHKeys)
> 0`, so an emptied key list left the stale key file installed and the
revoked key still permitted login. `applySystemLogin` now reconciles the
empty-key-list case in the matching `else` branch: when a configured user
has no keys, it removes the xpf-managed
`/home/<user>/.ssh/authorized_keys` so key-based login is revoked. The
removal is gated on the same UID-keyed provenance marker
(`xpfProvisioned`) as the removal path above — xpf only deletes a key file
it wrote wholesale, never a pre-existing / out-of-band user's
operator-installed keys — and is idempotent (an already-absent file is a
no-op). The password directive and the SSH keys remain independent: this
branch touches only `authorized_keys`, and removing the
`encrypted-password` directive still only locks the password.

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
