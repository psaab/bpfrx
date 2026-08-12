# System login & authentication

This is the operator contract for `system login user` and
`system root-authentication` password handling. It documents how a
configured login password reaches the OS account database, the
commit-time validation of the hash, and the declarative reconciliation
behaviour when a password directive is removed — for both per-user
accounts (#1944) and `root` (#5276).

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
allow-everything behavior (no class configured = no RBAC restriction) —
see the next section for the narrow, and only, way that state is reached.

### Which class you get: identity and the default (#6701)

The **in-process console shell's** class comes from the **OS credential of the
invoking process**, never from the environment. "The CLI" unqualified was wrong
here (#6706 review r11): the remote `cli` client has no class at all — its OS
credential only renders the prompt (`cmd/cli/main.go` `resolveUsername`), and
the gRPC listener it speaks to has no per-principal authentication yet (#5278),
so nothing on that path makes an authorization decision. See **Scope** below. `pkg/osident.Current()` reads the **real uid**
(`os.Getuid`) and resolves it through the passwd database; the resolved name
is matched against `system login user <name>`. `pkg/daemon`
`applyCLILoginClass` performs the lookup once, at shell start, and logs the
outcome (identity, uid, resolved class, reason) so an operator locked out by
their own config can see why in the journal.

Before #6701 the identity was `os.Getenv("USER")` and a non-match was handed
**`super-user`**. Both halves were exploitable, and either alone sufficed:
every `system login user` is provisioned with a real shell account
(`useradd -m -s /bin/bash`, #5278), so an operator restricted to
`class read-only` could run `USER=nobody xpf` — or unset the variable — and
receive the highest class in the system. The `!found` branch also promoted any
OS account that merely existed on the box but was absent from `system login`.

The decision, in order:

| Caller | Class |
|---|---|
| resolved name matches a `system login user` with a class | **that class** |
| **non-root** account listed with **no** class | `unauthorized` |
| uid 0 **with** an explicit `system login user root class <c>` | **`<c>`** — an explicit restriction is honoured |
| uid 0 listed with **no** class | `super-user` — an omission is not an instruction; see below |
| uid 0, no matching `system login user` | `super-user` (Junos root default) |
| OS account absent from `system login` | `unauthorized` |
| **non-root** uid with no passwd entry (unidentifiable) | `unauthorized` |
| **non-root** uid shared by several passwd accounts (ambiguous) | `unauthorized` — see below |
| **non-root** uid, passwd database unreadable | `unauthorized` |
| **uid 0** unidentifiable by any of those three | `super-user` — the root default; a class configured for an ALIAS is not applied |
| no `system login` stanza at all | **unset** — legacy allow-everything |

All three unidentifiable cases deny identically, but the journal line names
which one it was: "has no passwd entry", "is shared by more than one passwd
account", "the passwd database could not be read". They send the operator to
three different fixes, and reporting one as another sends them hunting for an
account that is in fact present.

**Why uid 0 listed with no class is not denied, when a non-root account in the
same shape is.** The two are different questions. For a non-root account
`system login` is the authority on what it may do, and saying nothing is not
permission. For uid 0 it is neither an instruction nor enforceable:
`set system login user root authentication ssh-ed25519 "…"` is an ordinary way
to give root a key and expresses no intent to restrict anything, so denying on
it would demote the **console** shell to `unauthorized` — a lockout of the
lifeline caused by a purely additive config. And uid 0 owns the config database,
the daemon process and the on-disk secrets, so a CLI denial is advisory
regardless. An **explicit** class on `user root` is a different matter and is
honoured.

**uid 0 restriction is advisory.** Honouring `system login user root class <c>`
prevents accidents; it is not a containment boundary, because uid 0 can edit the
config database directly. If uid 0 resolves through a passwd **alias** (a second
passwd row for uid 0, the classic `toor`), the resolved name is consulted first
and the literal `root` second, so an explicit restriction written for `root`
still applies to the aliased identity rather than being silently skipped. When
**both** rows exist the uid is ambiguous (below) and only the literal `root` is
consulted, which is deterministic and still the console lifeline.

**A uid shared by several accounts fails closed.** The kernel gives xpf a
number, not a name. If `/etc/passwd` maps that number to more than one account —

```
admin:x:2001:2001::/home/admin:/bin/bash
bob:x:2001:2001::/home/bob:/bin/bash
```

```
set system login user admin class super-user
set system login user bob   class read-only
```

— then bob's shell and admin's shell are indistinguishable to any consumer of
the credential, and resolving the uid to "whichever passwd row comes first"
(what `os/user` does) hands bob `super-user`. That is a privilege escalation
**between two legitimate accounts**, so it is not disposed of by "a duplicate-uid
passwd file is a broken host". xpf refuses to name such a caller: the identity is
unresolved and the class is `unauthorized`. The fix is to give the accounts
distinct uids.

xpf never creates the situation itself — `reconcileSystemUsers` invokes
`useradd` **without** `-o`, so a duplicate uid is rejected by the tool — but a
pre-existing, hand-edited or directory-supplied alias is outside its control,
and an authorization decision must not depend on that.

uid 0 is exempt from the denial for the usual reason: `root` + `toor` is a
supported layout, uid 0 is not a boundary xpf can enforce, and locking the
console out over it would be the larger failure. An ambiguous uid 0 keeps the
Junos root default and still honours an explicit `system login user root
class <c>`.

**Why the passwd database is read directly instead of through `os/user`.** The
appliance binaries are built `CGO_ENABLED=0` (Makefile), which selects the Go
standard library's pure-Go `os/user`. In that implementation `user.LookupId(uid)`
returns the cached `user.Current()` when the uid matches — it always matches,
since xpf asks about its own uid — and pure-Go `current()` **fabricates** a user
from `$USER` and `$HOME`, with a nil error, whenever the real passwd lookup
fails. On a box where the caller's uid has no passwd row (a minimal container,
an NSS/LDAP outage, a deleted account, an unreadable `/etc/passwd`),
`USER=admin HOME=/tmp cli` therefore resolved to the account name `admin` — the
#6701 hole reopened one layer below the call sites #6701 audited.

`pkg/osident` scans `/etc/passwd` itself instead. Under the shipped build that
is exactly what the standard library would have done for any uid that HAS a row
(pure-Go `os/user` reads the same file and consults no NSS), so resolved names
are unchanged; what changes is that a uid **without** one is now unidentified
rather than whatever the caller put in `$USER`. A cgo-enabled developer build
loses NSS name resolution — which affects the RBAC **class decision**, not just
the displayed prompt: an NSS-only account (LDAP, SSSD) resolves to unidentified
and is denied. That is a narrowing for every **non-root** uid. At uid 0 it is a
**promotion**, for the same reason as the table row above: an unnamed uid 0
takes the root default, so losing the name of an aliased root that carried an
explicit restrictive class hands it `super-user`. uid 0 is essentially always a
local passwd row, so this corrects the claim rather than describing a reachable
production regression, and the shipped build is `CGO_ENABLED=0` either way.
`TestNoOsUserInIdentityResolution_6701` keeps `os/user` out of the package.

The same narrowing reaches a second route worth naming explicitly. Host-account
provisioning gates `useradd` on `id -- <name>` failing
(`pkg/daemon/daemon_system.go`), so an operator account that exists only in a
directory service never gets a local passwd row — and therefore now resolves to
`unauthorized` on the CLI. This is sound: before #6701 that population was
"authenticated" by `$USER`, which is to say not authenticated at all. An
operator who needs CLI access for such an account should be given a local
`system login user` entry.

`unauthorized` is used rather than an unset class deliberately. The empty
string is the legacy no-RBAC mode: `checkPermission` returns `nil` (allow
everything) and `showConfigRedacted` returns `false` (render PSKs, SNMP
communities and authentication-keys in cleartext). Failing closed therefore has
to **name** a class. `unauthorized` resolves to an empty-but-present permission
set, so `checkPermission` denies every command by name and `showConfigRedacted`
masks secrets.

That safety depends on one property in a different function: `resolveClassPerms`
consults the system-defined table **first**. A config carrying
`system login class unauthorized { permissions all; }` would otherwise turn the
fail-closed default into a full-power one for every unidentifiable caller. Such
a definition is rejected at commit (see built-in shadowing below), but the
tolerant load / peer-sync path only warns, so the runtime precedence is what
actually holds — pinned by
`TestUnauthorizedClassCannotBeWidened_6701`.

The uid-0 default is Junos parity and is the console lifeline: uid 0 already
owns the config database, the daemon process and the on-disk secrets, so it is
not a boundary xpf could enforce. It applies **only** when `system login` says
nothing about root — an explicit `system login user root class <c>` wins,
because a configured restriction silently ignored is exactly the defect class
#6701 removes.

**Scope.** This is the on-box CLI boundary. The gRPC listener
(`127.0.0.1:50051`) still has no per-principal authentication, so a shell user
who speaks gRPC directly bypasses `checkPermission` entirely — that is a
separate, still-open defect (#5278) and is not addressed here. The remote `cli`
client's prompt identity was moved to the same OS credential so that when
#5278 wires per-principal auth it finds the identity already coming from the
kernel, but the client is not itself an authorization boundary today.

The class **name** is resolved once, at shell start, and is not re-evaluated
mid-session. That matches Junos (your class is bound at login). The class's
**permissions** are not bound: `resolveClassPerms` (`pkg/cli/permissions.go`)
reads `store.ActiveConfig()` on every check, so a custom class's permission set
is whatever the **currently active** config says.

An earlier revision called that "not an escalation path" on the grounds that
"changing `system login` requires `configure`, which none of the restricted
classes hold". The premise is false for **custom** classes, which may carry
`configure` (see below), and the conclusion does not follow. Measured by driving
the real store and checker: a session bound to a custom class holding
`[view configure]` is denied `request system reboot` and gets
`showConfigRedacted == true`; after that same session commits
`set system login class <its-own-class> permissions all`, the identical checks
return **allowed** and **false** — secrets in cleartext — with no re-login.

The accurate statement of the boundary is the asymmetry:

| Change | Takes effect mid-session? |
|---|---|
| widening the bound class's permissions | **yes**, immediately |
| narrowing the bound class's permissions | **yes**, immediately |
| moving the user to a different class | no — the class NAME is bound |
| deleting the user from `system login` | no — same reason |

The widening row is not a boundary being crossed that could not be crossed
otherwise: a class holding `configure` can already author a `super-user` account
and use it. What is worth stating plainly is that it happens **immediately and
in the same session**, and that the narrowing row is what makes a mid-session
revocation of a class's permissions actually effective.

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

A custom class **may not shadow a system-defined name** (#6701). At runtime
`resolveClassPerms` consults `LoginClassPermissions` **first**, so a definition
like

```
set system login class super-user permissions view
```

is completely **inert** — the built-in `[PermAll]` wins and the user holds every
permission — while the compile advisory reported `mapped to xpf coarse
permissions {view}`, i.e. told the operator the narrowing had taken effect. That
is the same "configured restriction silently absent in the permissive direction"
shape as the identity defect above, so a shadowing definition is now
**hard-rejected at commit** naming the collision, and downgraded to a warning on
the tolerant load / peer-sync path. Built-in-first precedence itself is
deliberately unchanged: inverting it would let
`class read-only permissions all` **escalate** a built-in, which is strictly
worse. Pick a distinct class name, or reference the built-in directly.

> **Compatibility break.** The system-defined names are `super-user`,
> `operator`, `read-only`, `config-viewer` and `unauthorized`. A migrated vSRX
> config that defines a **custom** class under one of those names — most
> plausibly `config-viewer`, which reads like an ordinary site-defined name and
> appears as one in this repository's own vSRX excerpt
> (`docs/junos-config-display-reference.md`) — now fails strict import and the
> next commit. This is intended: on Junos that definition was live, on xpf it
> was already inert, and the old silence is exactly the defect. **Upgrade boot
> does not brick** — the tolerant load path warns and keeps running — so the
> break surfaces on the operator's next `commit` / `load override`, with the
> collision named. Rename the class (`site-config-viewer`) and update the
> `system login user <name> class <c>` references, or drop the definition and
> reference the built-in.

**Both gates are evaluated for BOTH cluster nodes.** The packed-body gate and
the shadowing gate run **before** apply-group expansion and evaluate the
effective view of node 0 **and** node 1. Without that, a body scoped to the peer

```
groups {
    node1 { system { login { class super-user { permissions view; } } } }
}
apply-groups "${node}";
```

was stripped from node 0's view before either gate ran, so the commit passed on
node 0; the standby then ingested the config through `Store.SyncApply`, which is
the **tolerant** path and only warns. The stanza was live on node 1 with no
strict check anywhere in the cluster. Now whichever node commits rejects it, and
the verdict is identical on both. A body staged in a group that no
`apply-groups` references stays inert and is not rejected — it renders on no
node. (Same doctrine as the QinQ / vlan-map / unit-alias gates, and the
AST-layer analogue of the peer-effective source-NAT replay in
`compiler_peer_effective_snat.go`.)

### Write the body as a block or as `set` — never packed on the line (#6662)

Junos accepts a statement written on the instance line; xpf compiles the body
only from a **nested block** or a flat **`set`** statement:

```
system { login { user alice { class ops; } } }      # OK — class = "ops"
set system login user alice class ops               # OK — class = "ops"
system { login { user alice class ops; } }          # REJECTED at commit
```

Before #6662 the third form compiled a user with an **empty class** and the
commit **succeeded**. The mechanism is documented in
`docs/config-schema.md` ("Packed statements"): `namedInstances` resolves the
instance name across both AST shapes but leaves the body on `Keys`, and the
login compiler walks `.Children`, which is empty.

An empty class is precisely the legacy allow-everything mode, so a
`class read-only` operator hand-migrating a vSRX config got a CLI that allowed
every command and rendered secrets in cleartext — with `show configuration`
echoing their intent back. Rejecting is load-bearing because the downstream
safety nets are all guarded on non-emptiness, including the `deny-commands`
"MORE PERMISSIVE" advisory above (`if lc.DenyCommands != ""`): the field the bug
dropped is the field the guard reads.

This applies to the whole stanza, at every level:

| Statement | Packed spelling | Result |
|---|---|---|
| `login class <n>` — `permissions`, `idle-timeout`, `allow-commands`, `deny-commands`, `allow-configuration`, `deny-configuration`, `login-alarms`, `login-tip` | `class ops permissions view;` | **rejected** |
| `login user <n>` — `uid`, `class`, `authentication` | `user alice class ops;` | **rejected** |
| `login user <n> authentication` (a block) written inline inside a nested user body | `user alice { authentication ssh-rsa "…"; }` | **rejected** |
| the instance on the **`login`** statement line | `system { login user alice class ops; }` | **rejected** |
| `login` itself on the **`system`** statement line | `system login user alice class ops;` | **rejected** |

#### The `system` and `login` lines too (#6706)

The two ANCESTOR levels of the path drop the same way, and they were the
dangerous ones. `system login` compiles only when the path descends into a
nested block at **every** step:

```
system { login { user alice { class ops; } } }   # OK
system { login user alice { class ops; } }       # REJECTED — instance on the `login` line
system login { user alice { class ops; } }       # REJECTED — `login` on the `system` line
system login user alice class ops;               # REJECTED — the whole path on one line
```

Before #6706 all three of the rejected forms **committed green** and compiled
nothing. The cost differs by level, and the message says which:

| Packed at | Compiles to | Runtime |
|---|---|---|
| the instance line | a user with an **empty class** | fail-**closed**: `ResolveLoginClass` maps it to `unauthorized` |
| the `login` line | `System.Login` present but **empty** | fail-**closed** for non-root (`unauthorized`), root keeps its default |
| the `system` line | `System.Login == nil` | fail-**closed** since #6706: `LoginDroppedByPacking` suppresses the legacy early return, so a non-root caller gets `unauthorized` and root keeps its default. (Before #6706 this row WAS fail-OPEN — empty class, every command allowed, secrets in cleartext.) It applies to content-free prefixes too, e.g. `system login;`; whether it should is #6972 |

At every level, zero configured users also means `reconcileAbsentLoginUsers`
sees an empty desired set and **deprovisions every xpf-managed operator
account** on the next apply.

`system login;` and `system login user;` name no user and no class, so there is
no authored instance to report as dropped and they are **accepted** — rejecting
them would be an outage of its own. They are **not** equivalent between the two
spellings, though, and an earlier revision said they "declare nothing in either
spelling", which is false (#6706 review r11): `system { login; }` compiles a
non-nil empty `LoginConfig` and denies every non-root caller, while the packed
`system login;` compiles `System.Login == nil` and reaches the legacy
allow-everything mode. Deactivated config (`inactive:`) is pruned before any
gate runs and is unaffected.

The tolerant load / peer-sync path **warns** instead of rejecting (#1960
no-brick), so a node that persisted such a config under an older binary still
boots. An earlier revision claimed the resolver kept that from being an RBAC
hole because "a matched user with an empty class resolves to `unauthorized`".
That is true only of the `login`-line packing, where `System.Login` is non-nil
but empty. At the `system` line the stanza compiles to **nil**, there is no
matched user, and `applyCLILoginClass` used to take its
`cfg.System.Login == nil` early return — leaving the shell with **no class at
all**: every command permitted and secrets in cleartext, on a config that reads
as restrictive.

What closes it is `Config.System.LoginDroppedByPacking` (#6706 review r11): the
compiler records that a `system login` path was authored packed — for every
packed shape, including the two short prefixes above that the gate deliberately
does not report — and `applyCLILoginClass` refuses the legacy unset-class mode
when it is set, resolving through `ResolveLoginClass` instead. Non-root callers
get `unauthorized`; uid 0 keeps the console lifeline. A config that never
configured RBAC is untouched: the flag is false, the early return still fires,
and the legacy contract is unchanged.

`login-alarms` and `login-tip` are accepted by the grammar but have no compiler
arm in **either** spelling — a pre-existing accept-but-ignore gap, not a packed
drop.

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

**Config-root scope guard (#5684).** The wipe target is the daemon's configured
config root — `filepath.Dir(store.ConfigPath())`, the directory of the `-config`
path (#5280/#5554), so a non-default `-config /srv/xpf/site.conf` erases
`/srv/xpf`, not a hardcoded `/etc/xpf`. But `filepath.Dir` on a
custom/adversarial `-config` can resolve to a directory xpf does not own: a
config file placed directly in a shared directory (`-config /etc/xpf.conf` →
`/etc`; `-config /srv/site.conf` → `/srv`) or a directory-shaped `-config`
(`-config /srv/firewall`, where `filepath.Dir` climbs to the **parent** `/srv`).
Because the config-state sweep globs `*.conf` / `rollback*` and `RemoveAll`s
`<root>/.configdb` and `<root>/tls`, an unowned root would turn a factory reset
into a **broad deletion of sibling files** in that shared/parent directory.
`configstore.ValidateFactoryResetRoot` closes this: it refuses a config root
that is non-absolute (a relative/empty `-config` resolves to the daemon's
working directory) or equal to the filesystem root or a well-known shared/system
directory (`FactoryResetForbiddenRoots`: `/`, `/etc`, `/srv`, `/home`, `/var`,
`/usr`, …). The check is lexical on `filepath.Clean` (so a trailing slash and
`..` traversal normalize first). The default `/etc/xpf` and any dedicated
subdirectory pass. The guard runs at both resolution points
(`(*Server).zeroizeConfigRoot`, `(*CLI).zeroizeConfigRoot`) — so a bad root
fails **closed before any wipe leg runs**, erasing nothing — and, as
defense-in-depth, again inside **each** config-state wipe primitive before it
touches disk: the CLI's `configstore.FactoryResetConfigDir` and the gRPC
`grpcapi.zeroizeConfigDir` (the latter is the more destructive one — it
`RemoveAll`s `<root>/tls` and `<root>/.configdb`), so neither primitive trusts
its caller to have handed it an xpf-owned root.

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

Beyond those exact paths, each rendered directory (`/etc/frr`,
`/etc/swanctl/conf.d`, `/etc/kea`) is **swept for crash-leaked `fsatomic` write
temps** (`.<base>.tmp-<rand>`, #5509) — the rendered-config sibling of the
`/etc/xpf` sweep (#5475). All three renders are written via `pkg/fsatomic`
(`frr.WriteFileDurable`, `ipsec.WriteFileAtomic`, `dhcpserver.WriteFileAtomic`),
which drops a `.<base>.tmp-<rand>` temp holding the **full cleartext render**
(routing-auth keys, IKE PSKs, Kea credentials) before its atomic rename. A
daemon hard-killed mid-write leaves that temp behind; `fsatomic` self-heals a
leaked temp on the *next* write to that base, but a factory reset + reboot has no
next write, so an exact-path-only removal (`StripManagedSectionFile` /
`os.Remove`) would let the temp — and its secrets — survive to the next tenant.
The sweep is scoped to those xpf-owned rendered directories, matches only the
narrow temp shape (so a legitimate service config or operator snippet in the same
directory is untouched), and treats an absent/unmanaged directory as a clean
no-op.

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
- **All three marker roots are erased (#5841).** The account loop above
  enumerates only `provisioned-users`, but the #5841 split records
  password/key ownership in two **sibling** roots
  (`/var/lib/xpf/provisioned-passwords`, `/var/lib/xpf/provisioned-keys`). A
  factory reset erases those too (`zeroizeSweepResourceMarkerRoot`): a surviving
  per-account UID marker is #5869/#5871-class residue, and because
  `reconcileAbsentLoginUsers` **unions all three roots**, a re-tenant's
  reused-UID account (useradd hands the first non-system user UID 1000)
  colliding with a surviving marker would be deprovisioned — its password
  locked, its `authorized_keys` deleted — despite xpf never provisioning it, the
  exact overclaim #5841 kills, resurrected on a "factory-reset" box. The sweep
  removes every marker in the two resource roots (keeping only names **retained**
  for a fail-closed registry retry, so an account's three markers stay together)
  and drops the roots, so no marker survives in **any** of the three roots —
  mirroring the daemon's own `forgetProvenance`.
- **Key-only accounts' `authorized_keys` is removed too (#6190).** The account
  loop removes `authorized_keys` only for accounts in the `provisioned-users`
  registry, but a **key-only** account — a pre-existing operator/prior-tenant
  account xpf only added an SSH key to (`system login user <name> authentication
  ssh-*` with **no** `encrypted-password`) — gets a `provisioned-keys` marker and
  **no** registry marker (`applySystemLogin` writes `markProvisioned` only in the
  useradd branch; `reconcileUserPassword` only on a password apply). The registry
  loop never iterates it, so before #6190 the marker was swept (#5841/#6183) but
  the xpf-written `/home/<name>/.ssh/authorized_keys` **file** was not — the prior
  tenant kept SSH login on that account after a "factory reset", the #4598
  credential-leak class, **asymmetric** with the day-2 path
  (`reconcileAbsentLoginUsers` enumerates the **union** `provisionedNames()` and
  `deprovisionLoginUser` **does** remove that key file, gated on
  `keyProvisioned`). `zeroizeSweepProvisionedKeys` closes the asymmetry: it
  removes the xpf-written key **file** for every account with a `provisioned-keys`
  marker (the union delta the registry loop misses), **UID-gated and
  fail-closed** — the file is removed only when the live `/etc/passwd` UID equals
  the keys marker's recorded UID (a proven **UID-mismatch** is an out-of-band
  recreate whose `authorized_keys` belongs to someone else → left intact, marker
  retained), an unreadable passwd / unparseable marker **fails closed** (retain,
  surface the error), and an account whose registry teardown was **retained** is
  skipped entirely so its marker and key file stay consistent. `root` is never a
  key-only account (`applyRootAuth` writes the registry marker alongside the key
  marker) and its keys live at `/root/.ssh`, so this sweep never touches a
  `/home/root` key file — root is revoked in place by `zeroizeRootLoginAccount`.
  An **operator's own** (unmarked) `authorized_keys` is never touched — only what
  xpf wrote. On a **real key-removal error** (an immutable file, an
  `ENOTDIR`/`ENOTEMPTY` path shape, an I/O error) the key **file survives**, so
  the keys marker is **retained** and the error surfaced (`reset incomplete`), so
  a retried reset re-enumerates the account and re-attempts — mirroring the day-2
  `deprovisionLoginUser` contract, which keeps the markers and retries on a real
  `authorized_keys` removal error (#6201). The account-registry teardown may drop
  its marker after a key-removal error only because `userdel -r` backstops the
  removal by deleting the whole home tree; this key-only sweep has **no** such
  backstop, so dropping the marker while the key survives would strand the prior
  tenant's SSH key with no retry evidence (`zeroizeRemoveKeyFileThenMarker` gates
  both the proven-owned and genuinely-absent branches).
- **Ownership uncertainty fails CLOSED (#5496).** Deciding "is this the account
  xpf provisioned?" needs two reads — the live UID (`/etc/passwd`) and the
  recorded UID (the marker). If **either** cannot be resolved — `/etc/passwd`
  unreadable, a **malformed UID**, or an **unreadable/unparseable marker** —
  ownership is **UNKNOWN, not proven absent**. The teardown then makes **no**
  destructive change, **retains** the marker (durable evidence for a safe
  retry), and **surfaces** the error so the reset is reported **incomplete**.
  The earlier code conflated an unresolved read/parse with proof-of-absence (or
  a stale marker), erasing the marker and returning a clean result while a live
  xpf-provisioned **password** account survived — now un-rediscoverable because
  its retry marker was destroyed. A **proven UID-mismatch** is likewise reported
  (unresolved) and its marker retained, absent an explicit durable stale-marker
  policy. This is the factory-reset sibling of the day-2 login fail-closed rule
  (#5493) — the same `lookupUIDGIDErr` three-state discipline at a distinct
  locus.

**Never-touch safety invariant.** The teardown must never nuke a non-xpf account
or strand access:

- An **operator's own account** (created out of band, no xpf marker) is never
  iterated — its keys, sudoers, and login stay intact.
- **System accounts** (and an **unmanaged-root** appliance's `root`) have no
  marker and are never iterated — untouched by the teardown.
- **`root` on a managed-root appliance IS revoked (#5520).** Since #5276 the
  daemon writes a genuine provenance marker for `root`
  (`markProvisioned("root", 0)`), so `root` reaches the teardown. It must NOT
  take the generic path — root's `authorized_keys` is at **`/root/.ssh`**, not
  `/home/root/.ssh` (which the generic path would miss, leaving the prior
  tenant's root SSH key live), and **`userdel -r root` fails on UID 0** and can
  abort the whole reset. So `root` is special-cased and revoked **in place**
  (`zeroizeRootLoginAccount`): remove `/root/.ssh/authorized_keys` **and** lock
  the root password (`passwd -l root`), **never** `userdel`. Fail-closed like
  the rest — the marker is retained and the reset reported incomplete unless
  both revocations succeed. A factory reset MUST revoke root; a
  decommissioned/RMA'd appliance that kept prior-operator root login would be a
  false factory reset.
- An **out-of-band `userdel`+recreate** with a different UID (marker UID ≠ live
  UID) is left alone — the current owner is someone else, exactly the #1944
  leave-then-rejoin-vs-recreate distinction. Since #5496 this mismatch is also
  **reported** and its marker **retained** (rather than silently erased with a
  clean-reset report), so the anomaly is re-examined on a retry.

**Local config-archive erasure (#5186).** The three erasures above cover the
config SSOT/rollback/journal state, the rendered service configs, and the login
accounts — but they missed the last on-box generation of config secrets: the
**local configuration archive** at **`/var/lib/xpf/archive`**. `writeArchive`
drops timestamped `config-<ts>.<seq>.conf` snapshots there (Junos `system
archival`), each a **0600 copy of the full committed config TEXT** with the same
cleartext secret leaves as a rollback slot (IKE PSK, WireGuard private keys, SNMP
communities, BGP-MD5). A pre-#5186 `zeroize` left the archive untouched, so a
re-tenanted / RMA'd / resold device still handed the next owner the prior
tenant's archived secrets — a false factory reset. `zeroize` now erases it at
wipe time too (`configstore.FactoryResetArchiveDir`, same error-surfacing +
final-fsync durability discipline as the config-state wipe), and **both** the
gRPC `performZeroizeWipe` and the on-box CLI `request system zeroize` route
through that single shared primitive so they wipe the same archive.

- **Ownership guard.** Only the **xpf-owned default** path
  (`configstore.DefaultArchiveDir` = `/var/lib/xpf/archive`) is erased. An
  operator-configured **custom** archive directory — a remote mount, an NFS
  export, or a compliance/audit retention store — is **NOT** xpf's to destroy;
  blindly deleting it could wipe records the operator is required to keep. Such a
  path cannot be proven xpf-owned, so it is **skipped with a warning** rather
  than deleted (never a fail-closed delete). This mirrors how the config-state
  wipe proves ownership by its fixed default appliance path and how the
  login-account teardown refuses to touch a non-xpf-owned account.
- **Error surfacing.** A deletion or final directory-fsync failure is surfaced
  (folded into the wipe result / returned by the CLI), so a `zeroize` that could
  not fully erase the archive is never reported as a clean factory reset.
- **In-flight archive-writer fence + join (#5869).** Erasing the directory is not
  enough: auto-archive launches a **fire-and-forget writer goroutine** per commit
  (`commitWithDescriptionLocked`), and `writeArchive` starts with
  `os.MkdirAll(archiveDir)`. The #5281 terminal reset generation gates the
  daemon's config writers but **not** that configstore-owned goroutine, so a
  writer scheduled just before a `zeroize` could resume **after**
  `FactoryResetArchiveDir` removed the directory and **recreate** a
  `config-<ts>.<seq>.conf` snapshot of the **prior tenant's** full config text —
  re-tenant secret residue, a zeroize that did not actually erase everything. The
  daemon's factory-reset transaction (`daemon.factoryReset`) now calls
  `store.QuiesceArchival()` **after** entering the reset generation and **before**
  the wipe: it sets a one-way **archive fence** (a new/not-yet-written writer
  no-ops instead of recreating the archive) and **joins** every in-flight writer
  (`archiveWG.Wait()`) that has already begun, so once it returns no writer can
  recreate the directory the wipe is about to erase. The join is the load-bearing
  half — it closes the write-after-wipe window a fence alone cannot. On a
  **fail-closed recoverable wipe** the daemon stays up and resumes normal work, so
  it also `ResumeArchival()`s (clears the fence); on a **successful** wipe the
  daemon is stopped and the fence stays latched.
  - **Synchronous `Store.ArchiveConfig` is fenced too (#6185).** The same fence
    now also gates the **synchronous** archive path. `Store.ArchiveConfig` has
    **zero** production callers today, but if it were ever wired to an operator
    command (e.g. `request system configuration archive`) an unfenced call could
    run **after** the fence was set and the archive dir erased, `os.MkdirAll` it
    back, and drop a prior-tenant snapshot — reopening the residue for that path.
    It now (1) **no-ops** when the fence is set and (2) registers itself in
    `archiveWG` when it is not, so a concurrent `QuiesceArchival` **joins** an
    in-flight synchronous write before the wipe, exactly like the async writer.

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
config-render decision above) — **on the in-process console CLI only; see the
next paragraph for `cli`**. The TSIG key already showed `(secret redacted)` and
SNMPv3 renders auth/priv protocol names only, so the community name was the
last cleartext SNMP secret on these two surfaces.

**The same masking on the REST and gRPC surfaces (#5315, #6532).** The CLI is
not the only place that formats the typed active config by hand. The REST
show-text handler (`pkg/api/show_text.go`) rendered the same community and was
masked in #5315; the gRPC `ShowText{Topic:"snmp"}` renderer
(`pkg/grpcapi/server_show_dhcp_lldp_snmp.go`) was left in the clear until
#6532. Both mask **unconditionally**, unlike the CLI: neither surface carries a
login class to gate on, so there is no privileged caller to exempt — the same
call the sibling gRPC `ShowConfig` raw-AST redaction makes (#4051). The gRPC
one is not merely loopback-bound: `ShowText` is on the cluster-fabric allowlist
(#4122), so that render was reachable from the peer chassis over the fabric IP
(see `docs/architecture.md`).

All four render sites now share one implementation of the masking rule,
`config.SNMPCommunityDisplayName(name, redact)` (`pkg/config/types_system.go`,
next to the `SNMPCommunity` marshal redaction). The CLI passes
`redact=showConfigRedacted()` so its per-class behaviour is unchanged; REST and
gRPC pass `redact=true`. The reason a helper exists rather than an inline `if`
at each site: the community is the **one** operator secret not covered by the
`config.Secret` newtype's `String()` redaction (#2053) — it stays a plain
string because it is the `Communities` map key — so every manual renderer has
to remember to mask it, and three independent copies of that one-line rule are
exactly how the gRPC surface stayed in the clear through two hardening passes.

> [!IMPORTANT]
> **`cli show snmp` is masked for EVERY caller, including `super-user`
> (#6532).** The #4111 super-user cleartext allowance above survives only on
> the **in-process console CLI** (`pkg/cli`, which knows the login class). The
> remote `cli` binary — the primary operator interface — dispatches `show snmp`
> straight to the gRPC RPC (`cmd/cli/show.go`, `c.showText("snmp")`), and
> `cmd/cli` has no login-class awareness at all, so there is no class to
> exempt: it renders `##SECRET-DATA##` for every caller.
>
> Scope, precisely — the two sibling commands do **not** behave this way,
> because neither renders a community at all:
>
> - `cli show snmp v3` uses the `snmp-v3` topic, which prints only the USM
>   user table (user, auth protocol, privacy protocol). No community, so no
>   placeholder. The USM auth/privacy PASSWORDS were never rendered by it —
>   they are `config.Secret`-typed and masked by the newtype (#2053).
> - `cli show system services` uses the `system-services` topic, whose
>   renderer omits SNMP entirely (it lists the gRPC/REST endpoints). The
>   community masking described for #4111's `show system services` therefore
>   applies to the **console** CLI only; the remote command never showed a
>   community in the first place.
>
> This is a deliberate posture change, not an oversight. Threading a login
> class into `pkg/grpcapi` is not possible today (the package has no class
> plumbing) and would be actively wrong on the fabric listener, where the
> caller is the peer chassis rather than a user. Masking unconditionally is
> also what the sibling `ShowConfig` already does (#4051), so `cli show
> configuration snmp` was ALREADY masked for every class before #6532 — the
> two remote read-back paths now agree instead of contradicting each other.
>
> Operational consequence to be aware of: an operator has **no remote
> read-back path** for a configured community. Recover it from the console
> CLI as `super-user`, or from the DR archive (`request system configuration
> rescue`) — note that a redacted export is deliberately not restorable
> (#4060). The community remains fully functional on the wire; only its
> display is masked.

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

1. Enumerate the **union** of the three ownership roots (`provisionedNames`,
   #5841) — every account xpf provisioned any resource for (registry,
   password, or key marker).
2. For each such username **no longer present** in
   `system login { user ... }`, and **only** while a marker's recorded UID
   still equals the account's current `/etc/passwd` UID: **lock** the
   password (`<user>:!` via `chpasswd -e`, idempotent — skipped if already
   locked) **iff** xpf set it (`passwordProvisioned`) and **remove** the
   xpf-managed `/home/<user>/.ssh/authorized_keys` **iff** xpf wrote it
   (`keyProvisioned`), then drop all provenance markers so xpf forgets the
   account. An operator-managed credential xpf did not provision is left
   intact (#5841).

The path is scoped and fail-closed:

- An **out-of-band account** (no marker) is never enumerated, so it is
  never touched.
- A marker whose UID no longer matches the live account (deleted +
  recreated out of band with a different UID) is treated as **not ours**:
  the account is left intact and only the stale marker is cleaned.
- On a `/etc/passwd` **read** error the marker is **retained** and the
  deprovision is skipped, so the next apply retries (#5493). A transient
  mount/permission/I/O failure reading the identity database is
  **unknown**, not proof the account is gone — only a *readable* passwd
  that does **not** contain the name is the genuine out-of-band `userdel`
  that legitimately drops the marker. Distinguishing the two is what keeps
  a read hiccup from permanently abandoning a removed user's still-live
  password and keys: once passwd is readable again the marker would be
  gone, so the account would never be enumerated (or revoked) again. This
  mirrors the `/etc/shadow` fail-closed rule below.
- On a `/etc/shadow` read error, a `chpasswd` failure, or an
  `authorized_keys` removal failure, the marker is **retained** so the
  next apply retries — a credential is never forgotten while it may still
  be live.
- `root` is never deprovisioned **by this login-user path** — it is
  reconciled separately by `applyRootAuth` (see "Root credentials are
  revoked on removal (#5276)" below).

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
removal is gated on the **SSH-key** provenance marker (`keyProvisioned`,
#5841) — xpf only deletes a key file **it wrote** wholesale, never a
pre-existing / out-of-band user's operator-installed keys, and **not** merely
because xpf set the account's password — and is idempotent (an already-absent
file is a no-op; the key marker is dropped once the file is gone). The password
directive and the SSH keys remain independent: this branch touches only
`authorized_keys`, and removing the `encrypted-password` directive still only
locks the password.

### Scope — only xpf-managed accounts

The per-user lock-on-removal applies **only to the exact account xpf
provisioned**, and never to accounts absent from config (xpf does not
deprovision/`userdel` accounts). `root` is handled by its own
`applyRootAuth` reconcile (see "Root credentials are revoked on removal
(#5276)"), not this per-user path. Provenance is tracked by UID-keyed marker
files whose content is the account's numeric **UID**: an account **registry**
entry under `/var/lib/xpf/provisioned-users/<name>` (written on `useradd` and a
successful password apply), plus **resource-specific** password- and
SSH-key-ownership markers that gate the respective revocations (#5841, see
"Resource-specific, atomic credential ownership" above).

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

## Root credentials are revoked on removal (#5276)

`system root-authentication` (`encrypted-password` + `ssh-*` keys) gets
the **same** declarative revocation the per-user path has. Before #5276
`applyRootAuth` was **write-only**: it returned immediately when the
stanza was nil and had only positive branches for a nonempty password or
key list. Removing the stanza (or emptying a leaf) left the prior
`/etc/shadow` root hash and `/root/.ssh/authorized_keys` **live**, so
offboarding/rotation/compromise never revoked root access despite a
green commit — while non-root users already locked a removed password
and removed the last managed key.

`applyRootAuth` (`pkg/daemon/daemon_system.go`) now reconciles root
against the current config on every apply, reusing the per-user
machinery keyed on the account name `root` / **UID 0**:

- **Password** — delegated to `reconcileUserPassword` with a synthetic
  `root` login user. A configured `encrypted-password` is applied via
  `chpasswd -e` (with the same apply-boundary `ValidateCryptHash`
  re-check) and records the provenance marker; an **absent** password
  (stanza removed OR the `encrypted-password` leaf emptied) **LOCKS** the
  root shadow field (`root:!`) — but **only** when xpf itself provisioned
  root's credentials (marker present) and the field is not already
  locked, and **never** on a shadow read error.
- **Keys** — a configured key list is written wholesale to
  `/root/.ssh/authorized_keys` and records the provenance marker; an
  **empty** key list (stanza removed OR the `ssh-*` leaf emptied)
  **REMOVES** the xpf-managed `authorized_keys` — but **only** when the
  provenance marker is present, so an **operator-installed** key file xpf
  never wrote is left untouched (provenance-scoped removal, never a
  hand-placed key).

Provenance uses the **same resource-specific** UID-keyed markers as the
per-user path, with UID 0 (#5841): a root **password** marker
(`passwordProvisioned("root", 0)`) gates the password lock, a root **key**
marker (`keyProvisioned("root", 0)`) gates the key removal, and the account
**registry** entry (`markProvisioned("root", 0)`) keeps root enumerated by the
factory-reset teardown. A **keys-only** `root-authentication` (no
`encrypted-password`) writes only the key + registry markers, so it is
revocable **and** can never lock an out-of-band root password. The non-root
`reconcileAbsentLoginUsers` / `applySystemLogin` loops still **skip** `root`
entirely — root is
governed solely by this dedicated `applyRootAuth` path.

**Safety.** The marker gate is the fresh-boot lifeline: an appliance that
**never** configured `root-authentication` has no marker, so root is
**never** locked and console/recovery access is preserved — the same
`_never revoke what xpf did not provision_` invariant the per-user path
enforces. On typical images root's shadow field is already `!`
(distro-locked), so `isLockedShadow` makes the lock a no-op there.
Re-adding `root-authentication` restores the password/keys. Since #5841 the
prior residual edge is closed: a **keys-only** root-authentication writes no
password marker, so removing it revokes only the keys and **never** locks an
out-of-band root password xpf did not set (the password lock is gated on the
password marker, not the account/key marker).

**Idempotent.** Re-applying with the stanza still absent re-locks nothing
(the shadow field is already `!` → `pwNoop`) and removes nothing (the key
file is already gone → `os.Remove` `NotExist` no-op).

## Resource-specific, atomic credential ownership (#5841)

Before #5841 a **single** per-account provenance marker
(`/var/lib/xpf/provisioned-users/<name>`) carried the whole ownership
contract, which was wrong in two security-relevant ways:

- **Coarse (overclaim).** The one marker was treated as proof that xpf
  owned **both** the password and the SSH key. So if xpf provisioned only
  a user's **password** (marker present) while the operator kept their own
  `authorized_keys`, emptying that user's key list — or removing the user —
  let the emptied-key / deprovision reconcilers **delete an operator key
  file xpf never wrote**. For `root`, a keys-only `root-authentication`
  could likewise lock an out-of-band root **password**.
- **Best-effort (underclaim).** The marker was written **after** a
  successful credential mutation, and a marker-write failure was **logged
  and swallowed**. That left a live credential xpf had set but could no
  longer identify — so a later directive removal could **not** lock/clean
  it, and it survived a factory reset un-rediscoverable.

Ownership is now tracked **per resource**, in sibling marker roots that use
the **same UID-file format** as the account registry:

| Root | Meaning | Gates |
|---|---|---|
| `/var/lib/xpf/provisioned-users/<name>` | account/enumeration **registry** — which accounts xpf manages | `reconcileAbsentLoginUsers` + factory-reset teardown enumeration |
| `/var/lib/xpf/provisioned-passwords/<name>` | xpf set the `/etc/shadow` **password** | the declarative D2 password **lock** (`passwordProvisioned`) |
| `/var/lib/xpf/provisioned-keys/<name>` | xpf wrote the **`authorized_keys`** | the key-file **removal** (`keyProvisioned`) |

- **Resource-specific revocation.** The password lock consults **only** the
  password marker; the key removal consults **only** the key marker. Setting
  a password never claims the key file, so an operator-installed
  `authorized_keys` is left untouched. This holds for `root` too — a
  keys-only stanza writes only the key (and registry) marker, never the
  password marker, so it can never lock an out-of-band root password.
- **Marker-first atomicity (fail-visible).** Each resource marker is written
  **before** its credential mutation. If the durable marker cannot be
  written, the mutation is **skipped** (logged, retried next apply) rather
  than performed and swallowed — so xpf never leaves a mutated-but-unmarked
  credential. Because the applies are idempotent (`chpasswd` reads
  `/etc/shadow`; the key write compares content), a transient marker failure
  simply defers to the next commit.
- **Union enumeration.** `reconcileAbsentLoginUsers` deprovisions the
  **union** of all three roots (`provisionedNames`), so a pre-existing
  account xpf only added an SSH key to (key marker, no registry entry) is
  still revoked when removed from config — while its password (which xpf
  never set) is left alone.
- **Registry format unchanged.** The account registry
  (`/var/lib/xpf/provisioned-users`) keeps its exact location and UID-file
  format, so the factory-reset teardown (`pkg/grpcapi` `zeroize`, #4598/#5520)
  that enumerates it and `userdel`s xpf-provisioned accounts is untouched.
- **Marker override seam.** The two resource roots are computed as siblings
  of `provisionedUsersDir`, so pointing that one package var at a throwaway
  tree relocates all three roots together in tests.

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
entry itself also survives a power cut. All three provenance markers — the
account registry and the #5841 password/key resource markers — are likewise
DurableState (`writeProvenanceMarker`), and each is written **before** its
credential mutation (marker-first) so a marker-write failure skips the
mutation rather than leaving it unmarked.
