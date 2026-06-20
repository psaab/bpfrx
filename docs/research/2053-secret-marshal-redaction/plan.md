# #2053 — Redact config secrets at JSON/YAML marshal time

**Status: DRAFT** (Claude plan + Claude-SMR self-review only; awaiting
serial Codex + AGY plan-review)

| | |
|---|---|
| Issue | #2053 |
| Spun out of | #1387 / PR #2043 (Copilot review) |
| Branch | `research/2053-secret-marshal-redaction` |
| Recommendation | **PLAN-READY** (severity upgraded from issue's MEDIUM — see §2) |

---

## 1. Issue framing

The issue's premise: config secrets (TSIG HMAC key, IKE/IPsec PSKs,
OSPF/IS-IS/RIP/VRRP/interface auth keys, SNMPv3 passwords, root/login
crypt hashes, BGP MD5 password, WireGuard private key, REST API
passwords + API keys) live verbatim in the typed/compiled
`*config.Config` struct and are **not** redacted by JSON/YAML
marshalling. Only some carrying structs redact via `String()` (logging
hygiene for `%v`/`%s`/`slog`). The issue asserts there is "no live leak
today" because the only compiled-config marshaller cited —
`configstore.Store.ExportJSON` — is a debug helper with no production
callers.

**This research corrects the premise.** `ExportJSON` is indeed
dead-but-for-tests, but it is **not** the only production
compiled-config marshaller. `GET /api/v1/config` is a registered,
production REST route (`pkg/api/server.go:184`) whose handler
(`pkg/api/config.go:14-21`, `configHandler`) does:

```go
cfg := s.store.ActiveConfig()   // returns *config.Config (compiled)
writeOK(w, cfg)                 // -> writeJSON -> json.NewEncoder(w).Encode
```

i.e. it serializes the **entire compiled config including every secret
field, in plaintext**, to any caller authorized to reach the REST API.
So there **is** a live leak, not merely a by-convention guarantee.
See §2 for the corrected severity.

---

## 2. Honest scope / value framing (severity correction)

The issue rates this MEDIUM ("no live leak today, defense-in-depth").
That rating is built on the false premise above. Corrected picture:

**There is a live plaintext-secret leak on a production surface.**
`GET /api/v1/config` returns the full compiled config as JSON. Exposure
analysis:

- **Default posture**: HTTP API binds `127.0.0.1:8080`
  (`cmd/xpfd/main.go:221`). Loopback-only — so the leak is to *any
  local process / local user on the firewall*, not the network. That is
  still a real privilege/trust-boundary leak (a non-root local account
  that can curl localhost reads the IKE PSK / root crypt hash).
- **`web-management https interface` posture**: the daemon can bind the
  API to a **non-loopback** address over HTTPS with basic-auth/API-key
  auth (`pkg/daemon/daemon_run.go:1143-1165`, `pkg/api/server.go:345`
  comment). In that posture any authenticated operator — including a
  read-only-intended one — gets every secret in plaintext over the
  wire. The auth middleware gates *access* but not *redaction*.

Net: severity is **at least the MEDIUM the issue claims, and arguably
HIGH** because the documented "no live leak" assumption is wrong. Even
under the most charitable read (loopback-only default), defense-in-depth
+ the existence of a real exposed-binding mode justifies the fix.

**Value vs churn.** The fix is genuinely cross-cutting (≈14 secret
fields across 5 type files), but the round-trip risk that usually makes
this kind of change scary is **absent here** (see §6): nothing in the
tree unmarshals a compiled `*config.Config` back from JSON, so a
redacting marshaller cannot break any consumer. That removes the main
argument for PLAN-KILL/DEFER. The remaining cost is mechanical
(uniform wrapper conversion + tests). **Recommendation: PLAN-READY**,
not KILL/DEFER — there is a live leak and the fix is low-risk.

PLAN-KILL is *not* warranted (a live leak exists). PLAN-DEFER is only
defensible if someone argues the loopback-only default makes it
non-urgent — but the `web-management` exposed mode and the trivial
round-trip story argue against deferral.

---

## 3. What is already shipped / carried forward

- **`String()` redaction precedent** (logging hygiene, NOT marshal):
  - `TunnelConfig.String()` redacts `WgLocalPrivkeyHex` —
    `pkg/config/types_routing.go:342`.
  - `DHCPDynamicDNSConfig.String()` redacts `TSIGSecret` —
    `pkg/config/types_system.go:747` (the #2043 / #1387 field).
  - These protect `%v`/`%s`/`slog` only. They do **not** fire on
    `json.Marshal` (encoding/json ignores `Stringer`).
- **Control-char free-text defense** (`pkg/config/freetext.go`) — an
  orthogonal layer (injection, not secrecy); not a redaction mechanism.
- **No custom `MarshalJSON`/`MarshalYAML` exists on any config type**
  today — confirmed repo-wide.
- **No json struct tags on secret fields** — the config types are
  almost entirely tag-free (the only `json:` tags in `types_system.go`
  are on `DataplaneConfig`/`SharedUMEMConfig`, non-secret). Fields
  serialize by exported Go field name. This makes a wrapper-type swap
  clean (no tag churn).

---

## 4. Concrete design

### Chosen option: (A) a `Secret` wrapper type — preferred

Introduce a single string-backed wrapper in `pkg/config`:

```go
// Secret is a config string whose value is preserved in memory for the
// reconciler/render paths but is REDACTED on any JSON/YAML marshal so a
// compiled-config serializer can never leak it. The zero value marshals
// to "" (empty), a non-empty value marshals to the redaction sentinel.
type Secret string

const SecretRedacted = "<redacted>"

func (s Secret) String() string {            // logging hygiene
    if s == "" { return "" }
    return SecretRedacted
}
func (s Secret) MarshalJSON() ([]byte, error) {
    if s == "" { return []byte(`""`), nil }
    return json.Marshal(SecretRedacted)
}
func (s Secret) MarshalYAML() (any, error) {  // if/when yaml is used
    if s == "" { return "", nil }
    return SecretRedacted, nil
}
// Reveal returns the real value for render/reconcile paths.
func (s Secret) Reveal() string { return string(s) }
// (Optional) UnmarshalJSON: accept a plain string so the type is a
// drop-in if a tree value is ever decoded into it — see §6.
```

Then change each secret field from `string` to `config.Secret`
(same-package, so just `Secret`), and update the small set of
**producers** (compiler/parser assignments) and **consumers** (render
paths: `pkg/ipsec`, `pkg/frr`, `pkg/dhcp`, `pkg/api` auth, etc.) to use
`.Reveal()` where they need the cleartext.

**Why (A) over (B) and (C):**

- **(B) `MarshalJSON` on each carrying struct** — must hand-write a
  field-by-field marshaller for ~10 structs (`IKEPolicy`, `IPsecVPN`,
  `OSPFInterface`, `ISISConfig`, `ISISInterface`, `RIPConfig`,
  `VRRPGroup`, `RootAuthConfig`, `LoginUser`, `SNMPv3User`,
  `APIAuthUser`, `APIAuthConfig`, `BGPNeighbor`,
  `DHCPDynamicDNSConfig`, `TunnelConfig`). Each duplicates the full
  field list, so adding a field later silently drops it from JSON (a
  worse failure than a leak). Brittle. Rejected.
- **(C) redacting deep-copy before marshal** — a `Redact(cfg)` that
  clones and blanks secrets, called at each marshal site. Keeps types
  unchanged, but (i) the guarantee is again by-convention (every new
  marshal site must remember to call `Redact`), which is exactly what
  the issue wants to eliminate, and (ii) a deep-copy of the whole
  `*config.Config` graph is error-prone to keep in sync with new
  fields. Rejected as the *primary* mechanism, but see §8 — a
  `Redact`-style belt could be a cheap *secondary* guard at the two
  known marshal sites if reviewers want defense-in-depth.
- **(A) wrapper** — the guarantee is **type-enforced**: any present or
  future marshal of a struct containing a `Secret` field redacts
  automatically; adding a new secret field is one type annotation.
  This is precisely "type-enforced, not per-comment" as the issue asks.

### Secret-field inventory (complete — the conversion list)

| # | Field | Type file:line | Secret |
|---|-------|----------------|--------|
| 1 | `IKEPolicy.PSK` | types_security.go:475 | IKE pre-shared key |
| 2 | `IPsecVPN.PSK` | types_security.go:529 | IPsec PSK (legacy) |
| 3 | `DHCPDynamicDNSConfig.TSIGSecret` | types_system.go:739 | RFC2136 TSIG HMAC key |
| 4 | `OSPFInterface.AuthKey` | types_routing.go:246 | OSPF auth key |
| 5 | `RIPConfig.AuthKey` | types_routing.go:159 | RIP auth key |
| 6 | `ISISConfig.AuthKey` | types_routing.go:169 | IS-IS area auth key |
| 7 | `ISISInterface.AuthKey` | types_routing.go:181 | IS-IS iface auth key |
| 8 | `BGPNeighbor.AuthPassword` | types_routing.go:281 | BGP TCP-MD5 password |
| 9 | `VRRPGroup.AuthKey` | types_interfaces.go:78 | VRRP auth key |
| 10 | `RootAuthConfig.EncryptedPassword` | types_system.go:154 | root crypt(3) hash |
| 11 | `LoginUser.EncryptedPassword` | types_system.go:308 | login crypt(3) hash |
| 12 | `APIAuthUser.Password` | types_system.go:211 | REST basic-auth pw |
| 13 | `APIAuthConfig.APIKeys` | types_system.go:205 | REST bearer/API keys (`[]string` → `[]Secret`) |
| 14 | `SNMPv3User.AuthPassword` | types_system.go:274 | SNMPv3 auth pw |
| 15 | `SNMPv3User.PrivPassword` | types_system.go:276 | SNMPv3 priv pw |
| 16 | `TunnelConfig.WgLocalPrivkeyHex` | types_routing.go:331 | WireGuard private key |

Borderline / for reviewer ruling:
- `ArchiveSitesWithPassword []string` (types_system.go:171) — this is
  **site URLs whose password was *ignored***, deliberately kept for the
  warning. The passwords themselves are NOT stored. Likely **leave as
  `[]string`** (not a secret store), but flag for review (a URL could
  embed `user:pass@`). Open question OQ4.
- `MasterPassword` (types_system.go:34) — "pseudorandom-function value"
  (commit-encryption PRF salt, not a user secret). Needs ruling. OQ5.
- `SSHKeys []string` / `LoginUser.SSHKeys` — public keys, not secret.
  Leave.

### Render/consume sites that must call `.Reveal()`

(Not exhaustive — implementation must grep each converted field's
readers. Known render surfaces:)
- `pkg/ipsec` (swanctl.conf PSK), `pkg/frr` (OSPF/RIP/IS-IS/BGP auth),
  `pkg/networkd`/`pkg/vrrp` (VRRP auth), `pkg/dhcp` /dhcpserver (TSIG),
  `pkg/api/auth.go` + daemon wiring (REST password / API key compare),
  user provisioning (`chpasswd -e` crypt hashes), `userspace-dp`
  control-message build (WireGuard privkey), SNMP agent config.
- The HA **config-sync** path sends the *raw AST tree*, not the
  compiled struct (db.go marshals `*ConfigTree`), so HA sync is
  unaffected by the wrapper (the cleartext stays in the tree, which is
  the persisted/synced SSOT and is separately encrypted at rest —
  `pkg/configstore/crypto.go`). This is the crucial reason the wrapper
  is safe (see §6).

---

## 5. Preserved APIs / behavior

- **On-disk config DB**: unchanged. `pkg/configstore/db.go:190`
  marshals `*config.ConfigTree` (the Junos AST text tree), **not** the
  compiled `*config.Config`. The wrapper touches only the compiled
  struct, so the persisted secret bytes (in the tree, encrypted at
  rest) are untouched — the firewall still functions after restart.
- **`show configuration` (all formats)**: unchanged. Every
  `Show*`/`Export*` path renders the **ConfigTree** (set/text/xml/json
  via `tree.FormatJSON`), not the compiled struct. Operators still see
  their real secrets in `show configuration` (Junos parity — Junos
  shows `$9$...`-encrypted but present values; we show what's in the
  tree). This is intentional and out of scope (§9).
- **`GET /api/v1/config`** (the leak): behavior **changes** — secrets
  now render as `<redacted>`. This is the fix, not a regression. The
  endpoint already returns a debug-shaped dump of internal compiled
  state; no documented contract promises plaintext secrets.
- **`String()`/`slog` output**: unchanged or strictly-improved (now
  every secret field redacts, not just the two structs that hand-rolled
  it; the hand-rolled `String()` methods can optionally be simplified
  to lean on `Secret.String()` but that is not required).

---

## 6. Hidden invariants the change must preserve

1. **No compiled-config round-trip exists** — *the* load-bearing
   invariant. Repo-wide grep finds **zero** `Unmarshal`/`Decode` into a
   `*config.Config` (only into `*ConfigTree`, the AST). The compiled
   struct is always recomputed from the tree by the compiler. Therefore
   a `MarshalJSON` that emits `<redacted>` **cannot** feed a redacted
   value back into a consumer — there is no reader. (If this invariant
   ever changes — someone adds a compiled-config JSON ingest — the
   wrapper must ship `UnmarshalJSON` that *refuses* the sentinel, or the
   ingest must read the tree. OQ2.)
2. **The render path must read `.Reveal()`, never the marshalled form.**
   The risk is the *inverse* of round-trip: a render site that
   accidentally goes through JSON (e.g. logs the marshalled config and
   re-parses) would get `<redacted>`. No such site exists today; the
   conversion must not introduce one.
3. **HA config-sync integrity**: sync ships the AST tree, not the
   compiled struct — confirmed (`pkg/cluster` → `Store.SyncApply` →
   tree). The wrapper must not change what crosses the wire. Verified
   by §8 test that a synced peer compiles identical secrets.
4. **Empty vs unset**: `Secret("")` must marshal to `""` (not
   `<redacted>`) so absence stays distinguishable and `omitempty`-like
   semantics survive. Encoded in the design (§4).
5. **`encoding/json` honors `MarshalJSON` on a named string type even
   as a struct field and inside slices/maps** — true for value
   receivers; `[]Secret` (APIKeys) and `map[...]*IKEPolicy` both
   redact. Must be unit-tested (§8) — easy to get wrong with pointer vs
   value receivers.
6. **Stringer-vs-Marshaler**: `encoding/json` does **not** call
   `String()`; the redaction MUST be `MarshalJSON`, not `String`. The
   existing `String()` methods are necessary-but-insufficient — this is
   the whole reason the issue exists.

---

## 7. Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| A render site reads the field directly (now `Secret`, compile error) and is missed | Low | Build break (good — caught at compile) | Type change forces every reader to update; lean on compiler |
| A render site is "fixed" with `.Reveal()` in a *log* line, re-leaking to journald | Med | Secret in logs | Review every `.Reveal()` call site; keep `slog` on the struct's `String()` |
| Future compiled-config JSON-ingest added → reads `<redacted>` | Low | Broken secret on ingest | OQ2: ship `UnmarshalJSON` accepting plain strings; document "tree is SSOT" |
| Value vs pointer receiver makes redaction silently not fire in a slice/map | Med | Leak persists | Explicit table tests over slice + map + nested struct (§8) |
| Borderline fields mis-classified (`ArchiveSitesWithPassword`, `MasterPassword`) | Low | Over- or under-redaction | Reviewer ruling OQ4/OQ5 before conversion |
| Churn touches many packages, merge conflicts with in-flight work | Med | Rebase pain | Land promptly; field conversions are mechanical |
| `yaml.Marshal` not actually used on config anywhere → dead `MarshalYAML` | High | None (harmless) | Confirmed no yaml marshal of config today; ship `MarshalYAML` anyway for future-proofing or drop it — OQ3 |

No hot-path / dataplane / allocation impact (compile-time + control
plane only). No failover/cluster code touched (HA syncs the tree).

---

## 8. Test plan

Unit (pkg/config, VM-free — the bulk):
1. `Secret.MarshalJSON`: non-empty → `"<redacted>"`; empty → `""`.
2. `Secret` inside a struct field, inside `[]Secret` (APIKeys), and
   inside a `map[string]*Struct` value — all redact (covers
   invariant 5).
3. Marshal a fully-populated `*config.Config` with **every** secret in
   the §4 table set to a distinctive sentinel (`"LEAK-<field>"`), then
   assert the JSON output contains **none** of the `LEAK-` sentinels
   and the expected count of `<redacted>` tokens. This is the
   regression net: adding a new secret field without wrapping it fails
   this test (use reflection to walk for `string` fields named
   `*PSK|*Key|*Password|*Secret|*Privkey*` and fail if any is not
   `Secret` — a structural guard mirroring the issue's "type-enforced"
   ask). OQ1.
4. `.Reveal()` returns the real value (render path intact).
5. Round-trip negative test: assert there is no
   `json.Unmarshal(_, *config.Config)` consumer (documented as a
   grep-guard / comment, since you can't unit-test absence cleanly).

Integration / behavioral:
6. `pkg/api` handler test: `GET /api/v1/config` on a config with
   secrets → response body contains `<redacted>` and none of the
   plaintext secrets.
7. Render-correctness: compile a config with an IKE PSK + OSPF AuthKey
   + TSIG secret and assert the generated `swanctl.conf` / `frr.conf` /
   dhcp config still contain the **real** values (proves `.Reveal()`
   wiring). These render tests largely exist already; converting the
   field must keep them green.
8. `make test` clean; `go vet`; the existing `String()`-redaction tests
   (TunnelConfig, DHCPDynamicDNSConfig) stay green.

Cluster/VM: **none required** — no dataplane, cluster, VRRP, or failover
code changes. (If reviewers disagree, a single `make cluster-deploy` +
`show configuration` sanity + `GET /api/v1/config` curl confirms no
operational regression. The CLAUDE.md `make test-failover` gate does NOT
apply — no HA/sync/failover code is touched.)

---

## 9. Out of scope (explicitly)

- **`show configuration` redaction.** Operators legitimately read their
  own config (Junos shows `$9$`-encrypted-but-present values). Changing
  `show config` to redact is a separate UX/Junos-parity decision, not
  this leak fix. The tree-render paths are untouched.
- **Encrypting secrets at rest** beyond the existing
  `pkg/configstore/crypto.go` tree encryption.
- **`$9$` Junos-style reversible password obfuscation** for
  `set`-time / display. Separate feature.
- **Removing/auth-hardening `GET /api/v1/config`** itself (e.g. making
  it admin-only or dropping the compiled dump in favor of the tree).
  Reasonable follow-up; this plan only stops the plaintext leak. OQ6.
- **`ExportJSON` removal.** It's dead-but-for-tests; the wrapper fixes
  it for free. Deleting it is optional cleanup, not required.

---

## 10. Open questions for adversarial review (invite PLAN-KILL on any)

1. **OQ1 — structural guard**: should the regression test
   reflection-walk for unwrapped secret-named `string` fields and fail
   the build, or is a static one-time inventory enough? (The walk
   prevents future drift but can false-positive on a non-secret field
   that matches the name pattern, e.g. `AuthType`, `AuthMethod`,
   `AuthKeyID` — needs an allowlist.)
2. **OQ2 — round-trip future-proofing**: ship `Secret.UnmarshalJSON`
   (accept plain string; what to do on the `<redacted>` sentinel —
   error? keep prior?) now, or document "tree is SSOT, never ingest
   compiled config" and add it only if/when ingest appears?
3. **OQ3 — `MarshalYAML`**: no config YAML marshal exists today. Ship
   the YAML method speculatively, or keep the surface minimal (JSON
   only) and add YAML when a caller appears? (Issue title says
   "JSON/YAML".)
4. **OQ4 — `ArchiveSitesWithPassword`**: leave as `[]string` (it's
   URLs, passwords already discarded) or treat a URL with embedded
   `user:pass@` as a secret and wrap/scrub it?
5. **OQ5 — `MasterPassword`** (PRF value): is this a user-visible
   secret worth redacting, or an internal derived value where redaction
   is meaningless/harmful for debugging?
6. **OQ6 — endpoint scope**: is redacting `GET /api/v1/config` enough,
   or should the same PR also make that endpoint admin-gated / switch
   it to render the (already-encrypted) tree instead of dumping the
   compiled struct? The latter would arguably obviate the wrapper for
   *this* endpoint, but the wrapper still protects `ExportJSON` and any
   future compiled-config marshaller (type-enforcement is the point).
7. **OQ7 — severity**: given the live `GET /api/v1/config` leak, should
   the issue label move from `enhancement` to a security/bug label, and
   does the loopback-only *default* binding change urgency?
8. **OQ8 — `.Reveal()` ergonomics**: is a method named `Reveal()` the
   right safety affordance (greppable, explicit), or does it invite
   careless logging? Alternative: make the consume path take
   `Secret` and only `userspace-dp`/render serializers call a single
   audited unwrap.

---

## 11. Reviewer worksheet

| Reviewer | Round | Verdict | Notes |
|----------|-------|---------|-------|
| Claude-SMR | r1 | see `claude-smr-plan-r1.md` | hostile self-review |
| Codex | r1 | _pending_ | serial, parent-driven |
| AGY | r1 | _pending_ | serial, parent-driven |

Plan path: `docs/research/2053-secret-marshal-redaction/plan.md`.
