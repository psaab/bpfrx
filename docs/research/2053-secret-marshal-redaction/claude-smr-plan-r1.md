# Claude-SMR — hostile plan review r1 (#2053)

Reviewing `docs/research/2053-secret-marshal-redaction/plan.md`. Posture:
adversarial. Goal: try to PLAN-KILL it, or break the design, before
Codex/AGY do. Verdict at the end.

---

## A. Is this worth doing at all? (attempt to PLAN-KILL)

The issue self-rates MEDIUM with "no live leak today." If that were
true, the honest move is PLAN-KILL — defense-in-depth on a dead debug
function (`ExportJSON`) is pure churn across ~16 fields and 6+ packages.

**But the plan's §1/§2 correction holds up under scrutiny, and I
verified it independently against source:**
- `pkg/api/server.go:184` registers `GET /api/v1/config`.
- `pkg/api/config.go:14-21` `configHandler` calls
  `writeOK(w, s.store.ActiveConfig())` where `ActiveConfig()` returns
  `*config.Config` (compiled).
- `pkg/api/api.go:34-41` `writeJSON` → `json.NewEncoder(w).Encode(v)`.

So the compiled config — with PSKs, crypt hashes, API keys — is
serialized to the REST client. The issue's premise is **factually
wrong**, and the plan is right to call it out. **PLAN-KILL is off the
table: there is a live leak.** Good — the plan didn't rubber-stamp the
issue's framing. That's the single most important thing a research pass
on this issue had to get right, and it got it.

**Residual KILL argument I can still make:** the default binding is
`127.0.0.1:8080` (verified `cmd/xpfd/main.go:221`). A loopback-only leak
is a *local-process* trust-boundary issue, not a network CVE. One could
argue "the real fix is don't expose secrets to non-root local users via
file perms / don't run untrusted local code," and that the endpoint
should just be removed/tree-ified. That's a legitimate alternative
(plan's OQ6) — but it does **not** kill the wrapper, because:
(a) `web-management https interface` genuinely binds non-loopback
(`daemon_run.go:1143-1165`, server.go:345 comment) — verified — so the
network-exposure mode is real, and (b) the wrapper is the only
*type-enforced* guarantee, which is what the issue explicitly asks for.

**Verdict on value: NOT a kill. Live leak + low-risk fix.** I downgrade
my own enthusiasm only on urgency, not on doing it.

## B. Does a redacting wrapper break config round-trip? (the scary one)

This is the question the task flagged and the one most likely to sink a
wrapper design. The plan claims "no compiled-config round-trip exists."
I tried to falsify it:

- Grepped for `Unmarshal`/`Decode` into `config.Config` / `&cfg` /
  `compiled` — **none** (only `*ConfigTree` in `db.go:179`). Confirmed.
- The persistence SSOT is the **AST tree** (`db.go:190` marshals
  `*config.ConfigTree`), not the compiled struct. Confirmed.
- HA config-sync ships the tree (`Store.SyncApply`), not the compiled
  struct. Plausible from the architecture (CLAUDE.md: "Three-phase
  config compilation: AST → typed structs → control messages"); the
  typed struct is a terminal artifact, never re-ingested.

**So the wrapper does NOT break round-trip — because there is no
round-trip of the compiled config.** This is the linchpin and it holds.
If it *didn't* hold, option (A) would be a PLAN-KILL and we'd be forced
to (C) redacting deep-copy. The plan correctly makes this the load-
bearing invariant (§6.1) and flags the future-ingest hazard (OQ2).
Acceptable — but see C.3 for where I'd tighten it.

## C. Holes in the design

**C.1 — `.Reveal()` re-leak via logs is under-weighted.** The plan
lists it (risk table row 2, OQ8) but treats it as a review-time concern.
This is the *real* danger of the wrapper approach: today a maintainer
who writes `slog.Info("ike", "psk", policy.PSK)` leaks plaintext — but
so does today's code, so it's not a regression. After conversion, the
*compiler error* forces them to write `policy.PSK.Reveal()`, which is an
explicit, greppable act — arguably *safer*. I'll allow it, but the plan
should commit to a CI grep that flags `.Reveal()` inside any `slog.`/
`fmt.Print`/`log.` argument. Promote OQ8 to a concrete guard, not an
open question. **Minor.**

**C.2 — the structural reflection guard (OQ1) is half-baked.** Naming-
pattern walks will false-positive on `AuthType`, `AuthMethod`,
`AuthKeyID` (int), `AuthAlg`, `EncryptionAlg`, `AuthKeyName`, etc. —
all of which match `*Auth*`/`*Key*` and are NOT secrets. An allowlist is
mentioned but allowlists rot. Better framing: invert it — keep a
**canonical secret-field manifest** (the §4 table) as a Go slice of
`reflect.StructField` paths, and a test that asserts (a) every manifest
entry is now type `Secret`, and (b) marshalling a config with all
manifest fields populated emits zero plaintext. That's deterministic and
doesn't false-positive. The "fail if any *new* string field matches a
secret name pattern" walk can be an *advisory* test (log, don't fail) to
catch drift. The plan should pick the manifest approach as primary.
**Minor-to-Major** (gets the "type-enforced not by-convention" promise
right or wrong).

**C.3 — invariant 6.1 is true *now* but the plan's own §9 lists
"tree-ify the endpoint" as a possible direction.** If a future change
makes any endpoint *ingest* a compiled-config JSON, `<redacted>` round-
trips into the live secret. The plan defers this to OQ2 (ship
`UnmarshalJSON` or not). I want a firmer stance: ship
`Secret.UnmarshalJSON` now that **errors on the `<redacted>` sentinel**
(so a redacted blob can never be silently accepted as a real secret) and
otherwise accepts a plain string. Cheap insurance; turns a latent
foot-gun into a loud failure. Move from "open question" to "design
decision." **Minor.**

**C.4 — APIKeys `[]string` → `[]Secret` interaction with auth compare.**
`pkg/api/auth.go:checkAuthorization` compares the presented token to the
configured keys. After conversion those become `[]Secret`; the compare
must use `.Reveal()` and stay **constant-time** if it already is (check
`subtle.ConstantTimeCompare` usage). The plan names auth.go as a render
site but doesn't call out the timing-safety invariant. Add it. **Minor.**

**C.5 — `MarshalYAML` is speculative dead code.** Plan admits no YAML
marshal of config exists (risk table last row, OQ3). Shipping an unused
method that can drift from `MarshalJSON` is mild tech-debt. I'd **drop
`MarshalYAML`** until a YAML caller exists (YAGNI), or if kept, unit-
test it identically. The issue *title* says JSON/YAML, but the body and
the actual leak are JSON-only. Don't gold-plate. **Minor — lean toward
dropping.**

**C.6 — blast radius understated as "mechanical."** 16 fields across 5
type files, plus every reader in ipsec/frr/dhcp/vrrp/networkd/api/
userspace-dp/snmp/user-provisioning. Some readers are in *other
packages* that import `pkg/config` — the `string`→`Secret` change is a
breaking API change for anything outside the package reading the field
(they can't see it's a named string unless they import the type). The
plan says "lean on the compiler," which is correct, but the PR will be
*wide* and conflict-prone. Not a kill, but the plan should set
expectations: this is a 5-15 file PR, land it fast. The §7 "merge
conflicts" risk row covers it; fine.

**C.7 — `show configuration` is correctly out of scope, but verify the
JSON `show` path really renders the tree, not the compiled struct.** The
exploration says `Show*JSON` → `tree.FormatJSON()` (AST). I spot-checked
the claim is consistent (db.go/store.go marshal the tree). If any
`show ... | display json` path secretly serializes the compiled struct,
that's a *second* leak the plan would miss. The plan should add a test
asserting `show configuration | display json` output still contains the
real secrets (proving it renders the tree — and is therefore correctly
out of scope, not accidentally also redacted/leaking). The §8 test 7
covers render-correctness for generated files but NOT the `show` JSON
path specifically. **Minor — add one assertion.**

## D. Did the plan miss any secret field?

I re-grepped. The §4 table (16 fields) matches `grep -nE
'PSK|AuthKey|AuthPassword|Secret|Password|Privkey|APIKeys'` across
`pkg/config/types_*.go` minus the correctly-excluded non-secrets
(`AuthType/Method/Alg/KeyID`, `SSHKeys`=public, `RootLogin`=enum). The
borderline trio (`ArchiveSitesWithPassword`, `MasterPassword`) is
flagged as OQ4/OQ5. I did not find a 17th. **Inventory: complete.**

One nit: `IPsecGateway` has no PSK field (PSK lives on `IKEPolicy` and
`IPsecVPN`) — the plan's table is right to not list a gateway PSK even
though the issue prose says "IKE/IPsec pre-shared keys." Good catch by
omission.

## E. Severity / labeling

The plan's §2 + OQ7 push to re-rate from MEDIUM and possibly relabel
`enhancement`→security/bug. I agree the framing correction is the
headline. The parent should surface this to the user: **the issue's
"no live leak" assumption is false; `GET /api/v1/config` leaks all
secrets in plaintext to any authorized REST client.** That alone may
change how urgently this is scheduled.

---

## Verdict

**PLAN-READY**, with these required folds before implementation
(none are kills):

1. **C.2** — make the secret-field **manifest** the primary regression
   guard (deterministic), not a name-pattern walk. (Major-ish: it's the
   "type-enforced" promise.)
2. **C.3** — ship `Secret.UnmarshalJSON` now, erroring on the
   `<redacted>` sentinel. (Closes the future-ingest foot-gun.)
3. **C.1/C.8** — concrete CI grep guard against `.Reveal()` inside
   logging calls.
4. **C.4** — preserve constant-time API-key compare after the
   `[]string`→`[]Secret` change.
5. **C.7** — add a test that `show configuration | display json` still
   shows real secrets (proves the tree path is untouched).
6. **C.5** — drop speculative `MarshalYAML` (or test it); JSON is the
   real surface.

Nothing here blocks the design. The wrapper (option A) is the right
choice *specifically because* the no-round-trip invariant holds — the
plan correctly identified that as load-bearing and it survives hostile
checking. The one thing I'd have killed this over — round-trip breakage
— does not apply. Hand to serial Codex + AGY.
