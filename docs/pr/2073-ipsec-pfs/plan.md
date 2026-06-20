# #2073 — IPsec PFS group silently dropped when proposal ref missing

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`resolveESPSettings` (`pkg/ipsec/ike.go:54-72`) resolves the ESP (Phase 2)
proposal string for a VPN's child SA. It reads `pfsGroup =
ipsecPol.PFSGroup` (line 59), computes `propRef` (the policy's
`proposals` ref, or the policy name as a fallback), then looks up
`cfg.Proposals[propRef]`. The configured PFS DH group is applied **only**
inside `buildESPProposal(prop, pfsGroup)` at line 65 — i.e. only on the
branch where the proposal reference resolves.

When the IPsec policy exists (with a configured PFS group) but its
proposal reference does **not** resolve in `cfg.Proposals`, the function
falls through to the final `return "default", 0` (line 71). The rendered
child block then emits `esp_proposals = default`, which contains **no
modp group**, so the Perfect Forward Secrecy the operator explicitly
configured via `set security ipsec policy P perfect-forward-secrecy keys
groupN` is **silently disabled**. The broken config commits cleanly and
then quietly negotiates a weaker SA.

This is the same silent-crypto-weakening class the project already closes
for DH-group leaves (`ValidateDHGroup`,
`pkg/config/schema_validators.go:188-212`). The gap here is that there is
**no cross-reference validation** that an IPsec policy's `proposals`
reference actually resolves.

## 2. Honest scope / value framing

Control-plane config-compile + swanctl-render correctness fix. No
dataplane code, no hot path, no perf dimension. The value is preventing a
**silent downgrade of a security control** (PFS) on a misconfiguration
(dangling proposal reference) that today commits without complaint. This
is a MEDIUM-severity correctness fix, not a refactor.

*If reviewers conclude the change is the wrong shape (e.g. the render-path
fallback is judged more dangerous than the status quo, or the commit-time
validator is judged to over-reject legitimate configs), PLAN-KILL is an
acceptable verdict.*

## 3. What already exists / the doctrine to compose with

The project has a settled **strict cross-reference validator** pattern in
`pkg/config/compiler.go`, invoked at commit / commit-check time:

- `validatePolicySchedulerReferencesStrict` — rejects a policy that
  references an undefined scheduler.
- `validatePolicyMatchAddressesStrict` (#2008) — rejects a typo'd
  match-address that would silently fail open.
- `validateRPMProbePinsStrict`, `validateIPMonitoringStrict`,
  `validateDeviceMapStrict`, etc.

These are dispatched in `compileConfigWithOpts` (around
`pkg/config/compiler.go:499-570`). Several are split **strict on
commit / lenient on tolerant paths** (Load / peer-sync) via a per-check
`lenient*` flag in `compileOpts`, so an already-persisted or peer-synced
config still boots through while a fresh operator edit hard-rejects. This
is the established doctrine (`CompileConfigLenient`,
`compiler.go:144-164`).

The render path is `pkg/ipsec/policy.go renderConfig`, which **already
returns `(string, error)`** and whose sole production caller
(`Manager.Apply`, `pkg/ipsec/manager.go:67`) propagates the error.
`resolveESPSettings` is its only ESP resolver. The render path runs at
**runtime apply** on the already-active config — so a hard-error there
risks breaking a node that already accepted the (broken) config. That
constrains the render-path fix (see §5.2).

## 4. The two scenarios in `resolveESPSettings`

Given `vpn.IPsecPolicy != ""`:

- **(A) Policy resolves, proposal resolves** — `cfg.Policies[ipsecPol]`
  found AND `cfg.Proposals[propRef]` found → `buildESPProposal(prop,
  pfsGroup)`. PFS applied correctly. **No change.**
- **(B) Policy resolves, proposal does NOT resolve** — `cfg.Policies`
  found, `cfg.Proposals[propRef]` missing → **falls through to "default"
  and drops PFS. THE BUG.**
- **(C) Policy name == proposal name (common Junos idiom)** — no
  `cfg.Policies[name]` entry, but `cfg.Proposals[name]` exists → `else
  if` branch (line 67), `buildESPProposal(prop, 0)`. PFS=0 because the
  policy struct (which carries PFSGroup) was never found. This is the
  established idiom exercised by `TestGenerateConfig_WithProposal`. **No
  change** (PFS is configured on the *policy*; if there is no policy
  struct there is no PFS to drop).
- **(D) No IPsec policy at all** (`vpn.IPsecPolicy == ""`) → `return
  "default", 0`. Legitimate — no PFS was configured, nothing weakened.
  **No change.**

The bug is exclusively scenario **(B)**.

## 5. Concrete design (two complementary layers)

### 5.1 Layer A — commit-time strict cross-reference validator (PRIMARY)

New `validateIPsecPolicyProposalReferencesStrict(cfg *Config) error` in
`pkg/config/compiler.go`, modeled on
`validatePolicySchedulerReferencesStrict`:

```go
func validateIPsecPolicyProposalReferencesStrict(cfg *Config) error {
    if cfg == nil {
        return nil
    }
    ipsec := cfg.Security.IPsec
    for _, name := range sortedKeys(ipsec.Policies) { // deterministic order
        pol := ipsec.Policies[name]
        if pol == nil {
            continue
        }
        propRef := pol.Proposals
        if propRef == "" {
            propRef = pol.Name // mirror resolveESPSettings' policy-name fallback
        }
        if _, ok := ipsec.Proposals[propRef]; ok {
            continue
        }
        // Only fail when the dangling ref would actually drop a
        // configured security control or produce an unusable proposal.
        return fmt.Errorf("ipsec policy %q references undefined ipsec "+
            "proposal %q (configured perfect-forward-secrecy group "+
            "would be silently dropped)", pol.Name, propRef)
    }
    return nil
}
```

Decision point for review: **always reject a dangling ref, or only when
`pol.PFSGroup > 0`?**

- Rejecting **always** is the safer, more consistent choice: a dangling
  proposal ref means the operator's intended cipher/auth/DH set is
  silently replaced by strongSwan's `default` set — that is a silent
  substitution of the *entire* Phase-2 proposal, not just PFS. The
  scheduler/match-address precedents reject the dangling ref
  unconditionally. **Plan picks: reject always**, with the error message
  noting the PFS-drop consequence when PFS is set. (Open question Q1.)

Wire it into the strict accumulator group (`compiler.go` ~line 524,
alongside `validatePolicySchedulerReferencesStrict`) so `commit check`
surfaces it with the other independent cross-ref families. It reads only
`cfg.Security.IPsec` (independent of the other accumulator members), so
it belongs in the independent set.

**Lenient downgrade:** add a `lenientIPsecPolicyProposalRef` flag to
`compileOpts`, set in `CompileConfigLenient` (and the node-aware lenient
sibling if one exists for cluster paths). On the tolerant path, downgrade
to a `cfg.Warnings` entry instead of a hard error — so an
already-persisted / peer-synced config that carries this latent
misconfiguration still boots (consistent with `lenientPolicyMatchAddress`
/ `lenientDeviceMap`). The render-path safety net (Layer B) ensures PFS is
still not silently dropped on that boot.

### 5.2 Layer B — render-path safety net (DEFENSE IN DEPTH)

The render path runs at runtime apply on the active config and must not
hard-fail a node that already accepted a broken config. So instead of
erroring, `resolveESPSettings` must **stop silently dropping PFS** in
scenario (B): if the IPsec policy is found and `pfsGroup > 0` but the
proposal ref does not resolve, fall back to a proposal string that
**preserves the configured modp group** rather than bare `"default"`.

strongSwan accepts an `esp_proposals` line that lists multiple comma-
separated proposals; a proposal token may carry just a DH group only if
it also carries cipher/integrity, so we cannot emit a bare `modpNNNN`.
The faithful fallback is to keep strongSwan's `default` cipher/auth set
**and** append the operator's PFS group so PFS is not lost:

```
esp_proposals = default-modpNNNN
```

Wait — `default` is a keyword set, not a single proposal; `default-modpN`
is not valid swanctl syntax. The correct, swanctl-valid fallback is to
emit an explicit conservative proposal that carries the PFS group, e.g.
`aes256-sha256-modpNNNN` (the same shape `buildESPProposal` would have
produced for a default proposal), so the child SA still negotiates PFS.

```go
func resolveESPSettings(cfg *config.IPsecConfig, vpn *config.IPsecVPN) (string, int) {
    espProposals := "default"
    pfsGroup := 0
    if vpn.IPsecPolicy != "" {
        if ipsecPol, ok := cfg.Policies[vpn.IPsecPolicy]; ok {
            pfsGroup = ipsecPol.PFSGroup
            propRef := ipsecPol.Proposals
            if propRef == "" {
                propRef = vpn.IPsecPolicy
            }
            if prop, ok := cfg.Proposals[propRef]; ok {
                return buildESPProposal(prop, pfsGroup), prop.LifetimeSeconds
            }
            // (B): proposal ref dangling. Commit-check (Layer A)
            // rejects this for new edits; this branch is only reached on
            // a tolerant-path boot of an already-persisted/peer-synced
            // config. Do NOT silently drop a configured PFS group —
            // carry it on a conservative fallback proposal and warn.
            if pfsGroup > 0 {
                slog.Warn("ipsec policy references undefined proposal; "+
                    "preserving configured PFS group on fallback proposal",
                    "policy", vpn.IPsecPolicy, "proposal", propRef, "pfs_group", pfsGroup)
                return buildESPProposal(&config.IPsecProposal{}, pfsGroup), 0
            }
        } else if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok {
            return buildESPProposal(prop, 0), prop.LifetimeSeconds
        }
    }
    return espProposals, 0
}
```

`buildESPProposal(&IPsecProposal{}, pfsGroup)` yields
`aes256-modpNNNN` (empty EncryptionAlg defaults to `aes256`, empty
AuthAlg is omitted, pfsGroup adds the modp term) — a valid swanctl
proposal that preserves PFS. This is strictly safer than today's bare
`default` (which has no PFS). Open question Q2: is `aes256-modpN`
(no integrity) an acceptable fallback, or should we add a default
integrity (`aes256-sha256-modpN`)? GCM-less AES-CBC without an integrity
alg is not a valid ESP transform for strongSwan — **the fallback must
include an integrity alg.** Plan picks: seed the fallback proposal with
`AuthAlg: "hmac-sha-256"` so `buildESPProposal` emits
`aes256-sha256-modpNNNN`. (Confirm in review.)

## 6. Public API preservation

- `resolveESPSettings(cfg, vpn) (string, int)` — signature **unchanged**.
- `renderConfig` / `generateConfig` / `Manager.Apply` — unchanged.
- `CompileConfig` / `CompileConfigLenient` — signatures unchanged; new
  `compileOpts.lenientIPsecPolicyProposalRef` flag is internal.
- No new exported symbol except the unexported strict validator.

## 7. Hidden invariants the change must preserve

- **Scenario (C) idiom must keep working** — policy-name == proposal-name
  with no policy struct must still resolve via the `else if` branch.
  `TestGenerateConfig_WithProposal` pins this; it must still pass
  unchanged. Layer A's validator must NOT fire for it (there is no
  `cfg.Policies` entry, so the loop never sees it).
- **Scenario (D)** (no policy) must still emit `esp_proposals = default`
  with no error — no PFS was configured.
- **Tolerant-path boot resilience** — Layer A must downgrade to a warning
  on `CompileConfigLenient` so an already-persisted broken config still
  boots; Layer B must never hard-fail the render.
- **Deterministic commit-check output** — iterate `Policies` in sorted
  key order so the first-error message is stable across runs (the map is
  unordered). The scheduler precedent iterates ordered slices; here we
  must sort the map keys.
- **Strict-accumulator independence** — the new validator reads only
  `cfg.Security.IPsec`; safe to add to the independent accumulator set.

## 8. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression (over-reject) | LOW-MED | Validator could reject a previously-committing config that relied on the dangling-ref→default fallback. Mitigated by the lenient downgrade on tolerant paths; new edits *should* fail (that's the fix). Q1/Q3. |
| Render-path correctness | LOW | Layer B only changes scenario (B); (A)/(C)/(D) byte-identical. Covered by render unit tests. |
| swanctl-syntax validity of fallback | MED | Must emit a valid ESP proposal (cipher+integrity+modp). Q2 pins `aes256-sha256-modpN`. |
| Architectural mismatch | LOW | Directly mirrors the existing `*Strict` cross-ref + `lenient*` doctrine; not a new pattern. |

## 9. Test plan (control-plane only — NO dataplane smoke)

Per the task: this is config compile/render; no cluster smoke needed.

- `go build ./...` clean.
- `pkg/ipsec` unit tests:
  - **(B) commit-check / render**: IPsec policy with PFS + dangling
    proposal ref → render preserves the modp group (NOT `default`); assert
    `esp_proposals` contains `modp<bits>`.
  - **(A) regression**: policy + resolvable proposal + PFS → unchanged
    `aes256-sha256128-modp2048`.
  - **(C) regression**: `TestGenerateConfig_WithProposal` stays green.
  - **(D) regression**: VPN with no policy → `esp_proposals = default`.
- `pkg/config` unit tests:
  - `validateIPsecPolicyProposalReferencesStrict` rejects (B) via
    `CompileConfig` / commit-check with a clear cross-reference message.
  - `CompileConfigLenient` downgrades (B) to a warning (boots through).
  - (A)/(C)/(D) compile clean (no false reject).
  - Flat-set syntax path (`ParseSetCommand` + `tree.SetPath`) for the
    commit-check test, per the project's set-syntax testing rule.
- Full Go suite: `go test ./...` green.
- 5x flake check on the new named tests.

## 10. Out of scope (explicitly)

- IKE (Phase 1) proposal-ref validation. `resolveIKESettings` has a
  structurally similar fall-through (`return authMethod, "", 0, ...`),
  but an empty IKE `proposals` line makes strongSwan use its built-in IKE
  default set — it does NOT drop a *separately configured* PFS control
  (IKE DH is inside the proposal, not a separate policy leaf). The silent
  *security-control drop* is ESP/PFS-specific. A symmetric IKE validator
  is a reasonable follow-up but is not this issue. (Open question Q4 —
  reviewers may argue it belongs here.)
- Validating that an IPsec policy is actually referenced by some VPN
  (orphan-policy detection) — different class.

## 11. Open questions for adversarial review

- **Q1.** Reject a dangling proposal ref **always**, or only when
  `PFSGroup > 0`? Plan: always (consistent with scheduler/match-address
  precedents; a dangling ref silently substitutes the whole proposal set,
  not just PFS). Argue for PFS-only if the always-reject is judged to
  break legitimate "policy with no explicit proposal, relying on default"
  configs.
- **Q2.** Is `aes256-sha256-modpN` the right render-path fallback, or
  should the fallback mirror strongSwan's exact `default` cipher list
  with the modp appended? Is emitting any opinionated cipher in the
  fallback worse than the bare-`default`-plus-warning status quo?
- **Q3.** Does the lenient downgrade belong on the cluster/node-aware
  lenient path too (`CompileConfigForNodeLenient` / `SyncApply`), or is
  the standalone `CompileConfigLenient` sufficient? (Mirror whatever
  `lenientPolicyMatchAddress` does.)
- **Q4.** Should the symmetric IKE-side dangling-proposal validation be
  in-scope here, or is ESP/PFS genuinely the only silent
  *security-control* drop?
- **Q5.** Is the two-layer design (commit-reject + render-safety-net)
  over-engineered? Would commit-validation alone (Layer A) suffice, given
  that tolerant paths warn? (Counter: a peer-synced or pre-existing
  config reaching `Apply` would still silently drop PFS without Layer B.)
- **Q6.** Scenario (C) — should the policy-name==proposal-name idiom also
  carry PFS? Today it can't (no policy struct → no PFSGroup). Is that a
  latent second bug or intended Junos semantics?
