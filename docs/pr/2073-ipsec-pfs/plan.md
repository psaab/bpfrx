# #2073 — IPsec PFS group silently dropped when proposal ref missing

**Status:** v2 — revised after two hostile plan reviews (R1 PLAN-NEEDS-MAJOR,
R2 PLAN-NEEDS-MINOR; convergent findings folded below)

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
    // cfg.Security.IPsec.Policies is a map (unordered); sort keys so the
    // first-error commit-check message is deterministic across runs.
    // (R1/R2 F2: there is no sortedKeys helper in pkg/config — inline the
    // established sort.Strings idiom.)
    names := make([]string, 0, len(ipsec.Policies))
    for name := range ipsec.Policies {
        names = append(names, name)
    }
    sort.Strings(names)
    for _, name := range names {
        pol := ipsec.Policies[name]
        if pol == nil {
            continue
        }
        propRef := pol.Proposals
        explicitRef := propRef != ""
        if !explicitRef {
            propRef = pol.Name // mirror resolveESPSettings' policy-name fallback
        }
        if _, ok := ipsec.Proposals[propRef]; ok {
            continue
        }
        // R1 MAJOR: branch the message on whether the operator actually
        // typed a `proposals` leaf. A policy that configures PFS but no
        // explicit proposal must NOT be blamed for referencing a phantom
        // proposal named after the policy.
        if explicitRef {
            return fmt.Errorf("ipsec policy %q references undefined ipsec "+
                "proposal %q (the configured proposal set -- including any "+
                "perfect-forward-secrecy group -- would be silently dropped "+
                "to the strongSwan default)", pol.Name, propRef)
        }
        return fmt.Errorf("ipsec policy %q has no resolvable ipsec proposal "+
            "(no `proposals` reference and no proposal named %q); the "+
            "configured perfect-forward-secrecy group would be silently "+
            "dropped -- define a proposal or reference one", pol.Name, pol.Name)
    }
    return nil
}
```

Decision (Q1, both reviewers): **always reject a dangling ref**, regardless
of `PFSGroup`. A dangling proposal ref silently substitutes the operator's
*entire* Phase-2 proposal (cipher/auth/DH) with strongSwan's `default`
set -- the same silent-substitution class `ValidateDHGroup` already closes,
not just PFS. Both reviewers confirmed there is no legitimate Junos idiom of
a PFS policy with a dangling proposal ref. `validatePolicySchedulerReferencesStrict`
rejects unconditionally; this mirrors it. R1's MAJOR finding (a policy with
PFS but no explicit `proposals` leaf must not be blamed for a phantom
proposal) is folded via the dual-message branch above.

Wire it into the strict accumulator group (`compiler.go` ~line 524,
alongside `validatePolicySchedulerReferencesStrict`) so `commit check`
surfaces it with the other independent cross-ref families. It reads only
`cfg.Security.IPsec` (independent of the other accumulator members), so
it belongs in the independent set.

**Lenient downgrade (Q3, both reviewers — REQUIRED in BOTH entry points):**
add a `lenientIPsecPolicyProposalRef` flag to `compileOpts`, set in **both**
`CompileConfigLenient` AND `CompileConfigForNodeLenient`. The node-aware
sibling is load-bearing: HA peer-sync ingress (`Store.SyncApply`) and
standby boot route through `CompileConfigForNodeLenient` — if the flag were
only in `CompileConfigLenient`, a peer-synced config carrying this latent
misconfiguration would hard-reject the entire HA config sync at the standby
(exactly the failure class the `lenient*` doctrine exists to prevent;
`lenientPolicyMatchAddress`/`lenientDeviceMap` are set in both siblings,
`compiler.go:159-162` and `:237-240`). On the tolerant path, downgrade to a
`cfg.Warnings` entry instead of a hard error so an already-persisted /
peer-synced config still boots. The render-path safety net (Layer B) ensures
PFS is still not silently dropped on that boot. The validator lives in the
strict accumulator inside the shared `compileExpanded`/`compileConfig...WithOpts`
path that BOTH `CompileConfig` and `CompileConfigForNode` reach.

### 5.2 Layer B — render-path safety net (DEFENSE IN DEPTH)

> NOTE (superseded by §11/Q2 after CODE review): the exact fallback token
> in the snippets below (`aes256-sha256128-modp<bits>`, "byte-identical to
> the normal path") was found WRONG during code review — `sha256128` is not
> a strongSwan keyword. The SHIPPED fallback is `aes256-sha256-modp<bits>`,
> built directly (not via `buildESPProposal`). See §11/Q2 for the corrected
> decision and the ECP-group follow-up. The prose below is kept for the
> review trail.

The render path runs at runtime apply on the active config and must not
hard-fail a node that already accepted a broken config. So instead of
erroring, `resolveESPSettings` must **stop silently dropping PFS** in
scenario (B): if the IPsec policy is found and `pfsGroup > 0` but the
proposal ref does not resolve, fall back to a proposal string that
**preserves the configured modp group** rather than bare `"default"`.

The fallback must be a **single, valid swanctl ESP proposal** that carries
the PFS modp group. A non-AEAD (CBC) ESP transform with no integrity
algorithm is invalid for strongSwan (both reviewers confirmed: strongSwan
rejects a CBC proposal that lacks an integrity alg), so the fallback MUST
include both a cipher and an integrity alg in addition to the modp term.

**Pinned fallback (Q2 resolved):** seed the fallback proposal with the SAME
algorithm spellings the codebase already emits on the normal path, so the
fallback is byte-identical to a standard `aes256 / sha256 / dh<group>`
proposal and introduces no new keyword spelling:

```go
fallbackProp := &config.IPsecProposal{
    EncryptionAlg: "aes256-cbc",
    AuthAlg:       "hmac-sha256-128",
}
return buildESPProposal(fallbackProp, pfsGroup), 0
```

`buildESPProposal(fallbackProp, 14)` normalizes to `aes256-sha256128-modp2048`
— exactly the token the existing tests pin for a normal aes256/sha256/dh14
proposal (`ipsec_test.go:157,187`). This deliberately matches the codebase's
established output (`sha256128`) rather than emitting a divergent `sha256`
spelling. (R2 N3 notes `sha256128` vs `sha256` is a separate, pre-existing
keyword-spelling question across the whole package — out of scope for #2073;
matching the existing token keeps this fix consistent and avoids introducing
a second spelling.)

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
            // (B): proposal ref dangling. Commit-check (Layer A) rejects
            // this for new edits; this branch is only reached on a
            // tolerant-path boot of an already-persisted / peer-synced
            // config (Layer A downgraded to a warning). Do NOT silently
            // drop a configured PFS group -- carry it on a conservative,
            // valid fallback proposal and warn.
            if pfsGroup > 0 {
                slog.Warn("ipsec policy references undefined proposal; "+
                    "preserving configured PFS group on fallback proposal",
                    "policy", vpn.IPsecPolicy, "proposal", propRef,
                    "pfs_group", pfsGroup)
                fallbackProp := &config.IPsecProposal{
                    EncryptionAlg: "aes256-cbc",
                    AuthAlg:       "hmac-sha256-128",
                }
                return buildESPProposal(fallbackProp, pfsGroup), 0
            }
        } else if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok {
            return buildESPProposal(prop, 0), prop.LifetimeSeconds
        }
    }
    return espProposals, 0
}
```

The fallback fires ONLY when an IPsec policy is found AND `pfsGroup > 0` AND
the proposal ref dangles — scenarios (A)/(C)/(D) are byte-identical to today.
A dangling-ref policy with `pfsGroup == 0` still falls to `default` on the
render path (Layer A already rejected/warned it; there is no PFS control to
preserve, so the render behavior is unchanged from today and not worsened).

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
| swanctl-syntax validity of fallback | LOW | Resolved: fallback emits `aes256-sha256128-modp<bits>` (cipher+integrity+modp), byte-identical to the codebase's normal proposal token. Both reviewers confirmed CBC-without-integrity is invalid; this carries integrity. |
| Architectural mismatch | LOW | Directly mirrors the existing `*Strict` cross-ref + `lenient*` doctrine; not a new pattern. |

## 9. Test plan (control-plane only — NO dataplane smoke)

Per the task: this is config compile/render; no cluster smoke needed.

- `go build ./...` clean.
- `pkg/ipsec` unit tests:
  - **(B) render**: IPsec policy with PFS + dangling proposal ref → render
    preserves the modp group (NOT `default`); assert the EXACT fallback
    `esp_proposals = aes256-sha256128-modp2048` (not just a `modp` substring
    — a `Contains("modp2048")` assertion would pass for an invalid
    no-integrity `aes256-modp2048` too, per R2 N1).
  - **(B) render, PFSGroup==0**: dangling ref with no PFS → still
    `esp_proposals = default` (unchanged from today; nothing to preserve).
  - **(A) regression**: policy + resolvable proposal + PFS → unchanged
    `aes256-sha256128-modp2048`.
  - **(C) regression**: `TestGenerateConfig_WithProposal` stays green.
  - **(D) regression**: VPN with no policy → `esp_proposals = default`.
- `pkg/config` unit tests:
  - `validateIPsecPolicyProposalReferencesStrict` rejects (B) via
    `CompileConfig` / commit-check with a clear cross-reference message
    (explicit-ref message variant).
  - The `proposals`-leaf-omitted variant (policy with PFS, no `proposals`
    leaf) rejects with the SECOND message variant (does not blame a phantom
    proposal named after the policy — R1 MAJOR).
  - `CompileConfigLenient` AND `CompileConfigForNodeLenient` both downgrade
    (B) to a `cfg.Warnings` entry (boots through) — assert the warning is
    present and no error returned.
  - (A)/(C)/(D) compile clean (no false reject); explicitly assert
    `TestGenerateConfig_WithProposal`-shaped config (policy-name ==
    proposal-name, no `Policies` entry) does NOT trip the validator.
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
- Note (R2 N2): the strict validator iterates ALL `Policies`, so it also
  rejects a dangling-ref policy that no VPN references (a dead-config typo).
  This is intentional and matches the scheduler/match-address precedents
  (which validate the whole map/slice, not just referenced entries) — it is
  NOT orphan-policy detection (that would flag a *resolvable* policy unused
  by any VPN, a different class which stays out of scope).
- Note (R2 N1, version drift): strongSwan >= 6.0.2 changed the `default`
  ESP set to include all KE methods plus `none`, making PFS *optional*
  rather than absent. The bug still holds (operator configured a *specific*
  group; `default` makes it optional/negotiable-down to none), so the fix is
  unchanged. Documented in the docs update, not a code concern.

## 11. Resolved decisions (from the two hostile plan reviews)

- **Q1 — RESOLVED: reject always.** A dangling proposal ref silently
  substitutes the entire Phase-2 proposal set, not just PFS; mirrors
  `validatePolicySchedulerReferencesStrict`. Both reviewers agreed; no
  legitimate config relies on the dangling-ref→default fallback. R1's
  caveat (a PFS-policy with no explicit `proposals` leaf must not be blamed
  for a phantom proposal) is handled by the dual-message branch in §5.1.
- **Q2 — RESOLVED (corrected after CODE review): `aes256-sha256-modp<bits>`.**
  Non-AEAD ESP requires an integrity alg (both plan reviewers). The first
  implementation seeded `aes256-cbc / hmac-sha256-128` to match the
  codebase's normal output token — but a hostile CODE reviewer caught that
  buildESPProposal's normalization emits the NON-canonical `sha256128`,
  which strongSwan's proposal keyword table does not recognize (only
  `sha256`/`sha2_256` map to AUTH_HMAC_SHA2_256_128). Verified against the
  upstream `proposal_keywords_static.txt`: a `sha256128` token is rejected
  and the whole proposal discarded (tunnel down). FIX: build the fallback
  string directly with the canonical `aes256-sha256-modp<bits>` spelling,
  NOT via buildESPProposal. The earlier `aes256-modpN` (no-integrity) and
  `aes256-sha256128-modpN` (bad keyword) drafts are both wrong and removed.
  FOLLOW-UP: the package-wide `sha256128` spelling on buildESPProposal's
  NORMAL path is a separate pre-existing concern (out of scope for #2073),
  to be filed as its own issue. A second pre-existing, project-wide bug was
  surfaced by the code review: `dhGroupBits` maps the elliptic-curve PFS
  groups 19/20 to 256/384, so `buildESPProposal`/`buildIKEProposal` AND
  this fallback emit the strongSwan-invalid `modp256`/`modp384` for ECP
  groups (should be `ecp256`/`ecp384`). The #2073 fallback inherits the
  same helper rather than introducing the bug; MODP PFS groups (the common
  case) are preserved correctly. Both `sha256128` and the ECP `modp<bits>`
  spelling will be filed together as a swanctl-keyword normalization
  follow-up.
- **Q3 — RESOLVED: both lenient entry points.** Set the flag in
  `CompileConfigLenient` AND `CompileConfigForNodeLenient`; the node-aware
  one backs HA peer-sync (`Store.SyncApply`) and standby boot.
- **Q4 — RESOLVED: IKE out of scope, follow-up filed.** IKE DH lives inside
  the IKE proposal (no separate IKE-policy PFS leaf), so an empty IKE
  `proposals` line drops the whole proposal to strongSwan's IKE default
  (which always negotiates DH) — no *separately-configured* control silently
  survives-minus-PFS. The symmetric IKE dangling-ref validation is a
  reasonable ~10-line follow-up; will file an issue, not block #2073.
- **Q5 — RESOLVED: keep both layers.** Layer B is the only thing that
  preserves PFS on a tolerant/peer-synced boot where Layer A only warned —
  the lenient warning does not change the rendered crypto. Both reviewers
  traced `SyncApply/Load → CompileConfigForNodeLenient → ActiveConfig →
  ipsec.Apply → renderConfig → resolveESPSettings` and confirmed Layer-A-only
  leaves the peer-sync hole open.
- **Q6 — RESOLVED: not a bug.** Scenario (C) (policy-name == proposal-name)
  only fires when there is NO `IPsecPolicyDef` struct, in which case there
  is no `PFSGroup` to carry. When PFS is configured, the policy struct
  always exists (`compiler_ipsec.go:222-241` always creates it), so the
  config routes through scenario (A), where PFS is applied correctly. No
  silent drop in (C).
