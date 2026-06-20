# pkg/ipsec

strongSwan integration. Generates `swanctl.conf` from the typed config
(IKE proposals, traffic selectors, DPD profiles, NAT traversal, XFRM
interface IDs) and queries SA/SP state via `swanctl`.

The conf write is AtomicGeneratedConfig (#1894):
`fsatomic.WriteFileAtomic` — strongSwan never parses a torn file, and
the apply path pays no fsync (the file is regenerated on every apply).

## Entry points

- `Manager` — `manager.go`.
- `New()` — `manager.go`. Default swanctl conf dir
  `/etc/swanctl/conf.d`.
- `Apply(ipsecCfg *config.IPsecConfig) error` — `manager.go`. Generate config and reload strongSwan.
- `Clear() error` — `manager.go`.
- `SAStatus`, `TerminateAllSAs`, `InitiateConnection`, `GetSAStatus`,
  `ActiveConnectionNames` — `ike.go`.
- `PrepareConfig(cfg *config.Config) *config.IPsecConfig` — `policy.go`.

## Module layout (#1989)

The package is split by responsibility (one responsibility per module);
all files stay in `package ipsec`, so the public API is unchanged.

- `manager.go` — transactional SA-config reconciler: `Manager`
  lifecycle (`New`/`Apply`/`Clear`/`reload`) and the `swanctl`
  shell-out helper (`runSwanctl`, `swanctlTimeout`).
- `ike.go` — IKE/ESP settings resolution + proposal builders
  (`resolveIKESettings`/`resolveESPSettings`/`deriveDPD`/`buildESPProposal`/
  `dhGroupBits`) and the SA-status query + `swanctl --list-sas` SPI
  parsing (`SAStatus`/`GetSAStatus`/`parseSAOutput`/`TerminateAllSAs`/
  `InitiateConnection`/`ActiveConnectionNames`).
- `crypto.go` — **isolated** Junos `$9$` pre-shared-key decryption
  (`normalizePSK`/`decodeJunosSecret`/`junosGap`/`junosGapDecode` and the
  `$9$` alphabet tables). Kept in its own file so the decryption surface
  is auditable and unit-testable without pulling in the swanctl/XFRM
  machinery.
- `policy.go` — swanctl config generation (`renderConfig`/`generateConfig`,
  traffic-selector resolution, value sanitizers, identity formatting,
  `authMethodToSwan`, `xfrmiIfID`) plus XFRM bind-interface preparation
  (`PrepareConfig` and its interface-address resolvers).

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show / request commands).

## Dependencies

`pkg/config` only.

## File layout

- Writes `/etc/swanctl/conf.d/xpf.conf` with mode 0600.
- Reloads via `swanctl --reload`.

## Gotchas

- IKE version negotiation supports v1-only, v2-only, or dual (default).
  Aggressive mode is opt-in.
- NAT traversal modes: `disable`, `force`, `enable` (auto-detect).
  `NoNATTraversal` is a legacy flag retained for older configs.
- Traffic selectors are auto-derived from the policy source / destination
  prefixes when not given explicitly. Mixing explicit and derived
  selectors is supported but the explicit set wins.
- DPD (dead-peer detection) profiles auto-generate from IKE/ESP
  lifetimes. Operators can override with explicit `dead-peer-detection
  delay/timeout`.
- XFRM interface ID is derived from the bind-interface name via
  `xfrmiIfID()`. The same name → same numeric ID across reboots — don't
  rename a bind interface without expecting a reset of the SAs that ride
  it.
- **IPsec policy → proposal cross-reference (#2073).** An IPsec (Phase 2)
  policy's `proposals` reference (or, when omitted, a proposal named after
  the policy) is validated at commit / commit-check by
  `pkg/config` `validateIPsecPolicyProposalReferencesStrict`. A dangling
  reference is **hard-rejected** at commit: previously it fell through to
  `esp_proposals = default` in `resolveESPSettings`, silently substituting
  the operator's entire Phase-2 proposal set — including any configured
  `perfect-forward-secrecy` DH group — with the strongSwan default (which
  carries no required modp term), so PFS was silently disabled. On the
  tolerant load / peer-sync paths the commit check is downgraded to a
  warning (an already-persisted or peer-synced config still boots), and
  `resolveESPSettings` has a render-side safety net: when the policy
  resolves with a PFS group but the proposal ref dangles, it carries the
  configured PFS group on a conservative valid fallback proposal
  (`aes256-sha256-modp<bits>`, built with swanctl's canonical keyword
  spellings) instead of falling through to `default`,
  and logs a warning. Note: strongSwan ≥ 6.0.2 changed its `default` ESP
  set to make PFS *optional* rather than absent, so the silent weakening is
  a downgrade-to-negotiable-PFS there rather than no-PFS — the fix is the
  same.
- **Gateway reference resolution / `remote_addrs` (#2074).** A VPN's
  `ike gateway <name>` either names a defined `security ike gateway`
  object (whose `address` or `dynamic hostname` becomes `remote_addrs`)
  or, in the legacy inline shape, IS the peer endpoint directly (a
  literal IP or a dotted hostname/FQDN). The invariant is: **a bare
  gateway config-object NAME never reaches swanctl `remote_addrs`** — a
  config-object name strongSwan cannot use would DNS-resolve forever and
  the IKE SA would never come up (a silently-dead tunnel).
  - **Commit-time rejection** (`validateIPsecGatewayReferencesStrict`,
    `pkg/config/compiler_ipsec.go`, run from the strict-validator chain
    in `compileExpanded`): a VPN that references an undefined gateway, or
    a gateway object committed with neither `address` nor `dynamic
    hostname`, fails `commit` / `commit check`. On the tolerant load /
    peer-sync paths the same check is downgraded to a warning
    (`lenientIPsecGatewayRefs`) so a config persisted by an older binary
    or synced from a peer still boots.
  - **Render belt** (`resolveRemoteAddr`, `policy.go`): for any path that
    reaches render without passing local commit (HA sync / direct
    construction), an unrenderable VPN is SKIPPED (logged via
    `slog.Warn`) — its connection and secret are omitted — rather than
    leaking the name or aborting the whole file. Healthy VPNs always
    render, so one bad reference never zeroes healthy tunnels.
  - **Rule-A limitation:** an inline gateway hostname must be dotted
    (FQDN-like). A bare single-label inline hostname (e.g. `vpnpeer`,
    even if resolvable via the system resolver) is rejected so a typo'd
    single-label gateway name is caught. Migration: define a proper
    gateway — `set security ike gateway <name> address <ip>` (or
    `dynamic hostname <fqdn>`). The shared accept predicate is
    `config.IsUsableIPsecEndpoint`.
