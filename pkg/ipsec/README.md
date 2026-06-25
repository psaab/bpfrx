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
- **DH-group keyword rendering (#2392).** Every IKE/ESP proposal builder
  (`buildIKEProposalFromIKE`, `buildIKEProposal`, `buildESPProposal`, and
  the #2073 PFS fallback above) renders the Diffie-Hellman group suffix
  through the single `formatDHGroup` helper. It emits the canonical
  swanctl proposal keyword: `modp<bits>` for the MODP groups (1/2/5/14/
  15/16 and the MODP-with-subgroup variants 22/23/24), and the
  elliptic-curve spellings for the EC groups — group **19 → `ecp256`**,
  **20 → `ecp384`**, **21 → `ecp521`**, 25 → `ecp192`, 26 → `ecp224`, the
  brainpool groups 27→`ecp224bp`/28→`ecp256bp`/29→`ecp384bp`/30→`ecp512bp`,
  and the Montgomery curves 31 → `curve25519`, 32 → `curve448`. Before the
  helper, all four sites formatted the suffix as `modp<dhGroupBits>`, so an
  EC group emitted the strongSwan-invalid tokens `modp256`/`modp384` and
  swanctl rejected the whole proposal (the tunnel failed to load).
  `pkg/config` `ValidateDHGroup` accepts any positive-integer DH group, so
  the helper's table covers every group an operator can commit; an unlisted
  group falls back to `modp<dhGroupBits>` (which equals the group number
  for unknown groups). Spellings come straight from strongSwan's
  `proposal_keywords_static.txt` / `diffie_hellman_group_names`. Live
  swanctl load-verification of an EC tunnel is lab-bound; the
  `pkg/ipsec` swanctl-render tests are the gate.
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
- **Local-address family selection for dynamic-hostname gateways
  (#2757).** When a gateway has no explicit `local-address` but does name
  an `external-interface`, `PrepareConfig` derives `local_addrs` from the
  interface's address. On a dual-stack appliance the interface carries both
  an IPv4 and an IPv6 address, so the chosen family MUST match the family
  the remote peer is reached over — otherwise the IKE SA is sourced from
  the wrong family and never establishes.
  - **Family hint** (`gatewayRemoteFamilyHint`, `policy.go`): a gateway
    with a literal `address` takes that IP's family. A **dynamic-hostname**
    gateway (`address` empty, `dynamic hostname <fqdn>` set) is resolved
    via `resolveHostFamily` (an injectable package var; the default,
    `defaultResolveHostFamily`, uses `net.Resolver.LookupIPAddr` bounded by
    a 2s context timeout — see the bounded-resolver note below) — IPv6-only
    → family 6, IPv4-only → family 4. Before
    #2757 the empty `address` produced a family-agnostic hint (0), so
    `selectUnitAddress` returned whichever family was listed first on the
    interface (typically IPv4) regardless of the peer — the defect-#2 bug
    deferred from #2404.
  - **Family-matched selection** (`resolveInterfaceAddress`): the local
    address is constrained to the hinted family. If the interface is
    single-stack in the OTHER family, selection falls back to
    family-agnostic so a degraded config still emits a `local_addrs` line
    instead of an empty one.
  - **Dual-stack peer:** when the hostname resolves to BOTH families, no
    explicit preference is configured, so the hint stays family-agnostic
    (0) and the interface's first usable address decides — strongSwan then
    initiates from a routable local source. (An explicit `local-address`
    always wins outright; this path only fires when one is absent.)
  - **Bounded resolver (review fold):** `PrepareConfig` runs synchronously
    inside the daemon apply sequence (`pkg/daemon/daemon_apply.go`) and the
    CLI commit path (`pkg/cli/apply.go`), which did NO DNS before #2757.
    Because the lookup is only a family *hint* (strongSwan does the
    authoritative resolution at IKE time), the default `resolveHostFamily`
    bounds it with a 2s context timeout (`resolveHostFamilyTimeout`). On
    timeout / NXDOMAIN / SERVFAIL it returns family 0 (agnostic) — a slow or
    unreachable resolver degrades to the interface-decides path and NEVER
    stalls `commit` / apply for the full glibc resolver timeout.
  - **IPv6 link-local local binds (#2885):** the candidate filter
    `matchFamily` (`policy.go`) admits an IPv6 link-local unicast source
    (`fe80::/10`) when the gateway family hint is IPv6 (family 6). The
    earlier `IsGlobalUnicast()` gate rejected link-local outright, so an
    IPsec local-bind on a point-to-point / link-local IPv6 link could never
    source from `fe80::` — the documented dynamic-routing local-source over
    such links was unreachable. Link-local is admitted ONLY under an explicit
    family-6 hint: it is excluded from family-4 selection (and IPv4
    link-local `169.254.0.0/16` is never a usable source) and from
    family-agnostic (hint 0) selection, so it never wins implicitly over a
    global address on a dual-stack interface. Multicast, unspecified, and
    loopback stay excluded for every family.
- **IKE policy chain → proposal cross-reference (#2270).** A gateway's
  `ike-policy` reference walks gateway → `ike-policy` → `ike-proposal`
  (`resolveIKESettings`, `ike.go`). When that chain breaks — the
  `ike-policy` is undefined, or its `proposals` reference dangles —
  `resolveIKESettings` previously returned an EMPTY proposal string with a
  nil error, and `renderConfig` (which guards the line with
  `if ikeProposals != ""`) emitted the connection block with NO
  `proposals =` line. strongSwan then negotiated phase-1 with its
  compiled-in default proposal set instead of the configured/required
  crypto — a silent security-posture downgrade, the Phase-1 analogue of the
  #2073 ESP gap.
  - **Fail-closed resolution** (`resolveIKESettings`): the intentional
    no-policy case (gateway with no `ike-policy`) still returns an empty
    proposal with a nil error (strongSwan's default set is the operator's
    explicit choice). A gateway that DOES name an `ike-policy` whose chain
    cannot resolve now returns the `errIKEChainUnresolved` sentinel instead
    of an empty proposal. The legacy direct-proposal fallback (an
    `ike-policy` value that is itself the name of a defined Phase-2
    proposal, rendered via `buildIKEProposal`) is still accepted.
  - **Commit-time rejection** (`validateIKEPolicyChainReferencesStrict`,
    `pkg/config/compiler_validate_strict.go`, run from the strict-validator
    chain in `compileExpanded`): a VPN whose gateway names an undefined
    `ike-policy`, an `ike-policy` whose `proposals` reference dangles, or an
    `ike-policy` defined with no `proposals` leaf at all, fails `commit` /
    `commit check`. The diagnostics name the offending object precisely
    (#2279): the gateway message is stanza-agnostic ("under `security ike`
    or `security ipsec`", since both stanzas populate the same gateway map),
    and the missing-`proposals`-leaf case reports "has no proposals
    configured" rather than a misleading `undefined ike-proposal ""`.
    Only gateways actually referenced by a
    VPN are validated (an orphan never reaches render, matching Junos). On
    the tolerant load / peer-sync paths the same check is downgraded to a
    warning (`lenientIKEPolicyChainRef`) so a config persisted by an older
    binary or synced from a peer still boots (#1960 no-brick).
  - **Render belt** (`renderConfig`, `policy.go`): for any path that
    reaches render without passing local commit (HA sync / direct
    construction / pre-fix persisted config), a VPN whose IKE chain does
    not resolve is SKIPPED (logged via `slog.Warn`) — its connection and
    secret are omitted — rather than emitting a proposal-less connection.
    Healthy VPNs always render, so one bad reference never zeroes a healthy
    tunnel. A non-chain resolve error (e.g. an unknown auth-method token
    from `authMethodToSwan`) is a different class and still aborts the
    whole render.
- **AES-GCM IKE PRF + ICV-suffix canonicalization (#2125).** The
  load-bearing fix: a strongSwan IKEv2 AEAD (AES-GCM) proposal MUST
  name a PRF explicitly — an AEAD cipher carries no integrity algorithm
  for strongSwan to derive a PRF from — so a GCM IKE (Phase 1) proposal
  with no PRF is incomplete and the IKE SA fails to negotiate (a
  silently-dead tunnel while the commit succeeds). The IKE builders now
  append a PRF for GCM (`aes256gcm16-prfsha256-modp2048`); the PRF
  mirrors the proposal's auth algorithm when set, defaulting to
  `prfsha256`. ESP children take NO PRF (and no separate integrity alg —
  GCM carries its own ICV). Separately, `normalizeEncAlg` (`ike.go`)
  canonicalizes the Junos-native GCM names
  (`aes-128-gcm`/`aes-192-gcm`/`aes-256-gcm`) to the explicit
  16-octet-ICV swanctl tokens (`aes128gcm16`/`aes192gcm16`/`aes256gcm16`
  — Junos AES-GCM uses a 16-octet ICV). This is a clarity/consistency
  fix, NOT a parse fix: strongSwan also accepts the bare `aes<N>gcm`
  alias (it maps to `ENCR_AES_GCM_ICV16` in
  `proposal_keywords_static.txt`), so the previous `aes256gcm-modp2048`
  ESP render was valid — the canonicalization just makes the ICV
  explicit in the generated config. Already-suffixed forms (e.g.
  `aes256gcm128`) pass through unchanged.
- **swanctl double-quote / backslash escaping (#2126).** Free-text
  values interpolated inside a swanctl double-quoted string — the PSK
  `secret = "..."` and the `id = "..."` / `certs = "..."` lines — are
  run through `escapeSwanctlQuoted` (`policy.go`), which doubles
  backslashes then escapes double-quotes (order matters). The swanctl
  settings lexer treats a bare `"` as the string terminator and
  processes `\\`/`\"` escapes inside quotes, so a PSK or distinguished-
  name identity containing a literal `"` (e.g. `pa"ss`, `CN=fw, O=acme`)
  no longer corrupts the secrets/identity block (a silent IKE auth
  failure). This composes with — does not replace — the #1798
  `sanitizeSwanctlValue` control-char belt (sanitize first, then
  escape). Identity values are now always emitted quoted so a DN with
  spaces/commas parses as a single value.
