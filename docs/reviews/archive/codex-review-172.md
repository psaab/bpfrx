# codex-review-172

Base: `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc`

Scope: deep read-only quota audit from `../do-deep-review-audit.txt`. I ran
`git pull --rebase` first. I did not edit source, did not call `gh`, and used
prior `/tmp/{codex,agy,fable,opus,ps}-review*.md` plus repo docs/logs for
duplicate suppression.

Quota note: I did not fabricate 20 findings. Six agents plus local review
covered the required cohorts. After duplicate suppression and one live-bug
refutation, I found five credible non-duplicate findings plus one low-severity
documentation drift. The module-by-module log below records negative coverage
where no new candidate survived.

## Module Checklist

| Cohort | Inspection owner | Result |
| --- | --- | --- |
| Policy / zone / host-inbound | Tesla agent | No new non-duplicate live bug. Suppressed junos-host local-delivery bypass, unzoned host-inbound admit, ESP/AH raw accept, duplicate host-inbound/address-book last-writer issues as prior findings. |
| Config / schema / filters | Erdos agent + local verification | C172-M03 residual lenient-path `family any` prefix-list issue. Strict commit path is fixed. |
| Screen / session | Feynman agent | No new finding. Malformed-option candidate was refuted; session cap, SYN-cookie, flowless fragment, HA session-sync checks looked fail-closed. |
| NAT / NAT64 / NPTv6 / forwarding / fragments / GRE / checksum | Socrates agent + local verification | C172-M02 private IPv6 extension walkers still diverge from canonical bound. Synthetic-NAT64 policy blanket-permit candidate was refuted against production v3 snapshots. |
| IPsec / WireGuard / crypto | Aquinas agent + local verification | C172-H01 IPsec apply errors are swallowed after active config promotion. WG checks did not yield a new candidate. |
| Routing / PBR / HA | Pascal agent + local verification | C172-H02 HA heartbeat group count truncates/panics with many RGs. |
| DDNS / DHCP / RA / flowexport / services | Local | C172-M01 DDNS Surface A HTTP source binding falls open on the cached-client path. C172-L01 DDNS Surface A constructor comment is stale. Flowexport/API timeout issues appear recently fixed. |
| Observability / API / wire codecs | Local + prior docs | No new finding this pass. API body cap, HTTP timeouts, metrics auth gate, and flowexport write deadlines are present. |

## High Confidence Findings

### C172-H01 - IPsec apply failures are logged and ignored after active config promotion

Title: IPsec render/reload failure can leave stale strongSwan tunnels active under a new committed config.

Severity: High

Confidence: High

Class: fail-open apply path / stale security runtime / IPsec control-plane consistency

Evidence:
- `pkg/daemon/daemon_apply.go:1333-1338` calls `d.ipsec.Apply(...)` and only logs `failed to apply IPsec config`; the daemon apply path continues.
- `pkg/ipsec/manager.go:104-113` computes `newNames`, calls `removed := m.swapConnNames(newNames)`, then renders/reloads.
- `pkg/ipsec/manager.go:118-122` terminates removed SAs and returns `applyErr`, but the daemon caller ignores that error.
- `pkg/ipsec/manager.go:135-138` returns early from `applyConfig` when rendering fails.
- `pkg/ipsec/policy.go:275-279` can fail render on invalid PSK normalization.
- `pkg/config/schema_security.go:1050-1053` models VPN `pre-shared-key` as an unvalidated free-form argument.

Trace:
1. Operator commits a config that removes/rotates an existing VPN and adds a VPN with an invalid `$9$` PSK.
2. The config can reach daemon apply because the schema leaf does not validate the PSK encoding.
3. `Manager.Apply` advances `prevConnNames` before render/reload success.
4. `renderConfig` returns an error from `normalizePSK`.
5. The daemon logs a warning but treats the overall config application as continuing.
6. strongSwan keeps the old loaded connections/SAs; active config and runtime diverge.
7. A later corrected commit may also miss the original removal diff because `prevConnNames` was already advanced.

Refutation attempted:
- Prior finding F-175 covered successful `swanctl --load-all` not terminating deleted SAs. This is different: render/reload never succeeds, the daemon swallows the error, and `prevConnNames` is advanced before success.
- Prior finding F-221 covered hexadecimal PSK semantics. This finding uses PSK parse failure as one concrete error trigger; the apply failure handling is the bug.
- Aquinas ran `go test ./pkg/ipsec ./pkg/config` successfully; that does not cover the failure propagation invariant.

Why it matters:
A firewall commit can appear active while the kernel/strongSwan dataplane still enforces old VPN state. Deleted or revoked tunnels can keep forwarding ESP traffic, which is a direct security-appliance fail-open.

Fix direction:
- Validate/normalize PSKs on the strict commit path.
- Make IPsec apply failures fatal to daemon config application when strongSwan state was not updated.
- Move `swapConnNames(newNames)` until after successful render/write/reload, or roll it back on error.
- Add a regression where render failure leaves `prevConnNames` unchanged and causes the daemon apply to fail.

Labels: `bug`, `security`, `ipsec`, `strongswan`, `fail-open`, `config-apply`, `vsrx-parity`

Dedup note:
Adjacent to F-175 and F-221, but not a duplicate. Those are successful reload lifetime and PSK encoding issues; this is error propagation plus stale runtime after failed render/reload.

### C172-H02 - HA heartbeat group count is a uint8 and can truncate or panic with many redundancy groups

Title: 256 valid redundancy groups can be advertised as zero groups; 293 groups can panic heartbeat marshaling.

Severity: High

Confidence: High

Class: HA split-brain / wire codec bounds / availability

Evidence:
- `pkg/cluster/heartbeat.go:187-193` allocates a fixed heartbeat buffer and writes `buf[8] = uint8(len(pkt.Groups))`.
- `pkg/cluster/heartbeat.go:195-201` writes every group without checking that the group section fits.
- `pkg/cluster/heartbeat.go:274-280` unmarshals only `int(data[8])` groups.
- `pkg/cluster/heartbeat_manager.go:247-253` appends every configured group and casts `rg.GroupID` to `uint8`.
- `pkg/cluster/heartbeat_manager.go:283-286` rebuilds the peer group map only from parsed groups.
- `pkg/config/schema_chassis.go:18-21` explicitly says instance-name slots such as `redundancy-group <id>` are not schema-validated value slots.
- `pkg/config/compiler_system.go:1680-1687` parses the RG instance name with `strconv.Atoi` and stores it without a cardinality cap.

Trace:
1. A chassis cluster config contains RG IDs `0..255`.
2. `buildHeartbeat` appends 256 groups.
3. `marshalHeartbeatBody` writes count byte `uint8(256) == 0`, then still writes 256 group records after the header.
4. Receiver parses zero groups; the first group byte can be treated as the monitor count section instead of RG state.
5. `handlePeerHeartbeat` rebuilds an empty/truncated peer group map.
6. Election for local RGs sees the peer as alive but missing RG info, causing incorrect promote/hold decisions.
7. With 293 groups, `heartbeatHeaderSize + 293*heartbeatGroupSize` exceeds the 1472-byte body and the marshal loop writes past the buffer.

Refutation attempted:
- F-261 covered RG ID truncation when an individual RG ID is `>=256`. This finding holds even with all IDs in `0..255`; the group count byte itself cannot represent 256 entries.
- The HMAC/authenticated heartbeat layer does not help because the malformed/truncated payload is produced by a legitimate peer.

Why it matters:
HA election must be conservative. A signed heartbeat that silently loses all peer RG state can produce wrong per-RG ownership decisions or take down heartbeat sending entirely with a panic.

Fix direction:
- Add a strict commit cap on redundancy-group cardinality matching the heartbeat wire limit, or widen the heartbeat count field and bump protocol/version handling.
- Add marshal bounds checks before writing the group section.
- Add tests for exactly 255, 256, and 293 groups.

Labels: `bug`, `ha`, `cluster`, `heartbeat`, `split-brain`, `wire-format`, `availability`

Dedup note:
Not a duplicate of prior RG-ID truncation. This is RG-count overflow and marshal bounds, triggered with otherwise valid one-byte IDs.

## Medium Confidence Findings

### C172-M01 - DDNS Surface A HTTP providers fail open to an unbound client on cached-client source-address errors

Title: HTTP DDNS update calls can publish through the default route when provider `source-address` is malformed.

Severity: Medium

Confidence: High

Class: silently unenforced source-binding control / DDNS Surface A / control-plane security

Evidence:
- `pkg/ddns/surface_a.go:401-415` production `NewSurfaceAManager` creates `httpClients: newHTTPClientCache()` and sets `m.newBackend = m.resolveBackend`.
- `pkg/ddns/surface_a.go:486-503` builds `httpClientFor`; on `clients.clientFor(p)` error it logs `HTTP source bind unusable; using unbound client` and returns the client anyway.
- `pkg/ddns/backend_http.go:165-174` documents and implements that a bind-resolution error returns an unbound default client plus error.
- `pkg/ddns/backend_http.go:262-266` returns a nonnil supplied client with nil error, so backend constructors do not see the bind error.
- `pkg/ddns/backend_cloudflare.go:65-71` and `pkg/ddns/backend_dyndns2.go:82-87` rely on `ensureProviderHTTPClient` to enforce source binding.
- `pkg/ddns/checkip.go:69-99` has an explicit `CheckIPBound` fail-closed gate for the same bind-error class.
- `pkg/ddns/backend_http_sourcebind_2846_test.go:148-168` asserts the nil-client constructor path must error on malformed `source-address`; the cached production path bypasses that assertion.

Trace:
1. Configure a Surface A HTTP provider, for example Cloudflare, with `source-address not-an-ip`.
2. Production reconcile uses the manager's cached HTTP client path.
3. `httpClientCache.clientFor` returns an unbound client plus an error.
4. `resolveSurfaceABackend` logs the warning but passes the unbound client into the backend constructor.
5. `ensureProviderHTTPClient` sees a nonnil client and returns nil error.
6. The backend performs `UpsertLease` through the kernel default route instead of failing closed.

Refutation attempted:
- RFC2136 Surface A path does not use the cached HTTP client and still returns errors through `newRFC2136Updater`.
- CheckIP source-binding has a dedicated fail-closed function and tests.
- Prior DDNS reviews covered source binding and checkip; this is the HTTP update cached-client path introduced for connection reuse.

Why it matters:
The configured source address/interface/VRF is an operator control to ensure the provider sees the intended WAN. Falling back to the default route can publish the wrong address or bypass provider-side source ACLs.

Fix direction:
Return an error from `httpClientFor` instead of only `*http.Client`, or wrap the cached result in a `{client, bindErr}` object and make backend construction fail closed when `bindErr != nil`. Add a production Surface A HTTP cached-client regression test with malformed `source-address`.

Labels: `bug`, `security`, `ddns`, `surface-a`, `source-binding`, `fail-open`, `control-plane`

Dedup note:
Related to #2846/#3733 and `/tmp/codex-review-157.md`, but those cover direct constructor and checkip behavior. This is a new cached-client update-path bypass.

### C172-M02 - NAT64 and embedded-ICMP IPv6 extension walkers still use stale six-header surrender semantics

Title: NAT64 translation and embedded ICMP parsing diverge from the canonical IPv6 extension-header bound.

Severity: Medium

Confidence: High

Class: parser divergence / NAT64 correctness / IPv6 extension headers

Evidence:
- `userspace-dp/src/afxdp/frame/inspect.rs:15-24` defines `MAX_IPV6_EXT_HEADERS: usize = 8` and documents the prior six-header surrender bug.
- `userspace-dp/src/nat64.rs:576-620` has a private `ipv6_l4_offset_and_protocol` loop capped at `for _ in 0..6`, and returns `Some((offset, protocol))` after exhausting the loop.
- `userspace-dp/src/afxdp/icmp_embed/parse.rs:108-150` has the same `for _ in 0..6` shape and the same `Some((offset, protocol))` after the loop.
- Existing NAT64 tests found by search cover one extension header, not seven extension headers.

Trace:
1. An IPv6 TCP packet to a NAT64 prefix carries seven resolvable extension headers.
2. The canonical forwarding/screen parser can resolve the transport header under the current bound.
3. The NAT64 private walker stops after six iterations and returns the next extension-header protocol as if it were L4.
4. NAT64 translation either drops the valid packet or misclassifies the transport.
5. Embedded ICMP quote parsing can similarly fail to match the quoted session for packets the main parser handled.

Refutation attempted:
- Prior refactor reports flag `nat64.rs` as monolithic and mention header-walker extraction. I did not find this exact post-#2292 stale-bound operational divergence as a bug.
- The stale comments in `nat64.rs:568-571` say unification is tracked separately, but the bound mismatch now contradicts the canonical parser invariant.

Why it matters:
Security routers must make one parsing decision per packet. Divergent header walkers create hard-to-debug drops and can make ICMP error handling inconsistent with the forwarding path.

Fix direction:
Share the canonical IPv6 extension walker or the `MAX_IPV6_EXT_HEADERS` constant with NAT64 and ICMP embedded parsing. Return `None` when the bound is exhausted while still on an extension header. Add NAT64 and embedded-ICMP tests with seven accepted and eight rejected extension headers.

Labels: `bug`, `nat64`, `ipv6`, `parser`, `icmp`, `test-gap`, `hpc`

Dedup note:
Not a duplicate of the NAT64 module-split reports. This is a concrete stale semantic mismatch in two private walkers.

### C172-M03 - Lenient HA/load path can still apply the recently fixed `family any` single-family prefix-list fail-open

Title: Strict commit rejects #4426, but tolerant compile still promotes the unsafe filter in HA sync/load paths.

Severity: Medium

Confidence: Medium

Class: lenient-path residual / firewall filter fail-open / mixed-version HA risk

Evidence:
- `pkg/configstore/store.go:483-488` uses tolerant compile for peer-synced configs.
- `pkg/config/compiler.go:1497-1512` configures lenient compile options.
- `pkg/config/compiler_firewall.go:700-727` builds the #4426 warning and only returns an error when `!lenient`.
- `pkg/dataplane/userspace/filters.go:496-500` documents the empty `except` prefix-list case as constrained and matching all.
- `userspace-dp/src/filter/engine/matching.rs:273-280` returns `except` when a constrained prefix set is empty.
- `_Log.md` and `docs/config-schema.md` show strict #4426 was fixed on 2026-07-06, but keep the no-brick lenient doctrine.

Trace:
1. A peer-synced or persisted active config contains hierarchical `firewall family any` with `from source-prefix-list v4-only except` and `then accept`.
2. Strict commit now rejects this, but tolerant compile warns and continues.
3. `family any` dual-compiles the filter into both IPv4 and IPv6 pools.
4. The IPv6 arm resolves an empty prefix set with `except=true`.
5. Runtime matching treats empty+except as match-all, so the IPv6 arm accepts more traffic than the operator wrote.

Refutation attempted:
- This is not the primary strict-commit bug; #4426 appears fixed for new strict operator commits.
- The issue is intentionally narrowed to tolerant compile paths such as HA sync or persisted active load. That makes confidence medium: the blast radius depends on how often unsafe configs can reach those paths after upgrade.

Why it matters:
The no-brick doctrine is reasonable for some stale config, but this class is a known security fail-open. A standby or upgraded node can continue to enforce an accept-all arm for one family after the primary codebase knows it is unsafe.

Fix direction:
For #4426, make lenient compile fail closed in the published dataplane snapshot even if the stored config is accepted for recovery. Options: disable the affected filter term, mark the filter unsupported, or keep the config loaded but with forwarding support false until the operator repairs it.

Labels: `bug`, `security`, `firewall-filter`, `family-any`, `ha-sync`, `lenient-load`, `vsrx-parity`

Dedup note:
Related to `/tmp/codex-review-164.md` and #4426, but this report is the residual tolerant path after the strict fix, not the already-fixed commit path.

## Low Confidence / Low Severity Findings

### C172-L01 - DDNS Surface A constructor comments still describe RFC2136-only behavior

Title: Surface A manager comments understate that HTTP backends are live in the production path.

Severity: Low

Confidence: High

Class: documentation drift / maintainability

Evidence:
- `pkg/ddns/surface_a.go:391-415` says the production Surface A manager "resolves the live RFC 2136 backend per provider" but also wires `httpClients` and `m.resolveBackend`.
- `pkg/ddns/surface_a.go:505` switches on provider backend and now resolves HTTP backends as well.

Trace:
1. A maintainer reading the constructor comment can believe production Surface A is RFC2136-only.
2. The actual `resolveSurfaceABackend` path includes HTTP provider backends and cached clients.
3. That mismatch obscured C172-M01, where the HTTP cached-client path had different fail-open behavior than RFC2136/direct constructors.

Refutation attempted:
This is not an enforcement bug by itself. It is included because the stale comment points at a real code-review hazard in source-binding behavior.

Why it matters:
DDNS has high operational blast radius. Comments around production constructor invariants should name every live backend class so future reviewers do not audit only RFC2136.

Fix direction:
Update the constructor and backend-resolution comments to state that Surface A resolves RFC2136 and HTTP providers, and that HTTP source-binding errors must fail closed.

Labels: `docs`, `ddns`, `surface-a`, `maintainability`

Dedup note:
No prior review file found for this exact comment drift.

## Refuted Candidate

### NAT64 synthetic IPv6 destination policy blanket-permit

The Socrates agent proposed a High finding that a policy written only with a
synthetic IPv6 destination such as `64:ff9b::0808:0808/128` becomes `MatchAny`
on the IPv4 destination side after NAT64.

I do not include it as a live production bug. The proof used the legacy
`destination_addresses` unit-test shape. Current Go snapshot production code in
`pkg/dataplane/userspace/policies.go:429-466` also publishes v3
`DestinationLiterals`; Rust chooses v3 parsing whenever that field is nonempty
(`userspace-dp/src/policy.rs:2695-2724`). The v3 parser uses
`from_v3_literals`, where an IPv6-only destination yields `MatchNone` for the
IPv4 side, not `MatchAny`.

There may still be a test-quality issue because several NAT64 unit tests use
legacy fields directly, but the blanket permit trace is not a production-path
bug at current HEAD.

## Duplicate-Suppressed Findings

- Direct host-bound `to-zone junos-host` deny bypass via kernel local-delivery path: duplicate of prior `/tmp/fable-review-161.md` coverage.
- Unzoned interface host-inbound admit-open: duplicate of `/tmp/fable-review-171.md` HI-2.
- Raw ESP/AH globally accepted before host-inbound policy: duplicate of `/tmp/codex-review-128.md` M03.
- Duplicate host-inbound/address-book blocks in one zone last-write-wins: duplicate of `/tmp/fable-review-161.md` F-207.
- RG ID `>=256` truncates on heartbeat wire: duplicate of `/tmp/fable-review-161.md` F-261. C172-H02 is different because it is count overflow with IDs still in range.
- IPsec successful reload does not terminate deleted SAs: duplicate of F-175. C172-H01 is different because reload/render fails and the daemon swallows the error.
- DDNS checkip source-bind fall-open: duplicate of `/tmp/codex-review-157.md` and #3733. C172-M01 is the HTTP update cached-client path, not checkip.

## Negative Coverage Notes

- Policy default behavior appears fail-closed in the Rust core for no matching transit rule. Undefined zones and unrepresentable policy content poison snapshots rather than silently widening.
- Config schema strict path now rejects #4426 single-family prefix-lists under `family any`; the remaining concern is tolerant compile.
- Screen extraction, PoD/teardrop checks, rate counters, SYN-cookie gating, and session-cap handling looked fail-closed in the reviewed paths.
- NAT64 prefix parse, unavailable pool behavior, non-first fragment handling, and GRE checksum/reserved/version/routing-bit validation looked fail-closed outside C172-M02.
- WireGuard MAC/cookie/replay/AllowedIPs checks did not yield a new non-duplicate issue this pass.
- API HTTP server uses read/header/idle timeouts, request body caps, and loopback-aware metrics auth. Flowexport transports have write deadlines after the recent #4423 work.

## Validation

Commands run locally by the orchestrator:

```text
git pull --rebase
git status --short
git rev-parse --short=12 HEAD
```

Agent-reported validation:

```text
go test ./pkg/ipsec ./pkg/config
cargo test --manifest-path userspace-dp/Cargo.toml wg:: -- --test-threads=1
cargo test --manifest-path userspace-dp/Cargo.toml policy_inbound_nat64_matches_synthetic_v6_destination_permit -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml policy_inbound_nat64_denies_on_synthetic_v6_deny_rule -- --nocapture
```

No source files were modified.
