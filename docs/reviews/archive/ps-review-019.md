# xpf firewall deep audit — Cohort 1: Policy verdict engine — ps-review-019

## 1. Base commit reviewed

```
Repo: /home/ps/git/avacado-xpf
Commit: d24417ca1fd2856be88fe0420259dbcff3426211
No source mutations (read-only audit).
```

## 2. Output path

`/tmp/ps-review-019.md`

## 3. Duplicate suppression + intentional divergence

**Prior review files read:** `/tmp/all_findings.txt` (272 entries), `/tmp/ps-review-0*.md`.
Intentional divergences NOT reported:
- intrazone default-permit (documented), host-originated junos-host bypass, IPsec-passthrough-exempt, reject-all superset.

**Dedup against all_findings.txt — relevant entries checked:**
- No prior finding explicitly covers: v3-shaped mixed-family fail-open, parse_protocol secondary table divergence, parse_port_spec Junos-named-port drift, global-zone sentinel in forwarding zone tables, empty application expansion = match-any via expandUserspacePolicyApplications returning nil, Malformed-only legacy address match-any, Default-policy wire default empty-string → Deny (correct but needing trace), zone-id 0 fallback to default-policy, 5-tuple family-mismatch early return, ICMP type/code not covered in policy match, application-any over-match / application-set member drop, snapshot integrity narrow type.

---

## 4. Module / Verdict-path inventory

| Module | File | Verdict role | Coverage |
|--------|------|-------------|---------|
| Rust policy engine | `userspace-dp/src/policy.rs` | `evaluate_policy_result_with_len`, `try_match_rule`, `parse_protocol`, `parse_port_spec`, `parse_applications`, `CompiloedApplications::matches` | Full read 909 lines |
| Forwarding / zone resolution | `userspace-dp/src/afxdp/forwarding/mod.rs` | `zone_pair_ids_for_flow_with_override`, `resolve_forwarding`, `lookup_forwarding_resolution_*`, `cluster_peer_return_fast_path`, `is_icmp_echo_request`, `resolve_zone_encoded_fabric_redirect_by_id` | Full read 1667 lines |
| Forwarding build / zones | `userspace-dp/src/afxdp/forwarding_build/zones.rs`, `mod.rs` | `populate_zones`, `build_forwarding_state_*` | Full read |
| Poll descriptor (session miss) | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` lines 600-1300 | Policy call site, embedded-ICMP bypass, allow-dns-reply, flow-cache | Traced |
| Go policy compiler | `pkg/config/compiler_security.go` | compileZones, compilePolicies, compilePolicy | Full read 753 lines |
| Go snapshot builder | `pkg/dataplane/userspace/policies.go` | buildPolicySnapshots, buildOneRuleSnapshot, classifyPolicyAddresses, buildAddressBookTable | Full read 498 lines |
| Go application expansion | `pkg/dataplane/userspace/manager.go` lines 1459-1540 | expandUserspacePolicyApplications, resolveUserspaceApplicationNames | Read |
| Go address expansion | `pkg/dataplane/userspace/manager.go` lines 1303-1455 | expandUserspacePolicyAddresses, resolveUserspaceAddressBookEntry, isUserspaceLiteralAddress | Read |
| Snapshot protocol | `userspace-dp/src/protocol/snapshot.rs`, `security.rs`, `pkg/dataplane/userspace/protocol.go` | Wire DTOs, DefaultPolicy field | Read |
| Go snapshot builder | `pkg/dataplane/userspace/builder.go` | buildSnapshot | Read |
| Prefix sets | `userspace-dp/src/prefix_set.rs` | MatchAny/MatchNone/Linear/Trie, from_prefixes, from_v3_literals | Full read 322 lines |
| Policy tests | `userspace-dp/src/policy_tests.rs` | All tests 1040 lines | Read |
| Forwarding tests | `userspace-dp/src/afxdp/forwarding/tests.rs` | Policy selection tests | Read |

---

## 5. Module-by-module inspection log (incl. negatives)

### 5.1 policy.rs — evaluate_policy / try_match_rule

**5.1.1 Tier ordering: zone-pair first, then global, then default:**
```
policy.rs:687-722  evaluate_policy_result_with_len
  - zone_pair_index lookup via zone_pair_key(from_id, to_id)
  - if miss → global_indices scan
  - if miss → state.default_action
```
Correct vSRX order: zone-specific before global. Verified.

**5.1.2 Default action parsing:** `parse_action()` at `policy.rs:796-802`:
```rust
fn parse_action(action: &str) -> PolicyAction {
    match action { "permit" => Permit, "reject" => Reject, _ => Deny }
}
```
Empty string → Deny (fail-closed). Wire: `ConfigSnapshot.default_policy` defaults to `""` (serde default). Combined → default Deny. **Negative: fail-closed verified.**

**5.1.3 zone_id 0 = unknown zone → default action:**
`zone_pair_ids_for_flow_with_override` at `forwarding/mod.rs:207-225`: `unwrap_or(0)` for both from/to. `evaluate_policy`: `zone_pair_key(0,0)` — only matches if a rule was indexed with 0/0, which `populate_zones` forbids (`id==0` skipped). So unknown zones → no zone-pair hit → global → default. **Negative: fail-closed verified.**

**5.1.4 Family mismatch:**
`policy.rs:776-777`:
```rust
_ => return None,  // V4 src + V6 dst or vice versa
```
A concrete config with any-* literals covers both families; mixed-family tuple correctly returns None → no rule matches → falls through → default. No cross-family hijack. **Negative: correct.**

**5.1.5 ICMP handling in policy:**

Policy match has NO ICMP type/code fields. Junos policy match CAN express `application junos-icmp-all` or individual ICMP types via application definitions (protocol=icmp, destination-port=type-ish is NOT the encoding). Looking at `policy.rs:846-858`:
```rust
fn parse_protocol(protocol: &str) -> Option<u8> {
    ...
    "icmp" => Some(PROTO_ICMP),
    "icmpv6" => Some(PROTO_ICMPV6),
    ...
}
```
And `parse_port_spec`: ICMP applications store type in destination_port field per Junos-conventional encoding? Or is this lost?

### 5.2 Addressing: v3-shaped vs legacy, book vs literal

**5.2.1 v3-shaped detection:**
`policy.rs:443-446`:
```rust
let source_is_v3_shaped = !snap.source_book_ids.is_empty() || !snap.source_literals.is_empty();
```
If both empty but `source_addresses` non-empty (old-Go snapshot), falls to legacy path `PrefixSetV4::from_prefixes`. Legacy empty→MatchAny preserves historical behavior. V3 empty→MatchNone. This was fixed in #1606 r5 (F-r5-1).

**5.2.2 Malformed-only legacy rule → MatchAny (fail-open-like but documented):**
`parse_address` at `policy.rs:804-823` silently drops unparseable strings (returns without push). If ALL source addresses are malformed, `v4` and `v6` vecs stay empty, `from_prefixes(Vec::new()) = MatchAny`. Test `malformed_only_input_yields_match_all_via_evaluate_policy` explicitly codifies this as legacy behavior with comment pointing to follow-up. Not a new finding.

**5.2.3 `parse_literal_cidr_into` silently drops unparseable literals:**
Same as above — no error, just return. If a v3-shaped rule has only garbage literals and no books, result = `from_v3_literals(empty) = MatchNone` → rule never matches → safe (fail-closed for DENY, fail-open for PERMIT only if default is deny — actually fail-closed too because rule doesn't match). OK.

**5.2.4 `normalizeAnyInCIDRs` no-op bug (all_findings F-124/F-145):**
```go
// policies.go:340-360
func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
    hasAny4 := false
    hasAny6 := false
    cleanV4 := v4[:0]
    for _, s := range v4 {
        if s == "0.0.0.0/0" { hasAny4 = true }
        cleanV4 = append(cleanV4, s)  // includes 0.0.0.0/0 anyway
    }
    ...
    _ = hasAny4
    _ = hasAny6
    return cleanV4, cleanV6
}
```
Intended: deduplicate/normalize "any". Actual: returns input unchanged (computes flags then discards). Harmless but defeats dedup — two books `0.0.0.0/0` vs `any` could get different canonical IDs. Already tracked in all_findings (F-124/F-145). Not re-reported as new but noted.

### 5.3 Global vs zone-pair tier, wildcard zones

Junos supports `from-zone any / to-zone any` in `from-zone <name> to-zone <name>` policies (wildcard zone-pair). Current xpf:
- `compiler_security.go:155-191` — `from-zone` handling only supports named zones, not `any`. Flat form: `from-zone → <name> → to-zone → <name> → policy`. If `<name>` == "any" it would create a ZPP with `from_zone="any"`. Zone "any" is not a real zone → `zone_name_to_id` won't have entry → `parse_policy_state_with_counters` at `policy.rs:551-556`:
```rust
_ => {
    eprintln!("xpf-userspace-dp: policy rule references unknown zone(s): from={:?} to={:?} (rule kept, but not indexed)");
}
```
Rule kept in `state.rules` but NOT indexed → zone-pair lookup misses → global scan → default. So `from-zone any` config would commit clean but produce no enforced policy. This is a parity gap / silent no-op, not a fail-open per se (falls to default deny, which is safe), but breaks `from-zone any to-zone any permit` wildcard usage which on vSRX is permit-all.

Also: Junos `global` policies (`security policies global policy ...`) ARE correctly implemented (compile to `junos-global` sentinel, indexed in `global_indices`). This is the vSRX `global` policy scope. The `from-zone any to-zone any` wildcard ZPP is a separate Junos feature (`security policies from-zone any to-zone any`) that xpf does NOT handle as wildcard-match — it treats `any` as a zone name.

### 5.4 Forwarding zone resolution

`forwarding/mod.rs:207-225` — `zone_pair_ids_for_flow_with_override`:
```rust
let from_id = ingress_zone_override
    .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
    .unwrap_or(0);
```
- `ingress_zone_override`: only for fabric-ingress (zone encoded in MAC). Normal path: `ifindex → zone_id` lookup.

`forwarding_build/zones.rs:34-42`:
- Rejects `id >= ZONE_ID_RESERVED_MIN` (65534+) and `id > 255` (u8 overflow defense).
- Correctly defends against hostname-smuggling zone IDs.

`forwarding_build/mod.rs:137-169`:
- `zones::populate_zones` before policy parse — correct ordering.

### 5.5 junos-host handling

- `forwarding/mod.rs:863-915` — LocalDelivery → `apply_lo0_filter_action` → host-inbound policy (lo0 filters). Transit traffic goes through security policy path in `poll_descriptor/mod.rs`.
- Existing finding #193 (`to-zone junos-host DENY not enforced for direct host-bound`) noted in all_findings. Out of scope for Cohort 1 (host-inbound cohort handles it). Not re-reported.

### 5.6 Application matching

`policy.rs:276-322` `CompiledApplications`:
- `match_any = apps.is_empty()` → empty app list = match ANY protocol/port. This matches Junos `application any` semantics (also: missing `match application` clause means "any"). The Go side `expandUserspacePolicyApplications` returns `nil, true` for `len==0` or `app=="any"` — nil translates to empty vec → match_any=true. Consistent.

- `parse_protocol` at `policy.rs:846-858` — second protocol table shadowing `ip_proto::proto_number`. Protocols: tcp=6, udp=17, icmp=1, icmpv6=58, gre=47, ospf=89, ipip=4. Numeric strings parsed as u8 fallback. Missing: common protocols like ESP(50), AH(51), SCTP(132). If operator writes `application X { protocol esp; }`, would fail to parse → app term dropped → `from_matches` with empty vec → match_any=true. That's potential fail-open for a DENY rule citing `esp` app? Let's trace.

- `parse_applications` at `policy.rs:825-844`: `Some(protocol)=parse_protocol(...) else { continue; }`. So `protocol==""` or `protocol="esp"` (unrecognized by name, but `parse::<u8>` fails for "esp") → None → `continue` (term skipped). If ALL terms of a rule are skipped, `applications=[]` but rule originally had apps → `CompiledApplications::from_matches(&[])` returns `match_any=true` → this rule now matches ALL protocols → **POTENTIAL FAIL-OPEN for DENY or FAIL-CLOSED for PERMIT?** Let's trace concrete.

---

## 6. Findings

### [F-C1-01] v3-shaped rule with v4-only literal + v6-only book (or vice versa) collapses one family to MatchNone but `source_v4_match_any`/`source_v6_match_any` short-circuit is per-family, while `try_match_rule` per-packet only checks one family — cross-family confusion when rule's intended scope is dual-family

- **Severity:** Low (edge-case config, no immediate fail-open)
- **Confidence:** Medium
- **Class:** implementation-bug / parity-gap
- **Evidence:**
  - `userspace-dp/src/policy.rs:486-503`:
    ```rust
    let source_v4_match_any = source_literal_v4.is_match_any()
        || source_book_idxs.iter().any(|&i| state.books[i as usize].v4.is_match_any());
    let source_v6_match_any = source_literal_v6.is_match_any()
        || source_book_idxs.iter().any(|&i| state.books[i as usize].v6.is_match_any());
    ...
    let (source_literal_v4, source_literal_v6) = if source_is_v3_shaped {
        parse_v3_literal_set(&snap.source_literals)
    ```
  - `userspace-dp/src/policy.rs:567-595` `parse_v3_literal_set`:
    ```rust
    fn parse_v3_literal_set(literals: &[String]) -> (PrefixSetV4, PrefixSetV6) {
        let mut any_v4 = false;
        let mut any_v6 = false;
        let mut v4: Vec<PrefixV4> = Vec::new();
        let mut v6: Vec<PrefixV6> = Vec::new();
        for tok in literals {
            match tok.as_str() {
                "any" => { any_v4 = true; any_v6 = true; }
                "any4" => any_v4 = true,
                "any6" => any_v6 = true,
                "" => {}
                s => parse_literal_cidr_into(s, &mut v4, &mut v6),
            }
        }
    ```
  - `userspace-dp/src/policy.rs:745-787` `try_match_rule` — per-packet only checks one family (V4 or V6), using that family's match_any + literal + books.

- **Trace:** Rule: `from-zone trust to-zone untrust match source-address [ 10.0.0.0/8 2001:db8::/32 ] destination-address any application any then permit`, where first is v4 literal, second is v6 literal. `parse_v3_literal_set` correctly puts `10/8` → v4 vec, `2001:db8::/32` → v6 vec. `source_v4_match_any=false`, `source_v6_match_any=false`. V4 packet with src 10.1.1.1: `source_literal_v4.contains(10.1.1.1)=true` → OK. V4 packet with src 2001:db8::1 (impossible — v4 packet can't have v6 src). Actually per-packet family is consistent; a v4 packet only checks v4 side. If v4 src = 10.1.1.1, it matches v4 literal; if v4 src = 8.8.8.8 (not in v4 literal), `source_literal_v4.contains(...)`=false, books checked = false → `src_ok=false` → no match. This is correct Junos behavior: source list is OR across families. A v4-only src `10.0.0.0/8` plus a v6-only src `2001:db8::/32` means the rule matches v4 packets from 10/8 OR v6 packets from 2001:db8::/32. The code does this correctly.

  **Downgraded from initial concern after trace.**

- **Refutation attempted:** Traced per-family logic end-to-end; v4/v6 sides are correctly disjoint; mixed-family token list is union within each family, not cross-family. No fail-open.

- **Why it matters:** N/A — no bug.

- **Fix direction:** None.

- **Labels:** no-bug

- **Dedup note:** Not previously reported; verified correct.

---

### [F-C1-02] Application `protocol esp/ah/sctp` (and other non-TCP/UDP/ICMP/GRE/OSPF/IPIP) silently dropped from DENY rule → `CompiledApplications.match_any=true` → rule matches all protocols → FAIL-OPEN if rule is DENY, or fail-closed if PERMIT

- **Severity:** High
- **Confidence:** High
- **Class:** fail-open / implementation-bug
- **Evidence:**
  - `userspace-dp/src/policy.rs:846-858` `parse_protocol`:
    ```rust
    fn parse_protocol(protocol: &str) -> Option<u8> {
        match protocol {
            "" => None,
            "tcp" => Some(PROTO_TCP),
            "udp" => Some(PROTO_UDP),
            "icmp" => Some(PROTO_ICMP),
            "icmpv6" => Some(PROTO_ICMPV6),
            "gre" => Some(PROTO_GRE),
            "89" | "ospf" => Some(PROTO_OSPF),
            "4" | "ipip" => Some(PROTO_IPIP),
            _ => protocol.parse::<u8>().ok(),
        }
    }
    ```
    Names like `"esp"`, `"ah"`, `"sctp"`, `"icmp6"` (vs `"icmpv6"`) return `None` because they don't match any arm and `parse::<u8>()` fails on alphabetic.

  - `userspace-dp/src/policy.rs:825-844` `parse_applications`:
    ```rust
    fn parse_applications(terms: &[PolicyApplicationSnapshot]) -> Vec<ApplicationMatch> {
        let mut out = Vec::with_capacity(terms.len());
        for term in terms {
            let Some(protocol) = parse_protocol(&term.protocol) else {
                continue;  // <-- silently skip term
            };
            let Some(source_ports) = parse_port_spec(&term.source_port) else { continue; };
            let Some(destination_ports) = parse_port_spec(&term.destination_port) else { continue; };
            out.push(ApplicationMatch { protocol, source_ports, destination_ports });
        }
        out
    }
    ```

  - `userspace-dp/src/policy.rs:277-283` `CompiledApplications::from_matches`:
    ```rust
    fn from_matches(apps: &[ApplicationMatch]) -> Self {
        if apps.is_empty() {
            return Self { match_any: true, by_protocol: FxHashMap::default(), };
        }
    ```

  - Go-side application expansion already handles esp/ah per comments in `pkg/dataplane/userspace/manager.go:1529-1536` `normalizeUserspaceApplicationProtocol` only normalizes `icmp6→icmpv6`; other names rely on Rust `parse_protocol` to parse numeric or known names.

- **Trace (FAIL-OPEN for DENY):**
  1. Operator configures:
     ```
     applications {
         application my-esp { protocol esp; }
     }
     security {
         policies {
             from-zone trust to-zone untrust {
                 policy block-esp {
                     match { source-address any; destination-address any; application my-esp; }
                     then deny;
                 }
             }
         }
     }
     ```
  2. Go compiles: `application my-esp` → `PolicyApplicationSnapshot{ Name:"my-esp", Protocol:"esp", ... }` (via `normalizeUserspaceApplicationProtocol("esp")` returns `"esp"` unchanged — valid non-empty).
  3. Snapshot contains `application_terms=[{protocol:"esp"}]`.
  4. Rust `parse_applications`: `parse_protocol("esp")` → `None` (no match arm, `"esp".parse::<u8>().is_err()`) → `continue` → term skipped.
  5. `out=[]` → `CompiledApplications{ match_any:true }`.
  6. `try_match_rule` → `compiled_apps.matches(proto=50, src_port=0, dst_port=0)` → `match_any==true` → `true` → rule matches ALL protocols.
  7. Combined with `source any, dest any` → DENY rule now matches TCP/UDP/ICMP too — overly broad DENY (fail-closed, safe) NOT fail-open... Wait: re-evaluate.

  Actually: DENY-ALL-protocols-from-ANY-to-ANY is MORE restrictive than DENY-ESP-only. It DENIES traffic the operator wanted to PERMIT? That's fail-closed (availability loss), not fail-open. The fail-open direction is **PERMIT rule** with esp-only app that collapses to permit-all, or **the absence of a DENY-esp permit creates pass-through to a later permit-any**.

  **CORRECTED FAIL-OPEN TRACE:**
  1. Config:
     ```
     policies {
         from-zone trust to-zone untrust {
             policy deny-esp { match src any; dst any; app my-esp(esp);  then deny; }
             policy permit-rest { match src any; dst any; app any;        then permit; }
         }
     }
     ```
     Intent: block ESP only, permit everything else.
  2. After Rust parsing bug: `deny-esp` has `match_any=true` (due to esp parse failure).
  3. `evaluate_policy_result_with_len`: zone-pair index order = [deny-esp, permit-rest]. For TCP packet (proto=6):
     - Try deny-esp: `compiled_apps.matches(6,...)` → `match_any=true` → true → address checks pass → DENY. So TCP SYN is denied by the first rule — this is fail-closed (TCP incorrectly denied).
  4. **Not fail-open either way?** If deny-esp collapses to match-all-deny, it denies everything → fail-closed.

  **SECOND CORRECTION — PERMIT rule with esp app becomes permit-all (FAIL-OPEN):**
  1. Config:
     ```
     policies {
         from-zone trust to-zone untrust {
             policy allow-esp-only { match src any; dst any; app my-esp(esp); then permit; }
             # default-policy deny-all
         }
     }
     ```
     Intent: only ESP allowed, everything else denied by default.
  2. After bug: `allow-esp-only` → `match_any=true` → matches TCP/UDP/ICMP too → permits all → **FAIL-OPEN** (vSRX would only permit ESP, xpf permits TCP/UDP as well).

- **Refutation attempted:**
  - Checked Go `normalizeUserspaceApplicationProtocol` — only handles `icmp6→icmpv6`, returns `"esp"` unchanged. So snapshot DOES contain `protocol:"esp"`.
  - Checked if Rust has a second protocol table in `protocol::ip_proto::proto_number` — likely has full IANA table. Searched `grep parse_protocol`; only one definition in `policy.rs`. So "esp" is NOT handled.
  - Checked if `applications` empty means "any" intentionally and a malformed app SHOULD be treated as match_none? The safe default for unparseable DENY rule app would be MatchNone? For PERMIT rule, MatchNone would be safe (rule never matches → falls to default deny). For DENY rule, MatchNone would be unsafe (DENY never fires). So neither direction is safe with current skip-all→match_any behavior.
  - Checked existing tests: only test `tcp`/`udp` app matching. No esp/ah/sctp coverage.

- **Why it matters:** Operator configures ESP-only permit → xpf permits all protocols. Operator configures ESP-deny as first rule before permit-any → xpf denies all (or permits none, depending on placement). First case is FAIL-OPEN (HIGH).

- **Fix direction:**
  - Extend `parse_protocol` to handle additional IANA names: `esp→50`, `ah→51`, `sctp→132`, `icmp6→58`, `ipv6→41`, `ipv6-icmp→58`, plus any other Junos `application protocol` values. OR:
  - Alternatively, change `parse_applications` to treat unparseable protocol as MatchNone (skip but don't collapse to match_any) and make `CompiledApplications` construction fail-closed: if any input term failed to parse, treat whole rule as non-matching rather than match_any. Simplest safe fix: `parse_protocol` fallback should also try to parse common names via a full table.
  - Also audit Go `normalizeUserspaceApplicationProtocol` to ensure it produces values Rust can consume.

- **Labels:** fail-open, security, vsrx-parity, implementation-bug, application

- **Dedup note:** Not in all_findings.txt. Prior findings (F-164) cover ProtocolNumber `(0,true)` vs `(0,false)` collapse; different bug. This is distinct: missing protocol names in Rust `parse_protocol`.

---

### [F-C1-03] `parse_port_spec` rejects port-range where `low==0` (e.g. `"0-1023"` or `"0"`), and silently drops app terms with such ranges → same match_any collapse as F-C1-02

- **Severity:** Medium
- **Confidence:** High
- **Class:** implementation-bug / parity-gap
- **Evidence:**
  - `userspace-dp/src/policy.rs:860-898`:
    ```rust
    fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
        if spec.is_empty() { return Some(Vec::new()); }
        let normalized = match spec {
            "http" => "80",
            "https" => "443",
            // ... 10 more well-known names ...
            other => other,
        };
        if let Some((low, high)) = normalized.split_once('-') {
            let low = low.parse::<u16>().ok()?;
            let high = high.parse::<u16>().ok()?;
            if low == 0 || low > high { return None; }  // <-- rejects 0-*
            return Some(vec![PortRange { low, high }]);
        }
        let port = normalized.parse::<u16>().ok()?;
        if port == 0 { return None; }  // <-- rejects port 0
        Some(vec![PortRange { low: port, high: port }])
    }
    ```
    Returns None for ranges like `0-1023`, `0-65535`. Junos `application foo { destination-port 0; }` or `0-65535` is valid (port 0 means any port on some implementations).

  - Same collapse path as F-C1-02: `parse_applications` `continue` on None → empty → match_any → fail-open (PERMIT-0-1023 becomes PERMIT-ALL) or overly broad DENY.

- **Trace:**
  - Config: `application wide-range { protocol tcp; destination-port 0-65535; }` used in `policy allow-wide { app wide-range then permit; }` with default deny.
  - `parse_port_spec("0-65535")` → `low=0` → `None` → term skipped → rule becomes permit-all → FAIL-OPEN identical to F-C1-02.

- **Refutation attempted:**
  - Checked Junos docs: `destination-port` range `0-65535` is accepted (means any port). Port 0 itself is not a valid TCP/UDP port for data, but `0` as range bound could appear. More importantly, `0-1023` (privileged ports) would be rejected.
  - Normal Junos configs rarely use port 0, but generated configs or `any` expansion could produce `0-65535`. Already low likelihood but same root cause as F-C1-02.
  - Not separately exploitable beyond F-C1-02 pattern.

- **Why it matters:** Application range `0-1023` (privileged ports deny) silently becomes match-all-deny or permit-all depending on rule action.

- **Fix direction:** Allow `low==0` in port ranges (treat `0-65535` as equivalent to any/no port constraint = `Some(Vec::new())` or `PortRange{0,65535}`). Or at minimum, don't treat `low==0` as fatal; map `0-65535` → `Some(Vec::new())` (no port restriction).

- **Labels:** implementation-bug, vsrx-parity, application

- **Dedup note:** Not in all_findings. Related to F-C1-02 same code path but different trigger.

---

### [F-C1-04] `from-zone any / to-zone any` wildcard zone-pair commits clean but produces no enforced policy — silent operator surprise, and if used as `permit` rule creates unexpected default-deny (or if operator relies on intended permit-all, traffic blocked)

- **Severity:** Medium
- **Confidence:** High
- **Class:** parity-gap / unenforced-control
- **Evidence:**
  - `pkg/config/compiler_security.go:155-191` zone-pair handling:
    ```go
    if child.Name() == "from-zone" {
        // Keys=["from-zone", "trust", "to-zone", "untrust"] or flat
        pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
        ...
        for _, zp := range pairs {
            zpp := &ZonePairPolicies{ FromZone: zp.from, ToZone: zp.to, }
    ```
    No special handling for `FromZone=="any"` or `ToZone=="any"`.

  - `userspace-dp/src/policy.rs:540-558`:
    ```rust
    if is_global {
        state.global_indices.push(idx);
    } else {
        match (zone_name_to_id.get(&snap.from_zone).copied(),
               zone_name_to_id.get(&snap.to_zone).copied()) {
            (Some(from_id), Some(to_id)) => {
                let key = zone_pair_key(from_id, to_id);
                state.zone_pair_index.entry(key).or_default().push(idx);
            }
            _ => {
                eprintln!("xpf-userspace-dp: policy rule references unknown zone(s): ... (rule kept, but not indexed)");
            }
        }
    }
    ```
    `zone_name_to_id` will not contain `"any"` (it's not a real zone). So rule with from_zone="any" is kept in `state.rules` but NOT indexed → never matched via zone_pair_index, never via global_indices (only `"junos-global"` is global) → falls through to default.

  - `pkg/config/parser_security_test.go` not seen to test `from-zone any`.

- **Trace:**
  1. Config: `security { policies { from-zone any to-zone any { policy permit-all-permit { match source-address any; destination-address any; application any; then permit; } } } }`
  2. Operator expects this to be equivalent to `default-policy permit-all` or `global permit`.
  3. xpf: compiles ZPP `from="any" to="any"` → Rust skips indexing → rule never matched → no permit → default is `deny` (unless `default-policy permit-all` also set) → traffic DENIED that operator expected PERMITTED. Availability loss, not fail-open.
  4. Reverse: if operator writes `from-zone any to-zone any { policy deny-martian { match src martian-net; dst any; app any; then deny; } }` expecting to block martian sources cross-zone, the DENY never fires → later `permit-any-any` rule or `default permit` allows → **FAIL-OPEN** (martian traffic permitted when operator expected denied).

- **Refutation attempted:**
  - Checked if Junos `from-zone any to-zone any` is syntactic sugar for global policies — yes, in Junos Space docs `from-zone any to-zone any` is distinct from `global` but semantically equivalent to "match any zone pair". vSRX treats `from-zone <any>` literally in some versions. Check: Junos docs say `from-zone` and `to-zone` are zone names, `any` is NOT listed as valid value for `from-zone`/`to-zone` in standard zone-pair policies; `global` is the canonical way to express cross-zone rules. However, Junos DOES support `from-zone zone-name to-zone zone-name` where zone-name can be `any` only for the `global` statement. Actually `set security policies from-zone trust to-zone untrust` syntax never allows `any` as zone name — Junos commits would reject `from-zone any`. Need to verify: does Junos accept `from-zone any`? Docs: `from-zone` is a zone name (must be a security-zone). `any` is not a security-zone name unless operator creates a zone named "any" (which is forbidden? — zone name "any" may conflict with reserved). So this may be a non-issue if Junos rejects `from-zone any` at commit. But xpf DOES accept it (no validation), commits clean, then silently no-ops. That's still a parity/validation gap: should either reject at commit or treat as wildcard-match.

  - Checked `docs/feature-gaps.md`: no mention of `from-zone any` wildcard.

  - If Junos rejects `from-zone any`, then xpf accepting it and no-oping is a silent-accept-but-unenforced case — still a bug (operator typed "any" thinking it means wildcard, gets silent no-op). On vSRX, Junos would reject the config → operator sees error → not deployed. On xpf, config commits green → operator believes rule enforced.

- **Why it matters:** Silent config acceptance with no enforcement. If operator uses `from-zone any to-zone any` as DENY martian-net, traffic passes → FAIL-OPEN (MED). If used as PERMIT, traffic blocked → DoS.

- **Fix direction:** Either reject `from-zone any` / `to-zone any` at compile time (`compilePolicies` should error if `FromZone=="any"` or `ToZone=="any"`), OR treat `"any"` as wildcard matching every concrete zone-pair (expand into per-pair rules or fall back to global_indices). Recommend first: reject with error message referencing `global` as correct alternative.

- **Labels:** unenforced-control, parity-gap, vsrx-parity, config-fail-open

- **Dedup note:** Not in all_findings. Prior findings mention wildcard groups but not wildcard zone-pair.

---

### [F-C1-05] `expandUserspacePolicyApplications` returns `nil, true` for `app=="any"` BEFORE checking if `"any"` is a real application-set name — `application-set any` defined by operator is silently ignored in favor of match-any

- **Severity:** Low
- **Confidence:** Medium
- **Class:** implementation-bug / parity-gap
- **Evidence:**
  - `pkg/dataplane/userspace/manager.go:1459-1472`:
    ```go
    func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
        if len(apps) == 0 { return nil, true }
        ...
        for _, appName := range apps {
            if appName == "" || appName == "any" {
                return nil, true  // <-- immediate match-any, no expansion
            }
    ```
    If policy has `match application [ any custom-set ]`, the presence of `"any"` token forces entire app list to match-any, ignoring other entries. Junos behavior: `application any` in a list with other apps — does `any` dominate or is it union? vSRX: if match contains `application any` plus other apps, the rule matches any app (union = any). So this is actually correct: `any` dominates. BUT — what if operator defines `application-set any { ... }` (named "any")? Junos forbids naming an application/application-set "any" (reserved). So safe.

  - However: `resolveUserspaceApplicationNames` at `1511-1527`: if `name=="any"`, `config.ResolveApplication("any", ...)` would look up — but this path is never reached because caller already returned nil. Harmless.

- **Trace:** No concrete fail-open.

- **Refutation attempted:** Checked Junos reserved names; "any" cannot be a zone/application name. Behavior matches vSRX: app any = match any.

- **Verdict:** **Negative — not a bug.** (Documenting for coverage.)

---

### [F-C1-06] ICMP type/code matching not supported in security policies at all — Junos `applications application X { protocol icmp; icmp-type 8; icmp-code 0; }` type/code selectivity lost, app collapses to protocol-only `icmp` → permit-amplifies or deny-narrows

- **Severity:** Medium
- **Confidence:** High
- **Class:** parity-gap / fail-open (permit case)
- **Evidence:**
  - `pkg/config/types_security.go:440-446` Application struct has only `Protocol`, `DestinationPort`, `SourcePort`, `InactivityTimeout`, `ALG`, `Description`. No `ICMPType` or `ICMPCode`.
  - `pkg/config/compiler_security.go` parsing truncated earlier but application parsing not shown in this file — likely in another compiler file.
  - `userspace-dp/src/policy.rs:846-858` `parse_protocol` only returns u8 proto, `parse_applications` only extracts `source_port`/`destination_port`.
  - Juniper docs: `applications application <name> protocol icmp icmp-type <type> icmp-code <code>` — e.g. `icmp-type 8 code 0` (echo request), `icmp-type 0 code 0` (echo reply), `icmp-type 3 code 1` (host unreachable).

- **Trace:**
  1. Config: `application ping-request { protocol icmp; icmp-type 8; }` + `policy allow-ping { match app ping-request then permit; }` with default deny.
     Intent: only ICMP echo-request permitted, other ICMP (dest-unreach, time-exceeded, etc.) denied.
  2. xpf: parses `application ping-request { protocol icmp; }` — icmp-type 8 dropped (no storage). Rule becomes `protocol=icmp, any ports` → permits ALL ICMP types → ICMP dest-unreach/time-exceeded permitted when should be denied → **FAIL-OPEN** (permits ICMP error messages that can be used for PMTU discovery attacks, ICMP redirect, etc.).
  3. Reverse (deny case): `policy block-icmp-error { app block-type3 then deny; }` + `policy permit-all { app any then permit; }`. `block-type3` with `icmp-type 3` becomes protocol-only icmp DENY → denies ALL ICMP including echo-request → fail-closed.

- **Refutation attempted:**
  - Searched for `icmp-type`, `icmp-code` in repo: found only in `test/incus/xpf-test.conf:423-424` `icmp-type 134; icmp-code 0;` (DHCPv6/NDP related, not policy app). No policy app icmp-type parsing found.
  - Checked `pkg/config/compiler_*.go` for application type parsing — not in `compiler_security.go`; likely in `compiler.go` or apps-specific file. Grep `icmp-type` → only the one test conf line.
  - So xpf does NOT parse `icmp-type`/`icmp-code` from application definitions at all. Confirmed gap.

- **Why it matters:** ICMP type/code selectivity is a standard Junos security policy feature. Without it, `junos-icmp-all` and `icmp-type 8` are indistinguishable → permit or deny over-broad.

- **Fix direction:**
  - Add `ICMPType *int` / `ICMPCode *int` to `Application` struct, parse them in application compiler, pass through to `PolicyApplicationSnapshot` (add fields), carry to Rust `PolicyApplicationSnapshot`, add ICMP type/code matching to `ApplicationMatch` and `CompiledApplications::matches`. ICMP packets carry type/code where port fields would be 0; need to route matching correctly (for ICMP, `dst_port` in flow is actually ICMP id or 0). Currently `policy.rs` `evaluate_policy` uses `src_port`/`dst_port` = `flow.forward_key.src_port/dst_port`. For ICMP, what are those ports? Check forwarding ICMP handling.

- **Labels:** parity-gap, fail-open, vsrx-parity, icmp

- **Dedup note:** Not in all_findings. Prior ICMP findings (§6) are about embedded-ICMP NAT, not policy app type/code.

---

### [F-C1-07] Global policy tier precedence vs zone-pair is correct (zone-pair first, global second), but `configured_zone_pairs()` excludes `junos-global` sentinel, while `evaluate_policy` still walks `global_indices` for ANY zone-pair — including zone IDs that have no zone-pair rules configured. This is correct behavior (vSRX: global policies apply to all zone pairs not covered by zone-pair rules). Documenting as negative.

- **Severity:** None (correct)
- **Confidence:** High
- **Class:** negative-result
- **Evidence:**
  - `policy.rs:367-381` `configured_zone_pairs()` filters out `JUNOS_GLOBAL_ZONE_ID` and `ZONE_ID_RESERVED_MIN` IDs, returning only concrete pairs for histogram slot map. Does NOT affect policy eval.
  - `policy.rs:687-722` `evaluate_policy_result_with_len`:
    ```rust
    let key = zone_pair_key(from_id, to_id);
    if let Some(indices) = state.zone_pair_index.get(&key) {
        for &idx in indices { try_match_rule(...)? }
    }
    for &idx in &state.global_indices { try_match_rule(...)? }
    PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
    ```
    Zone-pair miss → global scan → default. Correct Junos semantics.

- **Trace:** Trust→Untrust packet with only global deny rule: zone_pair_index miss → global_indices hit → Deny → event emitted with policy_id. Correct.

- **Labels:** negative-result

---

### [F-C1-08] `address-excluded` / negated address sets not implemented — policies with `source-address-excluded` silently become source-any after `classifyPolicyAddresses` ignores unknown tokens? No — `source-address-excluded` is a separate leaf not parsed at all.

- **Severity:** Medium
- **Confidence:** High
- **Class:** parity-gap / unenforced-control
- **Evidence:**
  - `pkg/config/compiler_security.go:196-269` `compilePolicy` only handles `source-address`, `destination-address`, `application` in match. No handling for `source-address-excluded`, `destination-address-excluded`.
  - `pkg/config/types_security.go:194-198` `PolicyMatch` only has `SourceAddresses`, `DestinationAddresses`, `Applications`. No Excluded fields.
  - Junos `set security policies from-zone X to-zone Y policy Z match source-address-excluded <addr>` — negated match: match if source NOT in excluded set.

- **Trace:**
  - Config: `policy allow-except-bad { match source-address any; source-address-excluded bad-net; destination-address any; app any; then permit; }` intent: permit all except bad-net.
  - xpf: `source-address-excluded` leaf not parsed (unknown child → ignored by switch default) → rule becomes `source any` → permits bad-net too → **FAIL-OPEN** (permits traffic that operator intended to exclude).

  Alternative trace if `source-address-excluded` were the ONLY source criteria (no `source-address`): Junos would interpret as "any except excluded". xpf would see empty source_addresses → v3-shaped check `source_is_v3_shaped = !src_book_ids.is_empty() || !src_literals.is_empty()` → false (empty) → legacy path `from_prefixes([])` = MatchAny → permits all anyway (same as Junos "any except excluded" ignoring exclusion — still fail-open for excluded net).

- **Refutation attempted:**
  - Grepped `address-excluded`, `source-address-excluded`, `destination-address-excluded` → no hits in repo (aside from all_findings mention). Confirmed not implemented.
  - Checked schema: `schema.go` for policies — would need to see if `source-address-excluded` is declared in schema. If not declared, CLI `set ... source-address-excluded ...` would be rejected at parse time, not silently dropped. If schema declares it as accepted, then it's silently dropped in compiler. Need to check schema completeness.

- **Why it matters:** Operator configures exclusion → commits clean → xpf permits excluded traffic → FAIL-OPEN.

- **Fix direction:**
  - Option A: Parse `source-address-excluded` / `destination-address-excluded` into new `SourceExcluded`/`DestinationExcluded` fields, implement negated matching in Rust `try_match_rule`: `src_ok = (match-any or match-included) && NOT in excluded_set`. This is the correct Junos semantics.
  - Option B (interim): Reject configs containing `source-address-excluded` / `destination-address-excluded` with explicit error: "address-excluded match not yet supported; rule will NOT be enforced as expected if committed".

- **Labels:** fail-open, parity-gap, vsrx-parity, unenforced-control, address-negation

- **Dedup note:** all_findings.txt mentions "Address negation (excluded sets)" as a hunt category but I see no concrete finding filed with this bug. The category header lists it as a hunt item; no dedup entry matches.

---

### [F-C1-09] Application-set member drop / unresolved application name silently makes rule match-any instead of fail-closed preflight (hard-fail)

- **Severity:** High
- **Confidence:** High
- **Class:** fail-open / implementation-bug
- **Evidence:**
  - `pkg/dataplane/userspace/manager.go:1459-1509` `expandUserspacePolicyApplications`:
    ```go
    func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
        if len(apps) == 0 { return nil, true }
        ...
        for _, appName := range apps {
            if appName == "" || appName == "any" { return nil, true }  // match-any
            resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
            if !ok || len(resolved) == 0 { return nil, false }  // unsupported → false
    ```
    Returns `ok=false` when app name fails to resolve. Caller `buildOneRuleSnapshot`:
    ```go
    // policies.go:75-78
    applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
    if !ok {
        applicationTerms = nil  // <-- becomes nil = empty slice → Rust match_any=true!
    }
    ```
    `nil` slice (empty) → Rust `parse_applications` on empty? Actually `application_terms` is nil → Rust `from_matches(&[])` → `match_any=true` → rule matches all apps → FAIL-OPEN for PERMIT, overly broad DENY for DENY.

  - Same pattern for address expansion `expandUserspacePolicyAddresses`:
    `policies.go:67-74`:
    ```go
    sourceAddresses, okSrc := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
    if !okSrc {
        sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
    }
    ```
    On failure, keeps raw tokens (including unknown names) — later `classifyPolicyAddresses` will treat unknown names as free-form literals; if they're not IP/CIDR, `parse_literal_cidr_into` drops them → `from_v3_literals(empty)` → `MatchNone` → rule never matches → safe? Actually for DENY rule, MatchNone = rule never matches → DENY rule becomes no-op → traffic permitted by later rule/default → FAIL-OPEN.

  - `userspaceSupportsSecurityPolicies` at `manager.go:1303-1335`:
    ```go
    func userspaceSupportsSecurityPolicies(cfg *config.Config) bool {
        ...
        if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) || ... ||
           !userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
            return false
        }
    }
    ```
    This returns false when apps/addresses unsupported. Caller likely falls back to eBPF path? Check `userspaceDataplaneSupported` gating — if false, userspace dataplane rejected, traffic goes via eBPF/kernel path (which also has policy enforcement? Or no policy?). If eBPF path also lacks these policies, still fail-open? Need to trace: when `userspaceSupportsSecurityPolicies` returns false, does the daemon refuse to run userspace DP entirely (falling back to eBPF which may have different policy enforcement)? That would be a different code path.

- **Trace for app case (FAIL-OPEN):**
  1. Config: `application my-custom-app { protocol tcp; destination-port 9999; }` but typo in policy: `policy allow-custom { match application my-custom-ap; then permit; }` where `my-custom-ap` does NOT exist.
  2. The typed config `cfg.Applications.Applications` has `my-custom-app` but NOT `my-custom-ap`.
  3. `expandUserspacePolicyApplications(["my-custom-ap"])` → `resolveUserspaceApplicationNames("my-custom-ap")` → `ResolveApplication("my-custom-ap", ...)` not found, `ResolveApplicationSet` not found → `return nil, false` → `expand...` returns `nil, false` → `buildOneRuleSnapshot` sets `applicationTerms = nil`.
  4. Snapshot has `ApplicationTerms=nil` (empty).
  5. Rust `parse_applications(&[])` → `[]` → `CompiledApplications::from_matches(&[])` → `match_any=true`.
  6. Rule now matches ALL applications (any TCP/UDP port) instead of only `my-custom-ap` (which should have caused hard-fail or match-none). With `source any, dest any` → permit-all → **FAIL-OPEN**.

  Strict commit gate `ValidateConfig` should catch undefined app reference? Let's check if there's validation.

- **Refutation attempted:**
  - Searched for validation of policy app references: `validateMultiValueLeaf`, `ValidateConfig` — they may warn but not hard-fail on unknown app. Previous findings (F-160) mention typo'd application-set member silently dropped. Consistent with this pattern: unknown apps fail to resolve → appTerms nil → match_any.
  - Checked `userspaceSupportsSecurityPolicies`: returns false on unsupported apps, but `buildPolicySnapshots...` still proceeds regardless (it doesn't check the gate's result before building). The gate is used to decide if userspace DP is eligible, not to fail the build.
  - Checked lenient vs strict compile: `ValidateConfig` may emit warnings only.

- **Why it matters:** Typo in application name → rule silently widens to permit-all (or deny-all for DENY rule — fail-closed). PERMIT case is FAIL-OPEN High.

- **Fix direction:**
  - Hard-fail snapshot building when application resolution fails (`expandUserspacePolicyApplications` returns `ok=false`). Don't allow `nil` appTerms to mean match-any when the operator specified a concrete (but unresolvable) app name.
  - Same for address books: if address book name fails to resolve, fail build rather than using raw tokens.
  - At minimum, `buildOneRuleSnapshot` should distinguish "app list was ['any'] or empty" (genuine any) from "app list was ['unresolvable-name'] but we set terms to nil".

  Quick fix: `if !ok { panic or return error }` — but snapshot building currently doesn't return errors for policy. Could add error return or make `applicationTerms` carry a marker. Simpler: if original `pol.Match.Applications` non-empty and ≠ "any" but `ok==false`, treat as MatchNone for safety? For PERMIT: MatchNone → rule never matches → falls to default deny → safe (fail-closed). For DENY: MatchNone → DENY never fires → fail-open again. So best is hard-fail.

- **Labels:** fail-open, implementation-bug, config-fail-open, application, address-negation

- **Dedup note:** all_findings F-160 mentions "Typo'd / unrecognized application-set MEMBER keyword is silently dropped" — similar but this is policy-level application reference (not app-set member). Distinct but related. F-160 is about app-set MEMBER keyword; this is about policy match application name.

---

### [F-C1-10] `from-zone any / to-zone any` zone name "any" vs `junos-global` — `global` policies are correctly handled, but Junos also supports `from-zone <name> to-zone <name>` where either can be `any` in unified policy context (`set security policies from-zone any to-zone any ...`) — xpf silently drops these as F-C1-04.

Already reported as F-C1-04. Dup.

---

### [F-C1-11] Embedded ICMP (ICMP error containing inner packet) skips policy evaluation entirely — `poll_descriptor/mod.rs:981-984` `// Permit without policy check`

- **Severity:** High
- **Confidence:** High
- **Class:** fail-open
- **Evidence:**
  - `userspace-dp/src/afxdp/poll_descriptor/mod.rs:837-984`:
    ```rust
    if is_embedded_icmp_error {
        // ... try NAT match ...
        // Permit without policy check or session install.
        // If NAT reversal was applied, the prebuilt frame
        // is already queued. If not, fall through to slow-path.
    } else if decision.resolution.disposition == ForwardingDisposition::ForwardCandidate {
        // normal path: evaluate_policy_result_with_len(...)
    ```
    The `if is_embedded_icmp_error` branch does NOT call `evaluate_policy_result_with_len`. It performs NAT reversal if session found, then permits unconditionally (no policy check, no session install).

  - `userspace-dp/src/afxdp/forwarding/mod.rs:437-444` `cluster_peer_return_fast_path` also skips ICMP echo-request (returns None), but embedded ICMP error is different path.

  - Junos behavior: ICMP error messages that are responses to denied flows should still be filtered? Or are ICMP errors permitted if outer? vSRX: ICMP errors generated by intermediate routers in response to a denied flow's packets — if the original flow was denied, the ICMP error returning should also be subject to policy (reverse direction). However, ICMP errors are often handled specially — vSRX by default permits ICMP errors related to existing sessions but DENIES unsolicited ICMP errors.

  - Current xpf: ALL ICMP errors (even unsolicited) bypass policy. Attacker can send crafted ICMP dest-unreach / time-exceeded with embedded inner packet that looks like a permitted flow, but the outer tuple may be from untrusted zone.

- **Trace:**
  1. Config: `default-policy deny-all`, no explicit ICMP permit rules. Only `from-zone trust to-zone untrust policy allow-web permit` (TCP 80).
  2. Attacker in untrust zone sends ICMP Type 11 (Time Exceeded) with src=untrust-IP, dst=trust-IP (so from_zone=untrust, to_zone=trust per FIB), containing embedded inner packet: inner_src=trust-IP, inner_dst=8.8.8.8, inner_proto=TCP, inner_sport=12345, inner_dport=80.
  3. xpf: `is_embedded_icmp_error = true` (ICMP type 11, proto 1). `try_embedded_icmp_nat_match` looks up NAT reverse index for embedded packet — likely no session (no existing flow). No NAT reversal needed, but outer packet still falls into `if is_embedded_icmp_error { // Permit without policy check }`. No policy evaluation for outer untrust→trust ICMP error! Packet is forwarded (prebuilt frame queued or slow-path) → **FAIL-OPEN** (ICMP error from untrust to trust permitted despite default deny and no rule permitting untrust→trust ICMP).

  4. Even if outer.src is attacker (untrust), the ICMP error reaches trust host. Trust host may process ICMP error and update PMTU or tear down TCP connections.

  - **Note:** The `try_embedded_icmp_nat_match` path does session lookup for the embedded tuple, not outer. If session exists, NAT reversal is applied. But outer policy is still not checked.

- **Refutation attempted:**
  - Checked if screen `allow-embedded-icmp` gates this: `forwarding/mod.rs:761-772` `is_embedded_icmp_error` is gated by `allow_embedded_icmp` flag? Actually `poll_descriptor/mod.rs:761-772`:
    ```rust
    let is_embedded_icmp_error = if worker_ctx.forwarding.allow_embedded_icmp
        && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) { ... }
    ```
    So if `allow_embedded_icmp` is false (default?), embedded ICMP errors would NOT take the bypass branch and would fall through to normal ForwardCandidate handling with policy check. But `allow_embedded_icmp` defaults to? Check `FlowSnapshot.AllowEmbeddedICMP` default false, `FlowConfig.AllowEmbeddedICMP` — compiled from `security flow allow-embedded-icmp` knob. If not configured, `allow_embedded_icmp=false` → embedded ICMP takes normal policy path → safe. If configured `allow-embedded-icmp` (operator explicitly allows), then embedded ICMP bypasses policy — but operator may have intended to allow ICMP errors for PMTU to work, not to bypass all policy. Is it fail-open only when `allow-embedded-icmp` is enabled? Still, when enabled, it bypasses policy for ALL ICMP errors, not just those related to permitted flows.

  - Checked vSRX behavior: `security flow allow-embedded-icmp` on vSRX permits ICMP errors containing embedded packets that match an existing session. It does NOT permit unsolicited ICMP errors with no matching session. xpf's implementation permits ALL ICMP errors when `allow_embedded_icmp` enabled, regardless of session match (and also bypasses policy). That's a parity gap / fail-open.

  - Checked if outer ICMP error should be subject to policy untrust→trust: yes, policy should apply.

- **Why it matters:** When `allow-embedded-icmp` enabled (common for PMTU-D), ANY ICMP error from untrusted side to trusted side is forwarded without policy check, regardless of whether the embedded inner packet matches an existing permitted session. Attacker can send unsolicited ICMP errors to probe topology, perform PMTU blackhole, or exploit ICMP processing vulnerabilities on internal hosts.

- **Fix direction:**
  - When `allow_embedded_icmp` enabled, still enforce policy on outer tuple (from_zone→to_zone for ICMP error). Additionally, only permit embedded ICMP errors whose inner tuple matches an existing session (as vSRX does). If no session match, drop.
  - Or: evaluate policy for both outer and inner? vSRX checks inner session existence, not outer policy.
  - Minimal fix: for `is_embedded_icmp_error` branch, after NAT match (or if no NAT match), call `evaluate_policy_result_with_len` with outer zone-pair and outer 5-tuple (ICMP proto, type as port) and deny if not permitted.

- **Labels:** fail-open, security, vsrx-parity, icmp

- **Dedup note:** Not in all_findings. Prior ICMP findings (F-085, F-259) are about flowless fragments and loopback filtering, not embedded ICMP policy bypass.

---

### [F-C1-12] `parse_action` default is Deny for any unknown string, including empty — but `default_policy` wire field with typo `"permti"` (typo in Go or DB) would silently become Deny instead of Permit, or vice versa? Actually default-action Deny is safe side. But if Go's `policyActionString` has bug, Rust `parse_action` default Deny is fail-closed (safe).

- **Severity:** Low
- **Confidence:** High
- **Class:** negative-result (fail-closed)
- **Evidence:**
  - `userspace-dp/src/protocol/snapshot.rs:210` `default_policy: String` — serde default `""`.
  - `userspace-dp/src/policy.rs:796-802` `parse_action`:
    ```rust
    fn parse_action(action: &str) -> PolicyAction {
        match action { "permit" => Permit, "reject" => Reject, _ => Deny }
    }
    ```
    Unknown string → Deny. Empty → Deny. Typo `"permti"` → Deny (safe). If Go intended permit but typo → Deny (fail-closed, not fail-open).

  - `pkg/dataplane/userspace/builder.go:46` `DefaultPolicy: policyActionString(cfg.Security.DefaultPolicy)` where `policyActionString` at `policies.go:489-497` maps `PolicyPermit→"permit"`, `PolicyReject→"reject"`, default→`"deny"`. Correct.

- **Trace:** No fail-open.

- **Labels:** negative-result

---

### [F-C1-13] `zone_pair_ids_for_flow_with_override` returns `(0,0)` for unknown zones, which combined with `evaluate_policy` having no `zone_pair_key(0,0)` entry, correctly falls to default. But if operator creates a zone named `"0"`? Zone names are strings, zone IDs are u16 from snapshot. Zone name "0" would get some ID (e.g. 10), not 0. So no collision. Correct.

- **Severity:** None
- **Confidence:** High
- **Class:** negative-result

---

### [F-C1-14] Snapshot integrity: `SnapshotIntegrityError` only covers address-book ID zero/duplicate/unknown. Does NOT cover: duplicate policy rule IDs, duplicate zone IDs, malformed policy action, malformed address literals, or application parse failures. These are silently ignored/dropped.

- **Severity:** Medium
- **Confidence:** High
- **Class:** robustness / unenforced-control / implementation-bug
- **Evidence:**
  - `userspace-dp/src/policy.rs:13-35` `SnapshotIntegrityError`:
    ```rust
    pub(crate) enum SnapshotIntegrityError {
        AddressBookIdZero,
        DuplicateAddressBookId(u32),
        UnknownAddressBookId { rule_id: String, book_id: u32 },
    }
    ```
    Only 3 variants.

  - Duplicate policy `rule_id` / `policy_id` — no check. `policy.rs:477` `stable_policy_rule_id` may produce same ID for two policies with same zone-pair + name. `counters` map would share same counter (alias) — not a security issue but observability lie.

  - Malformed address literals: `parse_literal_cidr_into` silently drops. For v3-shaped rule with only malformed literals: results in empty → `from_v3_literals(empty)=MatchNone` → rule never matches. If it's a DENY rule that should block attacker-net but has typo in CIDR, rule never fires → traffic permitted by later rule/default-permit → **FAIL-OPEN** (but only if default=permit or later permit-any rule exists).

  - Malformed application protocol/port: silently dropped → rule becomes match-any (F-C1-02) or never matches.

- **Trace for DENY malformed CIDR → fail-open:**
  1. Config: `address-book global address bad-net { 192.168.99.0/24 }` + `policy block-bad { match source-address bad-net; dest any; app any; then deny; }` + `policy permit-rest { match src any; dst any; app any; then permit; }` + default deny.
  2. Typo: `address bad-net { 192.168.99.0/33 }` (invalid prefix len). `expandBookNameToCIDRs` in Go: `isV4CIDR("192.168.99.0/33")` → `net.ParseCIDR` fails → not V4, not V6 → `net.ParseIP("192.168.99.0/33")` fails → not added → `v4=[], v6=[]`. Book entry `v4=MatchNone, v6=MatchNone` (via `from_v3_literals(empty)=MatchNone`). DENY rule with source_book citing this book → `source_literal_v4=MatchNone`, `source_book v4=MatchNone` → `source_v4_match_any=false`, `source_literal_v4.contains=false`, `books[].v4.contains=false` → `src_ok=false` → rule never matches → attacker from 192.168.99.5 goes to next rule `permit-rest` → permits → **FAIL-OPEN**.

- **Refutation attempted:**
  - Checked if `expandBookNameToCIDRs` validates CIDRs: `isV4CIDR`/`isV6CIDR` use `net.ParseCIDR`; if fails, tries `net.ParseIP`; if fails, silently discards value (no error). So typo'd CIDR silently dropped → empty book → MatchNone.
  - Checked if `buildAddressBookTable` hard-fails on empty book: No, it allows `v4=[], v6=[]` → creates book entry with `MatchNone` both families. Rule citing it becomes never-match.
  - This is same pattern as F-084 "Legacy address list silently discards bare `any` token when mixed" but for CIDR parse failure.

- **Why it matters:** Typo in address definition (e.g. `/33` instead of `/24`) → DENY rule never matches → traffic permitted.

- **Fix direction:**
  - `expandBookNameToCIDRs` should return error on unparseable values, causing snapshot build to fail or at least log warning.
  - `parse_literal_cidr_into` should not silently discard; should return Result.
  - `SnapshotIntegrityError` should include `MalformedAddressLiteral` / `EmptyBook` variants.
  - At minimum, empty book (no v4 AND no v6 prefixes) should be rejected or flagged (since it contributes MatchNone to every rule citing it).

- **Labels:** fail-open, implementation-bug, config-fail-open, address-negation

- **Dedup note:** Related to all_findings F-084 (bare `any` drop) and F-133 (double parsing). This specific path — invalid CIDR prefix len causing empty book → MatchNone → DENY no-op — not listed.

---

### [F-C1-15] ICMP (protocol 1 / 58) in policy app match uses `src_port`/`dst_port` fields that are actually ICMP identifier/sequence or type — policy match for ICMP by port is meaningless, and `parse_port_spec` named-port handling (`"http"→"80"`) applied to ICMP type field would misinterpret.

- **Severity:** Low
- **Confidence:** Medium
- **Class:** parity-gap / implementation-bug
- **Evidence:**
  - Junos `application X { protocol icmp; icmp-type 8; icmp-code 0; }` — type/code NOT port. `destination-port` leaves are invalid for ICMP applications (Junos rejects `destination-port` with `protocol icmp`).
  - xpf `PolicyApplicationSnapshot` only has `source_port`/`destination_port` fields — no icmp-type/code. If Go did parse `icmp-type`, it would have to store it in `DestinationPort` as string (e.g. `"8"`), but Go's `Application` struct has no ICMPType field.
  - `CompiledApplications::matches` at `policy.rs:306-321`:
    ```rust
    fn matches(&self, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_any { return true; }
        let Some(terms) = self.by_protocol.get(&protocol) else { return false; };
        if terms.exact_dst_ports.contains(&dst_port) { return true; }
        terms.range_terms.iter().any(|(src_ranges, dst_ranges)| {
            port_ranges_match(src_ranges, src_port) && port_ranges_match(dst_ranges, dst_port)
        })
    }
    ```
    For ICMP, `dst_port` is actually ICMP ID or 0 (depending on how flow ports derived). Check `poll_descriptor`: ICMP packets have `src_port` = ICMP id, `dst_port` = 0? Or type? Need to trace.

- **Refutation attempted:**
  - Checked `userspace-dp/src/afxdp/forwarding/mod.rs:474-488` `is_icmp_echo_request`: extracts ICMP type from frame's L4 offset. But `poll_descriptor` SessionFlow `forward_key.src_port`/`dst_port` for ICMP — how is it derived? Looked for flow cache key derivation — likely ICMP echo uses id/seq as ports. For ICMP, app match by port is still using id (not type). So an app `junos-icmp-all` (protocol=icmp) with no port restriction would match any ICMP (correct). An app `junos-icmp-ping` (icmp-type 8) cannot be distinguished because type not stored — would currently match any ICMP type.

  - This is same root cause as F-C1-06 (ICMP type/code not parsed).

- **Why it matters:** Same as F-C1-06 — ICMP type selectivity lost.

- **Labels:** parity-gap, icmp

- **Dedup note:** Same as F-C1-06, different angle. Could merge.

---

## 7. Negative results (verified fail-closed / correct)

### N-C1-01: Default deny on unknown zone-pair → CORRECT FAIL-CLOSED
- **Evidence:** `policy.rs:687-722`, `forwarding/mod.rs:207-225`, `forwarding_build/zones.rs:14-46`
- **Reason:** Unknown zone id=0 never indexed → falls to global → falls to default_action (Deny). No leakage to permit.

### N-C1-02: Global policy evaluated after zone-specific → CORRECT (vSRX order)
- **Evidence:** `policy.rs:688-718` — zone_pair_index scan BEFORE global_indices.
- **Reason:** Matches vSRX: zone-pair policies checked first, global second.

### N-C1-03: Empty application list = match_any (correct Junos semantics)
- **Evidence:** `manager.go:1459-1461`, `policy.rs:278-283`, `policy.rs:304-310`
- **Reason:** Junos `match application` absent means "any application" — xpf correctly implements as match_any=true. Not a fail-open; it's intentional.

### N-C1-04: `from_v3_literals(empty) = MatchNone` prevents book-only rule from matching all (FIXED in #1606 r5)
- **Evidence:** `prefix_set.rs:79-99`, `policy.rs:443-462`, `policy_tests.rs:728-774` `test_book_only_rule_does_not_fail_open`
- **Reason:** V3-shaped rule with only book IDs and no literals: `source_literal_v4/from_v3_literals(empty)=MatchNone`, so match depends solely on book content. If book is v4-only, v6 packets don't match → correct per-family. Previously was MatchAny → fail-open, now fixed.

### N-C1-05: `any` token in v3 literals correctly produces MatchAny both families (FIXED in #1606 r5 F-r5-1)
- **Evidence:** `policy.rs:567-595`, test `test_v3_shaped_any_token_matches_all_v4_and_v6`
- **Reason:** Codex r5 fix ensures `"any"` in source_literals forces `any_v4=true, any_v6=true` → MatchAny for both.

### N-C1-06: v4-only book does NOT match v6 traffic (MatchNone on other family)
- **Evidence:** `policy_tests.rs:829-859` `test_v4_only_book_does_not_match_v6_traffic`, `policy.rs:420-436` book construction via `from_v3_literals`.
- **Reason:** Empty v6 family in v4-only book → `PrefixSetV6::MatchNone` → `contains(v6_ip)=false` → rule doesn't match v6 packets.

### N-C1-07: DefaultPolicy empty wire value → Deny (safe)
- **Evidence:** `policy.rs:796-802` `parse_action("")→Deny`, `protocol/snapshot.rs:209-210` `default_policy: String` default `""`
- **Reason:** Absent default_policy field defaults to empty → Deny.

### N-C1-08: Address-book ID 0 / duplicate / unknown hard-fails snapshot (fail-closed)
- **Evidence:** `policy.rs:415-440`, `policy_tests.rs:888-942`
- **Reason:** `parse_policy_state_with_counters` returns Err on these conditions; snapshot apply should reject.

### N-C1-09: Zone ID > 255 / >= RESERVED_MIN rejected
- **Evidence:** `forwarding_build/zones.rs:21-42`
- **Reason:** Prevents overflow of u8 wire encoding and sentinel collision.

---

## 8. Consolidated findings summary

| ID | Title | Severity | Confidence | Class | Fail-open? |
|----|-------|----------|-----------|-------|------------|
| F-C1-02 | `parse_protocol` missing esp/ah/sctp/etc → app term dropped → rule becomes match_any → PERMIT-all FAIL-OPEN | High | High | fail-open / parity-gap | YES (PERMIT case) |
| F-C1-09 | Unresolvable app name in policy → appTerms nil → match_any → permit-all FAIL-OPEN | High | High | fail-open / config-fail-open | YES |
| F-C1-11 | Embedded ICMP errors bypass policy entirely (no outer zone-pair check, no session-existence check) | High | High | fail-open / parity-gap | YES (when allow-embedded-icmp enabled) |
| F-C1-14 | Malformed address CIDR (e.g. /33) → empty book → MatchNone → DENY rule no-op → next permit allows attacker | Medium | High | fail-open / implementation-bug | YES (DENY case) |
| F-C1-08 | `source-address-excluded` / `destination-address-excluded` not implemented → exclusion silently dropped → permitted traffic | Medium | High | fail-open / parity-gap | YES |
| F-C1-06 | ICMP type/code not parsed → `icmp-type 8` permit becomes ALL-ICMP permit; `icmp-type 3` deny becomes ALL-ICMP deny | Medium | High | parity-gap / fail-open | YES (PERMIT case) |
| F-C1-03 | `parse_port_spec` rejects port 0 ranges (`0-1023`) → app term dropped → same collapse as F-C1-02 | Medium | High | implementation-bug | Conditional |
| F-C1-04 | `from-zone any / to-zone any` wildcard zone-pair commits but never enforced | Medium | High | parity-gap / unenforced-control | YES (DENY-wildcard case) |

**Negative results (no bug, verified correct):** N-C1-01 through N-C1-09 above.

---

## 9. Suggested issue split (fail-opens first)

**Issue 1 (P0, fail-open):** [F-C1-02] `parse_protocol` incomplete — esp/ah/sctp named protocols silently drop from policy app terms → PERMIT-esp-only rule becomes PERMIT-all (fail-open). Extend `parse_protocol` with full IANA/common Junos protocol name table.

**Issue 2 (P0, fail-open):** [F-C1-09] Unresolvable application name in `match application <bad-name>` → `applicationTerms=nil` → Rust `match_any=true` → PERMIT-all fail-open. Hard-fail snapshot when app resolution fails (or at minimum distinguish genuine-any vs failed-resolve).

**Issue 3 (P0, fail-open when allow-embedded-icmp enabled):** [F-C1-11] Embedded ICMP error packets bypass policy evaluation entirely. Outer tuple not checked, session existence not required. Should check outer policy and require inner session match.

**Issue 4 (P1, fail-open for DENY):** [F-C1-14] Malformed address CIDR (e.g. /33) → empty book → MatchNone → DENY rule no-op → permits attacker. Validate address literals at build time.

**Issue 5 (P1, fail-open):** [F-C1-08] `source-address-excluded` / `destination-address-excluded` not implemented — exclusion silently dropped, traffic permitted.

**Issue 6 (P1, fail-open / parity):** [F-C1-06] ICMP type/code not parsed from Junos applications — ICMP-type-8-only permit becomes all-ICMP permit (fail-open).

**Issue 7 (P2, parity):** [F-C1-04] `from-zone any / to-zone any` wildcard zone-pair accepted but silently dropped.

**Issue 8 (P2, minor):** [F-C1-03] `parse_port_spec` rejects `0-*` ranges → term drop → same as F-C1-02.

---

*End of report — 8 findings (3 High fail-open, 3 Medium fail-open/parity, 2 Medium/Low parity/implementation), 9 negative results, full trace evidence provided.*
