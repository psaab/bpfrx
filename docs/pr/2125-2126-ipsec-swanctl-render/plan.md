# #2125 + #2126 — IPsec swanctl render correctness (GCM ICV suffix + PSK/identity quoting)

Status: DRAFT v2 — diagnosis corrected after Codex round-1 PLAN-KILL
(the GCM-parse premise was wrong; load-bearing fix re-anchored to the
IKE PRF). Pending re-review.

## Issue framing

Two independent swanctl-render correctness bugs in `pkg/ipsec`
(the file the issues reference as `ipsec.go` was split on master
into `crypto.go` / `ike.go` / `manager.go` / `policy.go`; the
target code now lives in `ike.go` and `policy.go`):

- **#2125 (HIGH) — CORRECTED diagnosis.** The Junos-native GCM
  encryption-algorithm names (`aes-128-gcm`, `aes-192-gcm`,
  `aes-256-gcm`) are normalized only by stripping `-cbc` then all
  `-`, producing the bare token `aes256gcm`. The issue (and plan v1)
  claimed this is an unparseable swanctl token — that is **FALSE**:
  the strongSwan proposal-keyword table
  (`proposal_keywords_static.txt`, verified in master AND stable
  5.9.14) contains bare `aes128gcm`/`aes192gcm`/`aes256gcm` entries,
  each mapping to `ENCR_AES_GCM_ICV16` (16-octet ICV). So
  `aes256gcm-modp2048` is a *valid* ESP proposal — the ESP path does
  NOT silently fail at parse, and the ICV canonicalization alone is
  not the bug.
  - **The real, load-bearing #2125 bug is the IKE (Phase 1) PRF.**
    IKEv2 AEAD proposals carry no integrity algorithm for strongSwan
    to derive a PRF from, so the IKE proposal MUST name a PRF
    explicitly (strongSwan docs: "If AEAD ciphers are proposed there
    won't be any integrity algorithms from which to derive PRFs. Thus
    PRF algorithms have to be configured explicitly."). The current
    IKE builders (`buildIKEProposal`, `buildIKEProposalFromIKE`) emit
    `aes256gcm-modp2048` with NO PRF, so a GCM IKE proposal is
    incomplete and the IKE SA fails to negotiate — the silently-dead
    tunnel is real, but the cause is the missing PRF, not the ICV
    spelling.
  - **The ICV canonicalization is kept as a harmless clarity fix.**
    Mapping `aes-256-gcm` -> `aes256gcm16` produces the *same*
    algorithm (`ENCR_AES_GCM_ICV16`) as the bare alias, makes the ICV
    length explicit in the generated config (matching the operator's
    Junos intent — Juniper docs: AES-256-GCM uses a 16-octet ICV),
    and the already-suffixed pass-through preserves `aes256gcm128`
    etc. unchanged. It is NOT claimed to fix a parse failure.

- **#2126 (MEDIUM):** the PSK is emitted as `secret = "%s"` with the
  decoded value passed only through `sanitizeSwanctlValue` (which
  strips C0 controls + DEL but leaves `"` and `\` untouched). A PSK
  containing a literal `"` (legal in a real PSK) renders
  `secret = "ab"cd"`, which the swanctl lexer reads as the string
  `ab` followed by stray tokens — a corrupted/empty key → silent IKE
  auth failure. The same unquoted/unescaped exposure applies to the
  `id = ...` identity lines and `certs = ...`: a DN identity with
  spaces/commas (`id = CN=fw, O=acme`) is emitted unquoted and
  mis-parsed.

## Honest scope/value framing

This is a pure control-plane correctness fix in the swanctl.conf
generator. No dataplane/forwarding code is touched, so there is no
throughput/CPU dimension — the win is "documented Junos config that
silently produces a dead tunnel today now produces a swanctl-valid
config." If reviewers conclude any sub-part is wrong-target or the
risk outweighs the value, PLAN-KILL of that sub-part is an
acceptable verdict.

## Grammar verification (load-bearing — not guessed)

strongSwan / swanctl grammar confirmed against official docs +
the actual lexer source before drafting:

1. **AES-GCM tokens** (docs.strongswan.org Algorithm Proposals):
   `aes128gcm16`==`aes128gcm128`, `aes192gcm16`==`aes192gcm128`,
   `aes256gcm16`==`aes256gcm128` (16-octet / 128-bit ICV); also the
   8/12-octet variants. Junos AES-GCM uses a 16-octet ICV, so the
   correct mapping is `aes-256-gcm -> aes256gcm16` (and 128/192).
   We use the `...gcm16` spelling (the canonical strongSwan short
   form for the full 16-octet ICV).
2. **AEAD requires explicit PRF** (same doc): "If AEAD ciphers are
   proposed there won't be any integrity algorithms from which to
   derive PRFs. Thus PRF algorithms have to be configured
   explicitly." Token form `prfsha256` / `prfsha384` / `prfsha512`.
   Applies to IKE (Phase 1) only; ESP children take no PRF.
3. **swanctl string escaping** (settings_lexer.l, `<str>` state):
   inside a double-quoted string the lexer recognizes `\n`/`\r`/`\t`
   as the named escapes and `\\.` (backslash + any char) as that
   literal char; a bare `"` terminates the string. Therefore the
   correct render-time escaping is: replace `\` -> `\\` FIRST, then
   `"` -> `\"`. (Order matters; doing `"` first would then double the
   backslash it just inserted.) This makes a literal backslash render
   as `\\` (lexer `\\.` -> `\`) and a quote as `\"` (lexer `\\.` ->
   `"`), and `\` followed by `n` renders as `\\n` (lexer: `\\.` -> `\`
   then literal `n`), never the newline escape — round-trip exact.

## Concrete design

### Part A — GCM ICV suffix + IKE PRF (#2125), in `ike.go`

Add one shared normalizer used by all three builders
(`buildESPProposal`, `buildIKEProposal`, `buildIKEProposalFromIKE`):

```go
// gcmICVSuffix maps a Junos GCM encryption-algorithm name to its
// strongSwan token with the 16-octet ICV suffix swanctl requires
// (a bare "aes256gcm" is not a valid swanctl keyword). Returns
// (token, true) only for the Junos GCM variants; ("", false)
// otherwise so the caller falls through to the existing CBC/legacy
// normalization (strip "-cbc", strip "-").
func normalizeEncAlg(enc string) (token string, isGCM bool) {
	switch enc {
	case "aes-128-gcm", "aes128gcm":
		return "aes128gcm16", true
	case "aes-192-gcm", "aes192gcm":
		return "aes192gcm16", true
	case "aes-256-gcm", "aes256gcm":
		return "aes256gcm16", true
	}
	// Already-suffixed forms pass through unchanged so existing
	// configs / tests that feed aes256gcm128 etc. keep working.
	if strings.Contains(enc, "gcm") {
		return strings.ReplaceAll(strings.ReplaceAll(enc, "-cbc", ""), "-", ""), true
	}
	return "", false
}
```

Each builder becomes:

```go
enc := prop.EncryptionAlg
if enc == "" { enc = "aes256" }
if tok, isGCM := normalizeEncAlg(enc); isGCM {
	parts = append(parts, tok)
	// ESP: no auth, no PRF.
	// IKE: append a PRF (prfsha256, or derived from AuthAlg) — AEAD
	// has no integrity alg to derive a PRF from.
} else {
	enc = strings.ReplaceAll(enc, "-cbc", "")
	enc = strings.ReplaceAll(enc, "-", "")
	parts = append(parts, enc)
	// existing auth handling for non-GCM
}
```

For the two IKE builders, when `isGCM` append a PRF part. PRF is
derived from the proposal's AuthAlg when present (`hmac-sha-256` ->
`prfsha256`, `sha384`->`prfsha384`, `sha512`->`prfsha512`),
defaulting to `prfsha256` when AuthAlg is empty/unknown. ESP
(`buildESPProposal`) appends NO PRF (ESP AEAD children take only the
cipher + optional DH).

The GCM `gcm`-contains checks that currently gate auth-skipping are
preserved via `isGCM`. The `aes256gcm128` already-suffixed form
(fed by current tests) routes through the `strings.Contains(enc,
"gcm")` pass-through branch unchanged.

Result tokens after the fix:
- ESP `aes-256-gcm`, dh14: `aes256gcm16-modp2048`
- ESP `aes-256-gcm`, no dh: `aes256gcm16`
- IKE `aes-256-gcm`, dh14, no auth: `aes256gcm16-prfsha256-modp2048`
- IKE `aes-256-gcm`, dh14, auth hmac-sha-384: `aes256gcm16-prfsha384-modp2048`
- ESP `aes256gcm128` (legacy already-suffixed): `aes256gcm128-...` (unchanged)

### Part B — swanctl double-quote escaping (#2126), in `policy.go`

Add a dedicated quoter and apply it where a value is interpolated
inside `"..."` or where swanctl needs a quoted free-text value:

```go
// escapeSwanctlQuoted escapes a string for inclusion inside a
// swanctl double-quoted value. The swanctl settings lexer treats a
// bare double-quote as the string terminator and processes
// backslash escapes inside quotes (\" -> ", \\ -> \). Order
// matters: backslashes are doubled first, then quotes escaped.
func escapeSwanctlQuoted(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
```

- **PSK secret (line ~204):**
  `secret = "%s"` with `escapeSwanctlQuoted(sanitizeSwanctlValue(decoded))`.
  Control-char sanitization stays (belt for #1798); quote/backslash
  escaping is the new layer.
- **`id = ...` (lines ~115, ~123):** emit quoted +
  escaped — `id = "%s"`. swanctl accepts a quoted identity for every
  id type (docs example `id = "C=CH, O=strongSwan, CN=*"`), and a
  quoted `@fqdn` / quoted IP parse identically to the unquoted form,
  so this is safe AND fixes the DN-with-spaces/commas mis-parse. The
  two existing tests that assert unquoted `id = @vpn.example.com` /
  `id = 203.0.113.1` are updated to the quoted form (correct
  behavior, not a regression).
- **`certs = ...` (line ~112):** quote + escape the same way for
  consistency (a cert filename with a space would otherwise truncate).

`escapeSwanctlQuoted` is applied AFTER `sanitizeSwanctlValue` so the
control-char belt still runs first; the order is composition, not
conflict.

## Public API preservation

All target functions are unexported package-internal helpers
(`buildESPProposal`, `buildIKEProposal`, `buildIKEProposalFromIKE`,
`sanitizeSwanctlValue`, `formatIdentity`, `normalizePSK`). No
exported signature changes. New helpers (`normalizeEncAlg`,
`gcmPRF`, `escapeSwanctlQuoted`) are unexported.

## Hidden invariants the change must preserve

- **#1798 control-char belt** stays first in the PSK/id pipeline
  (sanitize then escape) — embedded newline still cannot inject a
  swanctl section.
- **Legacy already-suffixed GCM** (`aes256gcm128`, fed by current
  tests + any in-the-wild config) renders unchanged.
- **Non-GCM CBC path** (`aes-256-cbc` -> `aes256`, plus auth) is
  byte-identical to today.
- **ESP vs IKE PRF asymmetry**: PRF is appended ONLY for IKE GCM,
  never ESP — adding a PRF to an ESP proposal would itself be invalid.
- **DH/modp suffix ordering** preserved (cipher[-auth|-prf][-modp]).

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression (non-GCM / legacy GCM) | LOW | new code only diverges for Junos-native GCM names; legacy + CBC paths fall through unchanged, asserted by retained tests |
| Correctness of new grammar | LOW | tokens + escaping verified against strongSwan docs + lexer source, not guessed |
| id/certs quoting behavior change | LOW-MED | changes existing `id =` test expectations; quoted form is universally swanctl-valid, so functionally safe |
| Architectural mismatch | NONE | localized render fix, no new abstraction layer |

## Test plan (control-plane only — NO dataplane smoke per directive)

- `go build ./...` clean.
- `go test ./pkg/ipsec/... ./pkg/config/...` — full pass.
- New `pkg/ipsec` unit tests, each NON-tautological (must fail on
  pre-fix code):
  - GCM ESP: `buildESPProposal(aes-128/192/256-gcm, dh14)` ->
    `aes{128,192,256}gcm16-modp2048`; no-dh -> `aes{N}gcm16`. (These
    assert the canonical ICV spelling, not a parse fix — both bare
    and suffixed forms parse; the test pins the explicit-ICV output.)
  - GCM IKE (the load-bearing #2125 assertion): `buildIKEProposal` /
    `buildIKEProposalFromIKE` with `aes-256-gcm` -> contains
    `aes256gcm16` AND a `prfsha*` part AND `modp2048`; PRF derives
    from AuthAlg when set. This is the test that fails pre-fix for a
    real-grammar reason (no PRF == invalid IKE AEAD proposal).
  - Legacy already-suffixed `aes256gcm128` unchanged.
  - PSK with embedded `"` -> rendered `secret = "...\"..."` (assert
    exact bytes); PSK with `\` -> `\\`; PSK with both.
  - Full `GenerateConfig` render with a quote-bearing PSK parses to
    one balanced quoted secret (assert the exact secret line).
  - id with spaces/commas -> quoted+escaped `id = "..."`.
- If swanctl is installed in the test env, additionally pipe the
  rendered config through a swanctl syntax check; it is NOT available
  locally (`swanctl: command not found`), so the primary gate is
  exact-byte assertions against the verified grammar.

## Out of scope (explicitly)

- Commit-time schema validation of encryption-algorithm /
  PSK values (#2125/#2126 mention it as optional) — render-side fix
  is the load-bearing change; a schema validator is a separate
  follow-up and would not by itself fix already-committed configs.
- `0x`/`0s` hex/base64 secret encoding alternative — backslash
  escaping is simpler, lexer-correct, and keeps the secret
  human-diffable in generated config.
- **swanctl section/key NAME hardening** (Codex r1 finding #6).
  `renderConfig` interpolates operator-controlled section names
  (`<vpn> {`, `ike-<vpn> {`, traffic-selector child names) through
  only `sanitizeSwanctlValue` (control-char strip) — a name with a
  space/brace/`#`/`=` is not a free-text value and could still
  malform a section header. This is a real but separate exposure
  from the confirmed PSK/identity-value defects in #2125/#2126;
  config-object names are already constrained by the Junos parser
  grammar (the names come from parsed identifiers, not arbitrary
  free text), and `sanitizeChildName` already restricts child names
  to `[A-Za-z0-9._-]`. Deferred to a follow-up issue rather than
  silently claimed as covered. This plan does NOT assert all
  operator-influenced swanctl strings are hardened.
- Any non-IPsec swanctl value.

## Round-1 adversarial review record

- **Codex r1: PLAN-KILL** (task-mqn9xb9o-aaue4r). Correct and
  decisive: proved against `proposal_keywords_static.txt` (master +
  5.9.14) that bare `aes256gcm` IS a valid strongSwan keyword
  (-> `ENCR_AES_GCM_ICV16`), so plan-v1's "unparseable ESP token ->
  dead tunnel" premise was false. Re-anchored the load-bearing
  #2125 fix to the missing IKE PRF; demoted the ICV canonicalization
  to a harmless clarity fix; scoped out section-name hardening
  (finding #6) explicitly; confirmed the PSK/backslash escaping plan
  and order are correct (finding #4); confirmed `id`/`certs` quoting
  is safe but broader-than-the-PSK-defect (finding #5, kept in scope
  with tests). Junos 16-octet-ICV claim (finding #3) now backed by a
  primary Juniper-docs citation.
- **Gemini r1: infra failure** ("ACP initialize timed out after 30s",
  then a second attempt). Re-dispatched against the corrected v2 plan.

## Resolved questions

1. `aes256gcm16` vs `aes256gcm128` vs bare `aes256gcm`: all three map
   to `ENCR_AES_GCM_ICV16`. We emit `aes256gcm16` (explicit ICV,
   matches Junos 16-octet intent). RESOLVED.
2. PRF default `prfsha256` for a no-AuthAlg GCM IKE proposal; mirrors
   the proposal's auth algorithm when present (sha384 -> prfsha384,
   etc.). A reasonable, interoperable default. RESOLVED.
3. `id`/`certs` quoting kept in scope — swanctl strips config quotes
   before identity parsing, so a quoted `@fqdn`/IP/DN all parse
   identically AND a DN with spaces/commas now parses as one value.
   Existing test expectations updated. RESOLVED.
4. Escape order (backslash-first, then quote) verified against the
   lexer `\\.` rule; literal backslash-n round-trips as `\\n` (not a
   newline). RESOLVED.
5. No in-the-wild config can rely on the bare-`aes256gcm` ESP render
   being broken — it was actually valid, so the canonical respelling
   is behavior-equivalent for ESP; the IKE PRF addition is the only
   negotiation-affecting change. RESOLVED.
6. The added IKE PRF cannot break a previously-working peer: a GCM
   IKE proposal with no PRF could not have negotiated, so any peer
   using GCM IKE today is already failing; adding the PRF is what
   lets it work. RESOLVED.
