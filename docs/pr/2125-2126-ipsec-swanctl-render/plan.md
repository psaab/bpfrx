# #2125 + #2126 — IPsec swanctl render correctness (GCM ICV suffix + PSK/identity quoting)

Status: DRAFT v1 — pending adversarial plan review (Codex + Gemini + Claude SMR)

## Issue framing

Two independent swanctl-render correctness bugs in `pkg/ipsec`
(the file the issues reference as `ipsec.go` was split on master
into `crypto.go` / `ike.go` / `manager.go` / `policy.go`; the
target code now lives in `ike.go` and `policy.go`):

- **#2125 (HIGH):** Junos-native GCM encryption-algorithm names
  (`aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`) are normalized only
  by stripping `-cbc` then all `-`, producing the bare token
  `aes256gcm`. strongSwan's proposal parser has **no bare
  `aes<N>gcm` keyword** — GCM ciphers require an explicit ICV-length
  suffix (`aes256gcm16`, `aes256gcm128`, `aes256gcm12`,
  `aes256gcm8`). The rendered ESP/IKE proposal (e.g.
  `aes256gcm-modp2048`) is unparseable, so the SA never establishes
  while the commit succeeds — a silent dead tunnel. Secondary defect
  in the same path: for IKE (Phase 1) AEAD proposals strongSwan also
  requires an explicit PRF (e.g. `aes256gcm16-prfsha256-modp2048`);
  the current IKE builders skip auth for GCM and never add a PRF, so
  even a correct ICV suffix would leave the IKE proposal incomplete.

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
    `aes{128,192,256}gcm16-modp2048`; no-dh -> `aes{N}gcm16`.
  - GCM IKE: `buildIKEProposal` / `buildIKEProposalFromIKE` with
    `aes-256-gcm` -> contains `aes256gcm16` AND a `prfsha*` part AND
    `modp2048`; PRF derives from AuthAlg when set.
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
- Any non-IPsec swanctl value.

## Open questions for adversarial review

1. Is `aes256gcm16` the right spelling vs `aes256gcm128`? (Both are
   the 16-octet ICV; `gcm16` is the canonical short form. Either
   parses — is there a reason to prefer 128 for Junos parity?)
2. PRF default: is `prfsha256` the right default for a GCM IKE
   proposal with no AuthAlg, or should it derive from the DH/cipher
   strength (e.g. prfsha384 for aes256)? Junos default behavior?
3. Should `id`/`certs` quoting be in-scope, or kept minimal to the
   confirmed PSK defect to shrink the diff? (Quoting is safe but
   changes existing test expectations.)
4. Backslash-first then quote escaping order — any swanctl lexer
   corner the `\\.` analysis misses (e.g. `\n`/`\r`/`\t` named
   escapes interacting with a literal backslash-n in a PSK)?
5. Does any existing in-the-wild config rely on the (broken) bare
   `aes256gcm` rendering such that changing it is itself a
   regression? (It cannot establish today, so no — but call it out.)
6. Is appending a PRF to the IKE proposal safe when the peer
   negotiated without one before? (It could not have — bare
   `aes256gcm` never established.)
