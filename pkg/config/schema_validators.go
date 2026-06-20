package config

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schema validators used by #1319 SchemaValidate. Each returns nil for
// accepted input and a descriptive error otherwise. They run at commit
// check time only — the existing compiler parsers (parseBandwidthLimit,
// parseBurstSizeLimit, ...) keep their zero-return-on-error contract so
// downstream callers don't need to learn new error paths.
//
// Validators take a (raw string, cfg *Config) pair so future validators
// can cross-reference compiled state (e.g. "scheduler X must exist").
// Today the schedulers leaves don't need cfg, so they ignore it.

// LeafValidator is the function signature for typed-leaf validators.
// The mirrored cmdtree.LeafValidator alias has the same shape so
// cmdtree Nodes can hold one of these directly. We define it here too
// (rather than importing cmdtree) to avoid a config→cmdtree→config
// import cycle.
type LeafValidator func(raw string, cfg *Config) error

// validateRate accepts a Junos bandwidth value (bits/sec) like
// "100k", "10m", "1g", or a bare positive integer. Empty input is
// rejected — a typed leaf with no value is meaningless. Values below
// 8 bps are rejected because the compiler stores scheduler rates in
// bytes/sec; accepting 1..7 bps would round-trip as 0 and silently
// disable the configured rate.
func ValidateRate(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected bandwidth, e.g. 100k, 10m, 1g)")
	}
	bps, err := parseScaledDecimalUnitStrict(raw)
	if err != nil {
		return fmt.Errorf("not a valid bandwidth (expected k/m/g suffix, e.g. 10m): %w", err)
	}
	if bps < 8 {
		return fmt.Errorf("bandwidth must be at least 8 bps so it compiles to a non-zero byte/sec rate (got %q)", raw)
	}
	return nil
}

// validateByteSize accepts the byte-size form the current CoS compiler
// consumes. Reject bare integers here so `buffer-size 50` cannot pass
// validation and compile as a 50-byte queue.
func ValidateByteSize(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected byte-size with k/m/g suffix, e.g. 16m)")
	}
	if _, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
		return fmt.Errorf("bare byte-size %q is ambiguous; use an explicit suffix like 50k or 16m", raw)
	}
	if _, err := parseBurstSizeLimitStrict(trimmed); err != nil {
		return fmt.Errorf("not a valid byte-size (expected 16m, 256k, or 1g): %w", err)
	}
	return nil
}

// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
// that the CoS runtime can represent: explicit byte sizes with k/m/g
// suffixes, or Junos percent values with a trailing percent sign. Bare
// integers stay rejected because they are ambiguous between bytes and
// percent.
func ValidateByteSizeOrPercent(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if strings.HasSuffix(trimmed, "%") {
		if _, err := parsePercentWithSuffixStrict(trimmed); err != nil {
			return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
		}
		return nil
	}
	return ValidateByteSize(raw, nil)
}

func parsePercentWithSuffixStrict(raw string) (float64, error) {
	orig := raw
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("empty value")
	}
	if !strings.HasSuffix(trimmed, "%") {
		return 0, fmt.Errorf("missing percent suffix in %q", orig)
	}
	number := strings.TrimSpace(strings.TrimSuffix(trimmed, "%"))
	if number == "" {
		return 0, fmt.Errorf("empty percent in %q", orig)
	}
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid percent %q: %w", orig, err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("invalid percent %q: non-finite", orig)
	}
	// xpf intentionally rejects 0% even though Junos allows it.
	// A 0% buffer allocation compiles to zero bytes at runtime and is
	// indistinguishable from "no buffer-size configured" -- the runtime
	// would silently fall back to the default 10 ms burst calculation.
	// Using the default path directly is unambiguous; disallowing 0%
	// avoids silent no-op configs that look correct but do nothing.
	if v <= 0 || v > 100 {
		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
	}
	return v, nil
}

// MaxDurationMillis is the largest millisecond count that survives the
// runtime's `time.Duration(ms) * time.Millisecond` conversion without
// int64 overflow (math.MaxInt64 / 1e6 = 9223372036854). Above this, a
// configured millisecond knob converts to a negative Duration — e.g. the
// cluster heartbeat sender ticker panics on a non-positive interval. Used
// as the honest runtime-derived upper bound for millisecond typed leaves
// whose runtime otherwise accepts any positive value (#1319 PR 2; Codex
// review on PR #1845: no schema-only caps).
const MaxDurationMillis = int64(math.MaxInt64) / int64(time.Millisecond)

// MaxDurationSeconds is the seconds analogue of MaxDurationMillis: the
// largest second count that survives `time.Duration(n) * time.Second`
// without int64 overflow (math.MaxInt64 / 1e9 = 9223372036). Used for
// second-denominated typed leaves whose runtime otherwise accepts any
// non-negative value (e.g. services ip-monitoring hold-down,
// pkg/ipmon/ipmon.go:480 — an overflowed negative hold would silently
// invert the damping behaviour).
const MaxDurationSeconds = int64(math.MaxInt64) / int64(time.Second)

// maxWireU16 / maxWireU32 are the inclusive ceilings for typed leaves
// whose value lands in a Rust u16 / u32 wire field. #1979 Layer B uses
// these so the commit-time range gate agrees EXACTLY with the build-time
// coercion in pkg/dataplane/userspace/flow.go (Layer A, #1977): a value
// Layer B accepts is one Layer A leaves unchanged, and a value Layer B
// rejects is one Layer A would have coerced. (math.MaxUint16 /
// math.MaxUint32 are untyped constants; naming them keeps the schema
// aspect files import-free and the bound self-documenting.)
const (
	maxWireU16 = int64(math.MaxUint16)
	maxWireU32 = int64(math.MaxUint32)
)

// ValidateIntegerMin returns a closure that accepts any bare integer
// >= min — the "no upper bound" spelling for typed leaves whose runtime
// consumes the full integer range. The representational maximum is
// implied by strconv.ParseInt's 64-bit limit (larger inputs fail as
// "not an integer"). Preferred over ValidateInteger(min, math.MaxInt64)
// so the operator error reads "must be at least N" instead of quoting a
// 19-digit range bound.
func ValidateIntegerMin(min int64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected integer)")
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", raw)
		}
		if v < min {
			return fmt.Errorf("integer must be at least %d (got %d)", min, v)
		}
		return nil
	}
}

// validateInteger returns a closure that accepts a bare integer in
// [min, max] inclusive. min > max disables the range check.
func ValidateInteger(min, max int64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected integer)")
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", raw)
		}
		if min <= max && (v < min || v > max) {
			return fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
		}
		return nil
	}
}

// ValidateDHGroup accepts a Diffie-Hellman group as either a bare integer
// (e.g. "14") or the Junos "group<N>" spelling (e.g. "group14") — both are
// configured in the wild and both compile (compiler_ipsec.go strips the
// "group" prefix then Atoi's the remainder). The group number must be a
// positive integer: the compiler leaves DHGroup at 0 on a parse failure,
// and a 0/garbage group silently drops the modp term from the swanctl
// proposal (pkg/ipsec/ipsec.go buildIKEProposal / buildESPProposal gate on
// DHGroup > 0), so an invalid value commits and then quietly weakens the
// negotiated proposal. This validator closes that silent-drop while staying
// faithful to the two spellings the compiler already accepts.
func ValidateDHGroup(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a DH group, e.g. 14 or group14)")
	}
	num := strings.TrimPrefix(trimmed, "group")
	v, err := strconv.Atoi(num)
	if err != nil {
		return fmt.Errorf("not a valid DH group (got %q; expected an integer like 14 or group14)", raw)
	}
	if v < 1 {
		return fmt.Errorf("DH group must be a positive integer (got %d); 0 silently drops the modp term from the negotiated proposal", v)
	}
	return nil
}

// validateEnum returns a closure that accepts only one of the listed
// names (case-sensitive, exact match).
func ValidateEnum(allowed []string) LeafValidator {
	sorted := append([]string(nil), allowed...)
	sort.Strings(sorted)
	set := make(map[string]struct{}, len(sorted))
	for _, a := range sorted {
		set[a] = struct{}{}
	}
	return func(raw string, _ *Config) error {
		if _, ok := set[raw]; ok {
			return nil
		}
		return fmt.Errorf("invalid value %q (expected one of: %s)", raw, strings.Join(sorted, ", "))
	}
}

// IP / CIDR validators (#1319 PR 3, interfaces subsystem). They reuse the
// net package parsers the runtime consumers use (net.ParseIP /
// net.ParseCIDR), so schema acceptance mirrors runtime parse acceptance
// exactly — including the family classification rule ip.To4() != nil that
// pkg/dataplane/userspace/interfaces.go buildConfiguredAddressSnapshots
// applies to configured addresses.

// ValidateIPAddress accepts any IPv4 or IPv6 address WITHOUT a prefix
// length. Used for leaves the runtime feeds to net.ParseIP (e.g. GRE
// tunnel source/destination, pkg/routing/tunnel.go:194), where garbage
// silently disables the feature today.
func ValidateIPAddress(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an IP address, e.g. 10.0.1.10 or 2001:db8::1)")
	}
	if net.ParseIP(trimmed) == nil {
		if _, _, err := net.ParseCIDR(trimmed); err == nil {
			return fmt.Errorf("prefix length not allowed here (got %q; use a bare IP address)", raw)
		}
		return fmt.Errorf("not a valid IP address (got %q)", raw)
	}
	return nil
}

// ValidateIPv4CIDR accepts an IPv4 address with an explicit prefix
// length (e.g. 10.0.1.10/24). The prefix is REQUIRED: every runtime
// consumer of configured interface addresses net.ParseCIDRs the string
// and silently skips it on error (dataplane snapshot:
// pkg/dataplane/userspace/interfaces.go:391; RETH link-local checks:
// pkg/daemon/daemon_reth.go:308), so a bare IP would commit and then
// silently not exist. The v4/v6 family split mirrors the runtime
// classification ip.To4() != nil.
func ValidateIPv4CIDR(raw string, _ *Config) error {
	ip, err := parseCIDRStrict(raw, "10.0.1.10/24")
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return fmt.Errorf("not an IPv4 address (got %q; IPv6 addresses belong under family inet6)", raw)
	}
	return nil
}

// ValidateIPv6CIDR accepts an IPv6 address with an explicit prefix
// length (e.g. 2001:db8::1/64). See ValidateIPv4CIDR for why the prefix
// is required; the family rule mirrors the runtime's ip.To4() == nil
// classification, so 4-in-6 forms like ::ffff:10.0.1.1/96 — which the
// runtime classifies as inet — are rejected under family inet6.
func ValidateIPv6CIDR(raw string, _ *Config) error {
	ip, err := parseCIDRStrict(raw, "2001:db8::1/64")
	if err != nil {
		return err
	}
	if ip.To4() != nil {
		return fmt.Errorf("not an IPv6 address (got %q; IPv4 addresses belong under family inet)", raw)
	}
	return nil
}

// parseCIDRStrict is the shared require-a-prefix CIDR parse for the two
// family validators. It upgrades the two common operator mistakes to
// targeted messages: a bare IP (missing /prefix-length) and outright
// garbage.
func parseCIDRStrict(raw, example string) (net.IP, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("missing value (expected address/prefix-length, e.g. %s)", example)
	}
	ip, _, err := net.ParseCIDR(trimmed)
	if err != nil {
		if net.ParseIP(trimmed) != nil {
			return nil, fmt.Errorf("missing /prefix-length (got %q; the runtime silently skips addresses without one — write e.g. %s)", raw, example)
		}
		return nil, fmt.Errorf("not a valid address/prefix-length (expected e.g. %s): %v", example, err)
	}
	return ip, nil
}

// routeFilterMatchTypes are the match-type keywords accepted in a
// `from route-filter <prefix> <match-type>` node. The schema node is
// args:2, so the walker invokes ValidateRouteFilterArg for BOTH identity
// tokens (the prefix AND the match-type — Keys[1:3]); the validator must
// therefore accept a match-type keyword as well as a CIDR prefix.
//
// exact/longer/orlonger/upto are the rendered match-types (pkg/frr
// policy_render.go). prefix-length-range and through are ADMITTED but
// not yet rendered (a separate deferred follow-up). They are admitted
// rather than rejected because they commit fine today (there was no
// validator before #2105), so rejecting them would be a grammar
// regression breaking configs already on the wire; their default render
// (le 32 / le 128) is FRR-valid even at a max-length prefix.
var routeFilterMatchTypes = map[string]bool{
	"exact":               true,
	"longer":              true,
	"orlonger":            true,
	"upto":                true,
	"prefix-length-range": true,
	"through":             true,
}

// ValidateRouteFilterArg is the #2105 commit-check validator for a
// `policy-options policy-statement <p> term <t> from route-filter
// <prefix> <match-type>` identity arg token. The node is args:2, so the
// walker (schema_walk.go) calls this for the prefix token AND the
// match-type token. The `upto /N` length token lands as a CHILD of the
// route-filter node, never in Keys[1:3], so it does not reach here.
//
// A token is accepted when it is either a match-type keyword OR a
// syntactically valid CIDR prefix (v4 or v6 — route-filter is
// family-agnostic). A malformed prefix (no "/", non-numeric mask, or an
// out-of-range mask) that is neither is REJECTED, so it never reaches
// the FRR renderer where it would produce an FRR-invalid prefix-list
// line and could fail the whole managed frr-reload.
//
// Strictness is automatic: SchemaValidate is strict on the operator
// commit / commit-check path and lenient (warn, not fail) on Store.Load
// / SyncApply (the #1960 lenient-downgrade-on-load doctrine), so a
// prefix persisted by an older binary never blackouts boot. The renderer
// carries a belt-and-suspenders skip for any malformed prefix that
// reaches it via that lenient path.
//
// Known limitation: the validator is position-agnostic (the walker does
// not tell it which slot a token came from), so a match-type keyword in
// the prefix slot (e.g. `route-filter longer exact`) is accepted. This
// is strictly better than the pre-#2105 state (any garbage committed)
// and catches the real malformed-CIDR case; per-position validation
// would require schema restructuring and is deferred.
func ValidateRouteFilterArg(raw string, _ *Config) error {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return fmt.Errorf("missing route-filter prefix (expected CIDR, e.g. 10.0.0.0/24)")
	}
	if routeFilterMatchTypes[tok] {
		return nil
	}
	// Family-agnostic CIDR. parseCIDRStrict requires a /prefix-length
	// and upgrades the common operator mistakes (bare IP, garbage) to
	// targeted messages, matching the ValidateIPv4CIDR/ValidateIPv6CIDR
	// convention; the returned IP is discarded because both families are
	// valid here. Surface parseCIDRStrict's targeted message (e.g.
	// "missing /prefix-length") so the commit-check failure is actionable.
	if _, err := parseCIDRStrict(tok, "10.0.0.0/24"); err != nil {
		return fmt.Errorf("not a valid route-filter prefix (expected a CIDR, e.g. 10.0.0.0/24 or 2001:db8::/32, or a match-type keyword): %v", err)
	}
	return nil
}

// validateForwardingClassRef is the #1319 PR 3 tree-based
// cross-reference validator for `firewall family inet/inet6 filter
// <f> term <t> then forwarding-class <name>`. The dataplane resolves
// the name with a map lookup against the CONFIGURED forwarding classes
// (queue_by_forwarding_class, userspace-dp
// src/afxdp/tx/cos_classify.rs:371) and silently leaves the packet on
// the default queue when it misses — a dangling reference commits fine
// and then does nothing. The reference is valid when:
//
//   - the name is defined via `class-of-service forwarding-classes
//     queue <n> <name>` anywhere in the candidate tree (collected by
//     collectSchemaRefs from the SAME tree being committed, so a
//     definition + reference in one commit validates atomically), or
//   - the name is "best-effort": when no forwarding-classes are
//     configured the dataplane synthesizes a best-effort queue
//     (forwarding_build/cos.rs:404-407), so that name is always
//     resolvable.
//
// xpf-DIVERGENT from Junos: the other three Junos default classes
// (expedited-forwarding, assured-forwarding, network-control) are NOT
// implicitly defined by the xpf runtime — referencing them without a
// definition is exactly the silent no-op this gate exists to close.
func validateForwardingClassRef(raw string, refs *schemaRefs) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected a forwarding-class name)")
	}
	if raw == "best-effort" {
		return nil
	}
	if refs != nil {
		if _, ok := refs.forwardingClasses[raw]; ok {
			return nil
		}
	}
	return fmt.Errorf("forwarding-class %q is not defined; add `set class-of-service forwarding-classes queue <queue-id> %s` in the same commit (xpf does not implicitly define the Junos default classes other than best-effort)", raw, raw)
}

// validatePercent returns a closure that accepts a real number in
// [min, max] inclusive. The input must parse as a float.
func ValidatePercent(min, max float64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected percent %.0f..%.0f)", min, max)
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("not a number: %q", raw)
		}
		if v < min || v > max {
			return fmt.Errorf("percent out of range [%.2f..%.2f] (got %s)", min, max, raw)
		}
		return nil
	}
}

// cryptModularIDs is the set of crypt(3) modular-hash identifiers xpf
// accepts in an encrypted-password value. It is a permissive superset of
// what Debian 13 glibc / libxcrypt actually verify against — the OS, not
// this validator, is the final authority at PAM time, so we err toward
// "clearly a hash" rather than a brittle per-id structural parse. yescrypt
// ($y$) is the Debian 13 default; $6$ (sha512crypt) is universal; $2a$/
// $2b$/$2y$ (bcrypt), $5$ (sha256crypt), $1$ (md5crypt), $7$ (scrypt) and
// $gy$ (gost-yescrypt) are present via libxcrypt. #1944 §5.5.
var cryptModularIDs = map[string]bool{
	"1": true, "2a": true, "2b": true, "2y": true,
	"5": true, "6": true, "7": true, "y": true, "gy": true,
}

// cryptFieldRune reports whether r is allowed inside a crypt(3) salt or
// checksum field. The crypt-base64 alphabet is [./0-9A-Za-z]; modular
// param fields (e.g. yescrypt $y$j9T$... or sha512crypt
// $6$rounds=656000$...) additionally use '=' to introduce a parameter
// value. We allow '=' here and reject ':' implicitly (not in the set) so
// a value can never corrupt the `user:hash` chpasswd stdin line.
func cryptFieldRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '/' || r == '=':
		return true
	}
	return false
}

// ValidateCryptHash accepts a crypt(3) modular password hash or an
// explicit lock sentinel, and HARD-REJECTS plaintext. It is shared by
// `system root-authentication encrypted-password` and `system login user
// <name> authentication encrypted-password` (#1944, E1).
//
// Accepted:
//   - A modular crypt hash: an optional leading "!" or "!!" (the
//     locked-but-restorable form), then $<id>$<salt>$<checksum> where
//     <id> ∈ cryptModularIDs, <salt> is non-empty (and may itself carry
//     $-separated params such as rounds=N), and the FINAL $-field (the
//     checksum) is non-empty. A trailing empty checksum ($6$salt$) is
//     rejected — it writes a malformed shadow field PAM refuses.
//   - A bare lock sentinel: "*", "!", or "!!". This is the intentional
//     Unix way to lock an account and the only way to lock root via
//     config (root is excluded from the per-user D2 auto-lock). Accepting
//     a deliberate sentinel is NOT the plaintext footgun.
//
// Rejected: plaintext (no leading $-id, not a sentinel — the real
// footgun), the empty string, an unknown $<id>$, an empty salt or empty
// checksum, and any value carrying ':' (would corrupt chpasswd stdin) or
// a control character. Legacy 13-char DES is deliberately NOT accepted so
// that "reject plaintext" is an absolute guarantee (a 13-char alnum
// password would otherwise pass).
func ValidateCryptHash(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a crypt(3) hash, e.g. from `openssl passwd -6`)")
	}
	// Bare lock sentinels — deliberate, accepted as-is.
	if raw == "*" || raw == "!" || raw == "!!" {
		return nil
	}
	// Modular crypt hash, with an optional locked-but-restorable prefix.
	body := raw
	if strings.HasPrefix(body, "!!") {
		body = body[2:]
	} else if strings.HasPrefix(body, "!") {
		body = body[1:]
	}
	if !strings.HasPrefix(body, "$") {
		return fmt.Errorf("not an encrypted password hash (got %q) — plaintext is not "+
			"allowed; generate a hash with `openssl passwd -6` or `mkpasswd -m sha512crypt`", raw)
	}
	// Split into $-separated fields: leading "$" yields an empty first
	// element, so fields[0]=="" , fields[1]=<id>, fields[2..]=salt/params,
	// fields[last]=checksum. Require at least id + salt + checksum.
	fields := strings.Split(body, "$")
	// fields[0] is the empty string before the first '$'.
	if len(fields) < 4 {
		return fmt.Errorf("malformed crypt hash %q — expected $<id>$<salt>$<checksum>", raw)
	}
	id := fields[1]
	if !cryptModularIDs[id] {
		return fmt.Errorf("unknown crypt hash id %q in %q — expected one of "+
			"1, 2a, 2b, 2y, 5, 6, 7, y, gy", id, raw)
	}
	salt := fields[2]
	checksum := fields[len(fields)-1]
	if salt == "" {
		return fmt.Errorf("empty salt in crypt hash %q", raw)
	}
	if checksum == "" {
		return fmt.Errorf("empty checksum in crypt hash %q — a trailing $ "+
			"with no checksum writes a malformed shadow field", raw)
	}
	// Every salt/param/checksum field must be NON-EMPTY and use only the
	// crypt alphabet (which excludes ':' and whitespace), so the value can
	// never corrupt the chpasswd `user:hash` stdin line or smuggle a
	// separator. An empty intermediate field (e.g. "$6$salt$$hash", a
	// doubled '$') is not a valid modular crypt hash — it would pass an
	// alphabet-only check (no chars to reject) but fail at PAM, locking the
	// operator out. Reject it at commit (Copilot #1944 review).
	for _, f := range fields[2:] {
		if f == "" {
			return fmt.Errorf("empty field in crypt hash %q — a doubled "+
				"'$' (e.g. $6$salt$$hash) is malformed", raw)
		}
		for _, r := range f {
			if !cryptFieldRune(r) {
				return fmt.Errorf("invalid character %q in crypt hash %q", r, raw)
			}
		}
	}
	return nil
}

// ValidatePCIAddr accepts a PCI bus address in the canonical
// DDDD:BB:DD.F form (e.g. 0000:09:00.0), the #1956 device-map primary
// identity key. The format mirrors what extractPCIAddr produces from
// sysfs (pkg/daemon/linksetup.go) so a committed key resolves against the
// live enumeration without normalization drift. The shorter BB:DD.F form
// (no domain) is rejected: sysfs always carries the 4-digit domain, and
// accepting an ambiguous short form would silently never match.
func ValidatePCIAddr(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a PCI bus address, e.g. 0000:09:00.0)")
	}
	if !pciAddrCanonical(trimmed) {
		return fmt.Errorf("not a canonical PCI bus address (got %q; expected DDDD:BB:DD.F, "+
			"e.g. 0000:09:00.0 — copy it from `show chassis device-map candidates`)", raw)
	}
	return nil
}

// pciAddrCanonical reports whether s is exactly DDDD:BB:DD.F where each
// field is lower-case hex of the right width (domain 4, bus 2, device 2,
// function 1). sysfs uses lower-case; we require it so two spellings of
// the same address can never both be present in one map.
func pciAddrCanonical(s string) bool {
	// 0000:00:00.0 = 12 chars.
	if len(s) != 12 || s[4] != ':' || s[7] != ':' || s[10] != '.' {
		return false
	}
	isHex := func(lo, hi int) bool {
		for i := lo; i < hi; i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return isHex(0, 4) && isHex(5, 7) && isHex(8, 10) && isHex(11, 12)
}

// ValidateMAC accepts a 6-octet MAC address in colon-separated lower- or
// upper-case hex (xx:xx:xx:xx:xx:xx), the #1956 device-map permanent-MAC
// fallback key. It is compared against PermHWAddr at resolve time, never
// the running MAC. Reject the all-zero MAC (never a real factory MAC) and
// any multicast/group address (LSB of the first octet set) — neither can
// be a NIC's permanent unicast address, so accepting one guarantees a
// non-matching key.
func ValidateMAC(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a MAC address, e.g. 00:11:22:33:44:55)")
	}
	hw, err := net.ParseMAC(trimmed)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("not a valid 6-octet MAC address (got %q; expected xx:xx:xx:xx:xx:xx)", raw)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("all-zero MAC %q is never a valid device identity", raw)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("multicast/group MAC %q is never a NIC permanent address", raw)
	}
	return nil
}

// ValidateDeviceMapLogicalName accepts an xpf/vSRX logical interface name
// usable as a #1956 device-map binding target. It permits the management
// names (fxp0, em0), the vSRX revenue form ge-N/0/N (and other media
// prefixes), and bare alphanumeric forms — but rejects whitespace, unit
// suffixes (.N — the map binds the physical NIC, not a unit), and obvious
// garbage so a typo fails loud at commit rather than producing an unbound
// entry that only shows up at next boot.
func ValidateDeviceMapLogicalName(raw string, _ *Config) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		return fmt.Errorf("missing logical interface name (e.g. ge-0/0/3 or fxp0)")
	}
	if name != raw {
		return fmt.Errorf("logical interface name %q must not have leading/trailing whitespace", raw)
	}
	if strings.ContainsAny(name, " \t") {
		return fmt.Errorf("logical interface name %q must not contain whitespace", raw)
	}
	if strings.Contains(name, ".") {
		return fmt.Errorf("device-map binds the physical interface, not a unit — %q has a unit "+
			"suffix; map %q instead", raw, name[:strings.IndexByte(name, '.')])
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '/') {
			return fmt.Errorf("invalid character %q in logical interface name %q", r, raw)
		}
	}
	return nil
}
