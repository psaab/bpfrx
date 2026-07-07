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
	// maxWireI32 is the inclusive ceiling for a typed leaf whose value lands
	// in a Rust i32 wire field (e.g. RouteSnapshot.preference, #3771). Junos
	// route preference is a non-negative admin distance whose documented range
	// runs to 2^32-1, but the snapshot serializes it as i32, so the
	// wire-representable non-negative ceiling is math.MaxInt32 — a value above
	// it would overflow the Rust i32 decode (failing the whole snapshot). The
	// Rust helper backstops the lower bound too (RoutePreferenceOutOfRange).
	maxWireI32 = int64(math.MaxInt32)
)

// validateLoginClassRef accepts a `system login user <n> class <c>` value that
// is EITHER a system-defined built-in class (super-user/operator/read-only/
// config-viewer/unauthorized, from LoginClassPermissions) OR a custom `system
// login class <c>` defined in the same candidate tree (#4304 S-2). It replaces
// the fixed enum so a valid vSRX RBAC config that defines its own class is no
// longer hard-rejected at commit, while an undefined class still fails closed.
func validateLoginClassRef(raw string, refs *schemaRefs) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected a login class name)")
	}
	if _, ok := LoginClassPermissions[raw]; ok {
		return nil
	}
	if refs != nil {
		if _, ok := refs.loginClasses[raw]; ok {
			return nil
		}
	}
	return fmt.Errorf("login class %q is not defined; use a system-defined class (one of: %s) or add `set system login class %s permissions <...>` in the same commit",
		raw, strings.Join(ValidLoginClasses(), ", "), raw)
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

// MaxRingEntries is the inclusive upper bound for the AF_XDP `ring-entries`
// per-queue knob (#2524). The Rust helper preallocates UMEM frames directly
// from this value: per bind.rs binding_frame_count_for_driver, a virtio_net
// binding reserves ~3×ring_entries frames at UMEM_FRAME_SIZE=4096, i.e.
// ~96 MB per binding at ring_entries=8192 (×queues ×interfaces). With no
// ceiling a fat-fingered or malicious value drove an enormous preallocation
// and OOM'd at bring-up instead of failing as a clean commit/startup error.
// 16384 is double the documented 8192 example (~192 MB/binding worst case)
// and is the largest value we consider sane on a router; it must agree with
// the Rust backstop (afxdp/coordinator/reconcile/bringup.rs clamps to the
// same ceiling). The value must additionally be a power of two — the helper
// rounds ring sizes up to a power of two (xsk_ffi.rs next_power_of_two), so
// requiring it at commit keeps the configured number honest about the size
// actually allocated.
const MaxRingEntries = int64(16384)

// ValidateRingEntries accepts a bare integer in [1, MaxRingEntries] that is
// also a power of two. It is the typed-leaf gate for `system dataplane
// ring-entries` (#2524). Before #2524 the leaf used ValidateIntegerMin(1):
// any large value committed and was passed to the dataplane, where it sized
// per-binding UMEM preallocations and could OOM at bring-up. The power-of-two
// requirement matches the helper's own rounding so the operator-visible
// number equals the allocated ring depth.
func ValidateRingEntries(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected integer)")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %q", raw)
	}
	if v < 1 || v > MaxRingEntries {
		return fmt.Errorf("ring-entries out of range [1..%d] (got %d)", MaxRingEntries, v)
	}
	if v&(v-1) != 0 {
		return fmt.Errorf("ring-entries must be a power of two in [1..%d] (got %d)", MaxRingEntries, v)
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

// ValidateDDNSHostname rejects a Surface A DDNS hostname that the publish
// path (pkg/ddns surfaceAName -> sanitizeFQDN) would SILENTLY rewrite to a
// different DNS name (#2779). For router-owned Surface A records the hostname
// is operator intent — the operator types the exact public name to publish —
// so a name that sanitization would structurally change (drop a non-LDH
// character, collapse/drop an empty label, trim a leading/trailing dash off a
// label) must be a commit error, not a silent transform. The operator fixes
// the name rather than discovering wan_1.example.net was published as
// wan1.example.net.
//
// What is ACCEPTED (sanitization is a no-op or a benign canonicalization the
// operator clearly intended):
//   - lower-case [a-z0-9-] labels separated by single dots (the canonical LDH
//     form sanitizeFQDN produces),
//   - upper-case letters (sanitizeFQDN lower-cases; DNS is case-insensitive so
//     this is a benign canonicalization, not a structural change),
//   - a single trailing dot (absolute-name canonicalization; stripped before
//     publish).
//
// What is REJECTED (sanitization would change the published structure):
//   - any rune outside [A-Za-z0-9-] inside a label (underscore, space, '@',
//     IDN/punycode source chars, etc.) — sanitizeLabel drops it,
//   - an empty label (leading dot, double dot, or a label made only of dropped
//     characters) — sanitizeFQDN drops the whole label,
//   - a label that begins or ends with '-' — sanitizeLabel trims it,
//   - a label over 63 octets or a total name over 253 octets — capped.
func ValidateDDNSHostname(raw string, _ *Config) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		// An unset/blank hostname is handled by the binding-completeness
		// warning (validateSurfaceADDNSWarnings), not a hard reject — a
		// half-built candidate must still commit.
		return nil
	}
	// A single trailing dot is the only dot-position canonicalization the
	// publish path performs (TrimSuffix "."); strip it before the per-label
	// structural check so an absolute name is accepted.
	stripped := strings.TrimSuffix(name, ".")
	if stripped == "" {
		return fmt.Errorf("dynamic-dns hostname %q has no labels", raw)
	}
	if len(stripped) > maxDNSNameLen {
		return fmt.Errorf("dynamic-dns hostname %q exceeds %d octets and would be "+
			"truncated before publishing", raw, maxDNSNameLen)
	}
	labels := strings.Split(stripped, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("dynamic-dns hostname %q has an empty label "+
				"(leading/trailing/doubled dot); it would be dropped before "+
				"publishing — fix the name", raw)
		}
		if len(lbl) > maxDNSLabelLen {
			return fmt.Errorf("dynamic-dns hostname label %q exceeds %d octets and "+
				"would be truncated before publishing", lbl, maxDNSLabelLen)
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return fmt.Errorf("dynamic-dns hostname label %q begins or ends with '-'; "+
				"the dash would be trimmed before publishing — fix the name", lbl)
		}
		for _, r := range lbl {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9', r == '-':
				// LDH (letter-digit-hyphen); upper-case is lower-cased
				// at publish but that is benign (DNS is case-insensitive).
			default:
				return fmt.Errorf("dynamic-dns hostname %q contains the non-LDH "+
					"character %q; it would be silently stripped before publishing "+
					"(publishing a different name than configured) — use only "+
					"letters, digits, and hyphens", raw, r)
			}
		}
	}
	return nil
}

// maxDNSLabelLen / maxDNSNameLen mirror pkg/ddns hostname.go (maxDNSLabel /
// maxDNSName) so the commit-time hostname check rejects exactly the names the
// publish path would truncate. Kept as local constants to avoid a
// config->ddns import dependency.
const (
	maxDNSLabelLen = 63
	maxDNSNameLen  = 253
)

// ValidateSyslogSourceInterface accepts a `security log source-interface`
// value: an interface name with an optional `.<unit>` suffix where the unit,
// when present, MUST be a non-negative integer (#3349). The source resolver
// (pkg/daemon/daemon_system.go resolveSourceAddr) splits on the FIRST '.' and
// strconv.Atoi's the remainder; a non-numeric unit is an ignored error that
// silently falls back to unit 0 — binding the syslog source to the WRONG
// logical unit's address. Rejecting it at commit makes the typo
// operator-visible instead of misrouting the audit source IP. The split rule
// (first '.') mirrors resolveSourceAddr's strings.Cut exactly.
func ValidateSyslogSourceInterface(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an interface name, e.g. ge-0-0-0 or reth1.100)")
	}
	base, unit, hasUnit := strings.Cut(trimmed, ".")
	if base == "" {
		return fmt.Errorf("invalid interface name %q (empty name before '.')", raw)
	}
	if hasUnit {
		n, err := strconv.Atoi(unit)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid logical unit %q in %q (expected a non-negative "+
				"integer; a non-numeric unit silently binds the syslog source to unit 0)", unit, raw)
		}
	}
	return nil
}

// ValidateTimeOfDay accepts a scheduler time-of-day in HH:MM:SS 24-hour
// form (the exact layout the runtime evaluator parses,
// pkg/scheduler.parseTimeOfDay). Rejecting a malformed time at commit is the
// fail-closed half of #3849: an unparseable start-time/stop-time must never
// reach the compiler and silently zero the window (which the old evaluator
// then treated as always-active).
func ValidateTimeOfDay(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a time of day, e.g. 09:00:00)")
	}
	if _, err := time.Parse("15:04:05", trimmed); err != nil {
		return fmt.Errorf("invalid time of day %q (expected 24-hour HH:MM:SS, e.g. 09:00:00 or 17:30:00)", raw)
	}
	return nil
}

// ValidateDate accepts a scheduler calendar date in YYYY-MM-DD form (the
// layout the runtime evaluator parses in withinDateRange).
func ValidateDate(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a date, e.g. 2026-03-01)")
	}
	if _, err := time.Parse("2006-01-02", trimmed); err != nil {
		return fmt.Errorf("invalid date %q (expected YYYY-MM-DD, e.g. 2026-03-01)", raw)
	}
	return nil
}
