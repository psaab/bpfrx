package config

import (
	"fmt"
	"math"
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
