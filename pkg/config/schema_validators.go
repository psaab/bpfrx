package config

import (
	"fmt"
	"math"
	"regexp"
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

// MasterPasswordPRFNames is the set of `system master-password
// pseudorandom-function <fn>` selector names the configstore key-derivation
// (configstore.prfHash) understands. prfHash is the SSOT for the
// name->hash.Hash mapping; this list mirrors only the accepted NAMES so a
// commit-time typo is caught before it reaches the encrypt path (#4578). Keep
// the two in sync — a name added to prfHash must be added here. It is exported
// so a configstore test can drift-guard it against prfHash across the package
// boundary (config→configstore would be an import cycle, so the guard lives on
// the configstore side).
//
// configstore.prfHash lower-cases its input before matching, so
// ValidateMasterPasswordPRF matches case-insensitively too: any spelling the
// runtime would accept commits, and only a genuine typo/unknown selector is
// rejected.
var MasterPasswordPRFNames = []string{
	"juniper-prf1",
	"hmac-sha2-256", "sha256",
	"hmac-sha2-384", "sha384",
	"hmac-sha2-512", "sha512",
	"hmac-sha1", "sha1",
}

// ValidateMasterPasswordPRF accepts only a pseudorandom-function selector the
// configstore master-password key-derivation understands
// (configstore.prfHash), matched case-insensitively. Without this gate a
// typo'd selector (e.g. "hmac-sha256" missing the "2-", or "bugus-prf") is
// accepted open-world, then falls through configstore.masterPasswordPRF's
// default and silently DISABLES at-rest config encryption — or fails the
// persisted-tree write with an opaque error. Rejecting it at commit turns a
// silent security downgrade into a clear commit error (#4578). Pairs with the
// closedWorld flag on the master-password subtree (schema_system.go), which
// catches a typo in the KEYWORD (`pseudo-random-fnuction`) rather than the
// value.
func ValidateMasterPasswordPRF(raw string, _ *Config) error {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, name := range MasterPasswordPRFNames {
		if lower == name {
			return nil
		}
	}
	return fmt.Errorf("invalid pseudorandom-function %q (expected one of: %s)", raw, strings.Join(MasterPasswordPRFNames, ", "))
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

// maxLoginUsernameLen caps a `system login user <name>` identity token. The
// classic Linux useradd/UT_NAMESIZE practical limit is 32; keeping the cap
// there also bounds the derived /etc/sudoers.d/xpf-<name> filename and the
// grant line the daemon writes.
const maxLoginUsernameLen = 32

// loginUsernameRE is the safe POSIX/Linux account-name shape a `system login
// user <name>` identity must match: a lowercase letter or underscore, then
// lowercase letters, digits, underscores, or hyphens. It deliberately excludes
// whitespace, newlines, `/`, `:`, quotes, and every sudoers metacharacter so a
// crafted username cannot be formatted into an /etc/sudoers.d grant to inject
// additional directives (#4895 — the lexer decodes `\n` inside a quoted string
// into a literal newline, so a name like "x\nnobody ALL=(ALL) NOPASSWD: ALL"
// would otherwise smuggle a second sudoers line past visudo's syntax check).
var loginUsernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// ValidateLoginUsername is the commit-check validator for a `system login user
// <name>` identity token (wired as the schema keyValidator on the user
// container in schema_system.go). It rejects any name that is empty, over
// maxLoginUsernameLen, or does not match loginUsernameRE — the defense against
// the #4895 sudoers-injection path where the daemon formats the raw config key
// into /etc/sudoers.d/xpf-<name>. It is strict on the operator commit path and
// downgraded to a warning on the tolerant Load / SyncApply path
// (compileTreeLenient), the same #1960 doctrine as the other typed-leaf gates;
// the daemon's writeSudoersGrant/reconcileSudoers apply the SAME check
// defensively so a leniently-loaded or peer-synced bad name still never reaches
// the sudoers writer. The *Config arg is unused (part of the LeafValidator
// contract); daemon callers pass nil.
func ValidateLoginUsername(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("login user name must not be empty")
	}
	if len(raw) > maxLoginUsernameLen {
		return fmt.Errorf("login user name %q too long (max %d characters)", raw, maxLoginUsernameLen)
	}
	if !loginUsernameRE.MatchString(raw) {
		return fmt.Errorf("invalid login user name %q (must match %s: a lowercase letter or underscore "+
			"followed by lowercase letters, digits, underscores, or hyphens; no whitespace, newlines, or "+
			"sudoers metacharacters)", raw, loginUsernameRE.String())
	}
	return nil
}
