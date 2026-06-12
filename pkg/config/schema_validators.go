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
