package config

import (
	"fmt"
	"regexp"
	"strings"
)

// event-options policy `attributes-match` parsing and commit-time
// validation (#2008 M7).
//
// A match line has the Junos form "<event>.<attribute> matches <pattern>"
// where <pattern> is an RE2 regular expression (NOT a literal — that was the
// parity defect this closes). The parsing here is the single source of truth
// shared by the commit-time validator (ValidateEventAttributesMatch) and the
// runtime matcher (pkg/eventengine), so the two cannot drift on what counts
// as a well-formed match line or where the pattern starts.

const eventAttributesMatchSep = " matches "

// ParseEventAttributesMatch splits a raw attributes-match line of the form
// "<event>.<field> matches <pattern>" into its field name and regex pattern.
// It returns ok=false when the line is not a well-formed match expression
// (no " matches " separator, or no "." in the field spec). The returned
// field is the last dot-separated component of the left-hand side (the
// attribute name), mirroring the event_name.attribute Junos spelling.
func ParseEventAttributesMatch(attr string) (field, pattern string, ok bool) {
	parts := strings.SplitN(attr, eventAttributesMatchSep, 2)
	if len(parts) != 2 {
		return "", "", false
	}
	fieldSpec := strings.TrimSpace(parts[0])
	pattern = strings.TrimSpace(parts[1])

	dotIdx := strings.LastIndex(fieldSpec, ".")
	if dotIdx < 0 {
		return "", "", false
	}
	field = fieldSpec[dotIdx+1:]
	if field == "" || pattern == "" {
		return "", "", false
	}
	return field, pattern, true
}

// EventAttributesMatchPattern returns the regex pattern of a well-formed
// attributes-match line. It is a convenience wrapper over
// ParseEventAttributesMatch for callers that only need the pattern (e.g.
// building the engine's compiled-regex cache).
func EventAttributesMatchPattern(attr string) (pattern string, ok bool) {
	_, pattern, ok = ParseEventAttributesMatch(attr)
	return pattern, ok
}

// ValidateEventAttributesMatch checks that every event-options policy
// attributes-match line carries a compilable RE2 regex pattern. It returns
// the first error encountered so commit fails fast with a precise message.
// Malformed lines (missing " matches " or ".") are not validated here — they
// are silently ignored at runtime exactly as before, and rejecting them would
// be a separate, broader grammar change.
func ValidateEventAttributesMatch(cfg *Config) error {
	for _, pol := range cfg.EventOptions {
		if pol == nil {
			continue
		}
		for _, attr := range pol.AttributesMatch {
			pattern, ok := EventAttributesMatchPattern(attr)
			if !ok {
				continue
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf(
					"event-options policy %q attributes-match %q: invalid regex pattern %q: %w",
					pol.Name, attr, pattern, err)
			}
		}
	}
	return nil
}
