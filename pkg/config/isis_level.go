package config

import (
	"fmt"
	"sort"
	"strings"
)

// ISIS level (`is-type`) canonicalization — #8446.
//
// `protocols isis level` and `protocols isis is-type` spell the SAME concept
// and both compile into ISISConfig.Level. Two independent defects met there:
//
//   - the leaves were untyped in setSchema, so ANY string committed; and
//   - the FRR renderer switched on the stored string with no `default` arm,
//     so an unrecognized value emitted NO `is-type` line at all and FRR fell
//     back to its own default, `level-1-2`.
//
// The composition silently WIDENED the router's adjacency scope. The sharpest
// case was self-inflicted: `is-type level-2-only` is the exact string xpf
// itself writes into frr.conf, and feeding it back in turned a Level-2-only
// router into a Level-1-2 one. Leaving the leaf unset produced level-2-only,
// so configuring it explicitly was LESS restrictive than not configuring it.
//
// This file is the one canonicalizer both sides share, so the commit gate and
// the renderer cannot drift (the pattern #6686 established for as-path
// regexes: same predicate, one definition).

// isisLevelSpellings maps every accepted operator spelling to its canonical
// form. `level-2-only` is FRR's spelling and the one this product emits, so it
// is accepted as a synonym rather than rejected — rejecting the output of our
// own renderer would be a surprising failure mode.
var isisLevelSpellings = map[string]string{
	"level-1":      "level-1",
	"level-2":      "level-2",
	"level-1-2":    "level-1-2",
	"level-2-only": "level-2",
}

// DefaultISISLevel is the level a `protocols isis` stanza with no `level` /
// `is-type` runs at. It is level-2 (rendered `is-type level-2-only`), matching
// the renderer's long-standing behaviour for an empty value.
const DefaultISISLevel = "level-2"

// CanonicalISISLevel maps an authored `level` / `is-type` value to its
// canonical spelling. An empty value canonicalizes to DefaultISISLevel so the
// unset case and the explicitly-default case travel the same path. ok is false
// for a value no accepted spelling matches.
func CanonicalISISLevel(raw string) (canonical string, ok bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return DefaultISISLevel, true
	}
	c, ok := isisLevelSpellings[v]
	return c, ok
}

// ISISLevelSpellings returns the accepted spellings in sorted order, for
// operator-facing error text, schema value examples, and completion.
func ISISLevelSpellings() []string {
	out := make([]string, 0, len(isisLevelSpellings))
	for k := range isisLevelSpellings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateISISLevel is the setSchema typed-leaf validator for `level` and
// `is-type`. It is shared by both schema copies (the top-level `protocols` one
// and the `routing-instances` one) so a spelling cannot be accepted in one
// context and rejected in the other.
func ValidateISISLevel(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected one of %s)",
			strings.Join(ISISLevelSpellings(), ", "))
	}
	if _, ok := CanonicalISISLevel(raw); !ok {
		return fmt.Errorf("not a valid IS-IS level: %q (expected one of %s)",
			raw, strings.Join(ISISLevelSpellings(), ", "))
	}
	return nil
}
