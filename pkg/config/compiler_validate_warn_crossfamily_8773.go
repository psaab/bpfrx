package config

import (
	"fmt"
	"sort"
)

// #8773: a firewall filter term matching the DSCP / Traffic-Class field with the
// OTHER address family's spelling.
//
// Junos spells this field `dscp` in a `family inet` filter and `traffic-class`
// in `family inet6`. They name the same six bits in different headers, so xpf
// compiles either into term.DSCPs rather than refusing a configuration an
// operator can commit today. That acceptance is deliberate; being SILENT about
// it was not.
//
// WHY THIS EXISTS AS A WARNING RATHER THAN AS A REJECTION, stated because the
// alternative was seriously considered: refusing the cross-family spelling
// would be closer to Junos, and it would also fail commits that succeed on
// every shipped build, for a configuration that compiles to exactly the matcher
// the operator intended. The project's settled answer for that trade is the one
// `interface-specific` and the lo0-mirror modifiers already take — accept, and
// say so at commit (compiler_validate_warn.go). Never silently accept config
// that does not mean what it appears to mean.
//
// WHY IT IS NOT ENOUGH TO JUST MAKE THE SPELLINGS AGREE. Before #8773 the
// BRACED spelling (`from { traffic-class 0; }` in family inet) was accepted and
// applied, while the PACKED spelling (`from traffic-class 0;`) was dropped
// without a word — the packed reader resolves its tail through the schema, and
// the schema declared the criterion under one family only. Adding the schema
// alias makes the two spellings agree, and agreeing on ACCEPT without this
// warning would have traded a silent drop for a silent acceptance. Both halves
// are the fix; the alias alone is not.
func validateFilterCrossFamilyDSCPWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	report := func(family string, filters map[string]*FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		// Deterministic order: a warning list that reorders between runs makes
		// every diff of a commit transcript unreadable.
		sort.Strings(names)
		for _, name := range names {
			f := filters[name]
			if f == nil {
				continue
			}
			for _, term := range f.Terms {
				if term == nil || len(term.CrossFamilyMatchSpellings) == 0 {
					continue
				}
				seen := map[string]bool{}
				for _, spelling := range term.CrossFamilyMatchSpellings {
					if seen[spelling] {
						continue
					}
					seen[spelling] = true
					// Each spelling names its OWN counterpart. Deriving `want`
					// from the family alone was correct while this list held
					// only dscp/traffic-class, and became wrong the moment
					// protocol/next-header joined it (#8781): a field-specific
					// answer computed from a field-independent input.
					want, ok := crossFamilyCounterpart[spelling]
					if !ok {
						continue
					}
					out = append(out, fmt.Sprintf(
						"firewall family %s filter %q term %q matches `%s`, which is the "+
							"%s spelling of this field; Junos spells it `%s` here. The "+
							"match IS applied (both name the same thing), but the "+
							"configuration will not load on Junos as written (#8773/#8781)",
						family, name, term.Name, spelling, otherFamilyLabel(family), want))
				}
			}
		}
	}
	report("inet", cfg.Firewall.FiltersInet)
	report("inet6", cfg.Firewall.FiltersInet6)
	return out
}

// crossFamilyCounterpart maps a spelling to the one Junos uses in the OTHER
// address family. Both directions are listed explicitly rather than derived,
// so adding a third aliased field is a visible edit here rather than a silent
// gap in a warning nobody reads.
var crossFamilyCounterpart = map[string]string{
	"traffic-class": "dscp",
	"dscp":          "traffic-class",
	"next-header":   "protocol",
	"protocol":      "next-header",
}

func otherFamilyLabel(family string) string {
	if family == "inet6" {
		return "IPv4"
	}
	return "IPv6"
}
