package config

import (
	"fmt"
	"sort"
)

// compiler_validate_strict_aspath_ref_7471.go — #7471.
//
// A policy term may name an as-path that was never defined:
//
//	set policy-options policy-statement P1 term t1 from as-path NOPE
//	set policy-options policy-statement P1 term t1 then reject
//
// That committed clean -- CompileConfig nil, no warning, SchemaValidate nil.
//
// WHY IT IS A FAIL-OPEN, AND WHY THE MESSAGE DIFFERS FROM THE COMMUNITY GATE.
// xpf renders `match as-path NOPE` but renders no `bgp as-path access-list
// NOPE`, because there is no definition to render one from. FRR ACCEPTS that:
// `route_match_aspath_compile` merely stores the string, and evaluation-time
// `as_list_lookup` returns NULL for an undefined list, yielding RMAP_NOMATCH.
//
// So the term never matches, and nothing anywhere complains -- commit, `show
// configuration` and frr-reload all succeed. On a `then reject` term that is
// FAIL-OPEN: the routes the operator meant to block fall through to the next
// term or the policy default and are accepted. On `then accept` it is a silent
// blackhole of routes that were meant to be admitted.
//
// This is the OPPOSITE of the community case, whose message must not be copied.
// A dangling `match community` makes frr-reload FAIL, which fails the entire
// FRR config load -- loud, and self-limiting. A dangling `match as-path` is
// accepted and silently never matches. Telling an operator their as-path
// reference "would fail frr-reload" would be false and would send them looking
// for a load error that never happens.
//
// `from as-path` is `multi: true`, so a term can carry several. Every entry of
// every term of every policy-statement is walked.
func validatePolicyASPathReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.ASPaths == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.ASPaths[name]
		return ok
	}

	// Sorted for a deterministic first-error message; the typed-config map
	// iteration order is otherwise random, and a gate whose message changes
	// between runs on the same config is one nobody can write a test against.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, psName := range names {
		ps := cfg.PolicyOptions.PolicyStatements[psName]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, a := range term.FromASPath {
				if a == "" || defined(a) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `from as-path %s` "+
					"references undefined as-path %q — xpf renders no "+
					"`bgp as-path access-list %s`, and FRR ACCEPTS a `match as-path` "+
					"naming a list that does not exist: it resolves to NULL at "+
					"evaluation and the term NEVER MATCHES. On a `then reject` term "+
					"that is fail-open (the routes you meant to block are accepted by "+
					"the next term or the policy default); on `then accept` it "+
					"silently blackholes the routes you meant to admit. Nothing "+
					"reports it — commit, `show configuration` and frr-reload all "+
					"succeed. Define `policy-options as-path %s <regex>` or fix the name",
					psName, term.Name, a, a, a, a)
			}
		}
	}
	return nil
}
