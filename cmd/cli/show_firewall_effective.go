package main

// Remote-CLI argument helpers for `show firewall [filter <name>] effective
// [family <f>]` (#4967). They mirror the local CLI's loose-modifier scan
// (pkg/cli firewallArgsHaveWord / firewallFamilyArg): `effective` and
// `family <f>` may appear anywhere after `firewall`, and an optional
// `filter <name>` selects a single filter.

// firewallArgsContain reports whether word appears anywhere in args. Used to
// detect the trailing `effective` modifier regardless of its position.
func firewallArgsContain(args []string, word string) bool {
	for _, a := range args {
		if a == word {
			return true
		}
	}
	return false
}

// firewallFamilyValue returns the token following `family`, or "" when absent.
func firewallFamilyValue(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "family" {
			return args[i+1]
		}
	}
	return ""
}

// firewallFilterName returns the token following `filter`, or "" when absent.
// It is the single-filter selector for `show firewall filter <name> effective`.
func firewallFilterName(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "filter" {
			return args[i+1]
		}
	}
	return ""
}
