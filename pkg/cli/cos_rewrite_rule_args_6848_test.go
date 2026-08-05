package cli

import "testing"

// #6848: `show class-of-service classifier|rewrite-rule` argument grammar.
//
// PARITY REQUIREMENT: this table is mirrored by TestCoSNameTypeTopic6848 in
// cmd/cli (the remote binary builds a gRPC topic from the same tokens). The two
// live in different packages so one test cannot call both; keep the cases in
// step. If they diverge, the same keystrokes produce different output depending
// on whether the operator ran the interactive CLI or the `cli` binary — which
// is the failure this command was added to avoid, one level up.
func TestParseCoSNameTypeArgs6848(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantName string
		wantType string
	}{
		{"empty", nil, "", ""},
		// The bare positional form. cmdtree offers rule names directly under
		// the command, so this is what an operator submits after tab-completing
		// a name; before #6848 it was silently ignored and every rule was
		// dumped.
		{"bare name", []string{"rw-dscp"}, "rw-dscp", ""},
		{"keyword name", []string{"name", "rw-dscp"}, "rw-dscp", ""},
		{"keyword type", []string{"type", "dscp"}, "", "dscp"},
		{"both keywords", []string{"name", "rw-pcp", "type", "ieee-802.1"}, "rw-pcp", "ieee-802.1"},
		{"bare name then type", []string{"rw-pcp", "type", "ieee-802.1"}, "rw-pcp", "ieee-802.1"},
		// A dangling keyword must not consume the following token as a value
		// or panic on the missing one.
		{"dangling name", []string{"name"}, "", ""},
		{"dangling type", []string{"type"}, "", ""},
		// A later explicit `name` wins over the bare positional: the operator
		// typed the keyword form deliberately.
		{"keyword overrides bare", []string{"rw-dscp", "name", "rw-pcp"}, "rw-pcp", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotType := parseCoSNameTypeArgs(tc.args)
			if gotName != tc.wantName || gotType != tc.wantType {
				t.Errorf("parseCoSNameTypeArgs(%q) = (%q, %q), want (%q, %q)",
					tc.args, gotName, gotType, tc.wantName, tc.wantType)
			}
		})
	}
}
