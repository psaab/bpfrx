package main

import "testing"

// #6848: remote-CLI topic encoding for `show class-of-service
// classifier|rewrite-rule`.
//
// PARITY REQUIREMENT: the case table mirrors TestParseCoSNameTypeArgs6848 in
// pkg/cli, which covers the LOCAL interactive path. Both surfaces must accept
// the same grammar — including the bare positional name that cmdtree completion
// offers — or the same keystrokes give different answers depending on which
// binary the operator ran.
func TestCoSNameTypeTopic6848(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"empty", nil, "cos-rewrite-rule"},
		{"bare name", []string{"rw-dscp"}, "cos-rewrite-rule:name=rw-dscp"},
		{"keyword name", []string{"name", "rw-dscp"}, "cos-rewrite-rule:name=rw-dscp"},
		{"keyword type", []string{"type", "dscp"}, "cos-rewrite-rule:type=dscp"},
		{"both keywords", []string{"name", "rw-pcp", "type", "ieee-802.1"},
			"cos-rewrite-rule:name=rw-pcp,type=ieee-802.1"},
		{"bare name then type", []string{"rw-pcp", "type", "ieee-802.1"},
			"cos-rewrite-rule:name=rw-pcp,type=ieee-802.1"},
		{"dangling name", []string{"name"}, "cos-rewrite-rule"},
		{"dangling type", []string{"type"}, "cos-rewrite-rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cosNameTypeTopic("cos-rewrite-rule", tc.args); got != tc.want {
				t.Errorf("cosNameTypeTopic(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}

	// The builder is shared with the classifier command; the prefix is the only
	// difference.
	if got := cosNameTypeTopic("cos-classifier", []string{"type", "dscp"}); got != "cos-classifier:type=dscp" {
		t.Errorf("classifier prefix not honored: %q", got)
	}
}
