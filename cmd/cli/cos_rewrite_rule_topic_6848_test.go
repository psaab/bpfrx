package main

import "testing"

// #6848/#6858: remote-CLI topic encoding for `show class-of-service
// classifier|rewrite-rule`.
//
// The GRAMMAR and the round-trip property are tested once, in pkg/cmdtree
// (TestParseCoSNameTypeArgs6848 / TestCoSNameTypeTopicRoundTrip6858). This file
// asserts the WIRING: that the remote dispatcher's topic builder really routes
// through cmdtree rather than carrying a private copy of the grammar, which is
// what it did before #6858 — and that copy had already drifted from the local
// one.
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
		// #6858: the local surface has always honored a trailing `name`
		// keyword over a leading bare token; the private copy of the grammar
		// that used to live here did not, and emitted BOTH as duplicate params.
		{"keyword overrides bare", []string{"rw-dscp", "name", "rw-pcp"},
			"cos-rewrite-rule:name=rw-pcp"},
		// #6858: a committed name containing the param separator is escaped
		// rather than truncated. Unescaped, the decoder split here and the
		// server rendered the rule named "rw" — a different rule.
		{"comma in name", []string{"rw,x"}, "cos-rewrite-rule:name=rw%2Cx"},
		{"comma in name with type", []string{"name", "rw,x", "type", "dscp"},
			"cos-rewrite-rule:name=rw%2Cx,type=dscp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cosNameTypeTopic("cos-rewrite-rule", tc.args); got != tc.want {
				t.Errorf("cosNameTypeTopic(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}

	// The builder is shared with the classifier command; the prefix is the only
	// difference. #6858 fixed the encoding for BOTH — the classifier command
	// carried the same truncation since #4228, and they share one decoder.
	if got := cosNameTypeTopic("cos-classifier", []string{"type", "dscp"}); got != "cos-classifier:type=dscp" {
		t.Errorf("classifier prefix not honored: %q", got)
	}
	if got := cosNameTypeTopic("cos-classifier", []string{"c,1"}); got != "cos-classifier:name=c%2C1" {
		t.Errorf("classifier comma name not escaped: %q", got)
	}
}
