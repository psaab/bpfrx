package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #7083: every class-of-service `loss-priority` node's `?` help must agree with
// whether the userspace dataplane actually enforces that family's loss priority.
//
// The claim had drifted TWICE before this guard existed, in the same direction
// both times. #3995 made the dscp / ieee-802.1 classifier loss priorities live
// and did not update the description; #6847 added inet-precedence and COPIED the
// stale sibling text onto the new node. A claim that has gone stale twice by the
// same mechanism will go stale a third time, so it is bound rather than merely
// corrected.
//
// The binding is a BICONDITIONAL over the Rust, not a spot-check of the four
// that were wrong. Asserting only "these say ENFORCED" would be satisfied by a
// blanket edit — and a blanket edit is exactly what this issue warns against,
// because three of the seven nodes are correctly marked inert:
// `rewrite-rules ieee-802.1`, `inet-precedence` and `exp` have no rewrite table
// on the Rust side at all (docs/cos-validation-notes.md records the same).
//
// Keying on the Rust identifier rather than on a hand-kept list is what makes a
// future family self-reporting: add the table, and the node's help must move
// with it or this reds.
func TestCoSLossPriorityHelpMatchesTheDataplane_7083(t *testing.T) {
	rust := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", "userspace-dp", "src", rel))
		if err != nil {
			t.Fatalf("read %s: %v (the #7083 help-truth guard cannot run)", rel, err)
		}
		return string(b)
	}
	build := rust(filepath.Join("afxdp", "forwarding_build", "cos.rs"))
	classify := rust(filepath.Join("afxdp", "tx", "cos_classify.rs"))

	const inertClaim = "not enforced by the userspace dataplane"

	for _, tc := range []struct {
		path  []string // setSchema path to the loss-priority node
		table string   // the Rust identifier whose EXISTENCE means "enforced"
		src   string
	}{
		{[]string{"class-of-service", "classifiers", "dscp", "forwarding-class", "loss-priority"}, "dscp_lp_by_dscp", build},
		{[]string{"class-of-service", "classifiers", "ieee-802.1", "forwarding-class", "loss-priority"}, "ieee8021_lp_by_pcp", build},
		{[]string{"class-of-service", "classifiers", "inet-precedence", "forwarding-class", "loss-priority"}, "inet_precedence_lp_by_prec", build},
		{[]string{"class-of-service", "rewrite-rules", "dscp", "forwarding-class", "loss-priority"}, "dscp_rewrite_by_queue_lp", classify},
		// The three the dataplane genuinely does not rewrite. Their absence from
		// the Rust is the evidence, and it is asserted below rather than assumed:
		// if one of these ever gains a table, this row flips and the help must
		// follow.
		{[]string{"class-of-service", "rewrite-rules", "ieee-802.1", "forwarding-class", "loss-priority"}, "ieee8021_rewrite_by_queue_lp", classify},
		{[]string{"class-of-service", "rewrite-rules", "inet-precedence", "forwarding-class", "loss-priority"}, "inet_precedence_rewrite_by_queue_lp", classify},
		{[]string{"class-of-service", "rewrite-rules", "exp", "forwarding-class", "loss-priority"}, "exp_rewrite_by_queue_lp", classify},
	} {
		name := strings.Join(tc.path, " ")
		t.Run(name, func(t *testing.T) {
			children := setSchema.children
			var desc string
			for i, key := range tc.path {
				n, ok := children[key]
				if !ok {
					t.Fatalf("setSchema has no %q under %q — if the schema was reshaped, "+
						"update this guard rather than deleting it; the claim it binds is "+
						"still on the operator's screen", key, strings.Join(tc.path[:i], " "))
				}
				desc, children = n.desc, n.children
			}

			enforced := strings.Contains(tc.table, "_") && strings.Contains(tc.src, tc.table)
			claimsInert := strings.Contains(desc, inertClaim)

			if enforced && claimsInert {
				t.Errorf("%s: the help says %q, but the dataplane builds %s and uses it. "+
					"An operator reading this declines to configure a knob that works.\n  desc: %s",
					name, inertClaim, tc.table, desc)
			}
			if !enforced && !claimsInert {
				t.Errorf("%s: the help does NOT say %q, but no %s exists on the Rust side, so "+
					"this family's loss priority is accepted and inert. An operator reading "+
					"this configures a knob that does nothing — the worse direction.\n  desc: %s",
					name, inertClaim, tc.table, desc)
			}
		})
	}
}
