package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3298 — when two overlapping policy applications (same protocol + same exact
// destination port) carry different inactivity-timeouts, the Rust matcher is
// first-writer-wins on the exact port (policy.rs `exact_dst_ports.or_insert`,
// #3227). The effective idle timeout must therefore be decided by CONFIG order
// (the order the operator listed the apps / configured the application-set
// members), NOT by alphabetical application name. Before #3298 the Go side
// lexically sorted the expanded terms by Name, so the timeout that won was the
// alphabetically-first app — contradicting #3227's first-writer-wins-by-config-
// order contract. These tests pick names whose alphabetical order is the REVERSE
// of their config order, so a revert to name-sort flips terms[0] and the
// assertion goes RED.

// TestAppInactivityTimeoutPrecedenceFollowsPolicyListOrder pins the policy
// `match application [ ... ]` list ordering (the outer loop in
// expandUserspacePolicyApplications). The final sort.Slice-by-Name removal is
// what this guards.
func TestAppInactivityTimeoutPrecedenceFollowsPolicyListOrder(t *testing.T) {
	cfg := appTimeoutCfg(map[string]*config.Application{
		// Same protocol + exact dst port = overlapping; only the timeout and the
		// name differ. "z-web" sorts AFTER "a-web" alphabetically but is listed
		// FIRST in the policy below.
		"z-web": {Name: "z-web", Protocol: "tcp", DestinationPort: "80", InactivityTimeout: 30},
		"a-web": {Name: "a-web", Protocol: "tcp", DestinationPort: "80", InactivityTimeout: 600},
	})
	// Config order: z-web first, a-web second.
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"z-web", "a-web"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications ok=false, want true")
	}
	if len(terms) != 2 {
		t.Fatalf("len(terms) = %d, want 2", len(terms))
	}
	// First writer (config-order-first) must be z-web with timeout 30. A revert
	// to lexical name-sort would put a-web (timeout 600) first → RED.
	if terms[0].Name != "z-web" || terms[0].InactivityTimeout != 30 {
		t.Fatalf("terms[0] = {Name:%q InactivityTimeout:%d}, want {z-web 30} "+
			"(config order must beat alphabetical name)", terms[0].Name, terms[0].InactivityTimeout)
	}
	if terms[1].Name != "a-web" || terms[1].InactivityTimeout != 600 {
		t.Fatalf("terms[1] = {Name:%q InactivityTimeout:%d}, want {a-web 600}",
			terms[1].Name, terms[1].InactivityTimeout)
	}
}

// TestAppInactivityTimeoutPrecedenceFollowsAppSetMemberOrder pins the
// application-set member ordering (resolveUserspaceApplicationNames no longer
// sorts ExpandApplicationSet's config-order output).
func TestAppInactivityTimeoutPrecedenceFollowsAppSetMemberOrder(t *testing.T) {
	cfg := appTimeoutCfg(map[string]*config.Application{
		"z-web": {Name: "z-web", Protocol: "tcp", DestinationPort: "80", InactivityTimeout: 30},
		"a-web": {Name: "a-web", Protocol: "tcp", DestinationPort: "80", InactivityTimeout: 600},
	})
	// Application-set lists z-web BEFORE a-web — config order is the reverse of
	// alphabetical.
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-set": {Name: "web-set", Applications: []string{"z-web", "a-web"}},
	}
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"web-set"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(web-set) ok=false, want true")
	}
	if len(terms) != 2 {
		t.Fatalf("len(terms) = %d, want 2", len(terms))
	}
	// First writer must be the configured-first member z-web (timeout 30). A
	// revert to sorting the set members would emit a-web (600) first → RED.
	if terms[0].Name != "z-web" || terms[0].InactivityTimeout != 30 {
		t.Fatalf("terms[0] = {Name:%q InactivityTimeout:%d}, want {z-web 30} "+
			"(application-set member config order must beat alphabetical name)",
			terms[0].Name, terms[0].InactivityTimeout)
	}
}
