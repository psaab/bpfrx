package config

import (
	"strings"
	"testing"
)

// #4338: the canonical Junos "match any EXCEPT the management hosts, then
// reject" lockdown idiom —
//
//	from {
//	    source-address { 0.0.0.0/0; }
//	    source-prefix-list { management-hosts except; }
//	}
//	then reject;
//
// — is ACCEPTED by Junos. xpf's #3359 mutual-exclusion gate was STRICTER: it
// rejected the term (with an error that wrongly claimed "Junos rejects this")
// because a positive source-address coexisted with an except source-prefix-list.
// A match-any positive (0.0.0.0/0 / ::/0) is the universe, so `any AND NOT X`
// composes cleanly to the sole-`except` representation. #4338 accepts the
// match-any + except shape at commit; the runtime lowering emits it as
// except=true over X (proven in the userspace package,
// filters_address_matchany_except_4338_test.go).
//
// FAIL-ON-REVERT: restore the un-relaxed srcPositive/dstPositive check in
// validateFilterAddressExceptStrict (count a match-any literal as positive) and
// these accept-path tests go RED — CompileConfig rejects the lockdown idiom.

func TestFilterMatchAnyPlusExceptSourceAccepted_4338(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list management-hosts 10.1.0.0/24",
		"set firewall family inet filter mgmt term lockdown from source-address 0.0.0.0/0",
		"set firewall family inet filter mgmt term lockdown from source-prefix-list management-hosts except",
		"set firewall family inet filter mgmt term lockdown then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("match-any `source-address 0.0.0.0/0` + `source-prefix-list ... except` is the "+
			"Junos lockdown idiom and must COMMIT (#4338), got: %v", err)
	}
}

func TestFilterMatchAnyPlusExceptSourceAcceptedV6_4338(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list mgmt6 2001:db8:1::/48",
		"set firewall family inet6 filter mgmt6f term lockdown from source-address ::/0",
		"set firewall family inet6 filter mgmt6f term lockdown from source-prefix-list mgmt6 except",
		"set firewall family inet6 filter mgmt6f term lockdown then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("match-any `source-address ::/0` + except must COMMIT on inet6 (#4338), got: %v", err)
	}
}

// The destination direction composes identically.
func TestFilterMatchAnyPlusExceptDestAccepted_4338(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list servers 10.9.0.0/24",
		"set firewall family inet filter d term lockdown from destination-address 0.0.0.0/0",
		"set firewall family inet filter d term lockdown from destination-prefix-list servers except",
		"set firewall family inet filter d term lockdown then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("match-any `destination-address 0.0.0.0/0` + except must COMMIT (#4338), got: %v", err)
	}
}

// DISCRIMINATOR: a SPECIFIC positive address (10.0.0.0/8) + an except list is
// NOT the composable idiom — it would need both a positive and a negated set in
// one direction, which xpf cannot represent — so it stays REJECTED. The reject
// message must no longer claim "Junos rejects this" (the #4338 wording fix) and
// must explain the xpf representability limit.
func TestFilterSpecificPlusExceptStillRejected_4338(t *testing.T) {
	tree := buildFilterTree(t,
		"set policy-options prefix-list trusted 10.1.0.0/16",
		"set firewall family inet filter f term t from source-address 10.0.0.0/8",
		"set firewall family inet filter f term t from source-prefix-list trusted except",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a SPECIFIC positive source-address + except source-prefix-list must still be rejected (#4338)")
	}
	if strings.Contains(err.Error(), "Junos rejects this") {
		t.Fatalf("the reject message must not falsely claim Junos rejects this; got: %v", err)
	}
	if !strings.Contains(err.Error(), "no faithful single-term representation") {
		t.Fatalf("the reject message must explain the xpf representability limit; got: %v", err)
	}
}
