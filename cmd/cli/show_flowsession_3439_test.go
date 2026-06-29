// #3439 H5: the remote `show security flow session` parser must reject
// malformed/unknown filter tokens instead of silently dropping them.
// The historical loop used `if v, err := strconv.Parse...; err == nil`
// with no else (a bad numeric value left the field zero = wildcard,
// silently WIDENING the inspected traffic set) and had no default case
// (an unknown token fell through and was ignored). parseFlowSessionArgs
// now mirrors the strict local parser in pkg/cli/session_filter.go.
//
// FAIL-ON-REVERT: restoring the silent-drop loop makes the want-error
// cases below return nil and the assertions go RED.
package main

import "testing"

func TestParseFlowSessionArgsRejectsMalformed(t *testing.T) {
	wantErr := [][]string{
		{"destination-port", "abc"}, // unparseable numeric → was wildcard
		{"source-port", "abc"},
		{"source-port", "0"}, // out of 1-65535
		{"destination-port", "70000"},
		{"zone", "notanumber"},                 // remote Zone is a numeric id
		{"protocol", "tcpip"},                  // unknown protocol token
		{"limit", "0"},                         // non-positive limit
		{"bogus-token"},                        // unknown filter keyword
		{"destination-port"},                   // missing value
		{"summary", "destination-port", "abc"}, // malformed after a terminal subcmd
	}
	for _, args := range wantErr {
		if _, err := parseFlowSessionArgs(args); err == nil {
			t.Errorf("parseFlowSessionArgs(%v) = nil error; want a rejection", args)
		}
	}

	// Valid filters parse and populate the request.
	p, err := parseFlowSessionArgs([]string{
		"destination-port", "80", "protocol", "tcp", "source-port", "1024",
	})
	if err != nil {
		t.Fatalf("valid filter rejected: %v", err)
	}
	if p.req.DestinationPort != 80 || p.req.SourcePort != 1024 {
		t.Errorf("ports = src %d dst %d; want 1024/80", p.req.SourcePort, p.req.DestinationPort)
	}
	if p.req.Protocol != "TCP" {
		t.Errorf("protocol = %q; want TCP", p.req.Protocol)
	}
	if p.action != flowSessionList {
		t.Errorf("action = %v; want flowSessionList", p.action)
	}

	// Terminal subcommands are recognized.
	sum, err := parseFlowSessionArgs([]string{"summary"})
	if err != nil || sum.action != flowSessionSummary {
		t.Errorf("summary: action %v err %v; want flowSessionSummary", sum.action, err)
	}
	sort, err := parseFlowSessionArgs([]string{"sort-by", "bytes"})
	if err != nil || sort.action != flowSessionSortBy || sort.sortKey != "bytes" {
		t.Errorf("sort-by: action %v key %q err %v", sort.action, sort.sortKey, err)
	}
}
