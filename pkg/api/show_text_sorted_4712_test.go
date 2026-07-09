package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #4712: the /show-text handlers render config maps (schedulers, snmp,
// dhcp-relay, filters, feeds, address-book, applications, v9 templates) as
// operator/automation-facing text. Go randomizes map iteration order, so before
// the fix the same active config produced different orderings across requests,
// breaking config diffing/automation and making downstream tests flaky. The fix
// routes every map through the shared sortedKeys helper. These tests stage
// multi-key config maps, render each topic many times, and assert:
//   1. the rendered text is byte-identical across renders (determinism), and
//   2. entries appear in ascending key order (the sorted contract).
// Reverting show_text.go to a raw `for k := range m` makes assertion (1)
// essentially always RED (P(all N renders identical) ~ (1/k!)^(N-1)) and
// assertion (2) RED with probability ~1-1/k! on the very first render.

// renderShowTextBody drives the live showTextHandler for one topic and returns
// the decoded TextResponse Output payload.
func renderShowTextBody(t *testing.T, s *Server, topic string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/show-text?topic="+topic, nil)
	s.showTextHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("show-text topic=%s status = %d, want 200; body: %s", topic, rr.Code, rr.Body.String())
	}
	var env struct {
		Success bool         `json:"success"`
		Data    TextResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("show-text topic=%s: response not valid JSON: %v; body: %s", topic, err, rr.Body.String())
	}
	return env.Data.Output
}

// stageShowTextConfig compiles the given flat set commands into an active
// config and returns a Server bound to that store, via the real LoadSet +
// Commit path (same harness as the secret-redaction regression test).
func stageShowTextConfig(t *testing.T, setCommands []string) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join(setCommands, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// assertSortedEntries checks that each name in wantSorted appears in output and
// that their first-occurrence positions are strictly increasing — i.e. the
// section renders keys in ascending order. wantSorted MUST already be sorted;
// the caller passes distinct names that are not substrings of one another.
func assertSortedEntries(t *testing.T, topic, section, output string, wantSorted []string) {
	t.Helper()
	prev := -1
	for _, name := range wantSorted {
		idx := strings.Index(output, name)
		if idx < 0 {
			t.Fatalf("topic=%s %s: name %q missing from output:\n%s", topic, section, name, output)
		}
		if idx <= prev {
			t.Errorf("topic=%s %s: name %q at index %d is not after the previous entry (index %d) — map not iterated in sorted order:\n%s",
				topic, section, name, idx, prev, output)
		}
		prev = idx
	}
}

// assertDeterministic renders a topic renders-many times and requires every
// render to be byte-identical. Under a raw map-range this is flaky-RED because
// Go randomizes iteration order per range statement.
func assertDeterministic(t *testing.T, s *Server, topic string, renders int) string {
	t.Helper()
	first := renderShowTextBody(t, s, topic)
	for i := 1; i < renders; i++ {
		if got := renderShowTextBody(t, s, topic); got != first {
			t.Fatalf("topic=%s: render %d differs from render 0 — output is non-deterministic across requests\n--- render 0 ---\n%s\n--- render %d ---\n%s",
				topic, i, first, i, got)
		}
	}
	return first
}

func TestShowTextDeterministicSortedOrder(t *testing.T) {
	// Keys are intentionally staged in scrambled (non-sorted) order and chosen
	// so no name is a substring of another (or of a rendered value/proto/port).
	setCommands := []string{
		// applications: Applications map + ApplicationSets map.
		"set applications application zebra protocol tcp destination-port 22",
		"set applications application alpha protocol tcp destination-port 80",
		"set applications application mango protocol udp destination-port 53",
		"set applications application beta protocol tcp destination-port 443",
		"set applications application yak protocol tcp destination-port 8080",
		"set applications application delta protocol udp destination-port 123",
		"set applications application-set zulu application alpha",
		"set applications application-set apex application beta",
		"set applications application-set mid application delta",
		// address-book: Addresses map + AddressSets map.
		"set security address-book global address host_zeta 10.0.0.4/32",
		"set security address-book global address host_alpha 10.0.0.1/32",
		"set security address-book global address host_gamma 10.0.0.3/32",
		"set security address-book global address host_beta 10.0.0.2/32",
		"set security address-book global address-set set_yankee address host_alpha",
		"set security address-book global address-set set_bravo address host_beta",
		"set security address-book global address-set set_mike address host_gamma",
		// snmp: Communities map.
		"set snmp community comm_delta authorization read-only",
		"set snmp community comm_alpha authorization read-write",
		"set snmp community comm_charlie authorization read-only",
		"set snmp community comm_bravo authorization read-write",
	}
	s := stageShowTextConfig(t, setCommands)

	const renders = 40

	t.Run("applications", func(t *testing.T) {
		out := assertDeterministic(t, s, "applications", renders)
		apps := []string{"alpha", "beta", "delta", "mango", "yak", "zebra"}
		if !sort.StringsAreSorted(apps) {
			t.Fatalf("test bug: apps expectation not sorted: %v", apps)
		}
		assertSortedEntries(t, "applications", "Applications", out, apps)
		// ApplicationSets section renders after the members reference app names,
		// so anchor on the set names, which occur only in the sets section.
		sets := []string{"apex", "mid", "zulu"}
		assertSortedEntries(t, "applications", "Application sets", out, sets)
	})

	t.Run("address-book", func(t *testing.T) {
		out := assertDeterministic(t, s, "address-book", renders)
		addrs := []string{"host_alpha", "host_beta", "host_gamma", "host_zeta"}
		assertSortedEntries(t, "address-book", "Addresses", out, addrs)
		sets := []string{"set_bravo", "set_mike", "set_yankee"}
		assertSortedEntries(t, "address-book", "Address sets", out, sets)
	})

	t.Run("snmp", func(t *testing.T) {
		out := assertDeterministic(t, s, "snmp", renders)
		comms := []string{"comm_alpha", "comm_bravo", "comm_charlie", "comm_delta"}
		assertSortedEntries(t, "snmp", "Communities", out, comms)
	})
}
