package config

import (
	"encoding/json"
	"testing"
)

// TestFormatJSONRepeatedLeafArray_5194 is the #5194 A3-b2-F11 fail-on-revert
// guard. nodesToJSON projected every leaf into a single-value map, so REPEATED
// leaf statements (e.g. multiple `name-server`) overwrote last-wins and all but
// the last value silently vanished from `display json`. Junos renders repeated
// leaves as an ordered array; the fix promotes them to a []interface{}.
//
// Fail-on-revert: restore the direct `result[n.Keys[0]] = value` assignment and
// this goes RED — name-server collapses to a single scalar (the last value).
func TestFormatJSONRepeatedLeafArray_5194(t *testing.T) {
	tree := buildTree4953(t, []string{
		"set system name-server 8.8.8.8",
		"set system name-server 8.8.4.4",
		"set system name-server 1.1.1.1",
	})

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(tree.FormatJSON()), &m); err != nil {
		t.Fatalf("FormatJSON produced invalid JSON: %v", err)
	}
	sys, ok := m["system"].(map[string]interface{})
	if !ok {
		t.Fatalf("system is not a JSON object: %T", m["system"])
	}
	ns, ok := sys["name-server"].([]interface{})
	if !ok {
		t.Fatalf("repeated name-server must render as an array, got %T (%v) — last-wins overwrite dropped values",
			sys["name-server"], sys["name-server"])
	}
	want := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}
	if len(ns) != len(want) {
		t.Fatalf("name-server array = %v, want %v (all repeats preserved in order)", ns, want)
	}
	for i, w := range want {
		if ns[i] != w {
			t.Fatalf("name-server[%d] = %v, want %s (document order must be preserved)", i, ns[i], w)
		}
	}

	// A SINGLE occurrence must stay scalar (no spurious array promotion).
	single := buildTree4953(t, []string{"set system host-name onlyone"})
	var m2 map[string]interface{}
	if err := json.Unmarshal([]byte(single.FormatJSON()), &m2); err != nil {
		t.Fatalf("FormatJSON produced invalid JSON: %v", err)
	}
	sys2, ok := m2["system"].(map[string]interface{})
	if !ok {
		t.Fatalf("system is not a JSON object: %T", m2["system"])
	}
	if _, isArr := sys2["host-name"].([]interface{}); isArr {
		t.Fatalf("a single leaf must stay scalar, got array: %v", sys2["host-name"])
	}
	if sys2["host-name"] != "onlyone" {
		t.Fatalf("host-name = %v, want scalar %q", sys2["host-name"], "onlyone")
	}
}
