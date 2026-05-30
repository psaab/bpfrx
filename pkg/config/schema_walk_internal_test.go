package config

import (
	"strings"
	"testing"
)

// White-box tests for the generic walker's special-case rows that PR 1's
// typed schedulers leaves don't themselves exercise. These pin the walker
// contract (the schema-feature→AST-match table in the #1319 plan §6.4) so
// PR 2..N can type `multi` value-tail leaves and rely on the behaviour.

// rangeWalkTree builds an AST + a synthetic typed `multi && children==nil`
// leaf, then runs the leaf validator path directly. We construct the leaf
// schema in-test rather than typing a production leaf (PR 1 ships no typed
// multi leaf), so the contract is verified without expanding scope.
func runMultiValueTail(t *testing.T, leafKeys []string) error {
	t.Helper()
	// Typed multi leaf accepting bare integers in [0..65535] (port-like),
	// no schema children → value-tail/range shape.
	leafSchema := &schemaNode{
		args:      1,
		multi:     true,
		valueType: ValueInteger,
		validator: ValidateInteger(0, 65535),
	}
	parent := &schemaNode{children: map[string]*schemaNode{
		"destination-port": leafSchema,
	}}
	node := &Node{Keys: leafKeys, IsLeaf: true}
	return walkSchemaNode(node, parent, nil, nil, []*Node{node})
}

func TestWalker_MultiValueTail_AcceptsRange(t *testing.T) {
	// `destination-port 20000 to 20003`: both endpoints validated, `to`
	// treated as a separator.
	if err := runMultiValueTail(t, []string{"destination-port", "20000", "to", "20003"}); err != nil {
		t.Fatalf("expected valid port range, got %v", err)
	}
}

func TestWalker_MultiValueTail_AcceptsSingle(t *testing.T) {
	if err := runMultiValueTail(t, []string{"destination-port", "20000"}); err != nil {
		t.Fatalf("expected valid single port, got %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsBadEndpoint(t *testing.T) {
	// 99999 is out of [0..65535]; the range branch validates every value
	// token, so the high endpoint must be rejected (not silently passed as
	// an "unknown modifier" or ignored).
	err := runMultiValueTail(t, []string{"destination-port", "20000", "to", "99999"})
	if err == nil {
		t.Fatal("expected error for out-of-range high endpoint")
	}
	if !strings.Contains(err.Error(), "99999") {
		t.Fatalf("error should quote the bad endpoint: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsBadLowEndpoint(t *testing.T) {
	err := runMultiValueTail(t, []string{"destination-port", "abc", "to", "20003"})
	if err == nil {
		t.Fatal("expected error for non-integer low endpoint")
	}
	if !strings.Contains(err.Error(), "abc") {
		t.Fatalf("error should quote the bad endpoint: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsMissingValue(t *testing.T) {
	err := runMultiValueTail(t, []string{"destination-port"})
	if err == nil {
		t.Fatal("expected error for missing value")
	}
	if !strings.Contains(err.Error(), "missing value") {
		t.Fatalf("error should describe missing value: %v", err)
	}
}

func TestWalker_MultiValueTail_RejectsDanglingSeparator(t *testing.T) {
	for _, keys := range [][]string{
		{"destination-port", "to"},
		{"destination-port", "to", "20000"},
		{"destination-port", "20000", "to"},
		{"destination-port", "20000", "to", "to", "20003"},
	} {
		err := runMultiValueTail(t, keys)
		if err == nil {
			t.Fatalf("expected error for malformed range %v", keys)
		}
		if !strings.Contains(err.Error(), "missing value") {
			t.Fatalf("error should describe missing value for %v: %v", keys, err)
		}
	}
}
