// Wire-encoding fail-on-revert guard for #5864: an authoritative
// NeighborReplace that transitions the publishable set to EMPTY must
// encode as a present-but-empty "neighbors":[] so the helper can
// distinguish a CLEAR from an absent field (no-op). With omitempty the
// empty slice was dropped from the wire, the helper decoded it as absent
// and returned before applying the replacement, and stale dynamic
// neighbors stayed installed → blackhole after kernel neighbor deletion.
package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEmptyNeighborReplaceEncodesPresentEmpty asserts that the exact
// request the send path builds for an authoritative empty replace
// (filterPublishableNeighbors → non-nil empty slice, NeighborReplace:true)
// marshals to JSON that unambiguously signals a CLEAR.
//
// Fail-on-revert: restore `json:"neighbors,omitempty"` on
// ControlRequest.Neighbors and the empty slice is dropped from the wire —
// the `"neighbors":[]` assertion goes RED.
func TestEmptyNeighborReplaceEncodesPresentEmpty(t *testing.T) {
	// Mirror RegenerateNeighborSnapshot: the publishable set collapses to
	// empty when no usable neighbors remain. filterPublishableNeighbors
	// returns a non-nil, zero-length slice for this case.
	publishable := filterPublishableNeighbors(nil)
	if publishable == nil {
		t.Fatalf("filterPublishableNeighbors(nil) must be non-nil so the empty replace has a present slice to encode")
	}
	if len(publishable) != 0 {
		t.Fatalf("filterPublishableNeighbors(nil) = %d entries, want 0", len(publishable))
	}

	req := ControlRequest{
		Type:            "update_neighbors",
		Neighbors:       publishable,
		NeighborReplace: true,
	}
	raw, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)

	if !strings.Contains(got, `"neighbors":[]`) {
		t.Fatalf("empty replace must encode a present-empty neighbors field %q; got %s", `"neighbors":[]`, got)
	}
	if !strings.Contains(got, `"neighbor_replace":true`) {
		t.Fatalf("replace flag must be transmitted; got %s", got)
	}

	// A decoder must see the field as PRESENT (non-nil, zero-length),
	// distinct from a request that never set neighbors at all.
	var decoded ControlRequest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Neighbors == nil {
		t.Fatalf("clear-replace must decode to a present (non-nil) neighbors slice, not absent")
	}
	if len(decoded.Neighbors) != 0 {
		t.Fatalf("clear-replace neighbors len = %d, want 0", len(decoded.Neighbors))
	}
	if !decoded.NeighborReplace {
		t.Fatalf("clear-replace must decode NeighborReplace=true")
	}
}

// TestNonEmptyNeighborReplaceStillEncodesEntries is a sanity guard that
// the omitempty removal did not disturb the normal non-empty publish.
func TestNonEmptyNeighborReplaceStillEncodesEntries(t *testing.T) {
	publishable := filterPublishableNeighbors([]NeighborSnapshot{
		{Ifindex: 7, IP: "10.0.0.1", MAC: "02:00:00:00:00:01", State: "reachable", Family: "inet"},
	})
	if len(publishable) != 1 {
		t.Fatalf("one publishable neighbor expected, got %d", len(publishable))
	}
	req := ControlRequest{Type: "update_neighbors", Neighbors: publishable, NeighborReplace: true}
	raw, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, `"ip":"10.0.0.1"`) {
		t.Fatalf("non-empty replace must carry the neighbor entry; got %s", got)
	}
	if !strings.Contains(got, `"neighbor_replace":true`) {
		t.Fatalf("replace flag must be transmitted; got %s", got)
	}
}
