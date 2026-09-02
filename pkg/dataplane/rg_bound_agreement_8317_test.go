package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8317: the commit-time RG-id bound and the length of the arrays that id
// indexes must be the SAME number.
//
// They are, by construction — MaxRedundancyGroups here is an alias of
// config.MaxRedundancyGroups — so this cell cannot fail while that holds. It is
// here to fail the moment someone replaces the alias with a literal, which is
// the exact regression that produced #8317: the value 16 existed only as the
// arrays' max_entries and nothing connected it to the id an operator types, so
// ids 16..255 committed against valid indices 0..15.
//
// This is the cross-package half of the agreement. pkg/config cannot import
// pkg/dataplane (cycle), so the assertion has to live on this side.
func TestRGBoundAgreesWithDataplaneArrays8317(t *testing.T) {
	if MaxRedundancyGroups != config.MaxRedundancyGroups {
		t.Fatalf("dataplane.MaxRedundancyGroups (%d) != config.MaxRedundancyGroups (%d). "+
			"These size the rg_active/ha_watchdog arrays and bound the committable RG id "+
			"respectively; a divergence means an id can be committed that the dataplane "+
			"cannot index (or a usable slot is refused). Restore the alias rather than "+
			"syncing two literals — the duplicate is what caused #8317.",
			MaxRedundancyGroups, config.MaxRedundancyGroups)
	}
}
