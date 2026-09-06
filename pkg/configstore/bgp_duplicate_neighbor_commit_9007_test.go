package configstore

import (
	"strings"
	"testing"
)

// #9007 end-to-end at the REAL commit gate. The unit gate lives in pkg/config
// (validateBGPDuplicateNeighborStrict), but binding the WIRING matters
// separately from binding the function: CheckText is what `commit check` and
// `commit` actually run, and a gate that is correct but unreached is inert.
// The issue was reported against this channel, so it is the one guarded here.
func TestDuplicateBGPNeighborRejectedAtCommit9007(t *testing.T) {
	const dup = `protocols {
    bgp {
        local-as 65001;
        group ga { peer-as 65002; neighbor 192.0.2.1 { authentication-key "secretA"; } }
        group gb { peer-as 65003; neighbor 192.0.2.1 { authentication-key "secretB"; } }
    }
}
`
	cfg, err := CheckText(dup, 0)
	if err == nil {
		t.Fatalf("commit gate ACCEPTED a duplicate BGP neighbor (%d warning(s)) -- "+
			"this is the #9007 defect", len(cfg.Warnings))
	}
	for _, want := range []string{"192.0.2.1", "more than one group", "ga", "gb"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("commit diagnostic omits %q: %v", want, err)
		}
	}

	// Control: the same shape with distinct addresses must still commit, or
	// the gate is rejecting on group count rather than on the collision.
	const ok = `protocols {
    bgp {
        local-as 65001;
        group ga { peer-as 65002; neighbor 192.0.2.1 { authentication-key "secretA"; } }
        group gb { peer-as 65003; neighbor 192.0.2.2 { authentication-key "secretB"; } }
    }
}
`
	if _, err := CheckText(ok, 0); err != nil {
		t.Fatalf("commit gate rejected two DISTINCT neighbors: %v", err)
	}
}
