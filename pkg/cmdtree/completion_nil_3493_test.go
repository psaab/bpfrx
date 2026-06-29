package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3493: the `monitor security packet-drop from-zone <TAB>` DynamicFn in
// OperationalTree ranges cfg.Security.Zones (map[string]*ZoneConfig) and
// dereferences the value (z.Name) with only a `cfg == nil` guard. A nil zone
// map VALUE is reachable on the tolerant / HA-sync config path (#3474/#3476
// premise) the runtime walker (pkg/dataplane/userspace/zones.go) tolerates —
// same zone-name-completer crash family already guarded in cli/completion.go
// and grpcapi/server_cluster.go, missed here in the operational-tree SSOT
// consumed by local CLI + remote CLI + gRPC. This drives the real completer;
// reverting the `if z == nil { continue }` guard makes it panic (RED on revert).
func TestPacketDropFromZoneCompletionNilZoneNoPanic(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":       {Name: "trust"},
		"zz-nil-zone": nil, // #3493: nil zone value the strict compiler never emits
	}

	cands := CompleteFromTree(OperationalTree,
		[]string{"monitor", "security", "packet-drop", "from-zone"},
		"", cfg)

	// The nil zone must be skipped and the real zone name surfaced.
	if !contains(cands, "trust") {
		t.Fatalf("expected zone name trust in completions, got %v", cands)
	}
	for _, c := range cands {
		if c == "" {
			t.Fatalf("nil zone produced an empty completion candidate: %v", cands)
		}
	}
}
