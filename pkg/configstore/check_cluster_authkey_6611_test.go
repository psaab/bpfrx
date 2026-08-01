package configstore

import (
	"strings"
	"testing"
)

// #6611 review follow-up. CheckText is the third strict-compile path, behind
// `xpfd check-config`, and it is wired into three shipped tools:
// scripts/deploy/xpf-deploy.py (dies on reject), scripts/image/make_config_drive.py,
// and the first-boot loader scripts/image/xpf-day0-config (which falls back to
// the FACTORY bootstrap on reject, i.e. an unconfigured appliance). So an
// unkeyed cluster config is refused at day-0 validation, not only at commit.
//
// That is the intended posture for a NEW provision, but it must be a pinned
// verdict with a documented migration order rather than an emergent one.

const unkeyedClusterCheckConf = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 2;
    }
}
`

const keyedClusterCheckConf = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 2;
        authentication-key "day0-psk-6611-long-enough";
    }
}
`

// TestCheckTextRejectsUnkeyedCluster_6611 pins the day-0 validation verdict.
// RED on revert: with the #6611 gate call site removed, CheckText returns nil
// and xpf-deploy / the day-0 loader install an unkeyed cluster config.
func TestCheckTextRejectsUnkeyedCluster_6611(t *testing.T) {
	// nodeID 0 matches the fixture's `node 0` leaf; -1 is the standalone
	// spelling day-0 validation uses when no node-id file is present. Both must
	// refuse. (nodeID 1 is deliberately not exercised here — it would trip the
	// unrelated #4185 node-identity gate against this fixture's `node 0`.)
	for _, nodeID := range []int{0, -1} {
		cfg, err := CheckText(unkeyedClusterCheckConf, nodeID)
		if err == nil {
			t.Fatalf("node %d: check-config ACCEPTED an unkeyed chassis cluster — "+
				"xpf-deploy and the day-0 config-drive loader would install a config "+
				"that runs an unauthenticated cluster control channel (cfg=%v)",
				nodeID, cfg != nil)
		}
		if !strings.Contains(err.Error(), "authentication-key") {
			t.Fatalf("node %d: rejection does not name the missing leaf: %v", nodeID, err)
		}
	}
}

// TestCheckTextAcceptsKeyedCluster_6611 is the NEGATIVE CONTROL — day-0
// validation of a keyed cluster must pass for both node-id spellings, so the
// guard cannot be passing by rejecting every cluster config.
func TestCheckTextAcceptsKeyedCluster_6611(t *testing.T) {
	for _, nodeID := range []int{0, -1} {
		cfg, err := CheckText(keyedClusterCheckConf, nodeID)
		if err != nil {
			t.Fatalf("node %d: check-config rejected a KEYED cluster config: %v", nodeID, err)
		}
		if cfg.Chassis.Cluster == nil {
			t.Fatalf("node %d: keyed config compiled no cluster stanza", nodeID)
		}
		if cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal() == "" {
			t.Fatalf("node %d: keyed config compiled an empty control-link key", nodeID)
		}
	}
}
