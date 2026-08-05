package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5078: committing `chassis cluster authentication-key` must NOT restart
// cluster comms.
//
// This is load-bearing and was previously unguarded — `clusterTransportKey` had
// no test at all. It carries the six ENDPOINT fields whose change requires
// tearing down and rebuilding heartbeat + session sync; the auth key is
// deliberately absent, so a key commit leaves the established connection up.
//
// Why that matters now. A seated RG0 secondary CANNOT be configured locally:
// `Daemon.applyHAState` calls `store.SetClusterReadOnly(true)` on
// StateSecondary/StateSecondaryHold, and `EnterConfigureSession` then returns
// ErrClusterReadOnly before doing anything else. Config-sync is the secondary's
// only writer. So the ONLY way to key a live cluster is to commit on the
// primary while sync is connected and let the existing connection carry the key
// across. If a key change restarted comms, the primary would drop the
// connection at the moment it became keyed, the secondary would still be
// unkeyed, and — since #5078 makes a keyed node reject an unkeyed peer, with no
// migration window — the cluster could never converge. That is a PERMANENT
// deadlock recoverable only by console access to the secondary.
//
// Adding `ControlLinkAuthKey` to clusterTransportKey looks obviously correct
// ("restart comms when the key changes") and would silently create that
// deadlock with a green suite. This test is what stops it.
//
// RED on revert: add ControlLinkAuthKey to clusterTransportKey and populate it
// in clusterTransportFromConfig — the two configs below stop comparing equal.
func TestAuthKeyChangeDoesNotRestartClusterComms_5078(t *testing.T) {
	withKey := func(key string) *config.Config {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{
			ControlInterface:   "em0",
			PeerAddress:        "10.99.0.2",
			FabricInterface:    "fab0",
			FabricPeerAddress:  "10.99.1.2",
			Fabric1Interface:   "fab1",
			Fabric1PeerAddress: "10.99.2.2",
			ControlLinkAuthKey: config.Secret(key),
		}
		return cfg
	}

	unkeyed := clusterTransportFromConfig(withKey(""))
	keyed := clusterTransportFromConfig(withKey("a-real-cluster-psk-5078"))
	rekeyed := clusterTransportFromConfig(withKey("a-different-psk-5078"))

	if unkeyed != keyed {
		t.Fatalf("adding an authentication-key must not change the cluster transport key "+
			"(#5078): committing it would restart cluster comms and drop the very connection "+
			"that must carry the key to the read-only secondary.\n unkeyed=%+v\n keyed=%+v",
			unkeyed, keyed)
	}
	if keyed != rekeyed {
		t.Fatalf("rotating the authentication-key must not change the cluster transport key "+
			"(#5078).\n keyed=%+v\n rekeyed=%+v", keyed, rekeyed)
	}

	// Positive control: the fields that SHOULD force a comms restart still do,
	// so the test above is not passing because the key is simply always equal.
	moved := withKey("a-real-cluster-psk-5078")
	moved.Chassis.Cluster.FabricPeerAddress = "10.99.1.3"
	if clusterTransportFromConfig(moved) == keyed {
		t.Fatal("an endpoint change MUST change the cluster transport key; the equality above " +
			"would then prove nothing")
	}
}
