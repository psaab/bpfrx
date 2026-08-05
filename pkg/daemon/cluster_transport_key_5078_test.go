package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
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

// TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078 asserts the DECISION, not
// the struct.
//
// The sibling test above pins the field set of `clusterTransportKey`, and that
// is real: adding ControlLinkAuthKey to it makes the two configs stop comparing
// equal and REDs. But it cannot see the call site. The comparison that actually
// decides a restart is INLINE in applyTailReconciles step 20
// (daemon_apply_tail.go):
//
//	if d.activeClusterTransport != (clusterTransportKey{}) && newTransport != d.activeClusterTransport {
//	    d.stopClusterComms(); d.startClusterComms(d.daemonCtx)
//	}
//
// so a `|| keyChanged` clause added THERE, leaving clusterTransportKey and
// clusterTransportFromConfig byte-identical, produces exactly the permanent
// deadlock this PR exists to prevent — and the whole suite stays green. Before
// this test there was no coverage of that site at all: grep for
// `activeClusterTransport` or "restarting comms" across *_test.go returned
// nothing.
//
// Why the deadlock is permanent. A seated RG0 secondary is config read-only
// (SetClusterReadOnly(true) on demotion; EnterConfigureSession returns
// ErrClusterReadOnly), and config-sync rides the SAME SessionSync stream this
// PR fail-closes. So the key reaches the secondary ONLY over the already
// established connection. Restart comms at the moment the primary becomes keyed
// and that connection drops while the peer is still unkeyed; the now-keyed
// primary then rejects its handshake forever, and the secondary cannot be keyed
// locally. Recovery needs console access to the standby.
//
// Observable: clusterCommsGen. stopClusterComms bumps it before anything else,
// and startClusterComms bumps it via beginClusterCommsEpoch, so an unchanged
// generation across a commit means step 20 did not restart comms.
//
// RED on revert: add `|| keyChanged` (or any auth-key term) to the step-20
// condition and key_commit_must_not_restart fails while the endpoint_change
// positive control still passes.
func TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078(t *testing.T) {
	installFakeNetworkctl(t)

	transport := func() *config.Config {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{
			ClusterID:         1,
			NodeID:            0,
			ControlInterface:  "em0",
			PeerAddress:       "10.99.0.2",
			FabricInterface:   "fab0",
			FabricPeerAddress: "10.99.1.2",
		}
		return cfg
	}

	// The store deliberately holds NO committed cluster config: startClusterComms
	// early-returns on `cfg.Chassis.Cluster == nil`, so the positive control can
	// observe the restart (stopClusterComms already bumped the generation)
	// without this unit test standing up heartbeat/sync sockets.
	d := &Daemon{
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: context.Background(),
		opts:      Options{NoDataplane: true},
	}
	// Comms are "already up" on the base transport — the non-zero
	// activeClusterTransport that step 20 requires before it will restart.
	d.activeClusterTransport = clusterTransportFromConfig(transport())

	gen := func() uint64 {
		d.clusterCommsMu.Lock()
		defer d.clusterCommsMu.Unlock()
		return d.clusterCommsGen
	}

	t.Run("key_commit_must_not_restart", func(t *testing.T) {
		keyed := transport()
		keyed.Chassis.Cluster.ControlLinkAuthKey = config.Secret("a-real-cluster-psk-5078")

		before := gen()
		// The tail returns reconcile errors in this stripped-down harness; the
		// assertion is on the comms decision, which step 20 makes regardless.
		_ = d.applyTailReconciles(keyed, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if after := gen(); after != before {
			t.Fatalf("committing authentication-key restarted cluster comms "+
				"(clusterCommsGen %d -> %d): that drops the established session-sync "+
				"connection at the moment the primary becomes keyed, and it is the ONLY "+
				"path by which the key can reach a config read-only secondary — the "+
				"rollout then deadlocks permanently (#5078)", before, after)
		}
	})

	// Positive control: an endpoint change MUST still restart, or the assertion
	// above is satisfied by a step 20 that never fires at all.
	t.Run("endpoint_change_must_restart", func(t *testing.T) {
		moved := transport()
		moved.Chassis.Cluster.PeerAddress = "10.99.0.9"

		before := gen()
		_ = d.applyTailReconciles(moved, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if after := gen(); after == before {
			t.Fatalf("a peer-address change did NOT restart cluster comms "+
				"(clusterCommsGen stayed %d); the key-commit assertion above is "+
				"meaningless if step 20 never fires", before)
		}
	})
}
