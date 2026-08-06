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
// migration window — the cluster could never converge. The cluster cannot get
// itself out of that state. An operator can, but only by deliberately failing
// the cluster over — see the enumerated recovery paths below.
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
// locally.
//
// Recovery: exactly ONE path works, and it costs a controlled outage. Three
// revisions of this comment got it wrong in three different directions — first
// "console access to the standby", then a README path that is closed, then "no
// recovery at all". Each replaced a hedge with an absolute. So the paths are
// enumerated here individually rather than summarized into a verdict:
//
//   - Primary-only rekey — CLOSED. Clearing the key leaves an unkeyed
//     `chassis cluster`, which is what the commit gate rejects, so
//     `delete chassis cluster authentication-key; commit` is refused by
//     `validateClusterAuthKeyStrict` (#6630).
//   - Console on the seated secondary — CLOSED. The read-only gate is on the
//     CONFIG STORE, not the transport, so EnterConfigureSession returns
//     ErrClusterReadOnly however the operator reached the box.
//   - Controlled RG0 promotion — OPEN. Stop xpfd on the keyed primary; the
//     secondary wins the election and applyRG0OwnershipTransition(StatePrimary)
//     calls store.SetClusterReadOnly(false), so it accepts a local commit of
//     the same key. Restart the old primary and the pair converges keyed.
//
// So step 20 must never restart comms on a key commit not because the state is
// unrecoverable, but because the only way out is a deliberate single-node
// outage — a config commit that silently becomes a failover.
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

	// Second positive control, KEYED. The control above builds `moved` from
	// transport(), which sets no ControlLinkAuthKey, so on its own it cannot
	// distinguish "restarts on an endpoint change" from "restarts on an
	// endpoint change ONLY WHILE UNKEYED" — and the latter is the most
	// plausible over-correction of this very issue, because "don't restart
	// comms when a key is involved" is the obvious wrong way to satisfy
	// key_commit_must_not_restart.
	//
	// Measured, not assumed (#6865 review): suppressing step 20 whenever a key
	// is configured --
	//
	//	keyed := cfg != nil && cfg.Chassis.Cluster != nil &&
	//		cfg.Chassis.Cluster.ControlLinkAuthKey != ""
	//	if !keyed && d.activeClusterTransport != (clusterTransportKey{}) && ...
	//
	// -- left the ENTIRE pkg/daemon package green, both subtests above
	// included, while every keyed cluster silently stopped restarting comms on
	// a real endpoint move. This subtest is the one that reds it.
	//
	// SCOPE, and the two escapes MEASURED against it (#6865 review round 2).
	// Both are disclosed rather than closed because closing either needs a
	// different harness, not another assertion:
	//
	//  1. It binds a keyed decision derived from the CANDIDATE `cfg` only.
	//     Deriving it from `d.store.ActiveConfig()` instead escapes — the whole
	//     package stays green — because this fixture's store deliberately holds
	//     NO committed cluster config (see the comment on `d` above: that is
	//     what makes startClusterComms early-return so a unit test need not
	//     stand up sockets). A real commit promotes the new config BEFORE apply
	//     (store_commit.go / daemon_apply.go), so a store-derived check would
	//     see the key in production. Binding that needs a fixture with a
	//     committed keyed cluster stanza.
	//
	//  2. All three subtests observe `clusterCommsGen`, which stopClusterComms
	//     bumps FIRST. So they prove TEARDOWN, not that comms came back up:
	//     deleting `d.startClusterComms(d.daemonCtx)` from step 20 leaves vet
	//     and the entire package green. Binding restart COMPLETION needs a
	//     fixture where startClusterComms does not early-return.
	//
	// Tracked as #6878. Do not read "must still restart" as bound end to end.
	t.Run("keyed_endpoint_change_must_still_restart", func(t *testing.T) {
		movedKeyed := transport()
		movedKeyed.Chassis.Cluster.ControlLinkAuthKey = config.Secret("a-real-cluster-psk-5078")
		movedKeyed.Chassis.Cluster.PeerAddress = "10.99.0.9"

		// NOTE: there is deliberately no "seat a keyed active transport" step
		// here. `clusterTransportKey` carries the six ENDPOINT fields and not
		// the auth key — that is the invariant this whole file exists to pin —
		// so `clusterTransportFromConfig` of a keyed config is byte-identical
		// to the unkeyed one and such a step would be a no-op whose comment
		// claimed otherwise. It would also write shared daemon state from
		// inside a subtest: under a mutation that DOES add ControlLinkAuthKey
		// to clusterTransportKey, that write masked key_commit_must_not_restart
		// when this subtest ran first (measured). The three subtests are
		// order-independent because none of them REWRITES `d.activeClusterTransport`.
		// They do mutate `d` — applyTailReconciles reaches stopClusterComms, which
		// increments d.clusterCommsGen, and that is the very thing each subtest
		// measures. The distinction matters: a shared counter every subtest reads
		// before and after is fine; a shared field one subtest overwrites is not.
		//
		// "Keyed" here therefore means the CANDIDATE config is keyed while the
		// active transport is unchanged — which is exactly the production shape
		// after a key commit, since the key never entered the transport key.
		before := gen()
		_ = d.applyTailReconciles(movedKeyed, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if after := gen(); after == before {
			t.Fatalf("a peer-address change on a KEYED cluster did NOT restart "+
				"cluster comms (clusterCommsGen stayed %d); step 20 must key its "+
				"decision on the transport endpoints alone, never on whether an "+
				"authentication key is configured -- suppressing the restart while "+
				"keyed strands session-sync on the old peer address (#5078)", before)
		}
	})
}
