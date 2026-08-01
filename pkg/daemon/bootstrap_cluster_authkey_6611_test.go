package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6611 review follow-up. The original PR claimed the strict cluster-auth gate
// only affected the operator commit, and that "a rejected commit is inert for
// traffic". That is true for Store.Commit / CommitCheck / CommitConfirmed and
// FALSE for bootstrapFromFile, which strict-compiles /etc/xpf/xpf.conf
// UNATTENDED at first boot whenever the config DB has no active config
// (daemon_run_bringup.go). A node that takes that path with an unkeyed cluster
// config comes up with NO active config — reimage / node replacement / DR
// restore from archived text, and this repo's own `make cluster-deploy`, which
// wipes /etc/xpf/.configdb before restarting (test/incus/cluster-setup.sh).
//
// Refusing to provision an unkeyed cluster is the intended posture — a NEW
// provision should fail closed. These tests exist so that verdict is a pinned,
// deliberate choice with a documented migration order (key the RUNNING cluster
// first, then re-provision), and cannot silently drift again.

// bootstrapDaemon builds the minimal Daemon bootstrapFromFile needs: a real
// store over a temp DB and a config file path.
func bootstrapDaemon(t *testing.T, conf string) (*Daemon, func() bool) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	d := &Daemon{store: store, opts: Options{NoDataplane: true, ConfigFile: confPath}}
	return d, func() bool { return store.ActiveConfig() != nil }
}

const unkeyedClusterBootstrapConf = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 2;
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
    }
}
`

const keyedClusterBootstrapConf = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        reth-count 2;
        authentication-key "bootstrap-psk-6611-long-enough";
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
    }
}
`

// TestBootstrapFromFileRejectsUnkeyedCluster_6611 pins the UNATTENDED verdict:
// a fresh node handed an unkeyed cluster config refuses to bootstrap, and — the
// part that makes this different from a rejected operator commit — is left with
// NO active config rather than a warning.
//
// RED on revert: with the #6611 gate call site removed, bootstrapFromFile
// succeeds and the node comes up active with an unauthenticated control channel.
func TestBootstrapFromFileRejectsUnkeyedCluster_6611(t *testing.T) {
	d, hasActive := bootstrapDaemon(t, unkeyedClusterBootstrapConf)
	err := d.bootstrapFromFile()
	if err == nil {
		t.Fatal("bootstrapFromFile ACCEPTED an unkeyed chassis cluster: a freshly " +
			"provisioned node would come up running an unauthenticated cluster " +
			"control channel")
	}
	if !strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("bootstrap rejection does not name the missing leaf: %v", err)
	}
	// The consequence the operator doc must state: no active config, not a warning.
	if hasActive() {
		t.Fatal("precondition drift: a rejected bootstrap must leave NO active config")
	}
}

// TestBootstrapFromFileAcceptsKeyedCluster_6611 is the NEGATIVE CONTROL: the
// same unattended path accepts a keyed cluster and promotes it, so the guard
// above cannot be passing by rejecting every bootstrap. It is also the
// mechanical proof of the documented migration order — key the running cluster
// FIRST, then re-provision, and the provision succeeds.
func TestBootstrapFromFileAcceptsKeyedCluster_6611(t *testing.T) {
	d, hasActive := bootstrapDaemon(t, keyedClusterBootstrapConf)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile rejected a KEYED cluster config: %v", err)
	}
	if !hasActive() {
		t.Fatal("keyed bootstrap did not promote an active config")
	}
	active := d.store.ActiveConfig()
	if active.Chassis.Cluster == nil {
		t.Fatal("keyed bootstrap promoted a config with no cluster stanza")
	}
	if got := active.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got == "" {
		t.Fatal("keyed bootstrap promoted a config whose control-link key is empty")
	}
}

// TestBootstrapFromFileStandaloneUnaffected_6611 is the second NEGATIVE
// CONTROL: a non-clustered node has no control channel to authenticate and must
// still bootstrap unattended. A gate that broke standalone first boot would
// brick every non-HA appliance.
func TestBootstrapFromFileStandaloneUnaffected_6611(t *testing.T) {
	d, hasActive := bootstrapDaemon(t, `system {
    host-name standalone-6611;
}
`)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile rejected a standalone config: %v", err)
	}
	if !hasActive() {
		t.Fatal("standalone bootstrap did not promote an active config")
	}
}
