package config

import (
	"fmt"
	"strings"
)

// validateClusterAuthKeyStrict hard-rejects, at commit / commit-check, a
// `chassis cluster` stanza that configures no `authentication-key` (#6611).
//
// Three independent control-channel authentication mechanisms exist — fabric
// gRPC auth (#4357), heartbeat HMAC + anti-replay (#4326), and session-sync
// challenge/response + per-frame HMAC (#4369) — and ALL THREE key off the same
// `chassis cluster authentication-key` PSK. Each one deliberately fails OPEN
// when that PSK is absent, so the cluster keeps forming during a rolling
// upgrade:
//
//	pkg/grpcapi/fabric_auth.go  fabricAuthDecision:    !keyConfigured -> accept
//	pkg/cluster/heartbeat.go    heartbeatAuthDecision: !keyConfigured -> accept
//	pkg/cluster/sync_auth.go    performSyncHandshake:  no key -> no handshake
//
// An unkeyed cluster therefore runs the fabric gRPC listener, the heartbeat and
// the session-sync channel with NO authentication at all — allowlist-only. Any
// host that can reach the control segment can drive failover, read and clear
// sessions, and inject synthetic sessions. Before this gate, an unkeyed cluster
// committed silently: nothing in the configuration layer even mentioned it.
//
// STRICT applies to EVERY caller of compileTreeStrict, which is more than the
// operator commit. All three of these refuse an unkeyed cluster:
//
//	Store.Commit / CommitCheck / CommitConfirmed — the operator commit. A
//	  rejection here is inert for traffic: the active config and the dataplane
//	  are untouched, so the cluster keeps running while the operator adds a key.
//	daemon.bootstrapFromFile (daemon_apply_commit.go) — the UNATTENDED first-boot
//	  import of /etc/xpf/xpf.conf, taken whenever the config DB has no active
//	  config (daemon_run_bringup.go). A rejection here leaves the node with NO
//	  active config — it does not boot with a warning. This is the path a
//	  reimaged / replaced / DR-restored node takes, and the path
//	  test/incus/cluster-setup.sh takes on every cluster-deploy (it wipes
//	  /etc/xpf/.configdb).
//	configstore.CheckText — `xpfd check-config`, wired into
//	  scripts/deploy/xpf-deploy.py, scripts/image/make_config_drive.py and the
//	  first-boot loader scripts/image/xpf-day0-config (which falls back to the
//	  factory bootstrap on reject).
//	pkg/eventengine — AUTONOMOUS remediation (CommitCheck + the daemon commit
//	  closure). On a leniently-booted unkeyed cluster every `change-configuration`
//	  policy silently fails until the cluster is keyed; no operator is present to
//	  see it.
//
// So the migration order matters and is documented in pkg/cluster/README.md:
// key the RUNNING cluster first (that commit is accepted), and only then
// re-provision, reimage, or rebuild a day-0 drive.
//
// Lenient on load / peer-sync (opts.lenientClusterAuthKey): an already-persisted
// or peer-synced unkeyed config still BOOTS with a warning (#1960 no-brick).
// That is what preserves the IN-PLACE upgrade path — a cluster that was unkeyed
// before the upgrade keeps its config DB, loads it through CompileConfigLenient,
// comes up, and keeps forwarding. The heartbeat and fabric gRPC dual-accept
// grace means a key can then be rolled out one node at a time without dropping
// the cluster. SESSION SYNC is the exception: #5078 removed its dual-accept, so
// a keyed node rejects an unkeyed peer and session sync stays DOWN until both
// nodes are keyed AND both have restarted. pkg/cluster/README.md -> "Rolling it
// onto a live unkeyed cluster" marks the old sequence STALE (#6881).
//
// The key is compared only for emptiness and is never echoed into the error —
// the whole point of Secret (compiler_system.go) is that it never reaches a log
// or a CLI render.
func validateClusterAuthKeyStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	// TrimSpace normalizes emptiness: a whitespace-only key IS "configured" to
	// the runtime's len(key) > 0 test but is not a key, so trimming here makes
	// this gate deliberately STRICTER than the runtime rather than identical to
	// it — the right direction on the strict path. (The difference stays
	// observable on the tolerant path; see pkg/cluster/README.md "Key
	// strength".) This is an EMPTINESS floor, not an entropy floor — a
	// one-character key passes here. Key strength is a continuum and is
	// surfaced by ClusterAuthKeyStrengthWarnings rather than rejected, so a
	// weak-but-real key never becomes a new brick class for an operator who
	// already did the right thing.
	if strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()) != "" {
		return nil
	}
	return fmt.Errorf("chassis cluster: no authentication-key configured — the " +
		"cluster control channel (fabric gRPC, heartbeat, and session sync) " +
		"authenticates with a shared PSK and fails OPEN when none is set, so " +
		"any host able to reach the control segment could drive failover, read " +
		"or clear sessions, and inject sessions; set `chassis cluster " +
		"authentication-key <key>` to the SAME value on both nodes (generate " +
		"one with `openssl rand -base64 32`)")
}

// MinAdvisedControlLinkKeyLen is the length below which
// ClusterAuthKeyStrengthWarnings flags a control-link PSK as weak. The PSK
// backs HMAC-SHA256 on the heartbeat, the fabric bearer token and the
// session-sync frame MAC; 16 characters is the floor at which a key is worth
// more than a dictionary guess, and `openssl rand -base64 32` (the documented
// generator) produces 44.
const MinAdvisedControlLinkKeyLen = 16

// clusterAuthKeyPlaceholderMarkers are substrings that identify a key copied
// verbatim from a reference config in this repository. Those values are
// PUBLISHED, so a config carrying one satisfies validateClusterAuthKeyStrict
// while remaining trivially forgeable by anyone who has read the repo.
var clusterAuthKeyPlaceholderMarkers = []string{"change-me", "example-only"}

// ClusterAuthKeyStrengthWarnings reports control-link PSK weaknesses that are
// real but do not justify refusing the config: a key that is short, or one
// copied verbatim from a shipped reference config. These are WARNINGS on both
// the strict and tolerant paths — unlike absence, which is binary and is
// rejected, key strength is a continuum, and hard-rejecting a short key would
// brick a commit (and, via bootstrapFromFile, a provision) for an operator who
// already configured authentication.
//
// The warning never renders the key. It reports the LENGTH only, and for a
// placeholder it says that one matched WITHOUT naming which.
//
// Naming the marker was the obvious thing and it was wrong. The rationale was
// that a marker is a literal from this repository rather than operator key
// material — true right up until the two coincide. A key of exactly
// `change-me` makes the marker AND the key the same string, so printing the
// marker printed the whole key into the commit output and the log. That is the
// disclosure this advisory exists to warn about, produced by the advisory
// itself. The operator does not need to be told which placeholder they used;
// they need to be told to replace it.
func ClusterAuthKeyStrengthWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	key := strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal())
	if key == "" {
		return nil // absence is validateClusterAuthKeyStrict's business
	}
	var out []string
	if len(key) < MinAdvisedControlLinkKeyLen {
		out = append(out, fmt.Sprintf("chassis cluster authentication-key is %d "+
			"characters; %d or more is advised (the PSK backs HMAC-SHA256 on the "+
			"heartbeat, the fabric bearer token and the session-sync frame MAC) — "+
			"generate one with `openssl rand -base64 32`",
			len(key), MinAdvisedControlLinkKeyLen))
	}
	lower := strings.ToLower(key)
	for _, marker := range clusterAuthKeyPlaceholderMarkers {
		if strings.Contains(lower, marker) {
			// Deliberately does NOT name the marker: when the key IS the
			// marker, naming it prints the key.
			out = append(out, "chassis cluster authentication-key matches a "+
				"published placeholder from a reference config; those values are "+
				"in this repository, so the control channel is forgeable by "+
				"anyone who has read it — replace it with a key generated by "+
				"`openssl rand -base64 32`")
			break
		}
	}
	return out
}
