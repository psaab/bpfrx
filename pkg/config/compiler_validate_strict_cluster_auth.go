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
// Strict on commit / commit-check: an operator at a CLI can always add the key
// before re-committing, and the cluster keeps running while they do — a
// rejected commit does not disturb the active config or the dataplane.
//
// Lenient on load / peer-sync (opts.lenientClusterAuthKey): an already-persisted
// or peer-synced unkeyed config still BOOTS with a warning (#1960 no-brick).
// That is what preserves the upgrade path — a cluster that was unkeyed before
// the upgrade loads its stored config through CompileConfigLenient, comes up,
// and keeps forwarding; the operator is told to set a key on the next commit
// rather than losing the cluster at boot. The dual-accept grace in all three
// mechanisms means a key can then be rolled out one node at a time.
//
// The key is compared only for emptiness and is never echoed into the error —
// the whole point of Secret (compiler_system.go) is that it never reaches a log
// or a CLI render.
func validateClusterAuthKeyStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	// TrimSpace: a whitespace-only key satisfies the runtime's len(key) > 0
	// test and would "work" as a PSK with essentially no entropy. Treat it as
	// unset here so the strict path refuses it rather than blessing it.
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
