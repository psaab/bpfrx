# Codex hostile plan-review — round 46 (plan v46 @ f379489f8)

Task: task-ms9xpqcn-tehyk1 (session 019fbbcf-1847-7d82-adfa-10ce01603d19).
Verdict: NEEDS-REVISION (3 MAJOR, 3 MINOR; fold verification 3 FOLDED / 5 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The invariant at plan.md:3995-4008 and :5189-5200 is sound: Stop-wins publishes dead and later readers create no token; reader-wins nil/full rolls back its reservation; reader-wins send makes the item owned either by the consumer defer or teardown drain; cancel does not alter that ownership. The nonblocking enqueue introduces no current lock inversion: the consumer takes no s.mu (pkg/cluster/sync_conn_config.go:325-395), QueueConfig releases s.mu before writeMu (pkg/cluster/sync_conn_config.go:234-250), and Stop releases s.mu before waiting (pkg/cluster/sync_conn.go:363-385). But §9 freezes the reader while it holds this critical section and then requires Stop to publish/drain before it resumes (plan.md:6431-6438), which is impossible under the same exclusion.

2. NOT-FOLDED — Neither proposed epoch is globally monotonic. lastAppliedConfigGen ignores gen-0 and failed applies (pkg/cluster/sync_conn_config.go:275-286,351-395) and resets on bulk re-prime (pkg/cluster/sync_conn_gen.go:340-367). ConfigsReceived increments before queue-full/stale/failure disposition (pkg/cluster/sync_conn_read.go:298-330), and is scoped to a replaceable SessionSync (pkg/cluster/sync.go:293-301,805-857; pkg/cluster/sync_state.go:47-63). A transport-changing clean apply replaces that provider mid-callback (pkg/daemon/daemon_apply_tail.go:238-255), permitting old (0,0) → apply → fresh (0,0) ABA after the outstanding level retires. Only ConfigsReceived is exposed at pkg/cluster/status.go:340-356. Dropped-frame increments are conservative and retryable, but the runbook must explicitly rebaseline/repeat; continuous ingress safely prevents completion.

3. FOLDED — Normative and acceptance copies both say the APPLY lands in the window regardless of receipt time (plan.md:4134-4143,6332-6339), matching pkg/cluster/sync_conn_read.go:84-93 and sync_auth.go:352-369. “initiated BETWEEN” survives only in revision-history prose.

4. PARTIAL — Both copies add ActiveApplied() (plan.md:4239-4245,6378-6384), and it catches the named promote-then-new-text apply failure (pkg/configstore/store.go:797-809; pkg/daemon/daemon_apply_commit.go:464-494). It is not exposed on the operator’s health/status surfaces (pkg/api/health.go:65-84; pkg/cluster/status.go:340-356), and the resulting conjunction is not a complete clean-state predicate; see the MAJOR finding below.

5. PARTIAL — Authority-side configure; load override <file>; commit is valid: RG0 promotion clears read-only (pkg/daemon/daemon_ha.go:438-442), and load/commit then pass the writable gate (pkg/configstore/store_command.go:304-335; store_commit.go:132-143). The required capture is not generally reachable: gRPC, REST, and shipped remote CLI output are always redacted (pkg/grpcapi/server_config.go:347-380; pkg/api/config.go:304-352; cmd/cli/show.go:81-120). Cleartext show configuration exists only in the embedded privileged TTY CLI (pkg/cli/cli_show.go:45-53,101-109; pkg/daemon/daemon_run.go:601-616), which normal service mode does not instantiate.

6. PARTIAL — The main true-join and registered-reader text is correctly scoped (plan.md:4053-4057,4078-4105), as are two gap-free copies (:5164-5167,6283-6285). Residual unscoped claims remain at :3944 (“GAP-FREE”), :5202 (“ALL-INGRESS JOIN”), and :5234-5240/:6274-6282 (“every relevant ingress reader”), although IsSyncConnected observes only the registered provider (pkg/cluster/sync_state.go:66-74).

7. FOLDED — Closure is now the directory barrier plus intended digest, full aggregate, and ActiveApplied verification, explicitly not boot reclassification (plan.md:4254-4260,6357-6385).

8. NOT-FOLDED — plan.md:5219-5223 says the grpcapi/cli untouched scope was amended, while :5361 still declares both untouched. The active canonical-digest accessor and daemon-to-cluster provider wiring are also unspecified; current gRPC merely relays Manager.FormatStatus (pkg/grpcapi/server_show_cluster_text.go:66-74). The coherent implementation scope is pkg/configstore for the canonical accessor, pkg/daemon for injection, and pkg/cluster for status rendering; pkg/grpcapi and pkg/cli can remain code-untouched because they relay that formatted output.

9. FOLDED — Repository-wide grep finds exactly the listed 17 direct test sends: eight in sync_config_gen_test.go, three in sync_config_epoch_sweep_race_6284_test.go, and six in sync_config_health_6387_test.go; the sole production send is pkg/cluster/sync_conn_read.go:323.

New findings — MAJOR:

MAJOR — The pulse witness is still unsafe. plan.md:4021-4029,4107-4114,6297-6304,6439-6445 relies on resettable/provider-scoped quantities, allowing a transport-changing apply to erase the pulse through provider ABA. H2 needs one explicitly named node-lifetime monotonic dispatch epoch, exposed beside ConfigSyncOutstanding and preserved across every SessionSync replacement.

MAJOR — The final predicate is neither observable nor closed. ActiveApplied is internal, while IsConfirmPending and IsDirty are independent state already exposed by GetConfigModeStatus (pkg/configstore/store_commit.go:796-800; store_lock.go:334-338; pkg/grpcapi/server_config.go:98-103). LoadOverride can set dirty without changing active/applied/persistence state (pkg/configstore/store_command.go:304-334), and a healthy recovered confirm window can pass every stated field yet later roll back. Moreover, a same-text DHCP full reapply can fail without invalidating the old applied digest (pkg/daemon/daemon_dhcp.go:73-90; daemon_apply.go:49-70), while dataplane apply may retain stale enforcement (daemon_apply_dataplane.go:145-159); ActiveApplied therefore remains true. Require operator-visible ActiveApplied, ConfirmPending=false, Dirty=false or explicit candidate discard, and marker invalidation for failed full reapplies.

MAJOR — No universally available live-service command or endpoint captures the required complete unredacted artifact. The cited gRPC surface is explicitly redacted (pkg/grpcapi/server_config.go:347-380); archives are configuration-dependent. The only exact cleartext command today is embedded privileged show configuration, unavailable under normal non-TTY service startup (cmd/xpfd/README.md:51-55; test/incus/xpfd.service:6-14).

New findings — MINOR:

MINOR — JOIN-COHERENCE’s teardown schedule contradicts its mutex invariant (plan.md:4001-4008,6431-6438). The reader-wins test must assert Stop blocks, resume the reader through enqueue/unlock, then observe Stop publish and drain; a separate Stop-wins leg should test the dead-gate drop.

MINOR — load replace does not exist; supported modes are override, merge, and set (cmd/cli/main.go:549-590; pkg/grpcapi/server_config.go:220-244). Retain only load override <artifact>.

MINOR — The residual gap-free/all-reader wording and §5.1’s grpcapi/cli contradiction remain at plan.md:3944,5202,5234-5240,5361,6274-6282.

Structure confirmation: §4.7 stands at plan.md:5064-5107 and :6907-6914: PR-1 is the core; G+H+H2 remain together in the follow-up.

NEEDS-REVISION

Codex session ID: 019fbbcf-1847-7d82-adfa-10ce01603d19
Resume in Codex: codex resume 019fbbcf-1847-7d82-adfa-10ce01603d19
