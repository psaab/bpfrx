package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceSessionDescriptors() {
	c.userspaceSessionTableEntries = prometheus.NewDesc(
		"xpf_userspace_session_table_entries",
		"Aggregate live userspace session-table entries across workers.",
		nil, nil,
	)
	c.userspaceSessionTableCapacity = prometheus.NewDesc(
		"xpf_userspace_session_table_capacity",
		"Aggregate userspace session-table capacity across workers.",
		nil, nil,
	)
	c.userspaceNatReverseKeyCollisions = prometheus.NewDesc(
		"xpf_userspace_session_nat_reverse_key_collisions_total",
		"Aggregate NAT reverse-key (nat_reverse_index) 1:N collision "+
			"displacement events across userspace workers (#1758/#1760 "+
			"latent corruption made observable). Event count, not a "+
			"census (replica fanout over-counts; standing and seed-path "+
			"collisions under-count — pair with the shared displacements "+
			"counter). >=1 means at least one real collision occurred "+
			"and is the structural-fix revisit trigger.",
		nil, nil,
	)
	c.userspaceNatReverseKeySharedDisplacements = prometheus.NewDesc(
		"xpf_userspace_session_nat_reverse_key_shared_displacements_total",
		"Shared-map NAT reverse-key displacement events: a "+
			"publish_shared_session insert displaced a DIFFERENT forward "+
			"session's entry at the same reverse key (#1760 latent 1:N "+
			"reverse-path corruption). The shared map is the choke point "+
			"all transit forward NAT sessions pass through (including "+
			"MissingNeighborSeed installs invisible to the per-worker "+
			"counter). Event count, not a pair census: >=1 means at "+
			"least one real collision occurred; standing collisions "+
			"against an already-unindexed session are not counted.",
		nil, nil,
	)
	c.userspaceSessionCreateDrops = prometheus.NewDesc(
		"xpf_userspace_session_create_drops_total",
		"Aggregate session installs refused at the max_sessions cap "+
			"across userspace workers (#1861).",
		nil, nil,
	)
	c.userspaceSessionInstallAdmissionRefused = prometheus.NewDesc(
		"xpf_userspace_session_install_admission_refused_total",
		"Aggregate new flows refused (trigger packet dropped, Junos "+
			"parity) by the #1861 forward+reverse pair-admission "+
			"preflight at/near max_sessions, across userspace workers.",
		nil, nil,
	)
	c.userspaceSessionInstallPartial = prometheus.NewDesc(
		"xpf_userspace_session_install_partial_total",
		"Aggregate post-preflight partial session installs across "+
			"userspace workers (#1861 release residual arms; expected 0 "+
			"forever — nonzero means a preflight/install pairing bug).",
		nil, nil,
	)
	c.userspaceSessionPublishErrors = prometheus.NewDesc(
		"xpf_userspace_session_publish_errors_total",
		"Failed USERSPACE_SESSIONS BPF-map publishes across all helper "+
			"paths (worker poll, HA upsert, session-glue, post-reconcile "+
			"replay, activation/reverse prewarm). A failed publish means "+
			"the XDP shim never learns the session key and takes the "+
			"NO_SESSION degraded path (drop in STRICT mode); a rising "+
			"value attributes shim no-session fallbacks to publish "+
			"failures (session map at capacity, stale fd after "+
			"reconcile) (#1789).",
		nil, nil,
	)
	c.userspaceDnatPublishErrors = prometheus.NewDesc(
		"xpf_userspace_dnat_publish_errors_total",
		"Failed dnat_table reverse-SNAT BPF-map publishes across "+
			"userspace workers. The dnat_table backs embedded-ICMP NAT "+
			"reversal — the reverse lookup that maps an inbound ICMP "+
			"error (PMTUD Packet Too Big / Time Exceeded / traceroute) "+
			"back to the original pre-NAT source. A failed publish (map "+
			"at capacity, EINVAL, kernel resource exhaustion) silently "+
			"omits the reverse record, so the error is dropped or "+
			"mis-delivered; a rising value attributes that loss to "+
			"dnat_table map-capacity pressure (#2244).",
		nil, nil,
	)
	c.userspaceSyncedImportCapDrops = prometheus.NewDesc(
		"xpf_userspace_synced_import_cap_drops_total",
		"Peer-synced session imports rejected by the coordinator's "+
			"aggregate admission bound. Locally-created sessions are "+
			"capped per worker at max_sessions; peer-synced imports were "+
			"uncapped and fanned out to every worker command queue+table, "+
			"so a peer under session-table pressure (or a compromised "+
			"peer) could drive this node past its own aggregate session "+
			"ceiling and multiply that state across all workers. The "+
			"import path now bounds the shared synced map at this "+
			"appliance's own aggregate ENTRY ceiling "+
			"(2 * worker_count * max_sessions -- 2x the logical session "+
			"ceiling, because each admitted forward publishes a forward "+
			"plus a synthesized reverse companion) and drop-newest-rejects "+
			"an over-ceiling import; a rising value means a peer's import "+
			"would push THIS appliance past its own aggregate entry "+
			"ceiling (2N) — receiver-local, so a larger asymmetric peer "+
			"can legitimately trip a smaller receiver. A symmetric-pair "+
			"failover (N logical sessions = 2N entries) exactly fits and "+
			"never trips it (#5674).",
		nil, nil,
	)
	c.userspaceWorkerCommandQueuePoisonRecoveries = prometheus.NewDesc(
		"xpf_userspace_worker_command_queue_poison_recoveries_total",
		"Worker command-queue mutex poison recoveries across all "+
			"helper producer/consumer sites (worker poll, HA enqueues, "+
			"session replication, activation prewarm, tunnel install, "+
			"cross-binding shaped-TX redirect). A poisoned mutex means "+
			"a worker thread panicked while holding the lock; recovery "+
			"keeps the committed queue and clears the poison so the "+
			"queues keep flowing instead of going permanently deaf. "+
			"A nonzero value indicates a contained worker panic "+
			"occurred (#1807, extends #1790).",
		nil, nil,
	)
}
