### Final Confirmation Verdict: PLAN YES

#### 1. Config-Sync Generation Carriage & ForwardingState Placement
- **Availability:** In `pkg/cluster/sync_conn_config.go:222` (`nextConfigGen`), generation `item.gen` is carried in `configApplyCh` and fully available. Extending `OnConfigReceived` at `pkg/daemon/daemon_ha_sync.go:910` to pass `item.gen` allows `d.handleConfigSync` to capture and store it.
- **Publication Order Consistency:** Storing `admission_config_version` directly inside `ForwardingState` (`types/forwarding.rs:33`) ensures generation and policy publish atomically together. This eliminates the observation window between `shared_validation` (stored at `snapshot_refresh.rs:397`) and `forwarding` (stored at `398`), matching the worker load sequence in `loop_body/mod.rs:462,470`.

#### 2. Cohort-Scoped Replay Cleanup & Reactive Materialization Serialization
- **Mixed Cohort Behavior:** When forward replays reject but the reverse replay installs at `upsert_synced.rs:64`, the reverse entry retains its hold across the shared family allocation. Because cleanup requires zero holders across the complete `(incarnation, allocation, family)` cohort, the cleanup check skips.
- **Reactive Materialization:** A reactive materialization at `session_glue/mod.rs:1157` that commits a hold prior to the cleanup's incarnation check completes holds the allocation; serialization ensures the family is taken off the cleanup list and protected from deletion.

#### 3. Allocator Migration & Collision Prevention Sequence
- **Cross-Allocator Reservation:** Allocator B (`source.rs:549,726`) is an independent `PortAllocator` instance. Existing APIs `reserve_flow` (`allocator.rs:1654`) and `reserve_address_only` (`allocator.rs:1727`) invoked on allocator B via `reserve_synced_source_nat_allocation` (`source.rs:829`) create E1's reservation in B while A's hold remains active, requiring no new low-level allocation API.
- **Collision Window:** Reserving into B *before* releasing A sets B's occupancy bit and `live_by_flow` entry prior to A's release, structurally preventing B from assigning E1's public tuple to a competing flow (`allocator.rs:1617`).
