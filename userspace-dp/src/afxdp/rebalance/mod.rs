// #1748: reactive cross-worker ntuple rebalance controller.
//
// The per-flow CoV on shaped ports swings 14-29% under `-P12` because RSS
// hashes the N flows unevenly across the mlx5 VF RX queues, so workers serve
// different flow counts and a worker's capacity splits among its flows. The
// only lever that lifts slow flows AND preserves aggregate is moving an
// established flow off an overloaded worker onto an idle one — proven in the
// R1 spike (CoV 16.8% -> 2.3-4.2%, aggregate up).
//
// This module owns the default-OFF, opt-in forward-direction reactive
// rebalancer: it observes per-worker byte-rate imbalance, picks the flow
// whose move most flattens the per-worker byte-rate vector, and installs one
// exact-5-tuple ntuple rule via a direct SIOCETHTOOL ioctl (`ntuple.rs`).
//
// One responsibility per file (engineering-style.md modularity discipline):
//   - `ntuple.rs`     : the ethtool rxnfc ioctl + UAPI structs.
//   - `controller.rs` : the byte-rate-aware selection + barriered move
//                        protocol + metrics + per-flow cooldown/hysteresis.

mod controller;
pub(in crate::afxdp) mod ntuple;

pub(in crate::afxdp) use controller::{
    BarrierTransport, FlowSample, MoveOutcome, RebalanceConfig, RebalanceController,
    RebalanceMetrics, RebalanceTickInput, SkipReason, WorkerByteRate, cumulative_to_rate,
    flow_spec_from_key,
};
pub(in crate::afxdp) use ntuple::NtupleSocket;
