use super::*;

pub(crate) struct SharedCoSState {
    pub(crate) owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    pub(crate) owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    pub(crate) root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    pub(crate) exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    pub(crate) queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    /// #917: per-shared_exact-queue V_min coordination Arcs.
    /// Allocated once per shared_exact CoS queue (mirror of
    /// `queue_leases`) and Arc-cloned to every worker servicing the
    /// queue. Slot count = configured num_workers; updated by the
    /// same reconcile pass that rebuilds leases.
    pub(crate) queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
}

impl SharedCoSState {
    pub(super) fn new() -> Self {
        Self {
            owner_worker_by_queue: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            owner_live_by_queue: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            root_leases: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            exact_backlogs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            queue_leases: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            queue_vtime_floors: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        }
    }
}

/// #6593: the worker-visible sibling structures captured at the exact instant
/// the runtime view becomes visible, so their publication ORDER can be
/// asserted rather than assumed.
///
/// `refresh_runtime_snapshot` relies on a documented order: every structure
/// below must be published BEFORE the runtime view, because the view is the
/// single worker-visible gate and a worker reads it first. Publish one of them
/// AFTER and a worker can observe new forwarding paired with a stale sibling.
///
/// Only ONE of the seven had an ordering assertion, and it had a bypass. The
/// rest had none at all.
///
/// Each field holds the `Arc` that was worker-visible at the capture instant.
/// The test compares each against the corresponding post-refresh `Arc` with
/// `Arc::ptr_eq`: SAME means the structure was already published when the view
/// went out (correct); DIFFERENT means it was published afterwards, which is
/// exactly the window a worker can land in. A structure this refresh did not
/// republish compares equal, which is right — there is nothing to order.
///
/// `previous_view` makes the capture PROVE ITS OWN POSITION (the #6592
/// technique): it is the still-visible view at the same instant, and the test
/// asserts it is NOT the post-publish view. Hoisting the view store above this
/// capture would otherwise let every `ptr_eq` above pass vacuously by reading
/// already-published values. It retains an `Arc` rather than a raw pointer
/// deliberately — dropping it would let the next `Arc::new` reuse the freed
/// address and fool `ptr_eq`.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct PrePublishSiblings {
    pub(crate) cos_owner_worker_by_queue: Arc<BTreeMap<(i32, u8), u32>>,
    pub(crate) cos_owner_live_by_queue: Arc<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    pub(crate) cos_root_leases: Arc<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    pub(crate) cos_exact_backlogs: Arc<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    pub(crate) cos_queue_leases: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    pub(crate) cos_queue_vtime_floors: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    pub(crate) ha_fabrics: Arc<Vec<FabricLink>>,
    pub(crate) previous_view: Arc<RuntimeView>,
}
