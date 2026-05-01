use super::*;

pub(crate) struct NeighborManager {
    pub(crate) dynamic: Arc<ShardedNeighborMap>,
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) manager_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    pub(crate) monitor_stop: Option<Arc<AtomicBool>>,
}

impl NeighborManager {
    pub(super) fn new() -> Self {
        Self {
            dynamic: Arc::new(ShardedNeighborMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            manager_keys: Arc::new(Mutex::new(FastSet::default())),
            monitor_stop: None,
        }
    }
}
