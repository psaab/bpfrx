use super::*;

mod mmap;
pub(in crate::afxdp) use mmap::MmapArea;

/// The UMEM region plus the libxdp UMEM object registered against it.
///
/// **Field order is load-bearing (#5192).** `xsk_ffi::Umem::new` is
/// `unsafe` on the precondition that the mmap'd `area` "outlives this
/// Umem", and Rust destroys struct fields in DECLARATION order — so
/// `umem` (which calls `xsk_umem__delete`) MUST be declared before
/// `area` (which calls `munmap`). Reversed, the pages are unmapped
/// while the UMEM object is still registered against them: a latent
/// use-after-free whose only defence is that the linked libxdp's
/// `xsk_umem__delete` happens not to read the user area — an external
/// library's implementation detail, not an invariant this repo owns.
///
/// Rust offers no compile-time drop-order assertion, so the order is
/// pinned by observation instead: `afxdp::umem::tests::drop_order`
/// watches both destructors through `crate::drop_order_probe` and reds
/// if these two lines are ever swapped back.
pub(super) struct WorkerUmemInner {
    umem: Umem,
    area: MmapArea,
    total_frames: u32,
}

impl WorkerUmemInner {
    fn umem_mut(&mut self) -> &mut Umem {
        &mut self.umem
    }
}

#[derive(Clone)]
pub(super) struct WorkerUmem {
    inner: Rc<WorkerUmemInner>,
}

impl WorkerUmem {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((total_frames as usize) * (UMEM_FRAME_SIZE as usize))?;
        let ring_size = umem_ring_size(total_frames);
        let umem_cfg = UmemConfig {
            fill_size: ring_size,
            complete_size: ring_size,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = unsafe { Umem::new(umem_cfg, area.as_nonnull_slice()) }
            .map_err(|e| format!("create umem: {e}"))?;
        Ok(Self {
            inner: Rc::new(WorkerUmemInner {
                umem,
                area,
                total_frames,
            }),
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        total_frames: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((total_frames as usize) * (UMEM_FRAME_SIZE as usize))?;
        let ring_size = umem_ring_size(total_frames);
        let umem_cfg = UmemConfig {
            fill_size: ring_size,
            complete_size: ring_size,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = Umem::new_for_test(umem_cfg, area.as_nonnull_slice());
        Ok(Self {
            inner: Rc::new(WorkerUmemInner {
                umem,
                area,
                total_frames,
            }),
        })
    }

    pub(super) fn area(&self) -> &MmapArea {
        &self.inner.area
    }

    pub(super) fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    pub(super) fn umem_mut(&mut self) -> &mut Umem {
        Rc::get_mut(&mut self.inner)
            .expect("single-owner umem")
            .umem_mut()
    }

    pub(super) fn as_raw_umem_ptr(&self) -> *mut crate::xsk_ffi::XskUmemOpaque {
        self.inner.umem.as_raw_ptr()
    }

    pub(super) fn total_frames(&self) -> u32 {
        self.inner.total_frames
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn shares_allocation_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn allocation_ptr(&self) -> *const WorkerUmemInner {
        Rc::as_ptr(&self.inner)
    }
}

pub(super) struct WorkerUmemPool {
    pub(super) umem: WorkerUmem,
    pub(super) free_frames: VecDeque<u64>,
}

impl WorkerUmemPool {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let umem = WorkerUmem::new(total_frames.max(1))?;
        let mut free_frames = VecDeque::with_capacity(total_frames.max(1) as usize);
        for idx in 0..total_frames.max(1) {
            if let Some(frame) = umem.umem().frame(BufIdx(idx)) {
                free_frames.push_back(frame.offset);
            }
        }
        Ok(Self { umem, free_frames })
    }
}


#[cfg(test)]
mod tests;
