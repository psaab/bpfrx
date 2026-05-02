// Raw OS memory allocation for AF_XDP UMEM regions.
//
// Owns the mmap()/munmap() lifecycle and the hugepage selection
// policy: try explicit 2 MB hugepages first, fall back to standard
// pages with a transparent-hugepage advisory hint.

use std::io;
use std::os::raw::c_void;
use std::ptr::NonNull;

pub(in crate::afxdp) struct MmapArea {
    ptr: NonNull<u8>,
    /// Original requested size (passed to XSK via as_nonnull_slice).
    len: usize,
    /// Actual mmap size (may be rounded up for hugepage alignment).
    mapped_len: usize,
    /// Whether the region is backed by explicit 2 MB hugepages.
    hugepage: bool,
}

const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

impl MmapArea {
    pub(in crate::afxdp) fn new(len: usize) -> io::Result<Self> {
        // #1020: harden two corner cases that the syscall would otherwise
        // surface as a less-direct EINVAL or — worse — silently under-
        // allocate by wrapping past usize::MAX during alignment rounding.
        if len == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // Round up to 2 MB boundary for hugepage eligibility, with a
        // checked add so a `len` near usize::MAX produces a clean error
        // instead of a wrapped (smaller) `aligned_len` that would
        // succeed mmap but under-allocate the UMEM.
        let aligned_len = len
            .checked_add(HUGE_PAGE_SIZE - 1)
            .ok_or_else(|| {
                io::Error::other("umem len would overflow on hugepage alignment")
            })?
            & !(HUGE_PAGE_SIZE - 1);

        // Attempt 1: explicit 2 MB hugepages (requires system reservation).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE
                    | libc::MAP_ANONYMOUS
                    | libc::MAP_HUGETLB
                    | libc::MAP_POPULATE
                    | (21 << libc::MAP_HUGE_SHIFT), // MAP_HUGE_2MB
                -1,
                0,
            )
        };
        if ptr != libc::MAP_FAILED {
            let ptr = NonNull::new(ptr.cast::<u8>())
                .ok_or_else(|| io::Error::other("null mmap pointer"))?;
            eprintln!(
                "xpf-ha: umem alloc {} bytes ({} MB, 2MB hugepages)",
                aligned_len,
                aligned_len / (1024 * 1024)
            );
            return Ok(Self {
                ptr,
                len,
                mapped_len: aligned_len,
                hugepage: true,
            });
        }

        // Attempt 2: standard pages with MAP_POPULATE + THP advisory hint.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // Best-effort: request transparent hugepage backing.
        // `madvise(MADV_HUGEPAGE)` can fail (EINVAL on unsupported
        // kernels, ENOMEM under pressure); the return is ignored
        // intentionally because falling back to non-THP standard
        // pages is correct.
        unsafe {
            libc::madvise(ptr, aligned_len, libc::MADV_HUGEPAGE);
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mmap pointer"))?;
        eprintln!(
            "xpf-ha: umem alloc {} bytes ({} MB, standard pages + THP hint)",
            aligned_len,
            aligned_len / (1024 * 1024)
        );
        Ok(Self {
            ptr,
            len,
            mapped_len: aligned_len,
            hugepage: false,
        })
    }

    /// Returns the original requested length (for XSK registration).
    pub(in crate::afxdp) fn as_nonnull_slice(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }

    /// Whether this region is backed by explicit 2 MB hugepages.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::afxdp) fn is_hugepage_backed(&self) -> bool {
        self.hugepage
    }

    pub(in crate::afxdp) fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::afxdp) fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        unsafe { self.slice_mut_unchecked(offset, len) }
    }

    /// Returns a `&mut [u8]` view into the UMEM region from a
    /// shared `&self` reference.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that no other borrow (mutable or
    /// shared) into the same `[offset, offset + len)` byte range
    /// is live for the lifetime of the returned slice, and that no
    /// other thread is concurrently reading or writing that range.
    /// AF_XDP single-writer (owner-worker) discipline plus per-frame
    /// offset assignment from the free-frame ring is what holds
    /// these invariants in production.
    pub(in crate::afxdp) unsafe fn slice_mut_unchecked(
        &self,
        offset: usize,
        len: usize,
    ) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
    }
}

impl Drop for MmapArea {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.mapped_len) };
    }
}


#[cfg(test)]
#[path = "mmap_tests.rs"]
mod harden_tests;
