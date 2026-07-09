// MmapArea slice-bounds tests. Split from umem/tests.rs (#4667).

use super::*;

#[test]
fn mmap_area_rejects_access_beyond_registered_len_even_if_mapping_is_rounded() {
    let area = MmapArea::new(128).expect("mmap");

    assert!(area.slice(0, 128).is_some());
    assert!(area.slice(128, 1).is_none());
    assert!(area.slice(512, 1).is_none());
}
