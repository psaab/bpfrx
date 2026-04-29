//! #919: canonical zone-ID constants for test fixtures.
//!
//! Production zone IDs are assigned by the Go config compiler
//! (`pkg/dataplane/userspace/snapshot.go:183-187`) starting at 1.
//! These constants give test code stable, named IDs to use in
//! `SessionMetadata` constructors and `zone_name_to_id` /
//! `zone_id_to_name` test maps. They mirror the conventional zone
//! names used across most test fixtures.
//!
//! Tests that construct a custom `ForwardingState` should populate
//! `zone_name_to_id` and `zone_id_to_name` consistently with these
//! IDs, e.g.:
//!
//! ```ignore
//! forwarding.zone_name_to_id.insert("lan".to_string(), TEST_LAN_ZONE_ID);
//! forwarding.zone_id_to_name.insert(TEST_LAN_ZONE_ID, "lan".to_string());
//! ```

#![cfg(test)]

pub(crate) const TEST_LAN_ZONE_ID: u16 = 1;
pub(crate) const TEST_WAN_ZONE_ID: u16 = 2;
pub(crate) const TEST_TRUST_ZONE_ID: u16 = 3;
pub(crate) const TEST_UNTRUST_ZONE_ID: u16 = 4;
pub(crate) const TEST_SFMIX_ZONE_ID: u16 = 5;
pub(crate) const TEST_FABRIC_ZONE_ID: u16 = 6;
pub(crate) const TEST_DMZ_ZONE_ID: u16 = 7;
pub(crate) const TEST_MGMT_ZONE_ID: u16 = 8;
