//! SYN-cookie codec, SipHash24 MAC primitive, and validated-client
//! cache. Kept in one sibling so security-path crypto and its
//! supporting cache are auditable as a unit.
//!
//! Items live here:
//! - `SynCookieTuple` (4-tuple key)
//! - `SynCookieValidation`, `SynCookieChallenge`, `SynCookieAckVerdict`
//! - `SynCookieCodec` (mint/validate ISN, MAC derivation, epoch math)
//! - `SipHash24` (private MAC primitive)
//! - `SynCookieValidatedCache` (4-way set-associative recent-validated
//!   cookie cache so the ACK+SYN bypass path doesn't re-validate per
//!   packet)

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::packet::ScreenPacketInfo;

// Bit-layout constants. Tests inspect mint_isn output bit-by-bit so
// these are pub(crate) (re-exported under #[cfg(test)] by mod.rs).
pub(crate) const SYN_COOKIE_EPOCH_BITS: u32 = 5;
pub(crate) const SYN_COOKIE_MSS_BITS: u32 = 3;
pub(crate) const SYN_COOKIE_MAC_BITS: u32 = 24;
pub(crate) const SYN_COOKIE_ISN_BITS: u32 = 32;
pub(crate) const SYN_COOKIE_LAYOUT_BITS: u32 =
    SYN_COOKIE_EPOCH_BITS + SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
pub(crate) const SYN_COOKIE_EPOCH_MASK: u32 = (1 << SYN_COOKIE_EPOCH_BITS) - 1;
pub(crate) const SYN_COOKIE_MSS_MASK: u32 = (1 << SYN_COOKIE_MSS_BITS) - 1;
const SYN_COOKIE_MAC_MASK: u32 = (1 << SYN_COOKIE_MAC_BITS) - 1;
pub(crate) const SYN_COOKIE_EPOCH_SHIFT: u32 = SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
pub(crate) const SYN_COOKIE_MSS_SHIFT: u32 = SYN_COOKIE_MAC_BITS;
const SYN_COOKIE_MAC_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sync");
const SYN_COOKIE_SECRET_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck0");
const SYN_COOKIE_SECRET_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck1");
const SYN_COOKIE_CACHE_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv0");
const SYN_COOKIE_CACHE_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv1");
const SYN_COOKIE_VALIDATED_CACHE_CAPACITY: usize = 4096;
const SYN_COOKIE_VALIDATED_CACHE_WAYS: usize = 4;
const SYN_COOKIE_VALIDATED_CACHE_TTL_SECS: u64 = SynCookieCodec::EPOCH_SECS;
#[cfg(not(test))]
pub(super) const SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC: u32 = 4096;
#[cfg(test)]
pub(super) const SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC: u32 = 8;
const _: [(); SYN_COOKIE_ISN_BITS as usize] = [(); SYN_COOKIE_LAYOUT_BITS as usize];

/// Three-bit MSS table encoded in userspace SYN cookies.
///
/// The index, not the raw MSS, is transmitted in the ISN. Values are sorted so
/// selection can choose the largest value not exceeding the peer-advertised MSS.
pub(crate) const SYN_COOKIE_MSS_VALUES: [u16; 8] =
    [536, 1200, 1300, 1360, 1400, 1440, 1460, 8960];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SynCookieTuple {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_packet(pkt: &ScreenPacketInfo) -> Self {
        Self {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieValidation {
    pub full_epoch: u64,
    pub mss_index: u8,
    pub mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieChallenge {
    pub cookie_isn: u32,
    pub peer_mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SynCookieAckVerdict {
    NotApplicable,
    Validated,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieCodec {
    master_key: [u8; 16],
}

impl SynCookieCodec {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const EPOCH_SECS: u64 = 64;

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(master_key: [u8; 16]) -> Self {
        Self { master_key }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn full_epoch_from_unix_secs(unix_secs: u64) -> u64 {
        unix_secs / Self::EPOCH_SECS
    }

    pub(super) fn current_full_epoch() -> u64 {
        let unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        Self::full_epoch_from_unix_secs(unix_secs)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mss_index(peer_mss: u16) -> u8 {
        let mut selected = 0u8;
        let mut i = 1;
        while i < SYN_COOKIE_MSS_VALUES.len() {
            if peer_mss >= SYN_COOKIE_MSS_VALUES[i] {
                selected = i as u8;
            }
            i += 1;
        }
        selected
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mint_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        peer_mss: u16,
    ) -> u32 {
        let mss_index = Self::mss_index(peer_mss);
        let mac = self.cookie_mac(tuple, zone_id, full_epoch, mss_index);
        ((full_epoch as u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT)
            | ((mss_index as u32 & SYN_COOKIE_MSS_MASK) << SYN_COOKIE_MSS_SHIFT)
            | mac
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn validate_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        current_full_epoch: u64,
        cookie_isn: u32,
    ) -> Option<SynCookieValidation> {
        let wire_epoch = Self::wire_epoch(cookie_isn);
        let mss_index = ((cookie_isn >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK) as u8;
        let wire_mac = cookie_isn & SYN_COOKIE_MAC_MASK;
        let candidates = Self::candidate_validation_epochs(current_full_epoch);

        for (idx, candidate_epoch) in candidates.iter().copied().enumerate() {
            if candidates[..idx].contains(&candidate_epoch) {
                continue;
            }
            if (candidate_epoch as u32 & SYN_COOKIE_EPOCH_MASK) != wire_epoch {
                continue;
            }
            if self.cookie_mac(tuple, zone_id, candidate_epoch, mss_index) == wire_mac {
                return Some(SynCookieValidation {
                    full_epoch: candidate_epoch,
                    mss_index,
                    mss: SYN_COOKIE_MSS_VALUES[mss_index as usize],
                });
            }
        }

        None
    }

    fn candidate_validation_epochs(current_full_epoch: u64) -> [u64; 3] {
        [
            current_full_epoch.saturating_add(1),
            current_full_epoch,
            current_full_epoch.saturating_sub(1),
        ]
    }

    fn wire_epoch(cookie_isn: u32) -> u32 {
        (cookie_isn >> SYN_COOKIE_EPOCH_SHIFT) & SYN_COOKIE_EPOCH_MASK
    }

    pub(super) fn wire_epoch_matches_validation_window(
        current_full_epoch: u64,
        cookie_isn: u32,
    ) -> bool {
        let wire_epoch = Self::wire_epoch(cookie_isn);
        Self::candidate_validation_epochs(current_full_epoch)
            .iter()
            .any(|epoch| (*epoch as u32 & SYN_COOKIE_EPOCH_MASK) == wire_epoch)
    }

    fn cookie_mac(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        mss_index: u8,
    ) -> u32 {
        let secret = self.epoch_secret(zone_id, full_epoch);
        let mut sip = SipHash24::new(secret[0], secret[1]);
        sip.write_u64(SYN_COOKIE_MAC_DOMAIN);
        sip.write_u16(zone_id);
        sip.write_u64(full_epoch);
        sip.write_u8(mss_index);
        sip.write_ip(tuple.src_ip);
        sip.write_ip(tuple.dst_ip);
        sip.write_u16(tuple.src_port);
        sip.write_u16(tuple.dst_port);
        (sip.finish() as u32) & SYN_COOKIE_MAC_MASK
    }

    fn epoch_secret(&self, zone_id: u16, full_epoch: u64) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_SECRET_LEFT_DOMAIN);
        left.write_u16(zone_id);
        left.write_u64(full_epoch);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_SECRET_RIGHT_DOMAIN);
        right.write_u16(zone_id);
        right.write_u64(full_epoch);

        [left.finish(), right.finish()]
    }

    pub(super) fn cache_hash_keys(&self) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_CACHE_LEFT_DOMAIN);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_CACHE_RIGHT_DOMAIN);

        [left.finish(), right.finish()]
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SipHash24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: [u8; 8],
    tail_len: usize,
    len: u64,
}

impl SipHash24 {
    pub(super) fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
            tail: [0; 8],
            tail_len: 0,
            len: 0,
        }
    }

    pub(super) fn write_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.write_u8(4);
                self.write_bytes(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.write_u8(6);
                self.write_bytes(&v6.octets());
            }
        }
    }

    pub(super) fn write_u8(&mut self, value: u8) {
        self.write_bytes(&[value]);
    }

    pub(super) fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(super) fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(super) fn write_bytes(&mut self, mut bytes: &[u8]) {
        self.len += bytes.len() as u64;

        if self.tail_len > 0 {
            let fill = (8 - self.tail_len).min(bytes.len());
            self.tail[self.tail_len..self.tail_len + fill].copy_from_slice(&bytes[..fill]);
            self.tail_len += fill;
            bytes = &bytes[fill..];
            if self.tail_len == 8 {
                self.compress(u64::from_le_bytes(self.tail));
                self.tail = [0; 8];
                self.tail_len = 0;
            }
        }

        while bytes.len() >= 8 {
            let block = u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice"));
            self.compress(block);
            bytes = &bytes[8..];
        }

        if !bytes.is_empty() {
            self.tail[..bytes.len()].copy_from_slice(bytes);
            self.tail_len = bytes.len();
        }
    }

    pub(super) fn finish(mut self) -> u64 {
        let mut last = self.len << 56;
        let mut i = 0;
        while i < self.tail_len {
            last |= (self.tail[i] as u64) << (8 * i);
            i += 1;
        }
        self.compress(last);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }

    fn compress(&mut self, block: u64) {
        self.v3 ^= block;
        self.round();
        self.round();
        self.v0 ^= block;
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(13);
        self.v3 = self.v3.rotate_left(16);
        self.v1 ^= self.v0;
        self.v3 ^= self.v2;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(17);
        self.v3 = self.v3.rotate_left(21);
        self.v1 ^= self.v2;
        self.v3 ^= self.v0;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SynCookieValidatedKey {
    zone_id: u16,
    tuple: SynCookieTuple,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedEntry {
    key: SynCookieValidatedKey,
    expires_secs: u64,
    age: u64,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedSet {
    entries: [Option<SynCookieValidatedEntry>; SYN_COOKIE_VALIDATED_CACHE_WAYS],
}

impl Default for SynCookieValidatedSet {
    fn default() -> Self {
        Self {
            entries: [None; SYN_COOKIE_VALIDATED_CACHE_WAYS],
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SynCookieValidatedCache {
    sets: Box<[SynCookieValidatedSet]>,
    ttl_secs: u64,
    hash_keys: [u64; 2],
    len: usize,
    clock: u64,
}

impl Default for SynCookieValidatedCache {
    fn default() -> Self {
        Self::new(
            SYN_COOKIE_VALIDATED_CACHE_CAPACITY,
            SYN_COOKIE_VALIDATED_CACHE_TTL_SECS,
        )
    }
}

impl SynCookieValidatedCache {
    pub(super) fn new(capacity: usize, ttl_secs: u64) -> Self {
        let set_count = capacity.div_ceil(SYN_COOKIE_VALIDATED_CACHE_WAYS);
        Self {
            sets: vec![SynCookieValidatedSet::default(); set_count].into_boxed_slice(),
            ttl_secs,
            hash_keys: [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908],
            len: 0,
            clock: 0,
        }
    }

    pub(super) fn insert(&mut self, zone_id: u16, tuple: SynCookieTuple, now_secs: u64) {
        if self.sets.is_empty() {
            return;
        }
        let key = SynCookieValidatedKey { zone_id, tuple };
        let set_index = self.set_index(&key);
        self.clock = self.clock.wrapping_add(1);
        let set = &mut self.sets[set_index];
        let new_entry = SynCookieValidatedEntry {
            key,
            expires_secs: now_secs.saturating_add(self.ttl_secs),
            age: self.clock,
        };

        let mut empty_or_expired = None;
        let mut oldest_index = 0;
        let mut oldest_age = u64::MAX;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            match set.entries[index] {
                Some(entry) if entry.key == key => {
                    set.entries[index] = Some(new_entry);
                    return;
                }
                Some(entry) if entry.expires_secs <= now_secs => {
                    empty_or_expired.get_or_insert(index);
                }
                Some(entry) => {
                    if entry.age < oldest_age {
                        oldest_age = entry.age;
                        oldest_index = index;
                    }
                }
                None => {
                    empty_or_expired.get_or_insert(index);
                }
            }
        }

        let replace_index = empty_or_expired.unwrap_or(oldest_index);
        if set.entries[replace_index].is_none() {
            self.len += 1;
        }
        set.entries[replace_index] = Some(new_entry);
    }

    pub(super) fn take_valid(
        &mut self,
        zone_id: u16,
        tuple: SynCookieTuple,
        now_secs: u64,
    ) -> bool {
        if self.sets.is_empty() {
            return false;
        }
        let key = SynCookieValidatedKey { zone_id, tuple };
        let set_index = self.set_index(&key);
        let set = &mut self.sets[set_index];
        let mut valid = false;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            let Some(entry) = set.entries[index] else {
                continue;
            };
            if entry.key == key {
                valid = entry.expires_secs > now_secs;
                set.entries[index] = None;
                self.len = self.len.saturating_sub(1);
                break;
            }
            if entry.expires_secs <= now_secs {
                set.entries[index] = None;
                self.len = self.len.saturating_sub(1);
            }
        }

        valid
    }

    pub(super) fn set_hash_keys(&mut self, hash_keys: [u64; 2]) {
        if self.hash_keys != hash_keys {
            self.hash_keys = hash_keys;
            self.clear();
        }
    }

    pub(super) fn clear(&mut self) {
        for set in self.sets.iter_mut() {
            *set = SynCookieValidatedSet::default();
        }
        self.len = 0;
        self.clock = 0;
    }

    fn set_index(&self, key: &SynCookieValidatedKey) -> usize {
        debug_assert!(!self.sets.is_empty());
        (self.key_hash(key) as usize) % self.sets.len()
    }

    fn key_hash(&self, key: &SynCookieValidatedKey) -> u64 {
        let mut sip = SipHash24::new(self.hash_keys[0], self.hash_keys[1]);
        sip.write_u16(key.zone_id);
        sip.write_ip(key.tuple.src_ip);
        sip.write_ip(key.tuple.dst_ip);
        sip.write_u16(key.tuple.src_port);
        sip.write_u16(key.tuple.dst_port);
        sip.finish()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.sets.len() * SYN_COOKIE_VALIDATED_CACHE_WAYS
    }

    #[cfg(test)]
    pub(super) fn debug_set_index(&self, zone_id: u16, tuple: SynCookieTuple) -> Option<usize> {
        if self.sets.is_empty() {
            return None;
        }
        Some(self.set_index(&SynCookieValidatedKey { zone_id, tuple }))
    }
}
