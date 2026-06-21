// Destination NAT (DNAT) table — O(1) lookup by (protocol, dst_ip, dst_port).

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::DestinationNATRuleSnapshot;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub(super) use crate::ip_proto::{PROTO_TCP, PROTO_UDP};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    pub protocol: u8,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnatValue {
    pub new_dst_ip: IpAddr,
    pub new_dst_port: u16,
}

#[derive(Clone, Debug)]
struct DnatEntry {
    from_zone: Box<str>,
    value: DnatValue,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    hit_counter: Option<Arc<NatRuleCounter>>,
}

/// Destination NAT lookup table.
///
/// Entries are keyed by `(protocol, dst_ip, dst_port)`. A wildcard port
/// entry (`dst_port = 0`) matches any destination port when no exact-port
/// entry exists.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, Vec<DnatEntry>>,
}

impl DnatTable {
    pub(crate) fn from_snapshots(
        snaps: &[DestinationNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = DnatTable::default();
        for snap in snaps {
            let dst_ip: IpAddr = match snap.destination_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let pool_ip: IpAddr = match snap.pool_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            // Determine protocol(s) to insert entries for.
            let protos: Vec<u8> = match snap.protocol.as_str() {
                "tcp" => vec![PROTO_TCP],
                "udp" => vec![PROTO_UDP],
                "" => {
                    if snap.destination_port != 0 {
                        // Port-based rule with no explicit protocol: default TCP
                        vec![PROTO_TCP]
                    } else {
                        // No protocol, no port: expand to both TCP and UDP
                        vec![PROTO_TCP, PROTO_UDP]
                    }
                }
                _ => continue,
            };
            let hit_counter = nat_counters.rule_counter(snap.counter_id);
            for proto in protos {
                Self::insert_entry(
                    table.entries.entry(DnatKey {
                        protocol: proto,
                        dst_ip,
                        dst_port: snap.destination_port,
                    }),
                    DnatEntry {
                        from_zone: snap.from_zone.clone().into_boxed_str(),
                        value: DnatValue {
                            new_dst_ip: pool_ip,
                            new_dst_port: if snap.pool_port != 0 {
                                snap.pool_port
                            } else {
                                snap.destination_port
                            },
                        },
                        hit_counter: hit_counter.clone(),
                    },
                );
            }
        }
        table
    }

    /// Look up a DNAT entry for the given packet fields.
    ///
    /// 1. Exact match: `(protocol, dst_ip, dst_port)`
    /// 2. Wildcard port fallback: `(protocol, dst_ip, 0)`
    ///
    /// Returns just the decision; existing callers/tests keep their
    /// `Option<NatDecision>` shape. The cold path uses
    /// [`lookup_with_counter`] (#2218) to also obtain the matched rule's
    /// per-rule hit counter — `NatDecision` (wire-frozen over HA) does NOT
    /// grow a field.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        self.lookup_with_counter(protocol, dst_ip, dst_port, ingress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`lookup`] but also returns the matched entry's per-rule
    /// hit counter (if any), for the cold-path commit site.
    pub(crate) fn lookup_with_counter(
        &self,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        let (value, hit_counter) = self
            .match_entries(
                self.entries.get(&DnatKey {
                    protocol,
                    dst_ip,
                    dst_port,
                }),
                ingress_zone,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    ingress_zone,
                )
            })?;
        let rewrite_dst_port = if value.new_dst_port != 0 && value.new_dst_port != dst_port {
            Some(value.new_dst_port)
        } else {
            None
        };
        Some((
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(value.new_dst_ip),
                rewrite_src_port: None,
                rewrite_dst_port,
                nat64: false,
                nptv6: false,
            },
            hit_counter,
        ))
    }

    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        ingress_zone: &str,
    ) -> Option<(DnatValue, Option<Arc<NatRuleCounter>>)> {
        let entries = entries?;
        entries
            .iter()
            .find(|entry| !entry.from_zone.is_empty() && entry.from_zone.as_ref() == ingress_zone)
            .map(|entry| (entry.value, entry.hit_counter.clone()))
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.from_zone.is_empty())
                    .map(|entry| (entry.value, entry.hit_counter.clone()))
            })
    }

    fn insert_entry(
        slot: std::collections::hash_map::Entry<'_, DnatKey, Vec<DnatEntry>>,
        entry: DnatEntry,
    ) {
        let entries = slot.or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.from_zone == entry.from_zone)
        {
            *existing = entry;
            return;
        }
        entries.push(entry);
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all destination IPs (the external/public IPs that DNAT rules match on).
    /// These must be registered as local addresses so traffic to them is recognized.
    pub(crate) fn destination_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        // Deduplicate by collecting unique dst_ip values.
        let mut seen = FxHashMap::default();
        for key in self.entries.keys() {
            seen.entry(key.dst_ip).or_insert(());
        }
        seen.into_keys()
    }
}
