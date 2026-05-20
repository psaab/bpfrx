use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnet::IpNet;

/// A Trie-based Longest Prefix Match (LPM) map.
#[derive(Debug, Clone)]
pub(crate) struct PrefixMap<V> {
    v4: PrefixTrie<V>,
    v6: PrefixTrie<V>,
}

#[derive(Debug)]
struct PrefixTrie<V> {
    root: TrieNode<V>,
}

impl<V: Clone> Clone for PrefixTrie<V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}

impl<V> Default for PrefixTrie<V> {
    fn default() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }
}

#[derive(Debug)]
struct TrieNode<V> {
    value: Option<V>,
    children: [Option<Box<TrieNode<V>>>; 2],
}

impl<V: Clone> Clone for TrieNode<V> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            children: [
                self.children[0].clone(),
                self.children[1].clone(),
            ],
        }
    }
}

impl<V> Default for TrieNode<V> {
    fn default() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }
}

impl<V: Clone> PrefixMap<V> {
    pub(crate) fn new() -> Self {
        Self {
            v4: PrefixTrie::default(),
            v6: PrefixTrie::default(),
        }
    }

    pub(crate) fn insert(&mut self, net: IpNet, value: V) {
        match net {
            IpNet::V4(net_v4) => {
                let bits = u32::from(net_v4.addr());
                let depth = net_v4.prefix_len() as usize;
                let mut node = &mut self.v4.root;
                for i in 0..depth {
                    let bit = ((bits >> (31 - i)) & 1) as usize;
                    node = node.children[bit].get_or_insert_with(Box::default);
                }
                node.value = Some(value);
            }
            IpNet::V6(net_v6) => {
                let bits = u128::from(net_v6.addr());
                let depth = net_v6.prefix_len() as usize;
                let mut node = &mut self.v6.root;
                for i in 0..depth {
                    let bit = ((bits >> (127 - i)) & 1) as usize;
                    node = node.children[bit].get_or_insert_with(Box::default);
                }
                node.value = Some(value);
            }
        }
    }

    pub(crate) fn longest_match(&self, ip: IpAddr) -> Option<&V> {
        match ip {
            IpAddr::V4(ip_v4) => {
                let bits = u32::from(ip_v4);
                let mut node = &self.v4.root;
                let mut best_match = node.value.as_ref();
                
                for i in 0..32 {
                    let bit = ((bits >> (31 - i)) & 1) as usize;
                    match node.children[bit].as_deref() {
                        Some(next) => {
                            if next.value.is_some() {
                                best_match = next.value.as_ref();
                            }
                            node = next;
                        }
                        None => break,
                    }
                }
                best_match
            }
            IpAddr::V6(ip_v6) => {
                let bits = u128::from(ip_v6);
                let mut node = &self.v6.root;
                let mut best_match = node.value.as_ref();
                
                for i in 0..128 {
                    let bit = ((bits >> (127 - i)) & 1) as usize;
                    match node.children[bit].as_deref() {
                        Some(next) => {
                            if next.value.is_some() {
                                best_match = next.value.as_ref();
                            }
                            node = next;
                        }
                        None => break,
                    }
                }
                best_match
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_prefix_map_lpm() {
        let mut map = PrefixMap::new();
        map.insert(IpNet::from_str("10.0.0.0/8").unwrap(), "v4-8");
        map.insert(IpNet::from_str("10.1.0.0/16").unwrap(), "v4-16");
        map.insert(IpNet::from_str("10.1.1.0/24").unwrap(), "v4-24");
        map.insert(IpNet::from_str("0.0.0.0/0").unwrap(), "default-v4");

        // Exact match /24
        assert_eq!(map.longest_match(IpAddr::from_str("10.1.1.1").unwrap()), Some(&"v4-24"));
        // LPM match /16
        assert_eq!(map.longest_match(IpAddr::from_str("10.1.2.1").unwrap()), Some(&"v4-16"));
        // LPM match /8
        assert_eq!(map.longest_match(IpAddr::from_str("10.2.1.1").unwrap()), Some(&"v4-8"));
        // Default route
        assert_eq!(map.longest_match(IpAddr::from_str("192.168.1.1").unwrap()), Some(&"default-v4"));

        // V6 test
        let mut map6 = PrefixMap::new();
        map6.insert(IpNet::from_str("2001:db8::/32").unwrap(), "v6-32");
        map6.insert(IpNet::from_str("2001:db8:1::/48").unwrap(), "v6-48");
        map6.insert(IpNet::from_str("::/0").unwrap(), "default-v6");

        assert_eq!(map6.longest_match(IpAddr::from_str("2001:db8:1::1").unwrap()), Some(&"v6-48"));
        assert_eq!(map6.longest_match(IpAddr::from_str("2001:db8:2::1").unwrap()), Some(&"v6-32"));
        assert_eq!(map6.longest_match(IpAddr::from_str("fe80::1").unwrap()), Some(&"default-v6"));
    }
}
