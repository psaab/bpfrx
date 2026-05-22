use ipnet::IpNet;
use std::net::IpAddr;

struct PrefixTrie<V> {
    nodes: Vec<TrieNode<V>>,
}

struct TrieNode<V> {
    value: Option<V>,
    children: [Option<u32>; 2],
}

impl<V> PrefixTrie<V> {
    fn new() -> Self {
        Self {
            nodes: vec![TrieNode {
                value: None,
                children: [None, None],
            }],
        }
    }

    fn ensure_child(&mut self, idx: u32, bit: usize) -> u32 {
        if let Some(child) = self.nodes[idx as usize].children[bit] {
            return child;
        }
        let new_idx = self.nodes.len() as u32;
        self.nodes.push(TrieNode {
            value: None,
            children: [None, None],
        });
        self.nodes[idx as usize].children[bit] = Some(new_idx);
        new_idx
    }

    fn insert(&mut self, key: &[u8], prefix_len: usize, value: V) {
        let mut idx = 0u32;
        for i in 0..prefix_len {
            let byte = key[i / 8];
            let bit = ((byte >> (7 - (i % 8))) & 1) as usize;
            idx = self.ensure_child(idx, bit);
        }
        self.nodes[idx as usize].value = Some(value);
    }

    fn longest_match(&self, key: &[u8], total_bits: usize) -> Option<&V> {
        let mut idx = 0u32;
        let mut last: Option<&V> = self.nodes[0].value.as_ref();
        for i in 0..total_bits {
            let byte = key[i / 8];
            let bit = ((byte >> (7 - (i % 8))) & 1) as usize;
            match self.nodes[idx as usize].children[bit] {
                Some(child) => {
                    idx = child;
                    if let Some(ref v) = self.nodes[idx as usize].value {
                        last = Some(v);
                    }
                }
                None => break,
            }
        }
        last
    }
}

pub(crate) struct PrefixMap<V> {
    v4: PrefixTrie<V>,
    v6: PrefixTrie<V>,
}

impl<V: Clone> PrefixMap<V> {
    pub(crate) fn new() -> Self {
        Self {
            v4: PrefixTrie::new(),
            v6: PrefixTrie::new(),
        }
    }

    pub(crate) fn insert(&mut self, net: IpNet, value: V) {
        match net {
            IpNet::V4(v4) => {
                self.v4.insert(&v4.addr().octets(), v4.prefix_len() as usize, value);
            }
            IpNet::V6(v6) => {
                self.v6.insert(&v6.addr().octets(), v6.prefix_len() as usize, value);
            }
        }
    }

    pub(crate) fn longest_match(&self, ip: IpAddr) -> Option<&V> {
        match ip {
            IpAddr::V4(v4) => self.v4.longest_match(&v4.octets(), 32),
            IpAddr::V6(v6) => self.v6.longest_match(&v6.octets(), 128),
        }
    }
}
