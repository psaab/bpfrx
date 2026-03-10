use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixV4 {
    network: u32,
    mask: u32,
    prefix_len: u8,
}

impl PrefixV4 {
    pub(crate) fn from_net(net: Ipv4Net) -> Self {
        let prefix_len = net.prefix_len();
        let mask = mask_v4(prefix_len);
        Self {
            network: u32::from(net.addr()) & mask,
            mask,
            prefix_len,
        }
    }

    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub(crate) fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixV6 {
    network: u128,
    mask: u128,
    prefix_len: u8,
}

impl PrefixV6 {
    pub(crate) fn from_net(net: Ipv6Net) -> Self {
        let prefix_len = net.prefix_len();
        let mask = mask_v6(prefix_len);
        Self {
            network: u128::from(net.addr()) & mask,
            mask,
            prefix_len,
        }
    }

    pub(crate) fn contains(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask) == self.network
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub(crate) fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }
}

const fn mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_v4_matches_expected_addresses() {
        let prefix = PrefixV4::from_net("10.0.61.0/24".parse().expect("prefix"));
        assert!(prefix.contains("10.0.61.100".parse().expect("match")));
        assert!(!prefix.contains("10.0.62.100".parse().expect("mismatch")));
        assert_eq!(prefix.prefix_len(), 24);
    }

    #[test]
    fn prefix_v6_matches_expected_addresses() {
        let prefix = PrefixV6::from_net("2001:559:8585:80::/64".parse().expect("prefix"));
        assert!(prefix.contains("2001:559:8585:80::200".parse().expect("match")));
        assert!(!prefix.contains("2001:559:8585:81::200".parse().expect("mismatch")));
        assert_eq!(prefix.prefix_len(), 64);
    }
}
