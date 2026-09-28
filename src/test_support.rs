//! Helpers shared by the unit tests in each module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::Acl;

pub(crate) fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

pub(crate) fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

pub(crate) fn cidr(s: &str) -> IpNet {
    s.parse().unwrap()
}

pub(crate) fn deny_local() -> Acl {
    Acl::new().deny_local_network()
}
