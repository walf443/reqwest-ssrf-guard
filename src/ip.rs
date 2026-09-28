use std::net::IpAddr;

/// Returns `true` if `ip` belongs to a local / non-routable network.
///
/// Concretely: IPv4 private ranges (RFC1918), loopback (`127.0.0.0/8`),
/// link-local (`169.254.0.0/16`), shared / CGNAT (`100.64.0.0/10`, RFC6598
/// — covers Alibaba Cloud's `100.100.100.200` metadata endpoint),
/// `0.0.0.0/8`, broadcast; IPv6 loopback (`::1`), unspecified (`::`),
/// unique local (`fc00::/7`), link-local (`fe80::/10`), IPv4-mapped
/// (`::ffff:a.b.c.d`) variants of the above, and IPv4 addresses embedded in
/// NAT64 (`64:ff9b::/96`, RFC6052) or 6to4 (`2002::/16`, RFC3056) addresses
/// (e.g. `64:ff9b::7f00:1` resolves to `127.0.0.1`).
///
/// AWS / GCP / Azure / DigitalOcean / Oracle / Hetzner / IBM Cloud
/// metadata endpoints all live in `169.254.169.254` (link-local) and are
/// therefore covered. AWS IPv6 metadata (`fd00:ec2::254`) falls inside the
/// IPv6 ULA range and is covered too.
pub fn is_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                // 0.0.0.0/8 ("this network")
                || oct[0] == 0
                // 100.64.0.0/10 — RFC6598 shared address space / CGNAT
                || (oct[0] == 100 && (oct[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let segs = v6.segments();
            // Unique local fc00::/7
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // Link-local fe80::/10
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // IPv4-mapped (::ffff:a.b.c.d) — delegate to v4 check
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_network(IpAddr::V4(v4));
            }
            // NAT64 well-known prefix (64:ff9b::/96, RFC6052) and 6to4
            // (2002::/16, RFC3056) embed an IPv4 address that can be used to
            // reach an internal v4 target via a translating gateway. Extract
            // it and re-check against the v4 rules.
            if let Some(v4) = embedded_ipv4(segs) {
                return is_local_network(IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Extracts an IPv4 address embedded in an IPv6 address via the NAT64
/// well-known prefix (`64:ff9b::/96`, RFC6052) or 6to4 (`2002::/16`, RFC3056).
///
/// These transition mechanisms carry an IPv4 destination inside the IPv6
/// address, so e.g. `64:ff9b::7f00:1` maps to `127.0.0.1` and `2002:7f00:1::`
/// maps to `127.0.0.1` — both classic SSRF bypasses on networks where a
/// translating gateway is present. Returns `None` for any other address.
fn embedded_ipv4(segs: [u16; 8]) -> Option<std::net::Ipv4Addr> {
    // NAT64 well-known prefix 64:ff9b::/96 — IPv4 is the last 32 bits.
    if segs[0] == 0x0064
        && segs[1] == 0xff9b
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        return Some(std::net::Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ));
    }
    // 6to4 2002::/16 — IPv4 is bits 16..48 (segs[1] and segs[2]).
    if segs[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    // --- is_local_network -------------------------------------------------

    #[test]
    fn denies_ipv4_private_ranges() {
        for ip in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
        ] {
            assert!(is_local_network(v4(ip)), "{ip} should be denied");
        }
    }

    #[test]
    fn denies_ipv4_loopback_and_linklocal_and_zero_and_broadcast() {
        for ip in [
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
        ] {
            assert!(is_local_network(v4(ip)), "{ip} should be denied");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.0.2.1",
        ] {
            assert!(!is_local_network(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn denies_cgnat_range() {
        // 100.64.0.0/10 — RFC6598 shared address space.
        // Includes Alibaba Cloud's `100.100.100.200` metadata endpoint.
        for ip in [
            "100.64.0.0",
            "100.64.0.1",
            "100.100.100.200",
            "100.127.255.255",
        ] {
            assert!(is_local_network(v4(ip)), "{ip} should be denied (CGNAT)");
        }
    }

    #[test]
    fn allows_addresses_adjacent_to_cgnat() {
        // Guard against an over-broad mask catching neighbours of 100.64.0.0/10.
        for ip in ["100.63.255.255", "100.128.0.0", "99.255.255.255"] {
            assert!(!is_local_network(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn denies_cloud_metadata_endpoints() {
        // Sanity check for the most common cloud metadata IPs.
        assert!(
            is_local_network(v4("169.254.169.254")),
            "AWS/GCP/Azure IMDS"
        );
        assert!(is_local_network(v4("100.100.100.200")), "Alibaba IMDS");
        assert!(is_local_network(v6("fd00:ec2::254")), "AWS IPv6 IMDS");
    }

    #[test]
    fn denies_ipv6_local() {
        for ip in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1"] {
            assert!(is_local_network(v6(ip)), "{ip} should be denied");
        }
    }

    #[test]
    fn allows_public_ipv6() {
        for ip in ["2001:db8::1", "2606:4700:4700::1111"] {
            assert!(!is_local_network(v6(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn denies_ipv4_mapped_local() {
        assert!(is_local_network(v6("::ffff:127.0.0.1")));
        assert!(is_local_network(v6("::ffff:192.168.1.1")));
        assert!(!is_local_network(v6("::ffff:8.8.8.8")));
    }

    #[test]
    fn denies_nat64_embedded_local() {
        // 64:ff9b::/96 well-known prefix with a local IPv4 embedded.
        assert!(is_local_network(v6("64:ff9b::7f00:1")), "127.0.0.1");
        assert!(is_local_network(v6("64:ff9b::a00:1")), "10.0.0.1");
        assert!(
            is_local_network(v6("64:ff9b::a9fe:a9fe")),
            "169.254.169.254 IMDS"
        );
        // A NAT64-embedded public address must still be allowed.
        assert!(!is_local_network(v6("64:ff9b::808:808")), "8.8.8.8");
    }

    #[test]
    fn denies_6to4_embedded_local() {
        // 2002::/16 with a local IPv4 embedded in bits 16..48.
        assert!(is_local_network(v6("2002:7f00:1::")), "127.0.0.1");
        assert!(is_local_network(v6("2002:a00:1::")), "10.0.0.1");
        assert!(
            is_local_network(v6("2002:a9fe:a9fe::")),
            "169.254.169.254 IMDS"
        );
        // A 6to4-embedded public address must still be allowed.
        assert!(!is_local_network(v6("2002:808:808::")), "8.8.8.8");
    }
}
