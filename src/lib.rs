//! IP-based ACL for [`reqwest`] — mitigate SSRF / DNS rebinding by filtering
//! the addresses returned from DNS and rejecting URLs whose host is an IP
//! literal denied by the ACL.
//!
//! # Quick start
//!
//! The [`Acl`] builder is both the policy and the [`Resolve`] impl, so you
//! can hand it straight to reqwest:
//!
//! ```no_run
//! use std::sync::Arc;
//! use reqwest_acl::Acl;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = reqwest::Client::builder()
//!     .dns_resolver(Arc::new(Acl::new().deny_local_network()))
//!     .build()?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```
//!
//! # Customizing
//!
//! Combine presets with explicit rules. Explicit `allow_*` rules always win
//! over `deny_*`, so the natural "deny local network, except for this one
//! address" pattern just works:
//!
//! ```no_run
//! use std::sync::Arc;
//! use reqwest_acl::Acl;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let acl = Acl::new()
//!     .deny_local_network()
//!     .allow_cidr("192.168.1.100/32".parse()?);
//!
//! let client = reqwest::Client::builder()
//!     .dns_resolver(Arc::new(acl))
//!     .build()?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipnet::IpNet;
use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

pub use ipnet;

// ---------------------------------------------------------------------------
// IpAcl
// ---------------------------------------------------------------------------

/// An access-control predicate over IP addresses.
///
/// Custom ACLs implement [`is_allowed_ip`](Self::is_allowed_ip);
/// [`check_url`](Self::check_url) is provided by default and reuses
/// `is_allowed_ip` to filter URLs whose host is an IP literal (which would
/// otherwise bypass DNS).
pub trait IpAcl: Send + Sync + 'static {
    /// Return `true` if connecting to `ip` is permitted.
    fn is_allowed_ip(&self, ip: IpAddr) -> bool;

    /// Reject `url` if its host is a literal IP denied by
    /// [`is_allowed_ip`](Self::is_allowed_ip).
    ///
    /// URLs with domain hostnames are accepted here — the DNS-side filtering
    /// (via [`Acl`] or [`AclResolver`]) handles them. Call this before
    /// handing a user-supplied URL to reqwest to close the IP-literal gap.
    fn check_url(&self, url: &Url) -> Result<(), AclError> {
        let Some(host) = url.host() else { return Ok(()) };
        let ip = match host {
            url::Host::Ipv4(v4) => IpAddr::V4(v4),
            url::Host::Ipv6(v6) => IpAddr::V6(v6),
            url::Host::Domain(_) => return Ok(()),
        };
        if self.is_allowed_ip(ip) {
            Ok(())
        } else {
            Err(AclError::DeniedIp(ip))
        }
    }
}

/// Returned by [`IpAcl::check_url`] when a URL is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    /// A URL whose host is a literal IP that was denied.
    DeniedIp(IpAddr),
    /// A URL whose host is a domain name that was denied.
    DeniedHost(String),
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeniedIp(ip) => write!(f, "address {ip} is denied by ACL"),
            Self::DeniedHost(h) => write!(f, "host {h} is denied by ACL"),
        }
    }
}

impl std::error::Error for AclError {}

// ---------------------------------------------------------------------------
// Acl — composable builder
// ---------------------------------------------------------------------------

/// A composable ACL built from allow/deny rules.
///
/// # Evaluation
///
/// The ACL has two layers — host rules and IP rules — both following the same
/// "explicit allow always wins" semantics.
///
/// Host rules are checked first. The hostname (after lowercasing and
/// stripping any trailing dot) is matched against the host rules:
///
/// 1. Any host `allow_*` rule matches → **allow** the whole connection,
///    bypassing the IP layer entirely. ⚠ This disables the SSRF / DNS
///    rebinding protection for that host — use only for hosts you fully
///    trust.
/// 2. Any host `deny_*` rule matches → **deny** without even resolving DNS.
/// 3. Otherwise → fall through to the IP layer.
///
/// At the IP layer (after DNS resolution, or for IP-literal URLs):
///
/// 1. Any IP `allow_*` rule matches → **allow**.
/// 2. Else any IP `deny_*` rule matches → deny.
/// 3. Else fall back to the default (allow, unless flipped via
///    [`default_deny`](Self::default_deny)).
///
/// Rule order does not matter within a layer.
///
/// ```
/// use reqwest_acl::{Acl, IpAcl};
/// let acl = Acl::new()
///     .deny_local_network()
///     .allow_cidr("192.168.1.100/32".parse().unwrap());
/// assert!(!acl.is_allowed_ip("10.0.0.1".parse().unwrap()));      // denied
/// assert!( acl.is_allowed_ip("192.168.1.100".parse().unwrap())); // exception wins
/// assert!( acl.is_allowed_ip("8.8.8.8".parse().unwrap()));       // public — default allow
/// ```
#[derive(Clone)]
pub struct Acl {
    rules: Vec<Rule>,
    host_rules: Vec<HostRule>,
    default_allow: bool,
}

#[derive(Clone)]
enum Rule {
    Allow(Arc<dyn Fn(IpAddr) -> bool + Send + Sync>),
    Deny(Arc<dyn Fn(IpAddr) -> bool + Send + Sync>),
}

#[derive(Clone)]
enum HostRule {
    Allow(Arc<dyn Fn(&str) -> bool + Send + Sync>),
    Deny(Arc<dyn Fn(&str) -> bool + Send + Sync>),
}

/// Outcome of [`Acl::host_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDecision {
    /// The host is explicitly allowed; skip IP filtering.
    Allow,
    /// The host is explicitly denied; reject without resolving DNS.
    Deny,
    /// No host rule matched; proceed to the IP layer.
    Continue,
}

fn normalize_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

impl Acl {
    /// Create an empty ACL whose default decision is "allow". Use
    /// [`default_deny`](Self::default_deny) to switch to allowlist mode.
    pub fn new() -> Self {
        Self {
            rules: vec![],
            host_rules: vec![],
            default_allow: true,
        }
    }

    /// Append a deny rule matching every address on the local network.
    /// See [`is_local_network`] for the exact set.
    pub fn deny_local_network(self) -> Self {
        self.deny_ip_when(is_local_network)
    }

    /// Deny any IP for which `f` returns true.
    pub fn deny_ip_when<F>(mut self, f: F) -> Self
    where
        F: Fn(IpAddr) -> bool + Send + Sync + 'static,
    {
        self.rules.push(Rule::Deny(Arc::new(f)));
        self
    }

    /// Allow any IP for which `f` returns true. Explicit allow overrides any
    /// matching deny rule.
    pub fn allow_ip_when<F>(mut self, f: F) -> Self
    where
        F: Fn(IpAddr) -> bool + Send + Sync + 'static,
    {
        self.rules.push(Rule::Allow(Arc::new(f)));
        self
    }

    /// Deny every address inside `cidr`. For a single IP, pass `/32` (v4) or
    /// `/128` (v6).
    pub fn deny_cidr(self, cidr: IpNet) -> Self {
        self.deny_ip_when(move |ip| cidr.contains(&ip))
    }

    /// Allow every address inside `cidr` (overrides any matching deny rule).
    /// For a single IP, pass `/32` (v4) or `/128` (v6).
    pub fn allow_cidr(self, cidr: IpNet) -> Self {
        self.allow_ip_when(move |ip| cidr.contains(&ip))
    }

    /// Deny the exact hostname `name` (case-insensitive). Matches the host
    /// portion of the URL, *not* the URL's resolved IP — so this is checked
    /// before DNS resolution.
    pub fn deny_host(self, name: impl Into<String>) -> Self {
        let target = normalize_host(&name.into());
        self.deny_host_when(move |h| h == target)
    }

    /// Allow the exact hostname `name` (case-insensitive). ⚠ Bypasses all
    /// IP-level filtering for that host — see the type docs.
    pub fn allow_host(self, name: impl Into<String>) -> Self {
        let target = normalize_host(&name.into());
        self.allow_host_when(move |h| h == target)
    }

    /// Deny any hostname that ends with `suffix` (case-insensitive). Pass a
    /// leading dot (`".example.com"`) to match strict subdomains only.
    pub fn deny_host_suffix(self, suffix: impl Into<String>) -> Self {
        let suffix = normalize_host(&suffix.into());
        self.deny_host_when(move |h| h.ends_with(&suffix))
    }

    /// Allow any hostname that ends with `suffix` (case-insensitive). Pass a
    /// leading dot to match strict subdomains only. ⚠ Bypasses IP filtering.
    pub fn allow_host_suffix(self, suffix: impl Into<String>) -> Self {
        let suffix = normalize_host(&suffix.into());
        self.allow_host_when(move |h| h.ends_with(&suffix))
    }

    /// Deny any hostname for which `f` returns true. The hostname passed to
    /// `f` is already lowercased and stripped of any trailing dot.
    pub fn deny_host_when<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.host_rules.push(HostRule::Deny(Arc::new(f)));
        self
    }

    /// Allow any hostname for which `f` returns true. The hostname passed to
    /// `f` is already lowercased and stripped of any trailing dot. ⚠ Bypasses
    /// IP filtering.
    pub fn allow_host_when<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.host_rules.push(HostRule::Allow(Arc::new(f)));
        self
    }

    /// Apply the host rules to `host` and return what the ACL wants to do.
    pub fn host_decision(&self, host: &str) -> HostDecision {
        let host = normalize_host(host);
        let mut any_allow = false;
        let mut any_deny = false;
        for rule in &self.host_rules {
            match rule {
                HostRule::Allow(f) if f(&host) => any_allow = true,
                HostRule::Deny(f) if f(&host) => any_deny = true,
                _ => {}
            }
        }
        if any_allow {
            HostDecision::Allow
        } else if any_deny {
            HostDecision::Deny
        } else {
            HostDecision::Continue
        }
    }

    /// Flip the default decision to deny — useful for allowlist-style ACLs
    /// where only the explicitly allowed IPs are permitted.
    pub fn default_deny(mut self) -> Self {
        self.default_allow = false;
        self
    }
}

impl IpAcl for Acl {
    fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        let mut explicit_allow = false;
        let mut explicit_deny = false;
        for rule in &self.rules {
            match rule {
                Rule::Allow(f) if f(ip) => explicit_allow = true,
                Rule::Deny(f) if f(ip) => explicit_deny = true,
                _ => {}
            }
        }
        if explicit_allow {
            return true;
        }
        if explicit_deny {
            return false;
        }
        self.default_allow
    }

    fn check_url(&self, url: &Url) -> Result<(), AclError> {
        let Some(host) = url.host() else { return Ok(()) };
        match host {
            url::Host::Domain(name) => match self.host_decision(name) {
                HostDecision::Allow | HostDecision::Continue => Ok(()),
                HostDecision::Deny => Err(AclError::DeniedHost(normalize_host(name))),
            },
            url::Host::Ipv4(v4) => {
                let ip = IpAddr::V4(v4);
                if self.is_allowed_ip(ip) {
                    Ok(())
                } else {
                    Err(AclError::DeniedIp(ip))
                }
            }
            url::Host::Ipv6(v6) => {
                let ip = IpAddr::V6(v6);
                if self.is_allowed_ip(ip) {
                    Ok(())
                } else {
                    Err(AclError::DeniedIp(ip))
                }
            }
        }
    }
}

impl Resolve for Acl {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let host_decision = self.host_decision(&host);
        let acl: Arc<dyn IpAcl> = Arc::new(self.clone());
        Box::pin(async move {
            match host_decision {
                HostDecision::Deny => Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("host {host} is denied by ACL"),
                )) as Box<dyn std::error::Error + Send + Sync>),
                HostDecision::Allow => {
                    // Trusted host: resolve and return everything without IP filtering.
                    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                        .collect();
                    let addrs: Addrs = Box::new(resolved.into_iter());
                    Ok(addrs)
                }
                HostDecision::Continue => {
                    // Fall through to IP-layer filtering via resolve_with.
                    resolve_with_inner(host, acl).await
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// AclResolver — wrap any IpAcl as reqwest::dns::Resolve
// ---------------------------------------------------------------------------

/// Adapter that turns any [`IpAcl`] into a [`reqwest::dns::Resolve`].
///
/// Resolves the hostname via the system resolver (`tokio::net::lookup_host`),
/// then filters the results through the ACL. If every resolved address is
/// rejected, the request fails with `PermissionDenied`.
pub struct AclResolver {
    acl: Arc<dyn IpAcl>,
}

impl AclResolver {
    pub fn new<A: IpAcl>(acl: A) -> Self {
        Self { acl: Arc::new(acl) }
    }

    /// Forward to the wrapped ACL's [`IpAcl::check_url`].
    pub fn check_url(&self, url: &Url) -> Result<(), AclError> {
        self.acl.check_url(url)
    }
}

impl Resolve for AclResolver {
    fn resolve(&self, name: Name) -> Resolving {
        resolve_with(name, self.acl.clone())
    }
}

fn resolve_with(name: Name, acl: Arc<dyn IpAcl>) -> Resolving {
    let host = name.as_str().to_owned();
    Box::pin(resolve_with_inner(host, acl))
}

async fn resolve_with_inner(
    host: String,
    acl: Arc<dyn IpAcl>,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let iter = tokio::net::lookup_host((host.as_str(), 0))
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let allowed: Vec<SocketAddr> = iter.filter(|sa| acl.is_allowed_ip(sa.ip())).collect();

    if allowed.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("all resolved addresses for {host} were denied by ACL"),
        )) as Box<dyn std::error::Error + Send + Sync>);
    }

    let addrs: Addrs = Box::new(allowed.into_iter());
    Ok(addrs)
}

// ---------------------------------------------------------------------------
// is_local_network
// ---------------------------------------------------------------------------

/// Returns `true` if `ip` belongs to a local / non-routable network.
///
/// Concretely: IPv4 private ranges (RFC1918), loopback (`127.0.0.0/8`),
/// link-local (`169.254.0.0/16`), `0.0.0.0/8`, broadcast; IPv6 loopback
/// (`::1`), unspecified (`::`), unique local (`fc00::/7`), link-local
/// (`fe80::/10`), and IPv4-mapped variants of the above.
pub fn is_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                // 0.0.0.0/8 ("this network")
                || v4.octets()[0] == 0
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
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }
    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    // --- is_local_network -------------------------------------------------

    #[test]
    fn denies_ipv4_private_ranges() {
        for ip in ["10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1"] {
            assert!(is_local_network(v4(ip)), "{ip} should be denied");
        }
    }

    #[test]
    fn denies_ipv4_loopback_and_linklocal_and_zero_and_broadcast() {
        for ip in ["127.0.0.1", "169.254.1.1", "0.0.0.0", "0.1.2.3", "255.255.255.255"] {
            assert!(is_local_network(v4(ip)), "{ip} should be denied");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for ip in ["1.1.1.1", "8.8.8.8", "172.15.0.1", "172.32.0.1", "192.0.2.1"] {
            assert!(!is_local_network(v4(ip)), "{ip} should be allowed");
        }
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

    // --- Acl builder semantics -------------------------------------------

    #[test]
    fn acl_default_is_allow_all() {
        let acl = Acl::new();
        assert!(acl.is_allowed_ip(v4("10.0.0.1")));
        assert!(acl.is_allowed_ip(v4("8.8.8.8")));
    }

    #[test]
    fn acl_deny_local_network() {
        let acl = Acl::new().deny_local_network();
        assert!(!acl.is_allowed_ip(v4("10.0.0.1")));
        assert!(!acl.is_allowed_ip(v4("127.0.0.1")));
        assert!(acl.is_allowed_ip(v4("8.8.8.8")));
    }

    #[test]
    fn acl_explicit_allow_overrides_deny() {
        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("192.168.1.100/32"));
        assert!(!acl.is_allowed_ip(v4("192.168.0.1"))); // still denied
        assert!(acl.is_allowed_ip(v4("192.168.1.100"))); // exception
        assert!(acl.is_allowed_ip(v4("8.8.8.8"))); // default allow
    }

    #[test]
    fn acl_allow_wins_regardless_of_order() {
        // allow added before the deny rule — still wins
        let acl1 = Acl::new()
            .allow_cidr(cidr("192.168.1.100/32"))
            .deny_local_network();
        let acl2 = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("192.168.1.100/32"));
        for acl in [&acl1, &acl2] {
            assert!(acl.is_allowed_ip(v4("192.168.1.100")));
            assert!(!acl.is_allowed_ip(v4("192.168.0.1")));
        }
    }

    #[test]
    fn acl_default_deny_allowlist_mode() {
        let acl = Acl::new()
            .default_deny()
            .allow_cidr(cidr("1.1.1.1/32"))
            .allow_cidr(cidr("8.8.8.8/32"));
        assert!(acl.is_allowed_ip(v4("1.1.1.1")));
        assert!(acl.is_allowed_ip(v4("8.8.8.8")));
        assert!(!acl.is_allowed_ip(v4("9.9.9.9")));
        assert!(!acl.is_allowed_ip(v4("10.0.0.1")));
    }

    #[test]
    fn acl_cidr_range() {
        // /24 allows the whole prefix
        let acl = Acl::new()
            .default_deny()
            .allow_cidr(cidr("192.0.2.0/24"));
        assert!(acl.is_allowed_ip(v4("192.0.2.0")));
        assert!(acl.is_allowed_ip(v4("192.0.2.42")));
        assert!(acl.is_allowed_ip(v4("192.0.2.255")));
        assert!(!acl.is_allowed_ip(v4("192.0.3.0")));
    }

    #[test]
    fn acl_cidr_ipv6() {
        let acl = Acl::new()
            .default_deny()
            .allow_cidr(cidr("2001:db8::/32"));
        assert!(acl.is_allowed_ip(v6("2001:db8::1")));
        assert!(acl.is_allowed_ip(v6("2001:db8:ffff::1")));
        assert!(!acl.is_allowed_ip(v6("2001:db9::1")));
    }

    #[test]
    fn acl_deny_ip_when_custom_predicate() {
        let acl = Acl::new().deny_ip_when(|ip| match ip {
            IpAddr::V4(v4) => v4.octets()[0] == 198, // deny 198.x.x.x
            _ => false,
        });
        assert!(!acl.is_allowed_ip(v4("198.51.100.1")));
        assert!(acl.is_allowed_ip(v4("8.8.8.8")));
    }

    // --- check_url --------------------------------------------------------

    fn deny_local() -> Acl {
        Acl::new().deny_local_network()
    }

    #[test]
    fn check_url_rejects_ipv4_literal_local() {
        let url = Url::parse("http://127.0.0.1/admin").unwrap();
        let err = deny_local().check_url(&url).unwrap_err();
        assert_eq!(err, AclError::DeniedIp(v4("127.0.0.1")));
    }

    #[test]
    fn check_url_rejects_ipv6_literal_local() {
        let url = Url::parse("http://[::1]/").unwrap();
        let err = deny_local().check_url(&url).unwrap_err();
        assert_eq!(err, AclError::DeniedIp(v6("::1")));
    }

    #[test]
    fn check_url_allows_public_literal() {
        let url = Url::parse("http://1.1.1.1/").unwrap();
        assert!(deny_local().check_url(&url).is_ok());
    }

    #[test]
    fn check_url_defers_domain_names_to_resolver() {
        let url = Url::parse("http://localhost/").unwrap();
        assert!(deny_local().check_url(&url).is_ok());
        let url = Url::parse("http://example.com/").unwrap();
        assert!(deny_local().check_url(&url).is_ok());
    }

    #[test]
    fn check_url_via_acl_with_exception() {
        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("192.168.1.100/32"));
        // Exception is honoured at URL-check time too
        assert!(acl.check_url(&Url::parse("http://192.168.1.100/").unwrap()).is_ok());
        assert!(acl.check_url(&Url::parse("http://192.168.1.101/").unwrap()).is_err());
    }

    #[test]
    fn check_url_via_resolver() {
        let resolver = AclResolver::new(Acl::new().deny_local_network());
        assert!(resolver.check_url(&Url::parse("http://10.0.0.1/").unwrap()).is_err());
        assert!(resolver.check_url(&Url::parse("http://example.com/").unwrap()).is_ok());
    }

    // --- host rules ------------------------------------------------------

    #[test]
    fn host_decision_continues_when_no_rules_match() {
        let acl = Acl::new().deny_host("evil.example");
        assert_eq!(acl.host_decision("good.example"), HostDecision::Continue);
    }

    #[test]
    fn host_decision_exact_match_case_insensitive() {
        let acl = Acl::new().deny_host("Evil.Example");
        assert_eq!(acl.host_decision("evil.example"), HostDecision::Deny);
        assert_eq!(acl.host_decision("EVIL.EXAMPLE"), HostDecision::Deny);
        // trailing dot is stripped
        assert_eq!(acl.host_decision("evil.example."), HostDecision::Deny);
        // not a substring match
        assert_eq!(acl.host_decision("not-evil.example"), HostDecision::Continue);
    }

    #[test]
    fn host_decision_suffix_match() {
        let acl = Acl::new().deny_host_suffix(".internal.corp");
        assert_eq!(acl.host_decision("api.internal.corp"), HostDecision::Deny);
        assert_eq!(acl.host_decision("deep.api.internal.corp"), HostDecision::Deny);
        // leading dot guards against bare-string false matches
        assert_eq!(acl.host_decision("internal.corp"), HostDecision::Continue);
        assert_eq!(acl.host_decision("public.example"), HostDecision::Continue);
    }

    #[test]
    fn host_allow_wins_over_host_deny() {
        let acl = Acl::new()
            .deny_host_suffix(".example.com")
            .allow_host("api.example.com");
        assert_eq!(acl.host_decision("api.example.com"), HostDecision::Allow);
        assert_eq!(acl.host_decision("other.example.com"), HostDecision::Deny);
    }

    #[test]
    fn host_when_predicate_sees_normalized_host() {
        let acl = Acl::new().deny_host_when(|h| h == "lowered.example");
        assert_eq!(acl.host_decision("LOWERED.example."), HostDecision::Deny);
    }

    #[test]
    fn check_url_host_deny_rejects_domain_url() {
        let acl = Acl::new().deny_host("evil.example");
        let err = acl
            .check_url(&Url::parse("http://EVIL.example/path").unwrap())
            .unwrap_err();
        assert_eq!(err, AclError::DeniedHost("evil.example".into()));
    }

    #[test]
    fn check_url_host_allow_overrides_default_deny_for_domain() {
        // default_deny only affects the IP layer; domain URLs short-circuit on
        // host rules in check_url and otherwise pass (resolver handles them).
        let acl = Acl::new()
            .default_deny()
            .allow_host("api.example.com");
        // domain with explicit allow — passes
        assert!(acl
            .check_url(&Url::parse("http://api.example.com/").unwrap())
            .is_ok());
        // domain with no host rule match — check_url still says ok (resolver
        // would then deny per default_deny at IP layer)
        assert!(acl
            .check_url(&Url::parse("http://other.example.com/").unwrap())
            .is_ok());
    }
}
