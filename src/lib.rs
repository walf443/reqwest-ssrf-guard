//! Mitigate SSRF / DNS rebinding in [`reqwest`] by filtering DNS lookups,
//! redirect targets, and URL literals through an IP / host ACL.
//!
//! # Quick start
//!
//! The [`Acl`] builder is both the policy and the [`Resolve`] impl, so you
//! can hand it straight to reqwest:
//!
//! ```no_run
//! use std::sync::Arc;
//! use reqwest_ssrf_guard::Acl;
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
//! use reqwest_ssrf_guard::Acl;
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

/// Returned by [`Acl::validate_url`] when a URL is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    /// A URL whose scheme is not in the allowlist (see
    /// [`Acl::restrict_schemes`]). Covers host-less URLs like `file:///etc/passwd`
    /// or `data:` that would otherwise bypass the host/IP checks.
    DeniedScheme(String),
    /// A URL whose host is a literal IP that was denied.
    DeniedIp(IpAddr),
    /// A URL whose host is a domain name that was denied.
    DeniedHost(String),
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeniedScheme(s) => write!(f, "scheme {s} is denied by ACL"),
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
/// use reqwest_ssrf_guard::Acl;
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
    allowed_schemes: Vec<String>,
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
    ///
    /// The scheme allowlist defaults to `http` and `https` — [`validate_url`]
    /// rejects every other scheme. Override with
    /// [`restrict_schemes`](Self::restrict_schemes).
    ///
    /// [`validate_url`]: Self::validate_url
    pub fn new() -> Self {
        Self {
            rules: vec![],
            host_rules: vec![],
            allowed_schemes: vec!["http".to_owned(), "https".to_owned()],
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

    /// Restrict [`validate_url`](Self::validate_url) to exactly the given
    /// schemes, replacing the default allowlist.
    ///
    /// Unlike the accumulating `allow_*` / `deny_*` rule builders, this is a
    /// *set* — the argument becomes the complete allowlist, so pass every
    /// scheme you want to permit (not just the additions).
    ///
    /// Schemes are compared case-insensitively. The default is `["http",
    /// "https"]`, which is almost always what you want with reqwest — it
    /// blocks host-less schemes such as `file:`, `data:`, and `gopher:` that
    /// would otherwise slip past the host/IP checks. Narrow it to
    /// `["https"]` to also forbid plaintext, or widen it if you knowingly
    /// drive a non-HTTP transport.
    ///
    /// Passing an empty iterator denies *every* scheme.
    ///
    /// ```
    /// use reqwest_ssrf_guard::{Acl, AclError};
    /// let acl = Acl::new(); // defaults to http/https
    /// assert_eq!(
    ///     acl.validate_url(&"file:///etc/passwd".parse().unwrap()),
    ///     Err(AclError::DeniedScheme("file".into())),
    /// );
    ///
    /// let https_only = Acl::new().restrict_schemes(["https"]);
    /// assert_eq!(
    ///     https_only.validate_url(&"http://example.com/".parse().unwrap()),
    ///     Err(AclError::DeniedScheme("http".into())),
    /// );
    /// ```
    pub fn restrict_schemes<I, S>(mut self, schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_schemes = schemes
            .into_iter()
            .map(|s| s.as_ref().to_ascii_lowercase())
            .collect();
        self
    }

    /// Flip the default decision to deny — useful for allowlist-style ACLs
    /// where only the explicitly allowed IPs are permitted.
    pub fn default_deny(mut self) -> Self {
        self.default_allow = false;
        self
    }
}

impl Acl {
    /// Return `true` if connecting to `ip` is permitted by the IP-layer
    /// rules (host rules are not consulted here).
    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
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

    /// Reject `url` if its scheme or host violates the ACL.
    ///
    /// 1. The scheme must be in the allowlist (default `http`/`https`, see
    ///    [`restrict_schemes`](Self::restrict_schemes)) — otherwise
    ///    [`AclError::DeniedScheme`]. This is checked first, so host-less
    ///    URLs like `file:///etc/passwd` or `data:` are rejected here rather
    ///    than silently passing.
    /// 2. Domain hosts → consult host rules ([`host_decision`](Self::host_decision)).
    /// 3. IP-literal hosts → consult IP rules ([`is_allowed_ip`](Self::is_allowed_ip)).
    ///
    /// Domain hosts that no host rule matches return `Ok` — the actual IP
    /// filtering will happen at DNS resolution time via the [`Resolve`]
    /// impl. Call this before handing a user-supplied URL to reqwest so that
    /// IP-literal hosts (which bypass DNS) are still subject to the ACL.
    pub fn validate_url(&self, url: &Url) -> Result<(), AclError> {
        let scheme = url.scheme();
        if !self.allowed_schemes.iter().any(|s| s == scheme) {
            return Err(AclError::DeniedScheme(scheme.to_owned()));
        }
        let Some(host) = url.host() else {
            return Ok(());
        };
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

    /// Apply this ACL to a [`reqwest::ClientBuilder`] — installs the DNS
    /// resolver and the redirect policy in one shot.
    ///
    /// This is the recommended way to wire the ACL into a client: calling
    /// just `dns_resolver` or just `redirect` leaves a gap (IP-literal URLs
    /// or IP-literal redirect targets, respectively). Use this to set both
    /// at once, then chain any further reqwest settings:
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use reqwest_ssrf_guard::Acl;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let acl = Acl::new().deny_local_network();
    /// let client = acl
    ///     .configure(reqwest::Client::builder())
    ///     .timeout(Duration::from_secs(30))
    ///     .build()?;
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `validate_url` on the initial request URL is not covered here —
    /// either call it manually before each request, or enable the
    /// `middleware` feature and apply [`configure_middleware`](Self::configure_middleware).
    pub fn configure(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
            .dns_resolver(std::sync::Arc::new(self.clone()))
            .redirect(self.redirect_policy())
    }

    /// Return a [`reqwest::redirect::Policy`] that validates every redirect
    /// hop against this ACL.
    ///
    /// Each redirect target is run through [`validate_url`](Self::validate_url);
    /// a violation fails the request with the [`AclError`] wrapped as a
    /// redirect error. Allowed targets fall through to
    /// [`reqwest::redirect::Policy::default`], so the regular hop-limit (10
    /// at the time of writing — whatever reqwest's current default is)
    /// still applies.
    ///
    /// Combine with [`Resolve`] (for DNS hops) and the optional
    /// `middleware` integration (for the initial URL) to cover all three
    /// places a request URL can land on a denied host.
    pub fn redirect_policy(&self) -> reqwest::redirect::Policy {
        let acl = self.clone();
        reqwest::redirect::Policy::custom(move |attempt| {
            if let Err(e) = acl.validate_url(attempt.url()) {
                return attempt.error(e);
            }
            reqwest::redirect::Policy::default().redirect(attempt)
        })
    }
}

impl Resolve for Acl {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let host_decision = self.host_decision(&host);
        let acl = self.clone();
        Box::pin(async move {
            match host_decision {
                HostDecision::Deny => Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("host {host} is denied by ACL"),
                ))
                    as Box<dyn std::error::Error + Send + Sync>),
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
                    let iter = tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                    let allowed: Vec<SocketAddr> =
                        iter.filter(|sa| acl.is_allowed_ip(sa.ip())).collect();
                    if allowed.is_empty() {
                        return Err(Box::new(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("all resolved addresses for {host} were denied by ACL"),
                        ))
                            as Box<dyn std::error::Error + Send + Sync>);
                    }
                    let addrs: Addrs = Box::new(allowed.into_iter());
                    Ok(addrs)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// is_local_network
// ---------------------------------------------------------------------------

/// Returns `true` if `ip` belongs to a local / non-routable network.
///
/// Concretely: IPv4 private ranges (RFC1918), loopback (`127.0.0.0/8`),
/// link-local (`169.254.0.0/16`), shared / CGNAT (`100.64.0.0/10`, RFC6598
/// — covers Alibaba Cloud's `100.100.100.200` metadata endpoint),
/// `0.0.0.0/8`, broadcast; IPv6 loopback (`::1`), unspecified (`::`),
/// unique local (`fc00::/7`), link-local (`fe80::/10`), and IPv4-mapped
/// variants of the above.
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
            false
        }
    }
}

// ---------------------------------------------------------------------------
// reqwest-middleware integration (feature-gated)
// ---------------------------------------------------------------------------

/// Use [`Acl`] directly as a [`reqwest_middleware::Middleware`] so that
/// every outgoing request is filtered through [`Acl::validate_url`].
///
/// Enable the `middleware` feature, then:
///
/// ```ignore
/// use std::sync::Arc;
/// use reqwest_ssrf_guard::Acl;
/// use reqwest_middleware::ClientBuilder;
///
/// let acl = Acl::new().deny_local_network();
/// let inner = reqwest::Client::builder()
///     .dns_resolver(Arc::new(acl.clone()))
///     .build()?;
/// let client = ClientBuilder::new(inner).with(acl).build();
/// ```
///
/// Validation failures are surfaced as `reqwest_middleware::Error::Middleware`
/// wrapping the [`AclError`].
#[cfg(feature = "middleware")]
impl Acl {
    /// Register this ACL as a middleware on a
    /// [`reqwest_middleware::ClientBuilder`].
    ///
    /// Available with the `middleware` feature. Pair with
    /// [`configure`](Self::configure) on the underlying reqwest client:
    ///
    /// ```no_run
    /// # use reqwest_ssrf_guard::Acl;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let acl = Acl::new().deny_local_network();
    /// let inner = acl.configure(reqwest::Client::builder()).build()?;
    /// let client = acl
    ///     .configure_middleware(reqwest_middleware::ClientBuilder::new(inner))
    ///     .build();
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    pub fn configure_middleware(
        &self,
        builder: reqwest_middleware::ClientBuilder,
    ) -> reqwest_middleware::ClientBuilder {
        builder.with(self.clone())
    }
}

#[cfg(feature = "middleware")]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for Acl {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.validate_url(req.url())
            .map_err(reqwest_middleware::Error::middleware)?;
        next.run(req, extensions).await
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
        let acl = Acl::new().default_deny().allow_cidr(cidr("192.0.2.0/24"));
        assert!(acl.is_allowed_ip(v4("192.0.2.0")));
        assert!(acl.is_allowed_ip(v4("192.0.2.42")));
        assert!(acl.is_allowed_ip(v4("192.0.2.255")));
        assert!(!acl.is_allowed_ip(v4("192.0.3.0")));
    }

    #[test]
    fn acl_cidr_ipv6() {
        let acl = Acl::new().default_deny().allow_cidr(cidr("2001:db8::/32"));
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

    // --- validate_url --------------------------------------------------------

    fn deny_local() -> Acl {
        Acl::new().deny_local_network()
    }

    #[test]
    fn validate_url_rejects_ipv4_literal_local() {
        let url = Url::parse("http://127.0.0.1/admin").unwrap();
        let err = deny_local().validate_url(&url).unwrap_err();
        assert_eq!(err, AclError::DeniedIp(v4("127.0.0.1")));
    }

    #[test]
    fn validate_url_rejects_ipv6_literal_local() {
        let url = Url::parse("http://[::1]/").unwrap();
        let err = deny_local().validate_url(&url).unwrap_err();
        assert_eq!(err, AclError::DeniedIp(v6("::1")));
    }

    #[test]
    fn validate_url_allows_public_literal() {
        let url = Url::parse("http://1.1.1.1/").unwrap();
        assert!(deny_local().validate_url(&url).is_ok());
    }

    #[test]
    fn validate_url_defers_domain_names_to_resolver() {
        let url = Url::parse("http://localhost/").unwrap();
        assert!(deny_local().validate_url(&url).is_ok());
        let url = Url::parse("http://example.com/").unwrap();
        assert!(deny_local().validate_url(&url).is_ok());
    }

    #[test]
    fn validate_url_via_acl_with_exception() {
        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("192.168.1.100/32"));
        // Exception is honoured at URL-check time too
        assert!(
            acl.validate_url(&Url::parse("http://192.168.1.100/").unwrap())
                .is_ok()
        );
        assert!(
            acl.validate_url(&Url::parse("http://192.168.1.101/").unwrap())
                .is_err()
        );
    }

    // --- scheme allowlist ------------------------------------------------

    #[test]
    fn validate_url_rejects_non_http_schemes_by_default() {
        let acl = deny_local();
        for url in [
            "file:///etc/passwd",
            "data:text/plain,hello",
            "gopher://example.com/",
            "ftp://example.com/x",
        ] {
            let err = acl.validate_url(&Url::parse(url).unwrap()).unwrap_err();
            assert!(
                matches!(err, AclError::DeniedScheme(_)),
                "{url} should be denied by scheme, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_url_allows_http_and_https_by_default() {
        let acl = deny_local();
        assert!(
            acl.validate_url(&Url::parse("http://example.com/").unwrap())
                .is_ok()
        );
        assert!(
            acl.validate_url(&Url::parse("https://example.com/").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn validate_url_scheme_check_runs_before_host_check() {
        // A denied host over a denied scheme reports the scheme first.
        let acl = Acl::new().deny_host("evil.example");
        let err = acl
            .validate_url(&Url::parse("ftp://evil.example/").unwrap())
            .unwrap_err();
        assert_eq!(err, AclError::DeniedScheme("ftp".into()));
    }

    #[test]
    fn restrict_schemes_https_only_forbids_plaintext() {
        let acl = Acl::new().restrict_schemes(["https"]);
        assert_eq!(
            acl.validate_url(&Url::parse("http://example.com/").unwrap()),
            Err(AclError::DeniedScheme("http".into()))
        );
        assert!(
            acl.validate_url(&Url::parse("https://example.com/").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn restrict_schemes_is_case_insensitive() {
        // url normalizes the scheme to lowercase, and the allowlist is lowered
        // too, so a mixed-case configured scheme still matches.
        let acl = Acl::new().restrict_schemes(["HTTP"]);
        assert!(
            acl.validate_url(&Url::parse("http://example.com/").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn restrict_schemes_empty_denies_everything() {
        let acl = Acl::new().restrict_schemes(Vec::<String>::new());
        assert!(
            acl.validate_url(&Url::parse("https://example.com/").unwrap())
                .is_err()
        );
    }

    #[test]
    fn restrict_schemes_can_widen() {
        let acl = Acl::new().restrict_schemes(["http", "https", "ftp"]);
        assert!(
            acl.validate_url(&Url::parse("ftp://example.com/").unwrap())
                .is_ok()
        );
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
        assert_eq!(
            acl.host_decision("not-evil.example"),
            HostDecision::Continue
        );
    }

    #[test]
    fn host_decision_suffix_match() {
        let acl = Acl::new().deny_host_suffix(".internal.corp");
        assert_eq!(acl.host_decision("api.internal.corp"), HostDecision::Deny);
        assert_eq!(
            acl.host_decision("deep.api.internal.corp"),
            HostDecision::Deny
        );
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
    fn validate_url_host_deny_rejects_domain_url() {
        let acl = Acl::new().deny_host("evil.example");
        let err = acl
            .validate_url(&Url::parse("http://EVIL.example/path").unwrap())
            .unwrap_err();
        assert_eq!(err, AclError::DeniedHost("evil.example".into()));
    }

    #[test]
    fn validate_url_host_allow_overrides_default_deny_for_domain() {
        // default_deny only affects the IP layer; domain URLs short-circuit on
        // host rules in validate_url and otherwise pass (resolver handles them).
        let acl = Acl::new().default_deny().allow_host("api.example.com");
        // domain with explicit allow — passes
        assert!(
            acl.validate_url(&Url::parse("http://api.example.com/").unwrap())
                .is_ok()
        );
        // domain with no host rule match — validate_url still says ok (resolver
        // would then deny per default_deny at IP layer)
        assert!(
            acl.validate_url(&Url::parse("http://other.example.com/").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn redirect_policy_returns_a_usable_policy() {
        // Compile-only: ensure the return type is what reqwest's builder
        // expects.
        let acl = Acl::new().deny_local_network();
        let _policy: reqwest::redirect::Policy = acl.redirect_policy();
        let _client = reqwest::Client::builder()
            .redirect(acl.redirect_policy())
            .build()
            .unwrap();
    }

    #[test]
    fn configure_wires_resolver_and_redirect_policy() {
        // Compile-only: the returned builder must still be usable.
        let acl = Acl::new().deny_local_network();
        let _client = acl
            .configure(reqwest::Client::builder())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
    }
}

#[cfg(all(test, feature = "middleware"))]
mod middleware_tests {
    use crate::Acl;

    /// Compile-only check that `Acl` is accepted by `ClientBuilder::with`
    /// via `configure_middleware`.
    #[test]
    fn configure_middleware_returns_a_builder() {
        let acl = Acl::new().deny_local_network();
        let _client = acl
            .configure_middleware(reqwest_middleware::ClientBuilder::new(
                reqwest::Client::new(),
            ))
            .build();
    }

    /// Verify that a denied URL surfaces as an `Error::Middleware` with the
    /// wrapped `AclError`, without actually hitting the network.
    #[tokio::test]
    async fn middleware_rejects_local_network_ip_literal() {
        let acl = Acl::new().deny_local_network();
        let client = acl
            .configure_middleware(reqwest_middleware::ClientBuilder::new(
                reqwest::Client::new(),
            ))
            .build();
        let err = client.get("http://127.0.0.1/").send().await.unwrap_err();
        assert!(err.is_middleware(), "expected middleware error, got: {err}");
    }
}
