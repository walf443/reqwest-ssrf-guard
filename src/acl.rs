use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use reqwest::Url;

use crate::{AclError, is_local_network};

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
/// Independently of both layers, [`validate_url`](Self::validate_url) can
/// also reject URLs carrying an explicit non-default port — see
/// [`deny_non_default_ports`](Self::deny_non_default_ports). The port check
/// applies even to hosts matched by a host `allow_*` rule.
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
    default_allow: bool,
    deny_non_default_ports: bool,
    allowed_ports: Vec<u16>,
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

pub(crate) fn normalize_host(h: &str) -> String {
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
            deny_non_default_ports: false,
            allowed_ports: vec![],
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

    /// Reject URLs that carry an explicit port other than their scheme's
    /// default, e.g. `http://example.com:8080/`.
    ///
    /// Default ports are normalized away by URL parsing, so
    /// `http://example.com:80/` and `https://example.com:443/` still pass.
    /// Use [`allow_ports`](Self::allow_ports) to permit specific ports.
    ///
    /// The check runs in [`validate_url`](Self::validate_url) (and therefore
    /// in the redirect policy and the `middleware` integration), and applies
    /// even to hosts matched by a host `allow_*` rule. The [`Resolve`](reqwest::dns::Resolve) impl
    /// never sees ports, so without the `middleware` feature the initial
    /// request URL is only checked if you call `validate_url` yourself.
    /// [`default_deny`](Self::default_deny) does not affect ports.
    ///
    /// ```
    /// use reqwest_ssrf_guard::{Acl, AclError};
    /// use reqwest::Url;
    ///
    /// let acl = Acl::new().deny_non_default_ports().allow_ports([8080, 8443]);
    /// let check = |s: &str| acl.validate_url(&Url::parse(s).unwrap());
    /// assert!(check("https://example.com/").is_ok());
    /// assert!(check("https://example.com:443/").is_ok());   // default port
    /// assert!(check("https://example.com:8443/").is_ok());  // explicitly allowed
    /// assert_eq!(check("http://example.com:6379/"), Err(AclError::DeniedPort(6379)));
    /// ```
    pub fn deny_non_default_ports(mut self) -> Self {
        self.deny_non_default_ports = true;
        self
    }

    /// Allow each of `ports` even when
    /// [`deny_non_default_ports`](Self::deny_non_default_ports) is set. Has no
    /// effect otherwise. Calls accumulate, so a single port is
    /// `allow_ports([8443])`.
    pub fn allow_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.allowed_ports.extend(ports);
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

    /// Return `true` if an explicit, non-default `port` is permitted by the
    /// port rules. Always `true` unless
    /// [`deny_non_default_ports`](Self::deny_non_default_ports) is set.
    pub fn is_allowed_port(&self, port: u16) -> bool {
        !self.deny_non_default_ports || self.allowed_ports.contains(&port)
    }

    /// Reject `url` if its host or port violates the ACL.
    ///
    /// * Explicit non-default ports → consult port rules
    ///   ([`is_allowed_port`](Self::is_allowed_port)). This runs first, so a
    ///   URL denied by both its port and its host reports
    ///   [`AclError::DeniedPort`].
    /// * Domain hosts → consult host rules ([`host_decision`](Self::host_decision)).
    /// * IP-literal hosts → consult IP rules ([`is_allowed_ip`](Self::is_allowed_ip)).
    ///
    /// Domain hosts that no host rule matches return `Ok` — the actual IP
    /// filtering will happen at DNS resolution time via the [`Resolve`](reqwest::dns::Resolve)
    /// impl. Call this before handing a user-supplied URL to reqwest so that
    /// IP-literal hosts (which bypass DNS) are still subject to the ACL.
    pub fn validate_url(&self, url: &Url) -> Result<(), AclError> {
        let Some(host) = url.host() else {
            return Ok(());
        };
        if let Some(port) = url.port().filter(|&p| !self.is_allowed_port(p)) {
            return Err(AclError::DeniedPort(port));
        }
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
    #[cfg_attr(
        feature = "middleware",
        doc = "`middleware` feature and apply [`configure_middleware`](Self::configure_middleware)."
    )]
    #[cfg_attr(
        not(feature = "middleware"),
        doc = "`middleware` feature and apply `configure_middleware`."
    )]
    pub fn configure(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
            .dns_resolver(std::sync::Arc::new(self.clone()))
            .redirect(self.redirect_policy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

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

    // --- port rules ------------------------------------------------------

    fn check(acl: &Acl, url: &str) -> Result<(), AclError> {
        acl.validate_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn ports_are_unrestricted_by_default() {
        let acl = Acl::new();
        assert!(check(&acl, "http://example.com:8080/").is_ok());
        assert!(check(&acl, "http://1.1.1.1:6379/").is_ok());
        // default_deny is IP-layer only and must not restrict ports.
        let acl = Acl::new().default_deny().allow_cidr(cidr("1.1.1.1/32"));
        assert!(check(&acl, "http://1.1.1.1:6379/").is_ok());
    }

    #[test]
    fn deny_non_default_ports_allows_default_ports() {
        // URL parsing normalizes default ports away, so these carry no port.
        let acl = Acl::new().deny_non_default_ports();
        assert!(check(&acl, "http://example.com/").is_ok());
        assert!(check(&acl, "http://example.com:80/").is_ok());
        assert!(check(&acl, "https://example.com:443/").is_ok());
        assert!(check(&acl, "https://1.1.1.1:443/").is_ok());
    }

    #[test]
    fn deny_non_default_ports_rejects_explicit_ports() {
        let acl = Acl::new().deny_non_default_ports();
        assert_eq!(
            check(&acl, "http://example.com:8080/"),
            Err(AclError::DeniedPort(8080))
        );
        // Swapped defaults are non-default for the scheme.
        assert_eq!(
            check(&acl, "https://example.com:80/"),
            Err(AclError::DeniedPort(80))
        );
        assert_eq!(
            check(&acl, "http://example.com:443/"),
            Err(AclError::DeniedPort(443))
        );
        assert_eq!(
            check(&acl, "http://1.1.1.1:6379/"),
            Err(AclError::DeniedPort(6379))
        );
        assert_eq!(
            check(&acl, "http://[2606:4700:4700::1111]:25/"),
            Err(AclError::DeniedPort(25))
        );
    }

    #[test]
    fn allow_ports_is_an_exception() {
        let acl = Acl::new()
            .deny_non_default_ports()
            .allow_ports([8080, 8443]);
        assert!(check(&acl, "https://example.com:8080/").is_ok());
        assert!(check(&acl, "https://example.com:8443/").is_ok());
        assert_eq!(
            check(&acl, "https://example.com:8444/"),
            Err(AclError::DeniedPort(8444))
        );
        assert!(acl.is_allowed_port(8443));
        assert!(!acl.is_allowed_port(8444));
    }

    #[test]
    fn allow_ports_accumulates_across_calls() {
        // A later call must add to, not replace, the ports allowed earlier.
        let acl = Acl::new()
            .deny_non_default_ports()
            .allow_ports([8080, 8443])
            .allow_ports([9000]);
        assert!(check(&acl, "https://example.com:8080/").is_ok());
        assert!(check(&acl, "https://example.com:8443/").is_ok());
        assert!(check(&acl, "https://example.com:9000/").is_ok());
        assert_eq!(
            check(&acl, "https://example.com:9001/"),
            Err(AclError::DeniedPort(9001))
        );
    }

    #[test]
    fn allow_ports_combines_with_ip_rules() {
        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("::1/128"))
            .deny_non_default_ports()
            .allow_ports([8080]);
        assert!(check(&acl, "http://[::1]:8080/").is_ok());
        // Port allowed, but IP still denied.
        assert_eq!(
            check(&acl, "http://127.0.0.1:8080/"),
            Err(AclError::DeniedIp(v4("127.0.0.1")))
        );
    }

    #[test]
    fn host_allow_does_not_bypass_port_rules() {
        let acl = Acl::new()
            .allow_host("api.example.com")
            .deny_non_default_ports();
        assert!(check(&acl, "https://api.example.com/").is_ok());
        assert_eq!(
            check(&acl, "https://api.example.com:8443/"),
            Err(AclError::DeniedPort(8443))
        );
    }

    #[test]
    fn port_check_takes_precedence_over_host_and_ip_checks() {
        let acl = Acl::new()
            .deny_local_network()
            .deny_host("evil.example")
            .deny_non_default_ports();
        assert_eq!(
            check(&acl, "http://evil.example:8080/"),
            Err(AclError::DeniedPort(8080))
        );
        assert_eq!(
            check(&acl, "http://127.0.0.1:8080/"),
            Err(AclError::DeniedPort(8080))
        );
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
