use std::net::IpAddr;

/// Why the ACL rejected a connection.
///
/// Returned directly by [`Acl::validate_url`](crate::Acl::validate_url), and — because the [`Resolve`](reqwest::dns::Resolve)
/// impl must hand reqwest an [`io::Error`](std::io::Error) — also carried as the payload of
/// the `PermissionDenied` errors the resolver produces. Consumers can recover
/// it to tell an ACL block apart from a genuine network `PermissionDenied`:
///
/// ```
/// # use std::io;
/// # use reqwest_ssrf_guard::AclError;
/// fn acl_reason<'a>(
///     err: &'a (dyn std::error::Error + Send + Sync + 'static),
/// ) -> Option<&'a AclError> {
///     err.downcast_ref::<io::Error>()?
///         .get_ref()?
///         .downcast_ref::<AclError>()
/// }
/// ```
///
/// New rejection reasons may be added in future releases without a breaking
/// change, so a `match` on this enum needs a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AclError {
    /// A URL whose host is a literal IP that was denied.
    DeniedIp(IpAddr),
    /// A URL whose host is a domain name denied by a host rule (before DNS).
    DeniedHost(String),
    /// A URL with an explicit non-default port that was denied by the port
    /// rules (see [`Acl::deny_non_default_ports`](crate::Acl::deny_non_default_ports)).
    DeniedPort(u16),
    /// Every address the host resolved to was denied by the IP-layer rules.
    /// Produced at DNS-resolution time, never by [`Acl::validate_url`](crate::Acl::validate_url).
    NoAllowedAddress(String),
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeniedIp(ip) => write!(f, "address {ip} is denied by ACL"),
            Self::DeniedHost(h) => write!(f, "host {h} is denied by ACL"),
            Self::DeniedPort(p) => write!(f, "port {p} is denied by ACL"),
            Self::NoAllowedAddress(h) => {
                write!(f, "all resolved addresses for {h} were denied by ACL")
            }
        }
    }
}

impl std::error::Error for AclError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_port_display() {
        assert_eq!(
            AclError::DeniedPort(6379).to_string(),
            "port 6379 is denied by ACL"
        );
    }
}
