use std::io;
use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::acl::normalize_host;
use crate::{Acl, AclError, HostDecision};

/// Filters DNS results through the host and IP rules. Port rules are not
/// applied here — reqwest only hands the resolver a hostname — so they are
/// enforced by [`Acl::validate_url`] and the redirect policy instead.
impl Resolve for Acl {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let host_decision = self.host_decision(&host);
        let acl = self.clone();
        Box::pin(async move {
            match host_decision {
                HostDecision::Deny => Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    AclError::DeniedHost(normalize_host(&host)),
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
                            AclError::NoAllowedAddress(normalize_host(&host)),
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- Resolve impl deny path -------------------------------------------

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// Recover the `AclError` a resolver error carries, asserting along the
    /// way that it is a `PermissionDenied` `io::Error` with an `AclError`
    /// payload — i.e. the exact path a consumer uses to tell an ACL block
    /// apart from a genuine network error. Checks semantics + type, not the
    /// message wording.
    fn acl_error_of(err: &(dyn std::error::Error + Send + Sync + 'static)) -> AclError {
        let io_err = err
            .downcast_ref::<io::Error>()
            .unwrap_or_else(|| panic!("expected io::Error, got: {err}"));
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);
        io_err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<AclError>())
            .unwrap_or_else(|| panic!("expected AclError payload, got: {io_err}"))
            .clone()
    }

    #[tokio::test]
    async fn resolver_denies_host_rule_without_dns() {
        // A host-denied name must be rejected by the resolver before any DNS
        // lookup — so this resolves purely from the ACL, no network needed.
        let acl = Acl::new().deny_host("evil.example");
        let err = match acl.resolve(name("evil.example")).await {
            Err(e) => e,
            Ok(_) => panic!("expected denied host to error"),
        };
        assert_eq!(
            acl_error_of(err.as_ref()),
            AclError::DeniedHost("evil.example".into())
        );
    }

    #[tokio::test]
    async fn resolver_denies_when_all_resolved_ips_filtered() {
        // `localhost` resolves locally (no network) to loopback, which
        // deny_local_network filters out — so every resolved address is
        // denied and the resolver errors on the Continue path.
        let acl = Acl::new().deny_local_network();
        let err = match acl.resolve(name("localhost")).await {
            Err(e) => e,
            Ok(_) => panic!("expected all-denied resolution to error"),
        };
        assert_eq!(
            acl_error_of(err.as_ref()),
            AclError::NoAllowedAddress("localhost".into())
        );
    }

    #[tokio::test]
    async fn resolver_allows_loopback_when_host_explicitly_allowed() {
        // An explicitly allowed host bypasses IP filtering entirely: even
        // loopback is returned. `localhost` resolves locally, so no network.
        let acl = Acl::new().deny_local_network().allow_host("localhost");
        let addrs: Vec<_> = acl.resolve(name("localhost")).await.unwrap().collect();
        assert!(
            addrs.iter().any(|sa| sa.ip().is_loopback()),
            "expected loopback in {addrs:?}"
        );
    }
}
