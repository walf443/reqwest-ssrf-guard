use reqwest::Url;

use crate::{Acl, AclError};

impl Acl {
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
    /// Combine with [`Resolve`](reqwest::dns::Resolve) (for DNS hops) and the optional
    /// `middleware` integration (for the initial URL) to cover all three
    /// places a request URL can land on a denied host.
    pub fn redirect_policy(&self) -> reqwest::redirect::Policy {
        let acl = self.clone();
        reqwest::redirect::Policy::custom(move |attempt| {
            match redirect_decision(&acl, attempt.url()) {
                RedirectDecision::Deny(e) => attempt.error(e),
                RedirectDecision::Follow => reqwest::redirect::Policy::default().redirect(attempt),
            }
        })
    }
}

/// What the redirect policy decides for a single hop, factored out of the
/// `reqwest::redirect::Attempt` machinery so the logic can be unit-tested
/// without spinning up a server.
#[derive(Debug, PartialEq, Eq)]
enum RedirectDecision {
    /// The redirect target violates the ACL; fail the request with this error.
    Deny(AclError),
    /// The target is allowed; defer to reqwest's default hop-limit policy.
    Follow,
}

/// Pure decision function backing [`Acl::redirect_policy`]: a redirect target
/// is denied exactly when [`Acl::validate_url`] rejects it.
fn redirect_decision(acl: &Acl, url: &Url) -> RedirectDecision {
    match acl.validate_url(url) {
        Err(e) => RedirectDecision::Deny(e),
        Ok(()) => RedirectDecision::Follow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

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

    // --- redirect decision (the logic backing redirect_policy) ------------

    #[test]
    fn redirect_denies_local_ip_literal_target() {
        // A redirect to an IP-literal on the local network is rejected — this
        // is the SSRF-via-redirect case the policy exists to stop.
        let acl = deny_local();
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://127.0.0.1/admin").unwrap()),
            RedirectDecision::Deny(AclError::DeniedIp(v4("127.0.0.1")))
        );
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://[::1]/").unwrap()),
            RedirectDecision::Deny(AclError::DeniedIp(v6("::1")))
        );
    }

    #[test]
    fn redirect_denies_via_host_rule() {
        let acl = Acl::new().deny_host("evil.example");
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://evil.example/").unwrap()),
            RedirectDecision::Deny(AclError::DeniedHost("evil.example".into()))
        );
    }

    #[test]
    fn redirect_follows_allowed_target() {
        let acl = deny_local();
        // Public IP literal — allowed.
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://1.1.1.1/").unwrap()),
            RedirectDecision::Follow
        );
        // Domain target — deferred to the resolver, so the redirect is followed.
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://example.com/").unwrap()),
            RedirectDecision::Follow
        );
    }

    #[test]
    fn redirect_honours_allow_exception() {
        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr(cidr("192.168.1.100/32"));
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://192.168.1.100/").unwrap()),
            RedirectDecision::Follow
        );
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://192.168.1.101/").unwrap()),
            RedirectDecision::Deny(AclError::DeniedIp(v4("192.168.1.101")))
        );
    }

    #[test]
    fn redirect_denies_non_default_port() {
        let acl = Acl::new().deny_non_default_ports();
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://example.com:6379/").unwrap()),
            RedirectDecision::Deny(AclError::DeniedPort(6379))
        );
        assert_eq!(
            redirect_decision(&acl, &Url::parse("http://example.com/").unwrap()),
            RedirectDecision::Follow
        );
    }
}
