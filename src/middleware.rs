use crate::Acl;

/// Use [`Acl`] directly as a [`reqwest_middleware::Middleware`] so that
/// every outgoing request is filtered through [`Acl::validate_url`].
///
/// Enable the `middleware` feature, then register it with
/// [`configure_middleware`](Acl::configure_middleware), or pass it to
/// `ClientBuilder::with` directly:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use reqwest_ssrf_guard::Acl;
/// use reqwest_middleware::ClientBuilder;
///
/// let acl = Acl::new().deny_local_network();
/// let inner = acl.configure(reqwest::Client::builder()).build()?; // resolver + redirect policy
/// let client = ClientBuilder::new(inner).with(acl).build();
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
///
/// Validation failures are surfaced as `reqwest_middleware::Error::Middleware`
/// wrapping the [`AclError`](crate::AclError).
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

#[cfg(test)]
mod tests {
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
