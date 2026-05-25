//! End-to-end tests that hit a tiny in-process HTTP server, covering both
//! the "allowed" and "denied" paths through the resolver, redirect policy,
//! and (when the `middleware` feature is on) the middleware.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest_ssrf_guard::Acl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a one-shot-ish HTTP/1.1 server bound to `127.0.0.1:0` that replies
/// with `response` to every incoming request. Returns the bound address.
async fn spawn_server(response: Arc<String>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let response = response.clone();
            tokio::spawn(async move {
                // Read until we've seen the end of the request headers; we
                // don't care about the body since this is GET-only.
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn http_200() -> Arc<String> {
    Arc::new("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_owned())
}

fn http_302(location: &str) -> Arc<String> {
    Arc::new(format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ))
}

/// Walk the source chain of a `reqwest::Error` looking for our ACL message.
fn chain_contains(err: &dyn std::error::Error, needle: &str) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = current {
        if e.to_string().contains(needle) {
            return true;
        }
        current = e.source();
    }
    false
}

// --- positive paths through the resolver -------------------------------------

#[tokio::test]
async fn allowed_domain_request_via_resolver_succeeds() {
    let addr = spawn_server(http_200()).await;
    let acl = Acl::new()
        .deny_local_network()
        .allow_cidr("127.0.0.1/32".parse().unwrap());

    let client = acl.configure(reqwest::Client::builder()).build().unwrap();

    let url = format!("http://localhost:{}/", addr.port());
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn denied_domain_request_via_resolver_fails() {
    let addr = spawn_server(http_200()).await;
    let acl = Acl::new().deny_local_network();
    let client = acl.configure(reqwest::Client::builder()).build().unwrap();

    let url = format!("http://localhost:{}/", addr.port());
    let err = client.get(&url).send().await.unwrap_err();
    assert!(
        chain_contains(&err, "denied by ACL"),
        "expected ACL error in chain, got: {err:?}"
    );
}

// --- redirect policy ---------------------------------------------------------

#[tokio::test]
async fn redirect_to_allowed_host_follows() {
    let final_server = spawn_server(http_200()).await;
    let final_url = format!("http://127.0.0.1:{}/end", final_server.port());
    let redirect_server = spawn_server(http_302(&final_url)).await;

    let acl = Acl::new()
        .deny_local_network()
        .allow_cidr("127.0.0.1/32".parse().unwrap());
    let client = acl.configure(reqwest::Client::builder()).build().unwrap();

    let url = format!("http://localhost:{}/", redirect_server.port());
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn redirect_to_denied_host_errors_via_policy() {
    // TEST-NET-1 (RFC5737) — never routed, but the redirect policy should
    // reject before any connection attempt is made.
    let redirect_server = spawn_server(http_302("http://192.0.2.1:1/end")).await;

    let acl = Acl::new()
        .deny_local_network()
        .allow_cidr("127.0.0.1/32".parse().unwrap())
        .deny_cidr("192.0.2.0/24".parse().unwrap());
    let client = acl.configure(reqwest::Client::builder()).build().unwrap();

    let url = format!("http://localhost:{}/", redirect_server.port());
    let err = client.get(&url).send().await.unwrap_err();
    assert!(err.is_redirect(), "expected redirect error, got: {err}");
    assert!(
        chain_contains(&err, "denied by ACL"),
        "expected ACL error in chain, got: {err:?}"
    );
}

// --- middleware feature ------------------------------------------------------

#[cfg(feature = "middleware")]
mod with_middleware {
    use super::*;
    use reqwest_middleware::ClientBuilder;

    #[tokio::test]
    async fn allowed_ip_literal_passes_middleware_and_succeeds() {
        let addr = spawn_server(http_200()).await;

        let acl = Acl::new()
            .deny_local_network()
            .allow_cidr("127.0.0.1/32".parse().unwrap());
        let inner = acl.configure(reqwest::Client::builder()).build().unwrap();
        let client = acl.configure_middleware(ClientBuilder::new(inner)).build();

        let url = format!("http://127.0.0.1:{}/", addr.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn denied_ip_literal_blocked_by_middleware() {
        let addr = spawn_server(http_200()).await;

        let acl = Acl::new().deny_local_network();
        let inner = acl.configure(reqwest::Client::builder()).build().unwrap();
        let client = acl.configure_middleware(ClientBuilder::new(inner)).build();

        let url = format!("http://127.0.0.1:{}/", addr.port());
        let err = client.get(&url).send().await.unwrap_err();
        assert!(err.is_middleware(), "expected middleware error, got: {err}");
        assert!(
            chain_contains(&err, "denied by ACL"),
            "expected ACL error in chain, got: {err:?}"
        );
    }
}
