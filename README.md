# reqwest-ssrf-guard

Mitigate SSRF and DNS rebinding in [`reqwest`](https://docs.rs/reqwest) by
filtering DNS lookups, redirect targets, and URL literals through an IP /
host ACL.

## Quick start

The `Acl` builder is both the policy and the `Resolve` impl, so hand it
straight to reqwest:

```rust
use std::sync::Arc;
use reqwest_ssrf_guard::Acl;

let client = reqwest::Client::builder()
    .dns_resolver(Arc::new(Acl::new().deny_local_network()))
    .build()?;
```

`deny_local_network()` rejects RFC1918 private ranges, loopback, link-local,
shared / CGNAT (`100.64.0.0/10`, RFC6598), IPv6 ULA / link-local, IPv4-mapped
variants of the same, and a few related ranges. This blocks the cloud
metadata endpoints used by AWS / GCP / Azure / DigitalOcean / Oracle /
Hetzner / IBM (all at `169.254.169.254`) and Alibaba Cloud
(`100.100.100.200`). If every address returned for a hostname is denied,
the request fails with `PermissionDenied`.

## Customizing

Combine presets with explicit rules. **Explicit `allow_*` always wins over
`deny_*`**, so order does not matter and "deny a broad range, except for this
specific IP" reads naturally:

```rust
use std::sync::Arc;
use reqwest_ssrf_guard::Acl;

let acl = Acl::new()
    .deny_local_network()
    .allow_cidr("192.168.1.100/32".parse()?)   // a single IP
    .deny_cidr("203.0.113.0/24".parse()?);     // a whole range

let client = reqwest::Client::builder()
    .dns_resolver(Arc::new(acl))
    .build()?;
```

Builder methods:

| Method | Effect |
| --- | --- |
| `deny_local_network()` | Append a deny rule covering all local-network ranges. |
| `deny_cidr(net)` / `allow_cidr(net)` | Deny / allow an entire CIDR block. For a single IP pass `/32` (v4) or `/128` (v6). |
| `deny_ip_when(\|ip\| ...)` / `allow_ip_when(\|ip\| ...)` | Custom IP predicates when CIDR isn't enough. |
| `deny_host(name)` / `allow_host(name)` | Match the exact hostname (case-insensitive). |
| `deny_host_suffix(suf)` / `allow_host_suffix(suf)` | Match by trailing-string suffix. Pass a leading dot to limit to strict subdomains (e.g. `".example.com"`). |
| `deny_host_when(\|h\| ...)` / `allow_host_when(\|h\| ...)` | Custom host predicate. The hostname is normalized (lowercased, trailing dot stripped) before being passed in. |
| `default_deny()` | Flip the default IP-layer decision — useful for allowlist mode. |

Allowlist example:

```rust
let acl = Acl::new()
    .default_deny()
    .allow_cidr("1.1.1.1/32".parse()?)
    .allow_cidr("8.8.8.8/32".parse()?);
```

## Host name rules

Host rules are checked **before** DNS resolution. They cover two cases the
IP layer can't: blocking a specific domain regardless of where it resolves,
and pre-trusting a host so it isn't filtered.

```rust
let acl = Acl::new()
    .deny_local_network()
    .deny_host_suffix(".internal.corp")          // block a whole zone
    .deny_host("phishing.example")               // block a specific name
    .allow_host("api.example.com");              // trust this host fully
```

Semantics (same "explicit allow wins" model as the IP layer):

- **Host allow matches** → the connection is allowed, **and the IP layer is
  skipped**. ⚠ This means the SSRF / DNS rebinding protection is off for that
  host. Only use `allow_host*` for hosts you fully trust to resolve to safe
  addresses.
- **Host deny matches** → reject the request without resolving DNS at all.
- **No host rule matches** → fall through to the IP layer.

The hostname is lowercased and any trailing dot is stripped before
matching, so `Example.COM.` and `example.com` are equivalent.

## Wiring the ACL into a client

There are three places where a request can land on a denied host, and each
of them needs the ACL plugged in separately:

| Layer | Covers | Misses |
| --- | --- | --- |
| **Resolver** (`dns_resolver`) | DNS lookups — initial request and any redirect to a domain | URLs / redirects whose host is an IP literal (DNS isn't consulted) |
| **Redirect policy** (`redirect`) | Every redirect hop, including IP-literal targets | The initial URL itself |
| **`validate_url`** (or `middleware` feature) | The initial request URL, including IP-literal hosts | Anything reqwest decides to follow after that |

Use [`Acl::configure`] to install the first two in one shot:

```rust
use std::time::Duration;
use reqwest_ssrf_guard::Acl;

let acl = Acl::new()
    .deny_local_network()
    .deny_host_suffix(".internal.corp");

let client = acl
    .configure(reqwest::Client::builder())   // resolver + redirect policy
    .timeout(Duration::from_secs(30))        // any other reqwest settings work
    .build()?;
```

That leaves the initial URL — handle it with either a manual `validate_url`
call or the `middleware` feature.

### Manual URL pre-check

```rust
let acl = Acl::new().deny_local_network();
acl.validate_url(&url)?;                       // rejects IP literals
let resp = client.get(url).send().await?;
```

`Acl::validate_url` checks the URL scheme first, then consults both host
rules and IP rules.

### Scheme allowlist

`validate_url` only permits schemes in the allowlist, which defaults to
`http` and `https`. This rejects host-less URLs such as `file:///etc/passwd`,
`data:`, and `gopher://…` that would otherwise slip past the host/IP checks
(`AclError::DeniedScheme`). Override it when needed:

```rust
Acl::new().restrict_schemes(["https"]);            // forbid plaintext http too
Acl::new().restrict_schemes(["http", "https", "ftp"]); // widen if you must
```

### `reqwest-middleware` integration (feature: `middleware`)

Enable the `middleware` feature to have `validate_url` run automatically
before every outgoing request:

```toml
[dependencies]
reqwest-ssrf-guard = { version = "0.1", features = ["middleware"] }
```

```rust
use reqwest_ssrf_guard::Acl;
use reqwest_middleware::ClientBuilder;

let acl = Acl::new().deny_local_network();

let inner = acl.configure(reqwest::Client::builder()).build()?;
let client = acl
    .configure_middleware(ClientBuilder::new(inner))
    .build();
```

A failed `validate_url` surfaces as
`reqwest_middleware::Error::Middleware(_)` wrapping the `AclError`. Use
`error.is_middleware()` to distinguish it from network errors.

## Custom logic

When the built-in presets aren't enough, drop into a closure via
`deny_ip_when` / `allow_ip_when` / `deny_host_when` / `allow_host_when`. The
closures can capture any state you like:

```rust
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use reqwest_ssrf_guard::Acl;

let dynamic_blocklist: Arc<RwLock<HashSet<IpAddr>>> = Arc::default();

let acl = Acl::new()
    .deny_local_network()
    .deny_ip_when({
        let bl = dynamic_blocklist.clone();
        move |ip| bl.read().unwrap().contains(&ip)
    });
```
