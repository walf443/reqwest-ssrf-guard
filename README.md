# reqwest-acl

IP-based ACL for [`reqwest`](https://docs.rs/reqwest) — mitigate SSRF and DNS
rebinding by filtering the addresses returned from DNS and rejecting URLs
whose host is an IP literal denied by the ACL.

## Quick start

The `Acl` builder is both the policy and the `Resolve` impl, so hand it
straight to reqwest:

```rust
use std::sync::Arc;
use reqwest_acl::Acl;

let client = reqwest::Client::builder()
    .dns_resolver(Arc::new(Acl::new().deny_local_network()))
    .build()?;
```

`deny_local_network()` rejects RFC1918 private ranges, loopback, link-local,
IPv6 ULA / link-local, IPv4-mapped variants of the same, and a few related
ranges. If every address returned for a hostname is denied, the request fails
with `PermissionDenied`.

## Customizing

Combine presets with explicit rules. **Explicit `allow_*` always wins over
`deny_*`**, so order does not matter and "deny a broad range, except for this
specific IP" reads naturally:

```rust
use std::sync::Arc;
use reqwest_acl::Acl;

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

## Where the ACL gets a chance to fire

Three different layers see different parts of the request lifecycle, and
each one closes a gap the others can't. The same `Acl` plugs into all
three:

| Layer | Covers | Misses |
| --- | --- | --- |
| **Resolver** (`dns_resolver(Arc::new(acl.clone()))`) | DNS lookups — initial request and any redirect to a domain | URLs / redirects whose host is an IP literal (DNS isn't consulted) |
| **`validate_url`** / **`middleware` feature** | The initial request URL, including IP-literal hosts | Anything reqwest decides to follow after that |
| **Redirect policy** (`redirect(acl.redirect_policy())`) | Every redirect hop, including IP-literal targets | The initial URL itself |

Wire all three to cover every host the request can touch:

```rust
use std::sync::Arc;
use reqwest_acl::Acl;

let acl = Acl::new()
    .deny_local_network()
    .deny_host_suffix(".internal.corp");

let client = reqwest::Client::builder()
    .dns_resolver(Arc::new(acl.clone()))   // domain hops (initial + redirects)
    .redirect(acl.redirect_policy())       // every redirect URL, incl. IP literals
    .build()?;

// Then either call validate_url manually before each .send(),
// or enable the `middleware` feature and let it run automatically.
```

### Manual URL pre-check

```rust
let acl = Acl::new().deny_local_network();
acl.validate_url(&url)?;                       // rejects IP literals
let resp = client.get(url).send().await?;
```

`Acl::validate_url` consults both host rules and IP rules.

### `reqwest-middleware` integration (feature: `middleware`)

Enable the `middleware` feature to have `validate_url` run automatically
before every outgoing request:

```toml
[dependencies]
reqwest-acl = { version = "0.1", features = ["middleware"] }
```

```rust
use std::sync::Arc;
use reqwest_acl::Acl;
use reqwest_middleware::ClientBuilder;

let acl = Acl::new().deny_local_network();

let inner = reqwest::Client::builder()
    .dns_resolver(Arc::new(acl.clone()))
    .redirect(acl.redirect_policy())
    .build()?;

let client = ClientBuilder::new(inner).with(acl).build();
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
use reqwest_acl::Acl;

let dynamic_blocklist: Arc<RwLock<HashSet<IpAddr>>> = Arc::default();

let acl = Acl::new()
    .deny_local_network()
    .deny_ip_when({
        let bl = dynamic_blocklist.clone();
        move |ip| bl.read().unwrap().contains(&ip)
    });
```
