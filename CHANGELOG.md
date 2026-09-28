# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - Unreleased

### Breaking changes

- `AclError` is now `#[non_exhaustive]`, so new rejection reasons can be
  added later without another breaking release. A `match` on `AclError`
  now needs a wildcard (`_ =>`) arm. Code that only checks *whether* an
  error is an `AclError` (e.g. via `downcast_ref`) is unaffected. (#17)
- The minimum supported Rust version is now declared as 1.87
  (`rust-version` in `Cargo.toml`).

### Added

- Port rules: `Acl::deny_non_default_ports()` rejects URLs with an explicit
  port other than the scheme's default (e.g. `http://host:6379/`), and
  `Acl::allow_ports([...])` adds exceptions. The new variant
  `AclError::DeniedPort(u16)` reports these rejections, and
  `Acl::is_allowed_port` is available too. Port rules are opt-in and are
  enforced by `validate_url`, the redirect policy and the middleware. (#18)

### Documentation

- The Quick start now shows the recommended setup:
  `deny_non_default_ports()`, plus reqwest's `https_only(true)` and
  `no_proxy()`, with the reason for each. (#18, #20, #21)
- New section on the proxy gap: with `HTTP_PROXY` / `HTTPS_PROXY` /
  `ALL_PROXY` set, the proxy resolves the target hostname, so the ACL's IP
  rules don't apply to domain names. `Acl::configure` does not change proxy
  settings. (#21)

### Internal

- Split `src/lib.rs` into private modules. The public API is unchanged. (#19)

## [0.1.0] - 2026-06-08

- Initial release.

[0.2.0]: https://github.com/walf443/reqwest-ssrf-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/walf443/reqwest-ssrf-guard/releases/tag/v0.1.0
