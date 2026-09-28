#![doc = include_str!("../README.md")]

mod acl;
mod error;
mod ip;
#[cfg(feature = "middleware")]
mod middleware;
mod redirect;
mod resolve;
#[cfg(test)]
mod test_support;

pub use acl::{Acl, HostDecision};
pub use error::AclError;
pub use ip::is_local_network;
pub use ipnet;
