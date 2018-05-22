extern crate rand;
extern crate sha2;
extern crate clear_on_drop;
extern crate byte_tools;
extern crate constant_time_eq;

/// Utility functions such as generating a cryptographically strong key/nonce/salt/iv.
pub mod util;

/// HMAC (Hash-based Message Authentication Code) as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub mod hmac;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod hkdf;

/// orion's API with safe defaults.
pub mod default;

/// Sha2 options and hashing.
pub mod options;

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub mod pbkdf2;

/// Testing module for orion.
#[cfg(test)]
pub mod tests;