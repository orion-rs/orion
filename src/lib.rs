extern crate rand;
extern crate sha2;
extern crate clear_on_drop;

/// Utility functions such as constant time comparison.
pub mod util;

/// HMAC (Hash-based Message Authentication Code) as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub mod hmac;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod hkdf;

/// API for the rest of orion.
pub mod default;

/// Sha2 options.
pub mod options;

/// PBKDF2
pub mod pbkdf2;
