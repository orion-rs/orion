// NOTE: These tests use Vec<u8> to decode KATs.
#[cfg(any(feature = "safe_api", feature = "alloc"))]
pub mod c2sp_wycheproof;
#[cfg(any(feature = "safe_api", feature = "alloc"))]
pub mod nist_mldsa_keygen;
#[cfg(any(feature = "safe_api", feature = "alloc"))]
pub mod nist_mldsa_siggen;
#[cfg(any(feature = "safe_api", feature = "alloc"))]
pub mod nist_mldsa_sigver;
