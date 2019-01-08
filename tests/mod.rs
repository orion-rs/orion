#[cfg(test)]
pub mod aead;
#[cfg(test)]
pub mod kdf;
#[cfg(test)]
pub mod mac;
#[cfg(test)]
pub mod stream;
// See: https://github.com/brycx/orion/issues/15
#[cfg(test)]
pub mod hash;
#[cfg(test)]
#[cfg(target_endian = "little")]
pub mod xof;
