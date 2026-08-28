# `0.17` -> `0.18`

### General
Most common interfaces and their changes:

| **0.17** 	| **0.18** 	|
|----------	|----------	|
| `T::unprocted_as_bytes()`| `T::unprotected_as_ref()`/`T::unprotected_as_ref::<[u8]>()` |
| `T::Default` | Removed. |
| `T::Copy` (public newtypes) | Removed. |
| `T::from_slice()` | `T::TryFrom` |
| `T::generate(length)` | Removed (length is fixed). |
| `::hkdf::sha256` | `::hkdf::Hkdf<SHA256>` |
| `orion::hazardous::kem::mlkem{512,768,1024}::MlKem*` | Removed (use `mlkem*::KeyPair`). |
| `orion::{pwhash, kdf}::Password::generate()` | Removed. |
| `orion::kex` | Removed. |
| `orion::hazardous::kem::x25519_hkdf_sha256::DhKem` | `orion::hazardous::kem::x25519_hkdf_sha256::KeyPair` |
| `orion::hazardous::stream::chacha20::{encrypt(), decrypt()}` | `orion::hazardous::stream::chacha20::ChaCha20::{encrypt(), decrypt()}` | 
| `orion::hazardous::stream::xchacha20::{encrypt(), decrypt()}` | `orion::hazardous::stream::xchacha20::XChaCha20::{encrypt(), decrypt()}` | 
| `orion::hazardous::aead::chacha20poly1305::{seal(), open()}` | `orion::hazardous::aead::chacha20poly1305::ChaCha20Poly1305::{seal(), open()}` | 
| `orion::hazardous::aead::xchacha20poly1305::{seal(), open()}` | `orion::hazardous::aead::xchacha20poly1305::XChaCha20Poly1305::{seal(), open()}` |
| `orion::hazardous::kdf::argon2::{derive_key(), verify()}` | `orion::hazardous::kdf::argon2::Argon2::{derive_key(), verify()}` |
| `orion::hazardous::kdf::scrypt::{derive_key(), verify()}` | `orion::hazardous::kdf::scrypt::Scrypt::{derive_key(), verify()}` |
| `orion::hazardous::kdf::pbkdf2::{derive_key(), verify()}` | `orion::hazardous::kdf::pbkdf2::Pbkdf2::{derive_key(), verify()}` |


### `orion::pwhash`
This snippet shows a `0.17`-compatible way to derive a `PasswordHash` using the old Argon2i and verify existing `0.17`-generated password hashes in `0.18`: [doc/0.18/migration.rs](0.18/migration.rs).

### `orion::kdf`
This snippet shows a `0.17`-compatible way to derive a secret key using the old Argon2i: [doc/0.18/migration.rs](0.18/migration.rs).

### `orion::kex`
There is unfortunately no direct, compatible migration available. `orion::kex` was built upon a somewhat more bespoke construction, and not as standardized as for example `orion::hpke`. It was also not post-quantum secure.

It has been replaced by post-quantum/traditional hybrid alternatives:
- `orion::hpke`
- `orion::kem`

`orion::kem` is what closely resembles the ECDH notion of the now removed `orion::kex`. It allows establishing shared secrets between two parties. `orion::kex` built on top of this, to provide ephemeral client/server session keys based on ECDH, giving a specific shared key for each direction.

`orion::hpke` does nearly the same. It sets up a HPKE-sender or HPKE-receiver. Each direction gets a unique shared secret, whereas HPKE also takes care of encryption: multi-part with re-ordering protection for streaming ciphertexts, or one-shot encryption.

What HPKE does not offer is, because it isn't an interactive protocol (both sender/recipient need not exchange keys in the beginning but have long-term public receiving keys), is forward secrecy for the recipient. This can be handled by frequent rotation of recipient keys, but has to be evaluated whether or not a specific application or protocol suffices with that approach.