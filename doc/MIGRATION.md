# `0.17` -> `0.18`

### `orion::pwhash`
This snippet shows a `0.17`-compatible way to derive a `PasswordHash` using the old Argon2i and verify existing `0.17`-generated password hashes in `0.18`: [doc/0.18/migration.rs](0.18/migration.rs).

### `orion::kdf`
This snippet shows a `0.17`-compatible way to derive a secret key using the old Argon2i: [doc/0.18/migration.rs](0.18/migration.rs).

### `orion::kex`
There is unfortunately no direct, compatible migration available. `orion::kex` was built upon a somewhat more bespoke construction, and not as standardized as for example `orion::hpke`. It was also not post-quantum secure.

It has been replaced by post-quantum/traidtional hybrid alternatives:
- `orion::hpke`
- `orion::kem`

`orion::kem` is what closely resembles the ECDH notion of the now removed `orion::kex`. It allows establishing shared secrets between two parties. `orion::kex` built on top of this, to provide ephemeral client/server session keys based on ECDH, giving a specific shared key for each direction.

`orion::hpke` does nearly the same. It sets up a HPKE-sender or HPKE-receiver. Each direction gets a unique shared secret, whereas HPKE also takes care of encryption: multi-part with re-ordering protection for streaming ciphertexts, or one-shot encryption.

What HPKE does not offer is, because it isn't an interactive protocol (both sender/recipient need not exchange keys in the beginning but have long-term public receiving keys), is forward secrecy for the recipient. This can be handeled by frequent rotation of recipient keys, but has to be evaluated whether or not a specific application or protocol suffices with that approach.