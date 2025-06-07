### 0.17.11

**Date:** TBD.

**Changelog:**
- Bump `fiat-crypto` to `0.3.0`.

### 0.17.10

**Date:** April 12, 2025.

**Changelog:**
- Add `encap_deterministic()` and `auth_encap_deterministic()` to `DhKem` in `hazardous::kem::x25519_hkdf_sha256::DhKem` [#458](https://github.com/orion-rs/orion/pull/458).
- Make `hazardous::kem::x25519_hkdf_sha256::DhKem` available in `#![no_std]` context [#458](https://github.com/orion-rs/orion/pull/458).
- Add support for HPKE (RFC 9180) [#458](https://github.com/orion-rs/orion/pull/458).
- Switch to source-based code coverage [#462](https://github.com/orion-rs/orion/pull/462).
- ML-KEM (internal): Cache hash of encapsulation key to save computation on multiple `encap()` operations [#464](https://github.com/orion-rs/orion/pull/464).
- ML-KEM (internal): Cache encapsulation key within decapsulation key, to avoid re-computation after generation of decapsulation key [#447](https://github.com/orion-rs/orion/pull/447).

### 0.17.9

**Date:** March 1, 2025.

**Changelog:**
- Add support for post-quantum ML-KEM from FIPS-203 ([#431](https://github.com/orion-rs/orion/pull/431)).
- Add support for hybrid KEM X-Wing (draft06 version) ([#434](https://github.com/orion-rs/orion/issues/434)).
- Implement `core::error::Error` instead of the `std`-version ([#440](https://github.com/orion-rs/orion/pull/440)).
- Bump MSRV to `1.81.0`.
- Update CI dependencies.

### 0.17.8

**Date:** January 27, 2025.

**Changelog:**

- Bump `getrandom` to `0.3.0`.
- Update CI dependencies.

### 0.17.7

**Date:** September 10, 2024.

**Changelog:**

- Add support for SHAKE128 and SHAKE256 from FIPS 202 ([#398](https://github.com/orion-rs/orion/pull/398)).
- Bump copyright year to 2024.
- Bump MSRV to `1.80.0`.
- Update CI dependencies.
- SHA2: Switch from `checked_shl(3)` to `checked_mul(8)` during `increment_mlen()` (internal) ([#376](https://github.com/orion-rs/orion/issues/376)).

### 0.17.6

**Date:** September 19, 2023.

**Changelog:**

- Bump MSRV to `1.70.0`.
- Bump `fiat-crypto` to `0.2.1`.

### 0.17.5

**Date:** July 4, 2023.

**Changelog:**

- Add `experimental` crate feature.
- Add support for fully-committing AEAD variants based on CTX ([#324](https://github.com/orion-rs/orion/pull/324)).
- Add support for SHA3 ([#327](https://github.com/orion-rs/orion/pull/327)).
- Bump MSRV to `1.64`.
- Add support for DHKEM(X25519, HKDF-SHA256) from HPKE [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).

### 0.17.4

**Date:** March 4, 2023.

**Changelog:**

- Update Wycheproof test vectors ([#320](https://github.com/orion-rs/orion/issues/320)).
- Switch from `actions-rs/tarpaulin` to `cargo-tarpaulin` ([#322](https://github.com/orion-rs/orion/pull/322))
- Update documentation for PBKDF2 and Argon2i cost parameter selection ([#316](https://github.com/orion-rs/orion/pull/316), [#321](https://github.com/orion-rs/orion/pull/321)).
- Remove `cargo-audit` which was redundant to `cargo-deny` ([#311](https://github.com/orion-rs/orion/issues/311)).
- Bump MSRV to `1.59.0`.
- Remove `html_root_url` ([#325](https://github.com/orion-rs/orion/pull/325)).

### 0.17.3

**Date:** December 7, 2022.

**Changelog:**

- Fix misuse issue in (X)ChaCha20 and (X)ChaCha20-Poly1305 APIs ([#308](https://github.com/orion-rs/orion/issues/308)).
- Add benchmark check test without running any actual benchmarks ([#307](https://github.com/orion-rs/orion/pull/307)).
- Improve `Balek2b::new()` docs ([#303](https://github.com/orion-rs/orion/pull/303)).
- Migrated to Rust Edition 2021 ([#237](https://github.com/orion-rs/orion/issues/237)).
- MSRV bumped to `1.57.0` and `criterion` updated ([#299](https://github.com/orion-rs/orion/pull/299)).
- Added `serde` doc feature-tag to `PasswordHash` ser/deser impls ([#297](https://github.com/orion-rs/orion/pull/297)).

### 0.17.2

**Date:** August 16, 2022.

**Changelog:**

- BLAKE2b `Hasher` enum now implements `Debug + PartialEq` ([#278](https://github.com/orion-rs/orion/issues/278) (by [@black-eagle17](https://github.com/black-eagle17))).
- Removed unmaintained `audit-check` and replaced with `cargo-deny` ([#292](https://github.com/orion-rs/orion/pull/292)).
- Allow Unicode-DFS-2016 license in dev-dependency tree ([#291](https://github.com/orion-rs/orion/pull/291)).

### 0.17.1

**Date:** January 30, 2022.

**Changelog:**

- Use fiat-crypto from their provided crate on crates.io ([#201](https://github.com/orion-rs/orion/issues/201)) (by [Vince Mutolo](https://github.com/vlmutolo)).
- Doc-tests no longer fail if run with `cargo test --no-default-features`, as the erroneous usages have been feature-gated ([#254](https://github.com/orion-rs/orion/issues/254)).
- Specify MSRV in `Cargo.toml` via `rust-version` field ([#250](https://github.com/orion-rs/orion/issues/250)).
- `audit-check` GitHub Action added in addition to `cargo-audit` ([#257](https://github.com/orion-rs/orion/issues/257)).
- Updated copyright year to 2022 ([#267](https://github.com/orion-rs/orion/issues/267)).
- Implement `std::io::Write` for BLAKE2 and SHA2, also adding `orion::hash::digest_from_reader` ([#228](https://github.com/orion-rs/orion/pull/228)) (by [Vince Mutolo](https://github.com/vlmutolo)).
- Implement Poly1305 using fiat-crypto ([#198](https://github.com/orion-rs/orion/issues/198)).
- Correct capitalization of crate name in docs, README and wiki ([#259](https://github.com/orion-rs/orion/issues/259)).
- Fix the benchmarking targets that failed to compile after `0.17.0` ([#270](https://github.com/orion-rs/orion/pull/270)).
- Various internal cleanups and improvements.

### 0.17.0

**Date:** November 24, 2021.

**Changelog:**

- [Breaking change] Keyed and non-keyed BLAKE2b have been split into two separate modules (`orion::hazardous::mac::blake2b` and `orion::hazardous::hash::blake2::blake2b` respectively). The keyed now returns a `Tag` instead of `Digest` ([#208](https://github.com/orion-rs/orion/issues/208)).
- [Breaking change] `Tag`s (not only those used by BLAKE2b, but all) now implement `Drop` but no longer implement `Copy` ([#208](https://github.com/orion-rs/orion/issues/208)).
- [Breaking change] `seal_chunk()` used in streaming AEAD now take `StreamTag` by reference ([#212](https://github.com/orion-rs/orion/issues/212)) (by [24seconds](https://github.com/24seconds)).

### 0.16.1

**Date:** November 3, 2021.

**Changelog:**

- Add support for X25519 using fiat-crypto Curve25519 field arithmetic (new modules `orion::hazardous::ecc` and `orion::kex`) ([#197](https://github.com/orion-rs/orion/pull/197)).
- Implement serde `Serialize` and `Deserialize` for relevant types ([#192](https://github.com/orion-rs/orion/issues/192)) (by [Vince Mutolo](https://github.com/vlmutolo)).
- Fix incorrect documentation of SHA256 streaming state ([#196](https://github.com/orion-rs/orion/issues/196)).
- Add `is_empty()` to newtypes ([#206](https://github.com/orion-rs/orion/pull/206)).
- Add documentation for correct use of streaming AEAD API with `StreamTag::Finish` ([#139](https://github.com/orion-rs/orion/issues/139)).
- Convert uses of `assert!(a == b)` to `assert_eq!(a, b)` where possible ([#210](https://github.com/orion-rs/orion/issues/210)) (by [Emmanuel Leblond](https://github.com/touilleMan)).
- Derive `Clone` + `Copy` for `StreamTag` ([#211](https://github.com/orion-rs/orion/issues/211)) (by [24seconds](https://github.com/24seconds)).
- Harden security of GitHub Actions CI/CD ([#200](https://github.com/orion-rs/orion/issues/200)) (by [Vince Mutolo](https://github.com/vlmutolo)).
- Re-export HMAC `Tag`s used in their corresponding HKDF API ([#224](https://github.com/orion-rs/orion/issues/224)).
- Fix warnings from CI jobs and bump MSRV to `1.52.0` ([#222](https://github.com/orion-rs/orion/issues/222)) ([#223](https://github.com/orion-rs/orion/issues/223)).
- Update benchmarks ([#214](https://github.com/orion-rs/orion/issues/214)).
- Render feature badges for API on docs.rs ([#238](https://github.com/orion-rs/orion/issues/238)).
- Add new Crate Features page to wiki ([#215](https://github.com/orion-rs/orion/issues/215)).

### 0.16.0

**Date:** March 29, 2021.

**Changelog:**

- [Breaking change] Moved all libraries to the https://github.com/orion-rs organization and added [Vince Mutolo](https://github.com/vlmutolo) as a maintainer ([#191](https://github.com/orion-rs/orion/issues/191)).
- [Breaking change] Use Argon2i parameters from PasswordHash in `pwhash::hash_password_verify()` ([#138](https://github.com/orion-rs/orion/issues/138)) (by [Vince Mutolo](https://github.com/vlmutolo)).
- [Breaking change] Limit high-level, variable-length newtype's input to `isize::MAX` ([#130](https://github.com/orion-rs/orion/issues/130)).
- [Breaking change] Add support for SHA256 and SHA384 ([#152](https://github.com/orion-rs/orion/issues/152), [#181](https://github.com/orion-rs/orion/pull/181), [#162](https://github.com/orion-rs/orion/issues/162), [#183](https://github.com/orion-rs/orion/pull/183)).
- [Breaking change] Add support for HMAC-SHA(256/384), PBKDF2-HMAC-SHA(256/384) and HKDF-HMAC-SHA(256/384) ([#171](https://github.com/orion-rs/orion/pull/171), [#153](https://github.com/orion-rs/orion/issues/153), [#154](https://github.com/orion-rs/orion/issues/154), [#170](https://github.com/orion-rs/orion/issues/170)).
- [Breaking change] Remove `orion::kdf::derive_key_verify()` and `orion::hazardous::kdf::hkdf::verify()` ([#179](https://github.com/orion-rs/orion/issues/179), [#184](https://github.com/orion-rs/orion/pull/184)).
- [Breaking change] Convert `StreamTag` used in `orion::hazardous::aead::streaming` and `orion::aead::streaming` to lower-case acronyms (i.e `StreamTag::MESSAGE` -> `StreamTag::Message`) ([#190](https://github.com/orion-rs/orion/pull/190)).
- Use new intra-doc links ([#134](https://github.com/orion-rs/orion/issues/134), [#185](https://github.com/orion-rs/orion/pull/185)) along with other small improvements to documentation.
- Update fuzzing targets (#[182](https://github.com/orion-rs/orion/issues/182)).
- Add documentation for user-awareness of potential sensitive data in out-parameters during password-hash verification ([#178](https://github.com/orion-rs/orion/issues/178), [#187](https://github.com/orion-rs/orion/pull/187)) (contrib. by [Vince Mutolo](https://github.com/vlmutolo)).
- Replace `base64` dependency with `ct-codecs` to support constant-time encoding & decoding in `orion::pwhash::PasswordHash` ([#188](https://github.com/orion-rs/orion/issues/188), [#189](https://github.com/orion-rs/orion/pull/189)).
- Refactor property-based tests to use the `#[quickcheck]` attribute, introducing `quickcheck_macros` as a dev-dependency ([#180](https://github.com/orion-rs/orion/pull/180)).
- Bump MSRV to `1.51.0`.

### 0.15.6

**Date:** February 9, 2021.

**Changelog:**

- The entire CI infrastructure has been moved to GitHub Actions (removing AppVeyor and Travis CI).
- Add `cargo-deny` to CI jobs ([#174](https://github.com/brycx/orion/pull/174)).
- Refactoring of code related to testing and reading test vectors ([#136](https://github.com/brycx/orion/pull/136), [#143](https://github.com/brycx/orion/pull/143)).
- Add new public Matrix room for discussion ([#144](https://github.com/brycx/orion/issues/144)).
- Internal documentation improvements and clippy improvements (by [u5surf](https://github.com/u5surf)).
- Update and correct license years ([#164](https://github.com/brycx/orion/pull/164)).
- Update `quickcheck`.
- Fix documentation on the `generate()` output-size for HMAC-based secret key newtypes which was incorrect ([#169](https://github.com/brycx/orion/issues/169)).
- Improve the usage example in `orion::auth` ([Vince Mutolo](https://github.com/vlmutolo)).
- Add GitHub issue templates for bugs and feature requests ([#155](https://github.com/brycx/orion/pull/155)).
- Add `SECURITY.md`, specifying a disclosure policy, threat-model and information regarding yanking ([#163](https://github.com/brycx/orion/pull/163)).

### 0.15.5

**Date:** October 13, 2020.

**Changelog:**

- Documentation improvements.
- Update `base64` to `0.13.0`.

### 0.15.4

**Date:** September 25, 2020.

**Changelog:**

- Empty plaintexts are now allowed for `hazardous::aead` ([#127](https://github.com/brycx/orion/pull/127)).
- Update `getrandom` to `0.2`.
- Bump MSRV to `1.41` due to bump in `subtle`.

### 0.15.3

**Date:** August 8, 2020.

**Changelog:**

- Documentation improvements.
- Argon2i is now available in a `no_std` context, using the new `alloc` feature ([#126](https://github.com/brycx/orion/pull/126)).
- `release` and `bench` profiles now use the default LTO (thin local LTO) instead of fat LTO.

### 0.15.2

**Date:** June 7, 2020.

**Changelog:**

- Remove old `no_std` feature from CONTRIBUTING guidelines.
- Improve documentation and code around HKDFs maximum output length.
- Move clippy, rustfmt and basic tests to GitHub Actions ([#122](https://github.com/brycx/orion/pull/122)).
- Add random secret-key/nonce tests to AEADs and stream ciphers ([#123](https://github.com/brycx/orion/pull/123)).
- Address various clippy warnings.

### 0.15.1

**Date:** March 9, 2020.

**Changelog:**

- Update `base64` dependency from `0.11.0` to `0.12.0`.
- Documentation improvements.

### 0.15.0

**Date:** February 25, 2020.

**Changelog:**

- [Breaking change] `secure_cmp` and all verification functions now return `Result<(), UnknownCryptoError>` instead of `Result<bool, UnknownCryptoError>` ([#97](https://github.com/brycx/orion/issues/97)).
- [Breaking change] HChaCha20 is no longer public.
- [Breaking change] The default size of a randomly generated secret key in `hazardous::hash::blake2b` is now 32 bytes instead of 64 bytes ([#88](https://github.com/brycx/orion/pull/88#issuecomment-529423151)).
- [Breaking change] `orion::auth` now uses BLAKE2b in keyed-mode as MAC ([#88](https://github.com/brycx/orion/pull/88), by [Vince Mutolo](https://github.com/vlmutolo)).
- [Breaking change] The public API for structs used with incremental processing has been changed ([#106](https://github.com/brycx/orion/issues/106) and [#87](https://github.com/brycx/orion/pull/87)).
- [Breaking change] Support for Argon2i(single-threaded) has been added. This is now used in the `orion::kdf` and `orion::pwhash` modules ([#113](https://github.com/brycx/orion/pull/113)).
- [Breaking change] `chacha20::keystream_block` is no longer available.
- [Breaking change] Uses of (X)ChaCha20Poly1305 will return an error if a `usize` to `u64` conversion would be lossy.
- [Breaking change] orion is now `no_std`-compatible on stable Rust and the `no_std` and `nightly` features have been removed ([#111](https://github.com/brycx/orion/pull/111)).
- libsodium-compatible, streaming AEAD based on XChaCha20Poly1305 (libsodiums "secretstream") ([#99](https://github.com/brycx/orion/pull/99) and [#108](https://github.com/brycx/orion/pull/108), by [snsmac](https://github.com/snsmac)).
- Switch to Criterion for benchmarks.
- Add contribution guidelines in `CONTRIBUTING.md`.
- Move the changelog to a `CHANGELOG.md` file.
- Add test vectors to XChaCha20.
- Improvements to `secure_cmp` ([#93](https://github.com/brycx/orion/pull/93), by [snsmac](https://github.com/snsmac))
- Add explicit security warnings to `#[must_use]` public APIs that return a `Result` ([#95](https://github.com/brycx/orion/pull/95), by [Cole Lawrence](https://github.com/colelawrence))
- Cleanup in the orion-dudect tests and add tests for newtype `PartialEq<&[u8]>` impl.
- Remove hardcoded docs.rs links in the documentation ([#100](https://github.com/brycx/orion/pull/100), by [Kyle Schreiber](https://github.com/finfet)).
- Previously, the documentation for `util::secure_rand_bytes` stated that a panic would occur if the function failed to generate random bytes without throwing an error, which was not the case. This has been corrected.
- Add `Blake2b::verify` to fuzzing targets.
- orion-dudect now also tests for constant-time execution in CI on OSX and Windows platforms.
- Testing constant-time execution with WASM at [orion-sidefuzz](https://github.com/brycx/orion-sidefuzz).
- New testing framework which has greatly reduced the amount of duplicate testing code ([#96](https://github.com/brycx/orion/pull/96)).
- Document and test MSRV ([#104](https://github.com/brycx/orion/issues/104)).
- orion is now listed as an alternative to the old `rust-crypto` crate on [RustSec](https://rustsec.org/advisories/RUSTSEC-2016-0005.html).
- `UnknownCryptoError` now implements `std::error::Error` for better interoperability with error-handling crates.
- Added new test vectors from Wycheproof for ChaCha20Poly1305, XChaCha20Poly1305, HMAC-SHA512 and HKDF-HMAC-SHA512 ([#116](https://github.com/brycx/orion/pull/116)).
- `#![deny(warnings)]` has been removed and replaced with flags in CI build jobs.
- GitHub actions are used for daily security audit for the `crates-published` branch. Travis CI runs only weekly on `crates-published` branch now (daily before).
- Removed inlining attributes that did not provide any performance improvements when tested with benchmarks ([commit](https://github.com/brycx/orion/commit/eea1899c0b2967c17c0ee6d05559065c3f67c7d5)).
- Various performance improvements.
- Various improvements to fuzzing targets.
- Various improvements to tests.

### 0.14.5 [Yanked]

**Date:** January 25, 2020.

**Changelog:**

- Fix `nightly` build breakage.

### 0.14.4 [Yanked]

**Date:** August 21, 2019.

**Changelog:**

- Reduce the amount of allocations throughout most of orion.
- Vectorize the ChaCha20 implementation providing ~6% performance improvement for (X)ChaCha20Poly1305 and ~11.5% for (X)ChaCha20.
- Documentation improvements.

### 0.14.3 [Yanked]

**Date:** August 1, 2019.

**Changelog:**

- Improved performance for ChaCha20Poly1305/XChaCha20Poly1305 when AAD is empty.
- Refactoring of streaming contexts used by SHA512, BLAKE2b and Poly1305.
- Implement `PartialEq<&[u8]>` for all newtypes and provide documentation for usage of such (by [Vince Mutolo](https://github.com/vlmutolo)).
- Switched to stable rustfmt.
- Fix use of now deprecated (since `v0.1.7`) `getrandom` errors.
- Updated fuzzing targets in orion-fuzz.

### 0.14.2 [Yanked]

**Date:** June 10, 2019.

**Changelog:**

- Improved performance on all implementations, most notably: ~30% in ChaCha20/XChaCha20 and ~20% in ChaCha20Poly1305/XChaCha20Poly1305.
- Updated `zeroize` dependency.
- Testing WebAssembly (`wasm32-unknown-unknown`) support in CI.
- Improved documentation.

### 0.14.1 [Yanked]

**Date:** May 27, 2019.

**Changelog:**

- Update `zeroize` dependency.
- Improvements to documentation.

### 0.14.0 [Yanked]

**Date:** May 4, 2019.

**Changelog:**

- [Breaking change] Function `as_bytes()` for public newtypes are replaced with `AsRef<>` trait implementations. This means all `as_bytes()` calls need to be replaced with `as_ref()`.
- [Breaking change] The `SecretKey` for BLAKE2b is longer padded with zeroes to the length of the blocksize. Thus, the `SecretKey` no longer has a `get_original_length()` function, but the same result will be represented by the `get_length()` function instead.
- [Breaking change] All calls to `as_ref()` and `unprotected_as_bytes()` return the newtypes data with what it was initialized, regardless of padding. (With the exception of HMAC)
- [Breaking change] All calls to `get_length()` return the length of the newtype with what is what initialized, regardless of padding. (With the exception of HMAC)
- [Breaking change] All newtypes that offer `generate()` now panic if the RNG fails to initialize of read from its source. This also means that newtype `generate()` functions, that do not take in a size parameter, no longer return a `Result`.
- [Breaking change] `ValidationCryptoError` and `FinalizationCryptoError` have been removed. Though this doesn't mean that there is less information available, see [issue here](https://github.com/brycx/orion/issues/64).
- [Breaking change] Support for cSHAKE256 has been dropped, also meaning orion no longer depends on tiny-keccak. 8% decrease in `unsafe` code in dependencies.
- All fuzzing targets in `fuzz` that used libFuzzer have been deprecated in favor of those in [orion-fuzz](https://github.com/brycx/orion-fuzz) using honggfuzz-rs.
- Improvements to fuzzing targets in orion-fuzz.
- [Automated testing in CI, for constant-time execution](https://github.com/brycx/orion-dudect).
- Added `From<[u8; C]>` trait implementations for C-length fixed-sized newtypes, so that the caller may avoid using `Result` when not working with slices.
- [Breaking change] Module `hazardous::constants` has been removed and all types made private. Only a select number of constants have been re-exported in their respective modules. See [here for more information](https://github.com/brycx/orion/pull/72).
- It is now strictly advised against using orion in debug mode, for what is meant to be production use. Using `opt-level = 0` with orion, is also advised against. See [security section](https://github.com/brycx/orion/wiki/Security#release-and-codegen-options).
- `rand_os` has been replaced with `getrandom`.
- Improvements to documentation examples as they no longer use `.unwrap()` but `?` instead.

### 0.13.4 [Yanked]

**Date:** April 1, 2019.

**Changelog:**

- Fix build for latest nightly.

### 0.13.3 [Yanked]

**Date:** March 31, 2019.

**Changelog:**

- Updated `zeroize` to `0.6.0`.
- Added a small number of tests.
- Improvement to constant-time interfaces ([#66](https://github.com/brycx/orion/pull/66)).

### 0.13.2 [Yanked]

**Date:** March 13, 2019.

**Changelog:**

- PBKDF2 and BLAKE2b now panic on lengths exceeding (2^32-1) _ 64 and 2_(2^64-1), respectively.
- ChaCha20 length constrictions are now equivalent to those of the RFC and panics on trying to process more than 2^32-1 keystream blocks.
- Documentation improvements.
- OpenSSL test vectors for BLAKE2b.

**Note**: Strictly speaking, the first two changes are breaking, but because of the unlikeliness that this has an effect on anybody, they were not marked as such.

### 0.13.1 [Yanked]

**Date:** February 16, 2019.

**Changelog:**

- Documentation improvements ([#60](https://github.com/brycx/orion/issues/60)).

### 0.13.0 [Yanked]

**Date:** February 10, 2019.

**Changelog:**

- [Breaking change]: `orion::hazardous::hash::sha512` previously used the same `Digest` as BLAKE2b. This is no longer the case, making it impossible to specify a non fixed-length hash as `Digest` with SHA512.
- [Breaking change]: `HLEN` constant renamed to `SHA512_OUTSIZE` and `SHA2_BLOCKSIZE` constant renamed to `SHA512_BLOCKSIZE`.
- Added `POLY1305_OUTSIZE` constant.
- Improved documentation for high-level `Password`, `SecretKey` in `hazardous`s `hmac` and `blake2b`, as well as `Password` in `pbkdf2` of `hazardous`.
- Added AppVeyor builds and testing for Windows MSVC with Visual Studio 2017.

### 0.12.6 [Yanked]

**Date:** February 8, 2019.

**Changelog:**

- Switched to zeroize in favor of clear_on_drop, such that using orion on stable Rust no longer requires a C compiler.
- Fuzzing with honggfuzz-rs.

### 0.12.5 [Yanked]

**Date:** February 4, 2019.

**Changelog:**

- Refactored HMAC and improved performance for PBKDF2 by ~50%.
- Removed `byteorder` dependency using instead the endianness conversion functions that came with Rust 1.32.

### 0.12.4 [Yanked]

**Date:** January 31, 2019.

**Changelog:**

- Fixes a bug where hashing, with BLAKE2b, over 2^64-1 bytes of data would cause an overflowing addition on debug builds.
- Fixes a bug where hashing, with SHA512, over 2^64-1 bytes of data would not result in the counter being correctly incremented.
- Added property-based testing, using QuickCheck, to most of the library and improved testing for the library in general.
- `PartialEq` is now implemented for `orion::kdf::Salt` and `Nonce` in both `chacha20` and `xchacha20`.
- Added `get_length()` for `blake2b::Digest`.
- Updated fuzzing dependencies.

### 0.12.3 [Yanked]

**Date:** January 29, 2019.

**Changelog:**

- Improved compilation time.
- Bugfix [#50](https://github.com/brycx/orion/issues/50).
- Update `byteorder` and `serde_json` dependencies (fixes build-failures related to `rand_core`).

### 0.12.2 [Yanked]

**Date:** January 26, 2019.

**Changelog:**

- Fix a [bug](https://github.com/brycx/orion/issues/52) that lead to panics when using `out` parameters, with `seal()`/`open()` in `hazardous`, with a length above a given point.

### 0.12.1 [Yanked]

**Date:** January 16, 2019.

**Changelog:**

- Switched `rand` dependency out with `rand_os`.

### 0.12.0 [Yanked]

**Date:** December 29, 2018.

**Changelog:**

- [Breaking change]: All high-level functions now return a Result.
- [Breaking change]: `Password` in `pbkdf2`, `SecretKey` and `hmac()` of `hmac` and `extract()` of `hkdf` in `hazardous` now return a Result.
- [Breaking change]: Limit all `generate()` taking a `length` parameter, and `orion::kdf` calls to a length of less than `u32::max_value()` as maximum.
- [Breaking change]: `orion::kdf` and `orion::pwhash` take a new `Password` parameter that is heap-allocated and returns a Result.
- Removed `sha2` dependency and `ring` dev-dependency. `sha2` has been replaced with orion's own SHA512 implementation.
- Added support for BLAKE2b and SHA512.
- Updated to Rust 2018 Edition.
- Better performance for HMAC, HKDF and PBKDF2.

Thanks to Gabe Langlais for valuable feedback, especially on the API design.

### 0.11.2 [Yanked]

**Date:** December 22, 2018.

**Changelog:**

- Security fix: [#46](https://github.com/brycx/orion/issues/46) ([RUSTSEC-2018-0012](https://rustsec.org/advisories/RUSTSEC-2018-0012.html), [CVE-2018-20999](https://nvd.nist.gov/vuln/detail/CVE-2018-20999)).
- Updated subtle dependency.

### 0.11.0 [Yanked]

**Date:** November 24, 2018.

**Changelog:**

- Fix [missing error propagation](https://github.com/brycx/orion/issues/40) in `v0.10`.

### 0.10.0 [Yanked]

**Date:** November 23, 2018.

**Changelog:**

- New types for secret keys, nonces, tags, etc. This greatly increases misuse-resistance, usability and safety. To read more about the types and how they are implemented, see the [wiki section](https://github.com/brycx/orion/wiki/Design).
- `default` API has been dropped. All high-level functionality is now accessible through these interfaces: `orion::aead`, `orion::auth`, `orion::kdf` and `orion::pwhash`.
- AEAD interfaces in `hazardous` and in the high-level API (previously `default::encrypt`, etc.) have been renamed to `seal` and `open` to reflect the authentication and hopefully increase familiarity.
- `finalize_to_dst()` has been dropped for HMAC.
- Adaption of the `#[must_use]` attribute.
- Documentation improvements.
- HKDF and cSHAKE dropped from high-level API.
- High-level PBKDF2 now uses 64 byte salts and 64 byte password hashes and the iteration count has been made available for users to control.
- Argument `info` for HKDF and `ad` for AEADs are now `Option`.
- `util::gen_rand_key` and `util::compare_ct` are now `util::secure_rand_bytes` and `util::secure_cmp`.
- The password length enforcement in high-level PBKDF2 API has been removed.
- All other public types (eg. `CShake`, `Hmac` and `Poly1305`) now implement `Debug`.
- Using `clear_on_drop` to wipe memory in favor of `seckey`.
- New features `nightly` and `no_std`. To use orion in a `no_std` context, some dependency specifications are needed. Refer to the README for these.
- Major improvements to error propagation.

### 0.9.1 [Yanked]

**Date:** November 11, 2018.

**Changelog:**

- Fix bug in double-HMAC verification in the default API
- Documentation improvements

### 0.9.0 [Yanked]

**Date:** November 4, 2018.

**Changelog:**

- Added support for HChaCha20, XChaCha20 and AEAD XChaCha20Poly1305.
- The `default` APIs encryption/decryption interface has been reintroduced, now offering
  authenticated encryption through the AEAD XChaCha20Poly1305 implementation.
- Most of the library's structure has been revamped.
- Major additions to the project wiki detailing testing and some information regarding dependencies and security.
- Improved fuzzing targets and overall test suite.
- Documentation improvements.

### 0.8.0 [Yanked]

**Date:** October 7, 2018.

**Changelog:**

- Added AEAD ChaCha20Poly1305 from [RFC 8439](https://tools.ietf.org/html/rfc8439)
- Added `keystream_block()` public function to retrieve a keystream from `chacha20`
- Added Poly1305 from [RFC 8439](https://tools.ietf.org/html/rfc8439)
- `default::encrypt` and `default::decrypt` removed until orion offers XChaCha20 with Poly1305
- Documentation improvement
- Updated `sha2` dependency

### 0.7.4 [Yanked]

**Date:** September 27, 2018.

**Changelog:**

- Fix bug in PBKDF2 (See [issue](https://github.com/brycx/orion/issues/30))

### 0.7.3 [Yanked]

**Date:** September 26, 2018.

**Changelog:**

- Update `subtle` dependency

### 0.7.2 [Yanked]

**Date:** September 26, 2018.

**Changelog:**

- Fuzz test improvements
- Documentation improvements

### 0.7.1 [Yanked]

**Date:** September 20, 2018.

**Changelog:**

- `default::chacha20_*` initial counter set to 0

### 0.7.0 [Yanked]

**Date:** September 17, 2018.

**Changelog:**

- Added `FinalizationCryptoError` which means `cshake` and `hmac` now return a `Result` on finalization and update function calls.
- Added the ChaCha20 algorithm from the [RCF 8439](https://tools.ietf.org/html/rfc8439).
- Fix failed builds for `no_std`.
- Fix a bug where a user could call `update()` after finalization on both `cshake` and `hmac`.
- `cshake_verify()` function dropped from default API.
- Documentation improvement.

### 0.6.1 [Yanked]

**Date:** September 5, 2018.

**Changelog:**

- Update `subtle` dependency

### 0.6.0 [Yanked]

**Date:** August 31, 2018.

**Changelog:**

- Fix: `byteorder` and `rand` imported correctly for `no_std`
- Add default feature `safe_api`, meaning that for `no_std`, import orion with default features disabled
- Due to dependency fixing, Double HMAC Verification is now only done in the `safe_api`
- `gen_rand_key` now only available with `safe_api`

### 0.5.2 [Yanked]

**Date:** August 22, 2018.

**Changelog:**

- Replaced `byte-tools` with `byteorder` crate as `byte-tools` no longer offers the required functionality

### 0.5.1 [Yanked]

**Date:** August 20, 2018.

**Changelog:**

- Added `reset()` function to cSHAKE
- Added finalization check for HMAC and cSHAKE, making it impossible to call finalization functions twice without a reset in between. Preventing misuse.

### 0.5.0 [Yanked]

**Date:** August 13, 2018.

**Changelog:**

- Support for SHA256, SHA384, SHA512/256 and cSHAKE128 dropped.
- Support for `#![no_std]` added.
- HMAC streaming API.
- HMAC now uses SHA512.
- Switched out `clear_on_drop` with `seckey`.
- Switched out `constant_time_eq` with `subtle`.
- cSHAKE streaming API.
- `default::pbkdf2` no longer appends salt to password before hashing due to some problems integrating this using `#![no_std]`. This might be re-introduced later on.
- `orion::core` renamed to `orion::utilities`.
- cSHAKE verification function removed from hazardous.

Performance improvements compared to v0.4.3:

- HMAC: ~10% performance improvement
- HKDF: ~5% performance improvement
- PBKDF2: ~15% performance improvement
- cSHAKE: ~11% performance improvement

This was benchmarked on a MacBook Air 1,6 GHz Intel Core i5, 4GB.

### 0.4.3 [Yanked]

**Date:** August 8, 2018.

**Changelog:**

- Updated dependency
- Adopted faster HMAC key padding steps from `rigel` crate, avoiding allocation as before but without the `Cow` borrow
- Memory and performance improvement to the PBKDF2 implementation by avoiding many useless allocations
