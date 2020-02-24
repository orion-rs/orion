### 0.14.4

__Date:__ August 21, 2019.

__Changelog:__

- Reduce the amount of allocations throughout most of orion.
- Vectorize the ChaCha20 implementation providing ~6% performance improvement for (X)ChaCha20Poly1305 and ~11.5% for (X)ChaCha20.
- Documentation improvements.

### 0.14.3

__Date:__ August 1, 2019.

__Changelog:__

- Improved performance for ChaCha20Poly1305/XChaCha20Poly1305 when AAD is empty.
- Refactoring of streaming contexts used by SHA512, BLAKE2b and Poly1305.
- Implement `PartialEq<&[u8]>` for all newtypes and provide documentation for usage of such (by [Vince Mutolo](https://github.com/vlmutolo)).
- Switched to stable rustfmt.
- Fix use of now deprecated (since `v0.1.7`) `getrandom` errors.
- Updated fuzzing targets in orion-fuzz.

### 0.14.2

__Date:__ June 10, 2019.

__Changelog:__

- Improved performance on all implementations, most notably: ~30% in ChaCha20/XChaCha20 and ~20% in ChaCha20Poly1305/XChaCha20Poly1305.
- Updated `zeroize` dependency.
- Testing WebAssembly (`wasm32-unknown-unknown`) support in CI. 
- Improved documentation.

### 0.14.1

__Date:__ May 27, 2019.

__Changelog:__

- Update `zeroize` dependency.
- Improvements to documentation.

### 0.14.0

__Date:__ May 4, 2019.

__Changelog:__

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

### 0.13.4

__Date:__ April 1, 2019.

__Changelog:__

- Fix build for latest nightly.

### 0.13.3

__Date:__ March 31, 2019.

__Changelog:__

- Updated `zeroize` to `0.6.0`.
- Added a small number of tests.
- Improvement to constant-time interfaces ([#66](https://github.com/brycx/orion/pull/66)).

### 0.13.2

__Date:__ March 13, 2019.

__Changelog:__

- PBKDF2 and BLAKE2b now panic on lengths exceeding (2^32-1) * 64 and 2*(2^64-1), respectively.
- ChaCha20 length constrictions are now equivalent to those of the RFC and panics on trying to process more than 2^32-1 keystream blocks.
- Documentation improvements.
- OpenSSL test vectors for BLAKE2b.

__Note__: Strictly speaking, the first two changes are breaking, but because of the unlikeliness that this has an effect on anybody, they were not marked as such.

### 0.13.1

__Date:__ February 16, 2019.

__Changelog:__

- Documentation improvements ([#60](https://github.com/brycx/orion/issues/60)).

### 0.13.0

__Date:__ February 10, 2019.

__Changelog:__

- [Breaking change]: `orion::hazardous::hash::sha512` previously used the same `Digest` as BLAKE2b. This is no longer the case, making it impossible to specify a non fixed-length hash as `Digest` with SHA512.
- [Breaking change]: `HLEN` constant renamed to `SHA512_OUTSIZE` and `SHA2_BLOCKSIZE` constant renamed to `SHA512_BLOCKSIZE`.
- Added `POLY1305_OUTSIZE` constant.
- Improved documentation for high-level `Password`, `SecretKey` in `hazardous`s `hmac` and `blake2b`, as well as `Password` in `pbkdf2` of `hazardous`.
- Added AppVeyor builds and testing for Windows MSVC with Visual Studio 2017.

### 0.12.6 [Yanked]

__Date:__ February 8, 2019.

__Changelog:__

- Switched to zeroize in favor of clear_on_drop, such that using orion on stable Rust no longer requires a C compiler.
- Fuzzing with honggfuzz-rs.

### 0.12.5 [Yanked]

__Date:__ February 4, 2019.

__Changelog:__

- Refactored HMAC and improved performance for PBKDF2 by ~50%.
- Removed `byteorder` dependency using instead the endianness conversion functions that came with Rust 1.32.

### 0.12.4 [Yanked]

__Date:__ January 31, 2019.

__Changelog:__

- Fixes a bug where hashing, with BLAKE2b, over 2^64-1 bytes of data would cause an overflowing addition on debug builds.
- Fixes a bug where hashing, with SHA512, over 2^64-1 bytes of data would not result in the counter being correctly incremented.
- Added property-based testing, using QuickCheck, to most of the library and improved testing for the library in general.
- `PartialEq` is now implemented for `orion::kdf::Salt` and `Nonce` in both `chacha20` and `xchacha20`.
- Added `get_length()` for `blake2b::Digest`.
- Updated fuzzing dependencies.

### 0.12.3 [Yanked]

__Date:__ January 29, 2019.

__Changelog:__

- Improved compilation time.
- Bugfix [#50](https://github.com/brycx/orion/issues/50).
- Update `byteorder` and `serde_json` dependencies (fixes build-failures related to `rand_core`).

### 0.12.2 [Yanked]

__Date:__ January 26, 2019.

__Changelog:__

- Fix a [bug](https://github.com/brycx/orion/issues/52) that lead to panics when using `out` parameters, with `seal()`/`open()` in `hazardous`, with a length above a given point.

### 0.12.1 [Yanked]

__Date:__ January 16, 2019.

__Changelog:__

- Switched `rand` dependency out with `rand_os`.

### 0.12.0 [Yanked]

__Date:__ December 29, 2018.

__Changelog:__

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

__Date:__ December 22, 2018.

__Changelog:__

- Security fix: [#46](https://github.com/brycx/orion/issues/46) ([RUSTSEC-2018-0012](https://rustsec.org/advisories/RUSTSEC-2018-0012.html), [CVE-2018-20999](https://nvd.nist.gov/vuln/detail/CVE-2018-20999)).
- Updated subtle dependency.

### 0.11.0 [Yanked]

__Date:__ November 24, 2018.

__Changelog:__

- Fix [missing error propagation](https://github.com/brycx/orion/issues/40) in `v0.10`.

### 0.10.0 [Yanked]

__Date:__ November 23, 2018.

__Changelog:__

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

__Date:__ November 11, 2018.

__Changelog:__

- Fix bug in double-HMAC verification in the default API
- Documentation improvements

### 0.9.0 [Yanked]

__Date:__ November 4, 2018.

__Changelog:__

- Added support for HChaCha20, XChaCha20 and AEAD XChaCha20Poly1305.
- The `default` APIs encryption/decryption interface has been reintroduced, now offering
authenticated encryption through the AEAD XChaCha20Poly1305 implementation.
- Most of the library's structure has been revamped.
- Major additions to the project wiki detailing testing and some information regarding dependencies and security.
- Improved fuzzing targets and overall test suite.
- Documentation improvements.

### 0.8.0 [Yanked]

__Date:__ October 7, 2018.

__Changelog:__

- Added AEAD ChaCha20Poly1305 from [RFC 8439](https://tools.ietf.org/html/rfc8439)
- Added `keystream_block()` public function to retrieve a keystream from `chacha20`
- Added Poly1305 from [RFC 8439](https://tools.ietf.org/html/rfc8439)
- `default::encrypt` and `default::decrypt` removed until orion offers XChaCha20 with Poly1305
- Documentation improvement
- Updated `sha2` dependency

### 0.7.4 [Yanked]

__Date:__ September 27, 2018.

__Changelog:__

- Fix bug in PBKDF2 (See [issue](https://github.com/brycx/orion/issues/30))

### 0.7.3 [Yanked]

__Date:__ September 26, 2018.

__Changelog:__

- Update `subtle` dependency

### 0.7.2 [Yanked]

__Date:__ September 26, 2018.

__Changelog:__

- Fuzz test improvements
- Documentation improvements

### 0.7.1 [Yanked]

__Date:__ September 20, 2018.

__Changelog:__

- `default::chacha20_*` initial counter set to 0

### 0.7.0 [Yanked]

__Date:__ September 17, 2018.

__Changelog:__

- Added `FinalizationCryptoError` which means `cshake` and `hmac` now return a `Result` on finalization and update function calls.
- Added the ChaCha20 algorithm from the [RCF 8439](https://tools.ietf.org/html/rfc8439).
- Fix failed builds for `no_std`.
- Fix a bug where a user could call `update()` after finalization on both `cshake` and `hmac`.
- `cshake_verify()` function dropped from default API.
- Documentation improvement.

### 0.6.1 [Yanked]

__Date:__ September 5, 2018.

__Changelog:__

- Update `subtle` dependency

### 0.6.0 [Yanked]

__Date:__ August 31, 2018.

__Changelog:__

- Fix: `byteorder` and `rand` imported correctly for `no_std`
- Add default feature `safe_api`, meaning that for `no_std`, import orion with default features disabled 
- Due to dependency fixing, Double HMAC Verification is now only done in the `safe_api`
- `gen_rand_key` now only available with `safe_api`

### 0.5.2 [Yanked]

__Date:__ August 22, 2018.

__Changelog:__

- Replaced `byte-tools` with `byteorder` crate as `byte-tools` no longer offers the required functionality

### 0.5.1 [Yanked]

__Date:__ August 20, 2018.

__Changelog:__

- Added `reset()` function to cSHAKE
- Added finalization check for HMAC and cSHAKE, making it impossible to call finalization functions twice without a reset in between. Preventing misuse.

### 0.5.0 [Yanked]

__Date:__ August 13, 2018.

__Changelog:__

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

__Date:__ August 8, 2018.

__Changelog:__

- Updated dependency
- Adopted faster HMAC key padding steps from `rigel` crate, avoiding allocation as before but without the `Cow` borrow
- Memory and performance improvement to the PBKDF2 implementation by avoiding many useless allocations
