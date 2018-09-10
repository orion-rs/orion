<p align="center">
  <img src="logo/logo.png" alt="orion" height="200px">
</p>
<p align="center">
  <img src="https://travis-ci.org/brycx/orion.svg?branch=master">
  <img src="https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg">
</p>

### Warning
This library is not suitable for production code. There are no guarantees for the security of these implementations. Use at your own risk.


### About
This library aims to provide easy and usable crypto. 'Usable' meaning exposing high-level
API's that are easy to use and hard to misuse.  

In case you missed the warning above: **don't use orion for production code or instances where you need absolute confidence in security**. While security is a top priority goal for this library, the author is no
professional. Look in the Alternatives section if this means orion is not for you.


Currently contains:
* HMAC-SHA512
* HKDF-HMAC-SHA512.
* PBKDF2-HMAC-SHA512.
* cSHAKE256.

***Note on cSHAKE***:
The cSHAKE implementation currently relies on the `tiny-keccak` crate. Currently this crate
will produce **incorrect results on big-endian based systems**. See [issue here](https://github.com/debris/tiny-keccak/issues/15).

### Usage
```rust
extern crate orion;
use orion::default;

let password = "Password to be hashed".as_bytes();

let password_hash = default::pbkdf2(password).unwrap();

assert!(default::pbkdf2_verify(&password_hash, password).unwrap());
```

### Enabling `no_std`
To use orion in a `no_std` context, you need to specify the dependency as such:

```
orion = { version = "*", default-features = false }
```

Note that this means you will not have access to the `default` API.
This is because the `default` API depends on the `OsRng`, which in turn depends on `std`.


### Documentation
Can be viewed [here](https://docs.rs/orion) or built with:

```
cargo doc --no-deps
```

### Tests/Fuzzing
The [wiki](https://github.com/brycx/orion/wiki/Testing-suite) has details on how orion is tested. To run all tests:
```
cargo test
```

Fuzzing is done using libFuzzer with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). Fuzzing targets can be run with:
```
cargo +nightly fuzz run -O fuzz_target
```

### Benchmarks
The library can be benchmarked as below. All benchmarking tests are located in `benches/`.
```
cargo +nightly bench
```
### Changelog
Can be found [here](https://github.com/brycx/orion/releases).

### Acknowledgments
- Thanks to [@defuse](https://github.com/defuse) for a [quick audit](https://github.com/brycx/orion/issues/3) of the code.
- Thanks to [@ritalinn](https://github.com/ritalinn) for the logo.

### Alternatives
- [*ring*](https://crates.io/crates/ring) (HMAC, HKDF, PBKDF2)
- [RustCrypto HMAC](https://crates.io/crates/hmac)
- [RustCrypto HKDF](https://crates.io/crates/hkdf)
- [RustCrypto PBKDF2](https://crates.io/crates/pbkdf2)
- [sp800-185](https://crates.io/crates/sp800-185) (cSHAKE)

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
