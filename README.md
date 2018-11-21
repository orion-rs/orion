<p align="center">
  <img src="logo/logo.png" alt="orion" height="200px">
</p>
<p align="center">
  <img src="https://travis-ci.org/brycx/orion.svg?branch=master">
  <img src="https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg">
</p>

### About
orion is a cryptography library written in pure-Rust which aims to provide easy and usable crypto. 'Usable' meaning exposing high-level API's that are easy to use and hard to misuse. You can read more about orion in the [wiki](https://github.com/brycx/orion/wiki).

Currently supports:
* **AEAD**: ChaCha20Poly1305, XChaCha20Poly1305
* **Stream ciphers**: ChaCha20, XChaCha20
* **KDF**: HKDF-HMAC-SHA512
* **Password hashing**: PBKDF2-HMAC-SHA512
* **MAC**: HMAC-SHA512, Poly1305
* **XOF**: cSHAKE256

### Security
This library is not suitable for production code and usage is at own risk.

### Enabling `no_std`
To use orion in a `no_std` context, you need to specify the dependency as such:

```
orion = { version = "*", default-features = false }
```

When orion is used in a `no_std` context, access to nearly all functionality, except for that in
`hazardous`, is not available. This is because the high-level functionality depends on the `OsRng`
which is not available in `no_std`.

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
- [*ring*](https://crates.io/crates/ring) (HMAC, HKDF, PBKDF2, AEAD ChaCha20Poly1305)
- [RustCrypto HMAC](https://crates.io/crates/hmac)
- [RustCrypto HKDF](https://crates.io/crates/hkdf)
- [RustCrypto PBKDF2](https://crates.io/crates/pbkdf2)
- [sp800-185](https://crates.io/crates/sp800-185) (cSHAKE)
- [chacha](https://crates.io/crates/chacha) (ChaCha20, XChaCha20)

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
