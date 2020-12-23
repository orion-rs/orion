# orion
[![Tests](https://github.com/brycx/orion/workflows/Tests/badge.svg)](https://github.com/brycx/orion/actions) [![Daily tests](https://github.com/brycx/orion/workflows/Daily%20tests/badge.svg)](https://github.com/brycx/orion/actions) [![dudect](https://github.com/brycx/orion-dudect/workflows/dudect/badge.svg)](https://github.com/brycx/orion-dudect/actions)  [![Security Audit](https://github.com/brycx/orion/workflows/Security%20Audit/badge.svg)](https://github.com/brycx/orion/actions) [![codecov](https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/orion) [![Documentation](https://docs.rs/orion/badge.svg)](https://docs.rs/orion/) [![Crates.io](https://img.shields.io/crates/v/orion.svg)](https://crates.io/crates/orion) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) [![MSRV](https://img.shields.io/badge/MSRV-1.43-informational.svg)](https://img.shields.io/badge/MSRV-1.43-informational) [![Matrix](https://img.shields.io/matrix/orion-rs:matrix.org.svg?logo=matrix)](https://matrix.to/#/#orion-rs:matrix.org)

### About
Orion is a cryptography library written in pure Rust. It aims to provide easy and usable crypto while trying to minimize the use of unsafe code. You can read more about orion in the [wiki](https://github.com/brycx/orion/wiki).

Currently supports:
* **AEAD**: (X)ChaCha20Poly1305.
* **Stream ciphers**: (X)ChaCha20.
* **KDF**: HKDF-HMAC-SHA512, PBKDF2-HMAC-SHA512, Argon2i.
* **MAC**: HMAC-SHA512, Poly1305.
* **Hashing**: BLAKE2b, SHA512.

### Security
This library has **not undergone any third-party security audit**. Usage is at **own risk**.

See the [SECURITY.md](https://github.com/brycx/orion/blob/master/CHANGELOG.md) regarding recommendations on correct use, reporting security issues and more. Additional information about security regarding Orion is available in the [wiki](https://github.com/brycx/orion/wiki/Security).

### Minimum Supported Rust Version
Rust 1.43 or later is supported however, the majority of testing happens with latest stable Rust.

MSRV may be changed at any point and will not be considered a SemVer breaking change.

### Crate Features
By default Orion targets stable Rust with `std`. To use Orion in a `no_std` context, you need to specify the dependency as such:
```toml
orion = { version = "*", default-features = false }
# Replace * with the most recent version
```

When Orion is used in a `no_std` context, the high-level API is not available, since it relies on access to the systems random number generator. 

Argon2i is not available with `no_std` by default, but can be by enabling the `alloc` feature:

```toml
[dependencies.orion]
version = "*" # Replace * with the most recent version
default-features = false
features = ["alloc"]
```

### Documentation
Can be viewed [here](https://docs.rs/orion) or built with:

```
cargo doc --no-deps
```

### Tests and Fuzzing
The [wiki](https://github.com/brycx/orion/wiki/Testing-suite) has details on how orion is tested. To run all tests:
```
cargo test
```

Fuzzing is done using [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs) in [orion-fuzz](https://github.com/brycx/orion-fuzz). See [orion-fuzz](https://github.com/brycx/orion-fuzz) on how to start fuzzing orion.

Constant-time execution tests can be found at [orion-dudect](https://github.com/brycx/orion-dudect) and [orion-sidefuzz](https://github.com/brycx/orion-sidefuzz).

### Benchmarks
An overview of the performance that can be expected from Orion can be [seen here](https://github.com/brycx/orion/wiki/Benchmarks).

The library can be benchmarked with [Criterion](https://github.com/bheisler/criterion.rs) as below. All benchmarking tests are located in `benches/`.
```
cargo bench
```
### Changelog
Please refer to the [CHANGELOG.md](https://github.com/brycx/orion/blob/master/CHANGELOG.md) list.

### Contributing
Please refer to the guidelines in [CONTRIBUTING.md](https://github.com/brycx/orion/blob/master/CONTRIBUTING.md) for information on how to contribute to Orion.

### License
Orion is licensed under the MIT license. See the `LICENSE` file for more information.
