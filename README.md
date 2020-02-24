# orion
[![Build Status](https://travis-ci.org/brycx/orion.svg?branch=crates-published)](https://travis-ci.org/brycx/orion) [![Build status](https://ci.appveyor.com/api/projects/status/x4o6vneh087io03s/branch/crates-published?svg=true)](https://ci.appveyor.com/project/brycx/orion/branch/crates-published) [![Security Audit](https://github.com/brycx/orion/workflows/Security%20Audit/badge.svg)](https://github.com/brycx/orion/actions) [![dudect](https://img.shields.io/travis/brycx/orion-dudect/master?label=dudect)](https://github.com/brycx/orion-dudect) [![codecov](https://codecov.io/gh/brycx/orion/branch/crates-published/graph/badge.svg)](https://codecov.io/gh/brycx/orion) [![dependency status](https://deps.rs/repo/github/brycx/orion/status.svg)](https://deps.rs/repo/github/brycx/orion) [![Documentation](https://docs.rs/orion/badge.svg)](https://docs.rs/orion/) [![Crates.io](https://img.shields.io/crates/v/orion.svg)](https://crates.io/crates/orion) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) [![MSRV](https://img.shields.io/badge/MSRV-1.37-informational.svg)](https://img.shields.io/badge/MSRV-1.37-informational)

### About
orion is a cryptography library written in pure Rust. It aims to provide easy and usable crypto while trying to minimize the use of unsafe code. You can read more about orion in the [wiki](https://github.com/brycx/orion/wiki).

Currently supports:
* **AEAD**: (X)ChaCha20Poly1305.
* **Stream ciphers**: (X)ChaCha20.
* **KDF**: HKDF-HMAC-SHA512, PBKDF2-HMAC-SHA512, Argon2i.
* **MAC**: HMAC-SHA512, Poly1305.
* **Hashing**: BLAKE2b, SHA512.

### Security
This library has **not undergone any third-party security audit**. Usage is at **own risk**.

More information about security regarding orion is available in the [wiki](https://github.com/brycx/orion/wiki/Security).

### Minimum Supported Rust Version
Rust 1.37 or later is supported however, the majority of testing happens with latest stable Rust.

MSRV may be changed at any point and will not be considered a SemVer breaking change.

### Crate Features
By default orion targets stable Rust with `std`. To use orion in a `no_std` context, you need to specify the dependency as such:
```
orion = { version = "*", default-features = false }
# Replace * with the most recent version
```

When orion is used in a `no_std` context, the high-level API is not available, since it relies on access to the systems random number generator.

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
The library can be benchmarked with [Criterion](https://github.com/bheisler/criterion.rs) as below. All benchmarking tests are located in `benches/`.
```
cargo bench
```
### Changelog
Please refer to the [CHANGELOG.md](https://github.com/brycx/orion/blob/master/CHANGELOG.md) list.

### Contributing
Please refer to the guidelines in [CONTRIBUTING.md](https://github.com/brycx/orion/blob/master/CONTRIBUTING.md) for information on how to contribute to orion.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
