# orion
[![Build Status](https://travis-ci.org/brycx/orion.svg?branch=crates-published)](https://travis-ci.org/brycx/orion) [![Build status](https://ci.appveyor.com/api/projects/status/x4o6vneh087io03s/branch/crates-published?svg=true)](https://ci.appveyor.com/project/brycx/orion/branch/crates-published) [![codecov](https://codecov.io/gh/brycx/orion/branch/crates-published/graph/badge.svg)](https://codecov.io/gh/brycx/orion) [![dependency status](https://deps.rs/repo/github/brycx/orion/status.svg)](https://deps.rs/repo/github/brycx/orion) [![Documentation](https://docs.rs/orion/badge.svg)](https://docs.rs/orion/) [![Crates.io](https://img.shields.io/crates/v/orion.svg)](https://crates.io/crates/orion) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)


### About
orion is a cryptography library written in pure Rust. It aims to provide easy and usable crypto while trying to minimize the use of unsafe code. You can read more about orion in the [wiki](https://github.com/brycx/orion/wiki).

Currently supports:
* **AEAD**: (X)ChaCha20Poly1305.
* **Stream ciphers**: (X)ChaCha20.
* **KDF**: HKDF-HMAC-SHA512, PBKDF2-HMAC-SHA512.
* **MAC**: HMAC-SHA512, Poly1305.
* **Hashing**: BLAKE2b, SHA512.

### Security
This library is **not suitable for production code** and **usage is at own risk**.

More information about security regarding orion is available in the [wiki](https://github.com/brycx/orion/wiki/Security).


### Features and Requirements
- By default orion targets stable Rust and in this case, extra dependency specifications are not required.

- `no_std`: To use orion in a `no_std` context, you need to specify the dependency as such:
```
[dependencies.orion]
version = "*" # Replace * with the most recent version
default-features = false
features = ["no_std"]
```
`no_std` requires Rust nightly and benefits from the same inline assembly features as when using the `nightly` feature.

When orion is used in a `no_std` context, access to nearly all functionality, except for that in
`hazardous`, is not available. This is because the high-level functionality depends on the systems random generator,
which is not available in `no_std`.

- `nightly`: The nightly feature enables the use of inline assembly for [constant-time comparisons](https://crates.io/crates/subtle). Using `nightly` is recommended for security. Specify the dependency as such, to use the `nightly` feature:
```
[dependencies.orion]
version = "*" # Replace * with the most recent version
default-features = false
features = ["nightly"]
```
`nightly` requires Rust nightly.

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

### Benchmarks
The library can be benchmarked as below. All benchmarking tests are located in `benches/`.
```
cargo +nightly bench
```
### Changelog
Please refer to the [CHANGELOG.md](https://github.com/brycx/orion/blob/master/CHANGELOG.md) list.

### Contributing
Please refer to the guidelines in [CONTRIBUTING.md](https://github.com/brycx/orion/blob/master/CONTRIBUTING.md) for information on how to contribute to orion.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
