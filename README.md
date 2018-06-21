## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/orion)

### Warning
This library is not suitable for production code. There are no guarantees for the security of these implementations. Use at your own risk.


### About
This library aims to provide easy and usable crypto. 'Usable' meaning exposing high-level
API's that are easy to use and hard to misuse.  

In case you missed the warning above: **don't use orion for production code or instances where you need absolute confidence in security**. While security is a top priority goal for this library, the author is no
professional. Look in the Alternatives section if this means orion is not for you.


Currently contains:
* HMAC with SHA256, SHA384, SHA512 and SHA512/256.
* HKDF with the above HMAC options.
* PBKDF2 with the above HMAC options.

### Usage
```
extern crate orion;
use orion::{default, core::util};

// HMAC-SHA512/256
let key = util::gen_rand_key(64).unwrap();
let msg = "Some message".as_bytes();

let expected_hmac = default::hmac(&key, msg).unwrap();
assert!(default::hmac_verify(&expected_hmac, &key, &msg).unwrap());

// HKDF-HMAC-SHA512/256
let salt = util::gen_rand_key(64).unwrap();
let data = "Some data".as_bytes();
let info = "Some info".as_bytes();

let dk = default::hkdf(&salt, data, info, 64).unwrap();
assert!(default::hkdf_verify(&dk, &salt, data, info, 64).unwrap());

// PBKDF2-HMAC-SHA512/256
let password = "Secret password".as_bytes();

let dk = default::pbkdf2(password).unwrap();
assert!(default::pbkdf2_verify(&dk, password).unwrap());
```


### Documentation
Can be viewed [here](https://docs.rs/orion) or built with:

```
cargo doc --no-deps
```

### Tests/Fuzzing
The [wiki](https://github.com/brycx/orion/wiki) has details on how orion is tested. To run all tests:
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
### Acknowledgments
Thanks to [@defuse](https://github.com/defuse) for a [quick audit](https://github.com/brycx/orion/issues/3) of the code.

### Alternatives
- [*ring*](https://crates.io/crates/ring)
- [RustCrypto HMAC](https://crates.io/crates/hmac)
- [RustCrypto HKDF](https://crates.io/crates/hkdf)
- [RustCrypto PBKDF2](https://crates.io/crates/pbkdf2)

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
