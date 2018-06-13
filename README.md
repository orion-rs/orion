## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/orion)

**Warning:** There are no guarantees for the security of these implementations. Use at your own risk.

Cryptographic functions implemented in Rust, with a simple API.

Currently contains:
* HMAC with SHA2(256, 384, 512).
* HKDF with the above HMAC options.
* PBKDF2 with the above HMAC options.

### Usage
```
extern crate orion
use orion::{default, core::util};

// HMAC-SHA512
let key = util::gen_rand_key(64).unwrap();
let msg = "Some message".as_bytes();

let expected_hmac = default::hmac(&key, msg).unwrap();
assert!(default::hmac_verify(&expected_hmac, &key, &msg).unwrap());

// HKDF-HMAC-SHA512
let salt = util::gen_rand_key(64).unwrap();
let data = "Some data".as_bytes();
let info = "Some info".as_bytes();

let dk = default::hkdf(&salt, data, info, 64).unwrap();
assert!(default::hkdf_verify(&dk, &salt, data, info, 64).unwrap());

// PBKDF2-HMAC-SHA512
let salt = util::gen_rand_key(64).unwrap();
let password = "Secret password".as_bytes();

let dk = default::pbkdf2(password, &salt).unwrap();
assert!(default::pbkdf2_verify(&dk, password, &salt).unwrap());
```


### Documentation
To build the most recent: ```cargo doc --no-deps``` or view [here](https://docs.rs/orion).

### Tests/Fuzzing
Unit tests are located in the same file as what is being tested, apart from implementation verification tests - these are in `tests`. To run all tests: `cargo test`.

Fuzzing is done using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). Fuzzing targets are located in `fuzz/fuzz_targets`.

### Benchmarks
The library can be benchmarked as below. All benchmarking tests are located in `benches`.
```
cargo +nightly bench
```
### Acknowledgments
Thanks to [@defuse](https://github.com/defuse) for a [quick audit](https://github.com/brycx/orion/issues/3) of the code.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
