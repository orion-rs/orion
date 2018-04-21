## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master)

**Warning:** There are no guarantees for the security of these implementations. Use at your own risk.

Cryptographic functions implemented in Rust, with a simple API.

Currently contains:
* HMAC with SHA2(256, 384, 512).
* HKDF with the above HMAC options.

### Usage
Include it in your `Cargo.toml` file:
```
[dependencies]
orion = ">=0.2.0"
```
Use it like this:
```
extern crate orion
use orion::{default, util};

// HMAC-SHA512
let key = util::gen_rand_key(64);
let msg = "Some message.".as_bytes();

let expected_hmac = default::hmac(&key, msg);
// Verifying an HMAC-SHA512
assert_eq!(default::hmac_validate(&expected_hmac, &key, &msg), true);

// HKDF-HMAC-SHA512
let salt = util::gen_rand_key(64);
let data = "Some data.".as_bytes();
let info = "Some info.".as_bytes();

let hkdf = default::hkdf(&salt, data, info, 64);
```


### Documentation
[Find it here](https://docs.rs/orion).

### Tests
All unit-tests are located in the same file as the functions they are testing.
To run tests: `cargo test`.

### Acknowledgments
Thanks to [@defuse](https://github.com/defuse) for a quick audit of the code.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
