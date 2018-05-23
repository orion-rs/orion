## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/orion/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/orion)

**Warning:** There are no guarantees for the security of these implementations. Use at your own risk.

Cryptographic functions implemented in Rust, with a simple API.

Currently contains:
* HMAC with SHA2(256, 384, 512).
* HKDF with the above HMAC options.
* PBKDF2 with the above HMAC options.

### Usage
Use it like this:
```
extern crate orion
use orion::{default, util};

// HMAC-SHA512
let key = util::gen_rand_key(64);
let msg = "Some message.".as_bytes();

let expected_hmac = default::hmac(&key, msg);
// Verifying an HMAC-SHA512
assert_eq!(default::hmac_verify(&expected_hmac, &key, &msg), true);

// HKDF-HMAC-SHA512
let salt = util::gen_rand_key(64);
let data = "Some data.".as_bytes();
let info = "Some info.".as_bytes();

let hkdf = default::hkdf(&salt, data, info, 64);
// Verifying an HKDF HMAC-SHA512
assert_eq!(default::hkdf_verify(&hkdf, &salt, data, info, 64), true);

// PBKDF2-HMAC-SHA512
let salt = util::gen_rand_key(64);

let derived_password = default::pbkdf2("Secret password".as_bytes(), &salt);
// Verifying a derived key
assert_eq!(default::pbkdf2_verify(&derived_password, "Secret password".as_bytes(), &salt), true);
```


### Documentation
To build the most recent: ```cargo doc --no-deps```

### Tests
Unit tests are located in the same file as what is being tested, apart from implementation verification tests - these are in `tests`.
To run all tests: `cargo test`.

### Performance
```
PBKDF2-HMAC-SHA256, iterations = 1: 0.000009282000974053517 seconds
PBKDF2-HMAC-SHA256, iterations = 10000: 0.017861276000985526 seconds
PBKDF2-HMAC-SHA256, iterations = 16777216: 28.345894931999283 seconds

HKDF-HMAC-SHA256: 0.00002259599932585843 seconds
HKDF-HMAC-SHA384: 0.00001884199991764035 seconds
HKDF-HMAC-SHA512: 0.000005493000571732409 seconds

HMAC-SHA256: 0.00000212700069823768 seconds
HMAC-SHA384: 0.0000023610009520780295 seconds
HMAC-SHA512: 0.0000024699984351173043 seconds
```
Tested on an Intel® Core™ i7-4790.
### Acknowledgments
Thanks to [@defuse](https://github.com/defuse) for a [quick audit](https://github.com/brycx/orion/issues/3) of the code.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
