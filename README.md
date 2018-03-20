## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master)

**Warning:** You should not use this for anything that requires confidence in security.

Currently contains:
* HMAC with SHA2(256, 384, 512).
* HKDF with the above HMAC options.

### Usage
Include it in your `Cargo.toml` file:
```
[dependencies]
orion = ">=0.1.42"
```
and in relevant files:
```
extern crate orion
```
Check the documentation for more specific usage.
### Documentation
[Find it here](https://docs.rs/orion).

### Tests
All unit-tests are located in the same file as the functions they are testing.
To run tests: `cargo test`.

### License
orion is licensed under the MIT license. See the `LICENSE` file for more information.
