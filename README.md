## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master)

**Warning:** I'm no expert on cryptography, use this at your own risk.

This project is very early-stage. I plan on adding
more, as long as I can find the time for it. Contributions are more than welcome!

It relies on [ring](https://github.com/briansmith/ring) for things like SHA.

Currently contains:
* HMAC with SHA1, SHA256, SHA384, SHA512.
* HKDF with the above HMAC options.

### Usage
Include it in your `Cargo.toml` file:
```
[dependencies]
orion = ">=0.1.3"
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
orion is licensed under MIT. See the `LICENSE` file for more information.
