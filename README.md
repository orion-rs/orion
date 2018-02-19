## orion ![Build Status](https://travis-ci.org/brycx/orion.svg?branch=master)

orion aims to provide hassle-free cryptographic function(s).

This project is very early-stage and currently only contains HMAC. I plan on adding
more, as long as I can find the time for it. Contributions are more than welcome!

It relies on [ring](https://github.com/briansmith/ring) for things like SHA.

Currently contains:
* HMAC with SHA1, SHA256, SHA384, SHA512.

### Usage
Include it in your `Cargo.toml` file:
```
[dependencies]
orion = ">=0.1.0"
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
