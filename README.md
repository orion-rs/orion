## orion
![creates.io version](https://img.shields.io/crates/v/hmac-sha1.svg)

orion aims to provide hassle-free cryptographic functions.

This project is very early-stage and currently only contains HMAC. I plan on adding
more, as long as I can find the time for it. Contributions are more than welcome!

orion relies on [ring](https://github.com/briansmith/ring) for things like SHA.

orion currently contains:
* HMAC as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104)

### Usage
`extern crate orion`
```
[dependencies]
orion = ">=0.1.0"
```
Check the documentation on more specific usage.
### Documentation
[Find it here](https://docs.rs/orion).

### Tests
All unit-tests are located in the same file as the functions they are testing.
To run tests: `cargo test`.
