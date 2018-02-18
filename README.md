## orion
orion aims to provide hassle-free cryptographic functions.

This project is very early-stage and currently only contains HMAC. I plan on adding
more, as long as I can find the time for it.

orion relies on [ring](https://github.com/briansmith/ring) for things like SHA.

orion currently contains:
* HMAC as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104)

### Documentation
[Find it here]().

### Tests
All unit-tests are located in the same file as the functions they are testing.
To run test: `cargo test`.
