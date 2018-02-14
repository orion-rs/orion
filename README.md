## orion
orion is a soon-to-be collection of random cryptographic functions. It relies on [ring](https://github.com/briansmith/ring) for stuff like SHA-2 until these are
included in orion.

orion currently contains:
* HMAC as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104)

#### Tests
All unit-tests are located in the same file as the functions they are testing.
To run test: `cargo test`
