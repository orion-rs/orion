extern crate rand;
extern crate sha2;
extern crate clear_on_drop;

pub mod util;
pub mod hmac;
pub mod hkdf;

/// ```orion::default``` provides a small API to make it a little easier to use the functions that
/// ```orion``` provides, without worrying about details.
pub mod default;
pub mod options;
