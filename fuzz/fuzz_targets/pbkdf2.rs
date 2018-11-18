#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::kdf::pbkdf2;

fuzz_target!(|data: &[u8]| {
    let (password, salt, mut dk_out, iter) = pbkdf2_setup(data);
    let orion_password = pbkdf2::Password::from_slice(&password);
    pbkdf2::derive_key(&orion_password, &salt, iter, &mut dk_out).unwrap();
    let exp_dk = dk_out.clone();

    assert!(pbkdf2::verify(&exp_dk, &orion_password, &salt, iter, &mut dk_out).unwrap());
});
