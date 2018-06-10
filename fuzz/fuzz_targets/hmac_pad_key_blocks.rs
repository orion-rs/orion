#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hmac::Hmac;
use orion::core::options::ShaVariantOption;

fn make_hmac(secret_key: &[u8], message: &[u8]) -> (Vec<u8>, Vec<u8>)  {

    let mac = Hmac {
        secret_key: secret_key.to_vec(),
        message: message.to_vec(),
        sha2: ShaVariantOption::SHA256
    };

    mac.pad_key(secret_key)
}


fuzz_target!(|data: &[u8]| {
    make_hmac(data, data);
});
