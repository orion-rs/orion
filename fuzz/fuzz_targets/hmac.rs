#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hmac::Hmac;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;

fn make_hmac(secret_key: &[u8], message: &[u8]) -> ()  {

    let mut rng = thread_rng();

    let choices = [ShaVariantOption::SHA256, ShaVariantOption::SHA384, ShaVariantOption::SHA512];

    if rng.gen() {

        let hmac_choice = rng.choose(&choices).unwrap();

        let mac = Hmac {
            secret_key: secret_key.to_vec(),
            message: message.to_vec(),
            sha2: *hmac_choice
        };

        let (ipad, opad) = mac.pad_key(secret_key);
        let mac_def = mac.hmac_compute();
        let mac_pbkdf2 = mac.pbkdf2_hmac(ipad, opad, &mac.message);
        assert_eq!(mac_def, mac_pbkdf2);
        assert_eq!(mac.hmac_compare(&mac_def).unwrap(), true);
        assert_eq!(mac.hmac_compare(&mac_pbkdf2).unwrap(), true);
    }
}


fuzz_target!(|data: &[u8]| {
    make_hmac(data, data);
});
