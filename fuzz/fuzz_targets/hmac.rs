#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::hmac::*;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;

fn fuzz_hmac(secret_key: &[u8], data: &[u8]) -> ()  {

    let mut rng = thread_rng();

    let choices = [ShaVariantOption::SHA256, ShaVariantOption::SHA384, ShaVariantOption::SHA512];

    if rng.gen() {

        let hmac_choice = rng.choose(&choices).unwrap();

        let mac = Hmac {
            secret_key: secret_key.to_vec(),
            data: data.to_vec(),
            sha2: *hmac_choice
        };

        let (ipad, opad) = mac.pad_key(secret_key);
        let mac_def = mac.finalize();
        let mac_pbkdf2 = pbkdf2_hmac(ipad, opad, &mac.data, mac.sha2);

        assert_eq!(mac_def, mac_pbkdf2);
        assert_eq!(mac.verify(&mac_def).unwrap(), true);
        assert_eq!(mac.verify(&mac_pbkdf2).unwrap(), true);
    }
}


fuzz_target!(|data: &[u8]| {
    fuzz_hmac(data, data);
});
