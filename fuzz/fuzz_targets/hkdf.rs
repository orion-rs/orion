#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hkdf::Hkdf;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;


fn make_hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> () {

    let mut rng = thread_rng();

    let choices = [ShaVariantOption::SHA256, ShaVariantOption::SHA384, ShaVariantOption::SHA512];

    if rng.gen() {

        let hmac_choice = rng.choose(&choices).unwrap();

        let len: usize = match *hmac_choice {
                ShaVariantOption::SHA256 => rng.gen_range(1, 8161),
                ShaVariantOption::SHA384 => rng.gen_range(1, 12241),
                ShaVariantOption::SHA512 => rng.gen_range(1, 16321),
        };

        let dk = Hkdf {
            salt: salt.to_vec(),
            ikm: ikm.to_vec(),
            info: info.to_vec(),
            length: len,
            hmac: *hmac_choice,
        };

        let prk = dk.extract(ikm, salt);

        let dk_fin = dk.expand(&prk).unwrap();
        assert_eq!(dk_fin, dk.derive_key().unwrap());
        assert_eq!(dk.verify(&dk_fin).unwrap(), true);

    } else  { () }

}

fuzz_target!(|data: &[u8]| {
    make_hkdf(data, data, data);
});
