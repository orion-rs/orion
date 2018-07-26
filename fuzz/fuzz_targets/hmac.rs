#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
use orion::core::options::ShaVariantOption;
use orion::hazardous::hmac::*;

fn fuzz_hmac(secret_key: &[u8], data: &[u8], sha2: ShaVariantOption) {
    let mac = Hmac {
        secret_key: secret_key.to_vec(),
        data: data.to_vec(),
        sha2,
    };

    let (ipad, opad) = mac.pad_key(secret_key);
    let mac_def = mac.finalize();
    let mac_pbkdf2 = pbkdf2_hmac(ipad, opad, &mac.data, mac.sha2);

    assert_eq!(mac_def, mac_pbkdf2);
    assert_eq!(mac.verify(&mac_def).unwrap(), true);
    assert_eq!(mac.verify(&mac_pbkdf2).unwrap(), true);
}

fuzz_target!(|data: &[u8]| {
    fuzz_hmac(data, data, ShaVariantOption::SHA256);

    fuzz_hmac(data, data, ShaVariantOption::SHA384);

    fuzz_hmac(data, data, ShaVariantOption::SHA512);

    fuzz_hmac(data, data, ShaVariantOption::SHA512Trunc256);
});
