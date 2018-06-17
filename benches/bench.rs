#![feature(test)]
extern crate orion;
extern crate test;

use orion::core::options::ShaVariantOption;
use orion::hkdf::Hkdf;
use orion::hmac::Hmac;
use orion::pbkdf2::Pbkdf2;
use test::Bencher;

#[bench]
fn bench_hmac(b: &mut Bencher) {
    b.iter(|| {
        let hmac = Hmac {
            secret_key: vec![0x01; 32],
            data: vec![0x01; 32],
            sha2: ShaVariantOption::SHA256,
        };

        hmac.finalize();
    });
}

#[bench]
fn bench_hkdf(b: &mut Bencher) {
    b.iter(|| {
        let hkdf = Hkdf {
            salt: vec![0x01; 32],
            ikm: vec![0x01; 32],
            info: vec![0x01; 32],
            length: 32,
            hmac: ShaVariantOption::SHA256,
        };

        hkdf.derive_key().unwrap();
    });
}

#[bench]
fn bench_pbkdf2(b: &mut Bencher) {
    b.iter(|| {
        let pbkdf = Pbkdf2 {
            salt: vec![0x01; 32],
            password: vec![0x01; 32],
            iterations: 10000,
            dklen: 32,
            hmac: ShaVariantOption::SHA256,
        };

        pbkdf.derive_key().unwrap();
    });
}
