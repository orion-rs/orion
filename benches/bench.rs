#![feature(test)]
extern crate test;
extern crate orion;

use test::Bencher;
use orion::pbkdf2::Pbkdf2;
use orion::hmac::Hmac;
use orion::hkdf::Hkdf;
use orion::core::options::ShaVariantOption;

#[bench]
fn bench_hmac(b: &mut Bencher) {

    b.iter(|| {

        let hmac = Hmac {
            secret_key: vec![0x01; 32],
            message: vec![0x01; 32],
            sha2: ShaVariantOption::SHA256
        };

        hmac.hmac_compute();

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
            hmac: ShaVariantOption::SHA256
        };



        hkdf.hkdf_compute().unwrap();

    });
}

#[bench]
fn bench_pbkdf2(b: &mut Bencher) {

    b.iter(|| {

        let pbkdf = Pbkdf2 {
            salt: vec![0x01; 32],
            password: vec![0x01; 32],
            iterations: 10000,
            length: 32,
            hmac: ShaVariantOption::SHA256
        };

        pbkdf.pbkdf2_compute().unwrap();
    });
}
