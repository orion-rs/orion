#![feature(test)]
extern crate orion;
extern crate test;

use orion::hazardous::cshake;
use orion::hazardous::hkdf;
use orion::hazardous::hmac;
use orion::hazardous::pbkdf2;
use test::Bencher;

#[bench]
fn bench_hmac(b: &mut Bencher) {
    b.iter(|| {
        let mut mac = hmac::init(&vec![0x01; 64]);
        mac.update(&vec![0x01; 64]);
        mac.finalize();
    });
}

#[bench]
fn bench_hkdf(b: &mut Bencher) {
    b.iter(|| {
        let mut okm_out = [0u8; 64];
        hkdf::derive_key(
            &vec![0x01; 64],
            &vec![0x01; 64],
            &vec![0x01; 64],
            &mut okm_out,
        ).unwrap();
    });
}

#[bench]
fn bench_pbkdf2(b: &mut Bencher) {
    b.iter(|| {
        let mut dk_out = [0u8; 64];
        pbkdf2::derive_key(&vec![0x01; 64], &vec![0x01; 64], 10000, &mut dk_out).unwrap();
    });
}

#[bench]
fn bench_cshake(b: &mut Bencher) {
    b.iter(|| {
        let mut hash_out = [0u8; 64];
        let mut cshake = cshake::init(&vec![0x01; 64], None).unwrap();
        cshake.update(&vec![0x01; 64]);
        cshake.finalize(&mut hash_out).unwrap();
    });
}
