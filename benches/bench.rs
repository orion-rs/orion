// MIT License

// Copyright (c) 2018-2026 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

extern crate criterion;
extern crate orion;

use criterion::*;

use orion::KP;
use orion::hazardous::{
    aead::{chacha20poly1305, xchacha20poly1305},
    hash::*,
    kdf::{argon2, hkdf, pbkdf2},
    mac::{hmac, poly1305},
    stream::*,
};

static INPUT_SIZES: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];

mod mac {
    use super::*;

    pub fn bench_poly1305(c: &mut Criterion) {
        let mut group = c.benchmark_group("Poly1305");
        let key = poly1305::OneTimeKey::generate().unwrap();

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute mac", *size),
                &input,
                |b, input_message| {
                    b.iter(|| poly1305::Poly1305::poly1305(&key, input_message).unwrap())
                },
            );
        }
    }

    pub fn bench_hmac_sha256(c: &mut Criterion) {
        let mut group = c.benchmark_group("HMAC-SHA256");
        // NOTE: Setting the key like this will pad it for HMAC.
        // Padding is therefore not included in benchmarks.
        let key = hmac::sha256::SecretKey::generate().unwrap();

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute mac", *size),
                &input,
                |b, input_message| {
                    b.iter(|| hmac::sha256::HmacSha256::hmac(&key, input_message).unwrap())
                },
            );
        }
    }

    pub fn bench_hmac_sha512(c: &mut Criterion) {
        let mut group = c.benchmark_group("HMAC-SHA512");
        // NOTE: Setting the key like this will pad it for HMAC.
        // Padding is therefore not included in benchmarks.
        let key = hmac::sha512::SecretKey::generate().unwrap();

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute mac", *size),
                &input,
                |b, input_message| {
                    b.iter(|| hmac::sha512::HmacSha512::hmac(&key, input_message).unwrap())
                },
            );
        }
    }

    criterion_group! {
        name = mac_benches;
        config = Criterion::default();
        targets =
        bench_poly1305,
        bench_hmac_sha256,
        bench_hmac_sha512,
    }
}

mod aead {
    use super::*;

    pub fn bench_chacha20poly1305(c: &mut Criterion) {
        let mut group = c.benchmark_group("ChaCha20-Poly1305");
        let key = chacha20poly1305::SecretKey::generate().unwrap();
        let nonce = chacha20poly1305::Nonce::try_from(&[0u8; 12]).unwrap();

        for size in INPUT_SIZES.iter() {
            let mut bytes = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_function(BenchmarkId::new("encrypt", *size), |b| {
                b.iter(|| {
                    let _tag = chacha20poly1305::ChaCha20Poly1305::seal_inplace(
                        &key, &nonce, None, &mut bytes,
                    )
                    .unwrap();
                })
            });
        }
    }

    pub fn bench_xchacha20poly1305(c: &mut Criterion) {
        let mut group = c.benchmark_group("XChaCha20-Poly1305");
        let key = xchacha20poly1305::SecretKey::generate().unwrap();
        let nonce = xchacha20poly1305::Nonce::generate().unwrap();

        for size in INPUT_SIZES.iter() {
            let mut bytes = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_function(BenchmarkId::new("encrypt", *size), |b| {
                b.iter(|| {
                    let _tag = xchacha20poly1305::XChaCha20Poly1305::seal_inplace(
                        &key, &nonce, None, &mut bytes,
                    )
                    .unwrap();
                })
            });
        }
    }

    criterion_group! {
        name = aead_benches;
        config = Criterion::default();
        targets =
        bench_chacha20poly1305,
        bench_xchacha20poly1305,
    }
}

mod hash {
    use super::*;

    pub fn bench_sha256(c: &mut Criterion) {
        let mut group = c.benchmark_group("SHA256");

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute hash", *size),
                &input,
                |b, input_message| b.iter(|| sha2::sha256::Sha256::digest(input_message).unwrap()),
            );
        }
    }

    pub fn bench_sha384(c: &mut Criterion) {
        let mut group = c.benchmark_group("SHA384");

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute hash", *size),
                &input,
                |b, input_message| b.iter(|| sha2::sha384::Sha384::digest(input_message).unwrap()),
            );
        }
    }

    pub fn bench_sha512(c: &mut Criterion) {
        let mut group = c.benchmark_group("SHA512");

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute hash", *size),
                &input,
                |b, input_message| b.iter(|| sha2::sha512::Sha512::digest(input_message).unwrap()),
            );
        }
    }

    pub fn bench_blake2b_512(c: &mut Criterion) {
        let mut group = c.benchmark_group("BLAKE2b-512");

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute hash", *size),
                &input,
                |b, input_message| {
                    b.iter(|| {
                        blake2::blake2b::Hasher::Blake2b512
                            .digest(input_message)
                            .unwrap()
                    })
                },
            );
        }
    }

    pub fn bench_blake3_512(c: &mut Criterion) {
        let mut group = c.benchmark_group("BLAKE3-512");
        let mut dest = [0u8; 64];

        for size in INPUT_SIZES.iter() {
            let input = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("compute hash", *size),
                &input,
                |b, input_message| {
                    b.iter(|| {
                        let mut ctx = blake3::Blake3::new();
                        ctx.absorb(input_message).unwrap();
                        ctx.squeeze(&mut dest).unwrap();
                    })
                },
            );
        }
    }

    criterion_group! {
        name = hash_benches;
        config = Criterion::default();
        targets =
        bench_sha256,
        bench_sha384,
        bench_sha512,
        bench_blake2b_512,
        bench_blake3_512
    }
}

mod stream {
    use orion::hazardous::stream::{chacha20::ChaCha20, xchacha20::XChaCha20};

    use super::*;

    pub fn bench_chacha20(c: &mut Criterion) {
        let mut group = c.benchmark_group("ChaCha20");
        let key = chacha20::SecretKey::generate().unwrap();
        let nonce = chacha20::Nonce::from([0u8; 12]);
        let ctx = ChaCha20::new(&key, &nonce);

        for size in INPUT_SIZES.iter() {
            let mut out = vec![0u8; *size];
            let mut wctx = ctx.clone();

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_function(
                BenchmarkId::new("xor-stream", *size),
                |b: &mut Bencher<'_>| b.iter(|| wctx.xor_keystream_into(&mut out).unwrap()),
            );
        }
    }

    pub fn bench_xchacha20(c: &mut Criterion) {
        let mut group = c.benchmark_group("XChaCha20");
        let key = xchacha20::SecretKey::generate().unwrap();
        let nonce = xchacha20::Nonce::generate().unwrap();
        let ctx = XChaCha20::new(&key, &nonce);

        for size in INPUT_SIZES.iter() {
            let mut out = vec![0u8; *size];
            let mut wctx = ctx.clone();

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_function(
                BenchmarkId::new("xor-stream", *size),
                |b: &mut Bencher<'_>| b.iter(|| wctx.xor_keystream_into(&mut out).unwrap()),
            );
        }
    }

    criterion_group! {
        name = stream_benches;
        config = Criterion::default();
        targets =
        bench_chacha20,
        bench_xchacha20,
    }
}

mod kdf {
    use super::*;

    static OKM_SIZES: [usize; 1] = [512];
    static PBKDF2_ITERATIONS: [usize; 1] = [10000];

    pub fn bench_hkdf_sha256(c: &mut Criterion) {
        let mut group = c.benchmark_group("HKDF-HMAC-SHA256");

        let ikm = vec![0u8; 64];
        let salt = ikm.clone();

        for size in OKM_SIZES.iter() {
            let mut okm_out = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("derive bytes", *size),
                &ikm,
                |b, input_ikm| {
                    b.iter(|| {
                        hkdf::Hkdf::<hkdf::SHA256>::derive_key(&salt, input_ikm, None, &mut okm_out)
                            .unwrap()
                    })
                },
            );
        }
    }

    pub fn bench_hkdf_sha512(c: &mut Criterion) {
        let mut group = c.benchmark_group("HKDF-HMAC-SHA512");

        let ikm = vec![0u8; 64];
        let salt = ikm.clone();

        for size in OKM_SIZES.iter() {
            let mut okm_out = vec![0u8; *size];

            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("derive bytes", *size),
                &ikm,
                |b, input_ikm| {
                    b.iter(|| {
                        hkdf::Hkdf::<hkdf::SHA512>::derive_key(&salt, input_ikm, None, &mut okm_out)
                            .unwrap()
                    })
                },
            );
        }
    }

    pub fn bench_pbkdf2_sha256(c: &mut Criterion) {
        let mut group = c.benchmark_group("PBKDF2-HMAC-SHA256");
        // 10 is the lowest acceptable sample size.
        group.sample_size(10);
        group.measurement_time(core::time::Duration::new(30, 0));

        let ikm = vec![0u8; 64];
        let salt = ikm.clone();

        for iterations in PBKDF2_ITERATIONS.iter() {
            let mut dk_out = vec![0u8; 64];

            // NOTE: The password newtype creation is included
            // as this pads the salt for HMAC internally.
            group.bench_with_input(
                BenchmarkId::new("derive 64 bytes", *iterations),
                &iterations,
                |b, iter_count| {
                    b.iter(|| {
                        pbkdf2::Pbkdf2::<pbkdf2::SHA256>::derive_key(
                            &salt,
                            &ikm,
                            **iter_count,
                            &mut dk_out,
                        )
                        .unwrap()
                    })
                },
            );
        }
    }

    pub fn bench_pbkdf2_sha512(c: &mut Criterion) {
        let mut group = c.benchmark_group("PBKDF2-HMAC-SHA512");
        // 10 is the lowest acceptable sample size.
        group.sample_size(10);
        group.measurement_time(core::time::Duration::new(30, 0));

        let ikm = vec![0u8; 64];
        let salt = ikm.clone();

        for iterations in PBKDF2_ITERATIONS.iter() {
            let mut dk_out = vec![0u8; 64];

            // NOTE: The password newtype creation is included
            // as this pads the salt for HMAC internally.
            group.bench_with_input(
                BenchmarkId::new("derive 64 bytes", *iterations),
                &iterations,
                |b, iter_count| {
                    b.iter(|| {
                        pbkdf2::Pbkdf2::<pbkdf2::SHA512>::derive_key(
                            &salt,
                            &ikm,
                            **iter_count,
                            &mut dk_out,
                        )
                        .unwrap()
                    })
                },
            );
        }
    }

    pub fn bench_argon2i(c: &mut Criterion) {
        let mut group = c.benchmark_group("Argon2i");

        let mem = 128;
        let iter = 3;
        let cost = argon2::CostParams::new(iter, mem, 1).unwrap();
        let password = [0u8; 16];
        let salt = [0u8; 16];
        let mut dk_out = [0u8; 32];

        group.throughput(Throughput::Bytes(mem as u64));

        group.bench_with_input(
            BenchmarkId::new(
                "derive bytes",
                format!("iter: {}, mem (KiB): {}", iter, mem),
            ),
            &salt,
            |b, _| {
                b.iter(|| {
                    argon2::Argon2::<argon2::I, argon2::Sequential>::derive_key(
                        &password,
                        &salt,
                        &cost,
                        None,
                        None,
                        &mut dk_out,
                    )
                    .unwrap()
                })
            },
        );
    }

    criterion_group! {
        name = kdf_benches;
        config = Criterion::default();
        targets =
        bench_argon2i,
        bench_hkdf_sha256,
        bench_hkdf_sha512,
        bench_pbkdf2_sha256,
        bench_pbkdf2_sha512,
    }
}

mod ecc {
    use super::*;
    use core::convert::TryFrom;
    use orion::hazardous::ecc::x25519;

    pub fn bench_x25519(c: &mut Criterion) {
        let mut group = c.benchmark_group("X25519");

        let alice_sk = x25519::PrivateKey::generate().unwrap();
        let alice_pk = x25519::PublicKey::try_from(&alice_sk).unwrap();

        group.sample_size(100);
        group.bench_function("key_agreement", move |b| {
            b.iter_with_setup(
                || x25519::PrivateKey::generate().unwrap(),
                |bob_sk| x25519::key_agreement(&bob_sk, &alice_pk).unwrap(),
            )
        });
    }

    criterion_group! {
        name = ecc_benches;
        config = Criterion::default();
        targets =
        bench_x25519
    }
}

mod kem {
    use super::*;
    use orion::hazardous::kem::{mlkem512, mlkem768, mlkem1024};

    pub fn bench_mlkem512(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-KEM-512");

        let alice_kp = mlkem512::KeyPair::generate().unwrap();

        group.sample_size(100);
        group.bench_function("encap+decap", move |b| {
            b.iter(|| {
                let (_, ct) = alice_kp.public().encap().unwrap();
                alice_kp.private().decap(&ct).unwrap();
            })
        });
    }

    pub fn bench_mlkem768(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-KEM-768");

        let alice_kp = mlkem768::KeyPair::generate().unwrap();

        group.sample_size(100);
        group.bench_function("encap+decap", move |b| {
            b.iter(|| {
                let (_, ct) = alice_kp.public().encap().unwrap();
                alice_kp.private().decap(&ct).unwrap();
            })
        });
    }

    pub fn bench_mlkem1024(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-KEM-1024");

        let alice_kp = mlkem1024::KeyPair::generate().unwrap();

        group.sample_size(100);
        group.bench_function("encap+decap", move |b| {
            b.iter(|| {
                let (_, ct) = alice_kp.public().encap().unwrap();
                alice_kp.private().decap(&ct).unwrap();
            })
        });
    }

    criterion_group! {
        name = kem_benches;
        config = Criterion::default();
        targets = bench_mlkem512, bench_mlkem768, bench_mlkem1024
    }
}

mod dsa {
    use super::*;
    use orion::hazardous::dsa::{mldsa44, mldsa65, mldsa87};

    // Uses the deterministic signing benchmark approach from: https://github.com/C2SP/CCTV/tree/main/ML-DSA/benchmark
    // Taken at commit: https://github.com/C2SP/CCTV/commit/d091f096c98eaaf9a42a824eb923a457867e4eae

    const ML_DSA_44_MSG: [&str; 188] = [
        "BUS7IAZWYOZ4JHJQYDWRTJL4V7",
        "MK5HFFNP4TB5S6FM4KUFZSIXPD",
        "DBFETUV4O56J57FXTXTIVCDIAR",
        "I4FCMZ7UNLYAE2VVPKTE5ETXKL",
        "56U76XRPOVFX3AU7MB2JHAP6JX",
        "3ER6UPKIIDGCXLGLPU7KI3ODTN",
        "JPQDX2IL3W5CYAFRZ4XUJOHQ3G",
        "6AJOEI33Z3MLEBVC2Q67AYWK5L",
        "WE3U36HYOPJ72RN3C74F6IOTTJ",
        "NMPF5I3B2BKQG5RK26LMPQECCX",
        "JRGAN2FA6IY7ESFGZ7PVI2RGWA",
        "UIKLF6KNSIUHIIVNRKNUFRNR4W",
        "HA252APFYUWHSZZFKP7CWGIBRY",
        "JFY774TXRITQ6CIR56P2ZOTOL6",
        "ZASYLW5Y3RAOC5NDZ2NCH5A4UY",
        "42X4JXNPXMFRCFAE5AKR7XTFO7",
        "YAHQUWUH534MUI2TYEKQR7VR3A",
        "HBP7FGEXGSOZ5HNOVRGXZJU2KG",
        "HG4O7DCRMYMQXASFLMYQ6NMIXK",
        "2KPQMDZKS65CLJU4DHTMVV5WI3",
        "G6YSUTEX4HHL44ISK2JVVK45BV",
        "PUJGPEQUBQM3IK2EXDQFJ2WGBG",
        "PNS6HMQAWA3RORSMSNEUAINMIR",
        "L35MZS4XYIJK453OFXCZG4WHIK",
        "CRY54YZMFRF6JTB3FPNNBWPUOG",
        "Y25TSZBWGU4HJCRMWZHAWXQ2DN",
        "23W64TW3AKZPKCM4HMKEHFI6VQ",
        "PWQAOZ24B4VLNEQR4XKN7LZHDI",
        "YINPDR3ZSAKPPXP6J6VAXHIPYO",
        "JDBB52ZRAB3PYBPNE7P4COY5PJ",
        "4DYU52LQLVG3LTREOTLBCJK3XC",
        "AB45MV6RKUGPCW4EUK7DX23MJX",
        "HEJSITE5K7J6YJ74OEATVTCERV",
        "ZKI5QCFCGM26UK7F5KYTENXKD2",
        "VH5G3ZLF5XC22QAEJ6JDGOBE5Y",
        "HYGXFHH3JW5SENG26MXLL54IGV",
        "MJUCRL36JZ757UYHBFPCJBPZRH",
        "IBH3T6NAVLCJQBYSVHAQFUITYA",
        "VMWCS7JMIMFQB6TPRAMOUXIKWD",
        "SXRPGPNNW2MMBKQS3HJURIQ3XV",
        "YPPYMJZW6WYXPSCZIPI57NTP5L",
        "N3SH6DUH6UOPU7YMQ6BJJEQSPI",
        "Q243DGA6VC6CW66FFUAB5V3VLB",
        "OUUBXEU4NJBRN5XZJ7YQUPIZLA",
        "H5TWHVGC7FXG6MCKJQURD3RNWG",
        "OONG2ZZ7H3P5BREEEURNJHBBQG",
        "HWROSSRTBCQOAIQAY5S4EQG4FX",
        "AJW6PW62JQNU72VKGIQMPBX64C",
        "OXECVUVAWBBBXGGQGQBTYVEP4S",
        "M5XN6V2LQJDEIN3G4Z6WJO6AVT",
        "NHGJUX3WGRTEIRPFWC2I467ST4",
        "SEOADTJDKAYYLDSC4VAES2CRDJ",
        "J5AT674S577ZFGEURNIAGYOHKW",
        "VJQVNMGHG4ITFX2XSPSDEWVZWD",
        "ZWY3KJPXTAVWWVHNAJDUXZ52TG",
        "HY46PBUGP4EMH34C6Q56MO7CJP",
        "MQTUO7CF6R6CRJPVV6F673M6VW",
        "35Z2Z5KV2RBJPQ7OZ24ZJE6BKR",
        "OVUEVXBLCU2BBY25QP5WJACDIX",
        "LNJX7PCLYL35WYJBW6CTXENPUU",
        "IH7E766LCENOQ5ZKZVCMLEPACU",
        "T2HZFGDDSFQ6YADB52NIFLBFEV",
        "RHQUJMN4MB5SYY4FP4ARZH52QJ",
        "W7GZC5ZM63UF2EJ7OC4WJM3OTH",
        "T2NHNFVOMICY33AQZSR53HXFQ6",
        "7ZVB4Y4K4Y2VAM5NC7HHAJNZIB",
        "UX2I4VF62XJGP2XTNN6LDKXTOH",
        "HJAMJR5RQTQW7JMW7ZLPRBZE7E",
        "HKWSKX7MB5346PHYNWNBAYDSYK",
        "BVWSB75HFLLE45MWA6EPHPTCFR",
        "YDH2J6NMM7UINHGUOPIUI7PSSR",
        "SYQPZLK52HMUAQFMVHGRJYKBEY",
        "7AA6UQFGSPBGNUDPLWXSGNKKPP",
        "AYXRJGRWZ5S3QOEDVWYHHCICHV",
        "KFJYAWO7IATSBCSTDUAA5EPFAN",
        "3JABTLB6T2ICHGVT3HXZZ3OAIT",
        "WCM3IBOCQJ36WSG627CCNK3QA7",
        "5FB5H3BZN2J4RGR2DUW7M37NKZ",
        "VKDDAD3BVOMPSNEDGIRHKX5S6R",
        "LFH5HVUR726OSFD3YVYM3ZHEIH",
        "Y4ETQB2KZVFB4M7SALLCTHX2FB",
        "E6SAU3C25MO2WBBVBKCKP2N4ZE",
        "3JA54Q3NEKURB5EAPL2FOFIESD",
        "FZPBW7BIQIW3FTKQD4TLKNWLMD",
        "LY5W6XFA2ZRI53FTUJYGWZ5RX6",
        "QID236JY3ICR55O5YRED33O7YT",
        "HDRU3L6MFEBCBQFNLF5IRPMOAL",
        "232ANKJBDBG4TSKQ7GJMWTHT23",
        "CDWE3CELZM5AOJGYEFHMUNSP5O",
        "7LNJRBOKN6W7RXUU34MDJ2SNKL",
        "S3IZOADTW2A6E5IGRO5WKX7FVH",
        "ZAISTLXC55EBMTN6KZ6QX5S7OS",
        "4Z5ZIVCMFR2PY2PY4Z47T4YPYA",
        "NE36L53Z6AMYQU7Q5REFUF76MK",
        "WND5UP5M6KWPBRFP5WIWTOWV3I",
        "7OC54DLFWMADJEMKEJ3Y2FMMZS",
        "BWJVZHGEN43ULNIOZCPZOB64HG",
        "VDFPQSR7RE54A75GT4JDZY5JK2",
        "HFCD5EPBZBSVMXIDA47DZ6MRD6",
        "RNBVFIUUJUM7EHRE3VNWSTORGO",
        "VO5NLQJBR22CRRYUETGTU6JLMR",
        "RZOMNFHBTL6HMGWH4PEEDASK7U",
        "QL73UBTOLK5O2TW43YWAIKS6T3",
        "NE3QVSMWS5G3W5C3BMKTJNMI2L",
        "YHI6EYQ4GZMB2QPGHPUG2ZUOEL",
        "6MBATW7MFNRUQBFD3GM35B7YPM",
        "AIYRY6P5T4XU44CGVPEV6W43FR",
        "MIAQ2FHXMAPY5NXSS45VRDPRMG",
        "2SNLHQYKK2K6NSWOF6KPGZ3CPC",
        "RVBHIQO5LH77ZWEAO3SVL72M2V",
        "XXTGJCJNRSNLE7ARAH2UU6LVKR",
        "DQMGILY5IDMWN5OYQYYXH26ZGR",
        "627VTXXMM455KMTFNUUTKNFXPY",
        "HC7IBFGLZCWGUR4K7REPMPW6W4",
        "CHL6JRQUS7D4NML3PFT37PPZAA",
        "Y767HXJAGJ75KE3JLO4DTLQIXC",
        "NTIODXI5I7TF2KXXWXOAYGT7G4",
        "PKZYEK2WAI4D4HEYYZH6H5IOMP",
        "FG6J6G7HZDEDF4JQBQOTC7RQGZ",
        "3VHM2VZU77Y25E3UUYZJLB2QLA",
        "WRZQJQW7ARH4DXYHVLCJ4HRTTB",
        "LQXKV5HD2AZHENSJ2VFLJ5YU5L",
        "MF6Q4OA2EN6TG6BUDK7RWCQNPU",
        "3USKYKPC5CB3EC4ZRMZVE3R2UO",
        "3WICO2GVS3IRBFUHNDLNKWVP7N",
        "P6ZR2UZZOVUZKT4KUS5WICW5XE",
        "PYPZUU76RYVOUZGUUX33HLDKYA",
        "2FTSURHV34VYTVIUU7W6V5C3NK",
        "YABDYMGXS2MD2CYF3S4ALG4FLG",
        "MHIBDH25RRPWV3P4VAWT6SAX3I",
        "OINSMWJQ2UTOOKZ3X6ICXXBQR7",
        "PFTQS7JNU2Q3Q6L4CGBXVLOYNE",
        "A4MZ7CCVYQUDJ2AFHNXBBQ3D24",
        "CPUB5R3ORTCMSMCLUQURE6AN5O",
        "NF5E7U3DFTXWFFXXHUXTEP4VZQ",
        "AWB5WDFERWSSJG53YGJMDORQKR",
        "U5JQUILKD6SEL6LXAMNFZP6VSW",
        "M45NLOAFLO74EJKG5EXNET6J5Y",
        "P2KTEUMZ5DZZMYSPOHDR2WJXAN",
        "KVO7AXZNFBUBPYLOTZQQ42TFNS",
        "WGJJ7SAEV6SBBWWYS4BTLD63WM",
        "Y6GURVDV4ESRBPWSTV25T4PE4K",
        "ESK7MPFPUZ5ZAQ52RP4SQIYCCC",
        "623M3CIABZ3RANERQ2IREXAVYO",
        "OQ4CQCFO42RS4BMMSGSDLUTOQO",
        "AMFHRDVGM6G2TIR3TKIFGFSDVM",
        "7VVSGGCVC53PLOYG7YHPFUJM5X",
        "Z3HMESVL7EZUSZNZ33WXEBHA2N",
        "AWWVRQD5W7IBSQPS26XOJVDV5H",
        "OQBZ5ZST3U3NZYHSIWRNROIG6L",
        "II573BW7DJLBYJSPSYIABQWDZD",
        "MOKXOQFOCUCLQQH4UKH2DPE7VN",
        "XR54NGUOU6BBUUTINNWBPJ35HX",
        "DNK36COZGFXI6DY7WLCNUETIRT",
        "R5M2PV7E3EHEM3TLGRCL3HSFMC",
        "ITKENZQYDQMZFCUPOT7VF3BMU7",
        "5GDCB74PPPHEP5N5G3DVRCYT7R",
        "ZMKXVRPLI5PY5BDVEPOA3NQZGN",
        "GBLIALWTHTUDTOMDERQFVB77CS",
        "VKRTTXUTFOK4PJAQQZCCT7TV3T",
        "ZJBUJJ4SW62BXOID3XO2W2M2PF",
        "SKWT5T6QJTCD3FCINIK22KMVBJ",
        "EHINNU6L33HRLOOJ3A2XFJSYQL",
        "N4HRQJEFPAT5SU3YPO74WSMQIR",
        "TGPTZ3ENMFWB5CZKJFR5WHIRI4",
        "O4HNFTAUJJ2LZPQXPXRAXOVABA",
        "4JVB5STP2YG5GYOXDWIF4KCKFB",
        "MY554X3YZHBECLHNNZ7A3SPJTU",
        "ASCJMAH7VCQAD2QJSWXPSVSM3H",
        "NBNGL5DZ623KCG2JNZFGZMZ7KD",
        "KGMZSW35AEQOJ6FA7IR7BHZI52",
        "Q7QUHHS4OJFMJ4I3FY6TDKSMZQ",
        "MZAE7TOEXAS76T7KIC73FEYRU4",
        "2BVESR3REAWADCGYOYM7T646RG",
        "EK3L2ORP4LT3HU3EMXDSQWFOKJ",
        "3X4A6VMGMIDLVK72FZSDHSERWY",
        "I3UHWI6M6HQFRBSQ6W2SABUNUP",
        "REKPXW4DIB4MTKMPHN3RBVHVME",
        "W37FNFZE35NX65Z7CVQ7L5U4L5",
        "4AGYK6U2KP6RAOADCBUDDCBECV",
        "IXM4SFQUDW2NOTXZIPWTNGET3F",
        "6YE4G3VELF27MN3Z5B4VIQ3XYK",
        "LPOZCPZAG3MD47MIWGR4FIOCDH",
        "WGREKUL2LD7C7SYGKH7APIY2A6",
        "WWW277FKTKUXQMP4BECSRHLWJI",
        "UYE4IQPMSTXVQG7EJALKWWEGDN",
        "TIV2L5Z6K7SNGNUVWSNKTAF4UE",
        "I3FQOAW3PINUK26P62HCX657FO",
    ];

    const ML_DSA_65_MSG: [&str; 147] = [
        "NDGEUBUDWGRJJ3A4UNZZQOEKNL",
        "ACGYQUXN4POOFUENCLNCIPHFAZ",
        "Z3XETEYKROVJH7SIHOIAYCTO42",
        "DXWCVCEFULV7XHRWHJWSEXWES7",
        "BCR2D5PNLGFYX6B3QFQFV23JZP",
        "2DVP5HNG54ES64QK4D37PWUYTJ",
        "UJM4ADPJLURAIQH4XA6QYUGNJ6",
        "B5WRCIPK5IVZW52R6TJOKNPKZH",
        "7QNL6JTSP62IGX6RCM2NHRMTKK",
        "EJSZQYLM7G7AJCGIEVBV2UW7NN",
        "UFNA2NKJ3QFWNHHL5CXZ4R5H46",
        "QZAXRTT3E4DOGVTJCOTBG3WXQV",
        "KH2ETOYZO5UHIHIKATWJMUVG27",
        "V5HVVQTOWRXZ2PB4XWXSEKXUN5",
        "5LA7NAFI2LESMH533XY45QVCQW",
        "SMF4TWPTMJA2Z4F4OVETTLVRAY",
        "FWZ5OJAFMLTQRREPYF4VDRPPGI",
        "OK3QMNO3OZSKSR6Q4BFVOVRWTH",
        "NQOVN6F6AOBOEGMJTVMF67KTIJ",
        "CCLC4Y6YT3AQ3HGT2QNSYAUGNV",
        "CAZJHCHBUYQ6OKZ7DMWMDDLIZQ",
        "LVW5XDTHPKOW5D452SYD7AFO6Q",
        "EYA6O6FTYPC6TRKZPRPX5N2KQ4",
        "Z6SGAEZ2SAAZHPQO7GL7CUMBAG",
        "FKUCKW6JQVF4WQYXUSXYZQMAVY",
        "LN2KDF4DANPE4SC4GKJ4BES3IZ",
        "AVCRTWB6ALOQHY34XI7NTMP2JH",
        "A5WHIS6CBWPCYIEC6N2MBAOEZ6",
        "JC2BH476BXUQFIDA6UCR5V4G4F",
        "NU6XH6VLSSFHVSRZCYXPFYKYCD",
        "GSUXVZBDDYSZYFGXNP6AZW3PTC",
        "XJPRNJ26XP4MIYH2Q7M7MPZ73M",
        "INUTUP3IRFWIIT23DNFTIYKCFY",
        "T4KH7HKLEYGXHBIRFGFCRUZCC4",
        "GGQX4JFVWZHE5Y73YTLMSSOXNS",
        "BUA4Q3TQZGLVHMMJU62GQOSHLV",
        "WXW3SJXLSZO2MYF4YFIMXL2IQP",
        "Q32XBVVGFQTSXAIDJE6XSEPRZG",
        "6TEXT6SA7INRCTDSCSVZJEQ2YG",
        "ZBN4UL43C3SJIG4HYR236PXCVS",
        "TVWPLLC7NROBREWOM75VA3XCR3",
        "CCDGL2FURLBABQ4IJBYCB75JFR",
        "XBZGCOVTZHCPAARBTMAKPIE6GJ",
        "TPRAENJ7I54XRIVH6LL6FDIA3I",
        "RKOM3PHFILPIIQZL4ILQWGRYWI",
        "CEEZIZ2WUXHQQFATYYGQ3ZDBTI",
        "SLKOVAP6WLIVJBVU7VZG3ZGEOW",
        "TWMCLJJSWEEQQPQGGDKEJ5SU2R",
        "IFMUXXCD2LC7IGQLZ2QEK5UOQ2",
        "C7IWFEBHW2CXN4XBJS7VLWH3VK",
        "7KJYUEW3F264727TM4LE6RMGDO",
        "BPG2XAPBMBTA4VMPUM7IZVZPK3",
        "Y5X577BWRZNPLNUHJVSKGMUXYB",
        "ZCKMKM23E4IUPTNQDFN2LTLZVX",
        "4RKK223JNBDAP4G5DOAHHZ3VNO",
        "5UZ3TQZHZT22ISTB4WJEVO6MC4",
        "YMVS4HFSJ32CRZRL23PXZUEJFJ",
        "UQEUJUTPSZLZARNBXWMCTMHPFF",
        "CZAAZ5WK7EIPMW7NA3EZNNBF45",
        "227PBHH23WM7F2QLEZSPFYXVW4",
        "YUYS2J5CRFXZ4J4KJT2ZKIZVW3",
        "MFLHZJOZV44SN4AH6OJ3QZWM2O",
        "H2B3CRBCXYN7QWDGYUPHQZP23A",
        "T4L6YWQUQ3CTACENAJ5WUXZWFH",
        "N723H6MUGPZSRZ72C635OD4BP7",
        "NI4TUMVA6LQPQV2TXPN4QOIGBZ",
        "CQI3S4LSTQASSJJVZXEFPOVW7K",
        "ANPY4HJ64LLSB3GK2R4C6WDBS3",
        "RGWQCZKQLMT5FZRDE4B3VMASVK",
        "Q3WCCF2HA3CA4WWRJBMGBW7WI7",
        "2AKJRXFHXLUQPOXPTLSZN5PW4A",
        "IJWOOTI4N7RWXJIHAPXN6KEWEN",
        "4D53T6N6ATOVTD4LKSTAAWBJMU",
        "B4G5HDD6RITG6NIH6FXCRZDYZM",
        "TJCDFKMRUY2OG6KRSMNVCGQFUP",
        "PB33IHQKALAY6H6GVBVLI6ZRXK",
        "SCCWGW2J5S4WL4FTTMQ435F6DB",
        "ZVJH2HSMTLHGXMGPMXLJCKCLLE",
        "62LG37U6JXR77YRZQQCDSBHVCS",
        "BU4CBWOXQ352TEOKIXO245ID4O",
        "UEZOH7KEIODSEVRUF6GMWGA2RB",
        "IPJWROME4GM66CGLUWP5BJ4SX6",
        "355GDC7TG64AZJ7IJX6K62KZCZ",
        "AHTFKX3V7XUB3EWOMQVCGZYGUE",
        "N4RV2GKXJ4SPHHJ52Z7K5EGLER",
        "ZY7V7NE5F66XHDHWM6YNFEWZA6",
        "DIKFO5KAVT4WAP7BOEFM56ZUSR",
        "4TDFOFKDAPIOM3MU5GD7NPXNWQ",
        "AD7YZO756HDK6YWFILAKW3JWA7",
        "NUA53JS2ZK2BGHH3A7BJTJZYW7",
        "QLCNC3AQNKLRMSYR62WQSQP5VI",
        "SJ7OBS7ZYXSGXOYXPE5KW2XKN6",
        "44HBMOGMIMJS63CEXQU7FCXE2E",
        "KCK3J7ZL6QF4SLHHSWTJURK7PG",
        "HLH4CLUGBSOOBSS3BPO62N5MC3",
        "3FNS4GITO6OEUBAVDDXK4WOBTD",
        "IAC3K3I4AQGY3G6UHG7PL2N6TE",
        "KUKLNH74POJI5DYAEWUD7RABTQ",
        "ETM6N7VU3GBSQ7P5MCD6UF3E3S",
        "IZITM5NYBGJZLSI3BI4VEMW43U",
        "46OPQU4LL6N3Z2U7KYPKUMBAGI",
        "EV7YZ5DMAV7VKYJQUFSRD37GPP",
        "AV7W2PGYDJIAKLFVEBL6BXQSGC",
        "M2FOX5QZEZKV4QXKPI5XUZDHEM",
        "R4IFPLVMOVYCHRTR6LXAUGP3LL",
        "JGH6XJUMP4DRVAM27P2JNOKXVO",
        "D2XN3ZLLU6VFPMDYM7NBHSQEOI",
        "2PO3BYENOMQK6SHQDCFSRPJQI3",
        "IBVQ7U3QEUC6PQRE4PV53JTZTK",
        "ZBCOX4P7NG2IXXFB2R43MG2SLV",
        "5NJDPQVVDO7ADNZ2CV7L6QBNGZ",
        "V7ASFIIYUMXFGW4B7ZM6LOGUTE",
        "PX5IJZ7W2LUPKM6YN4PMZ43ZLM",
        "AYK7SZ23DHC7Q56MWAJXBG76LB",
        "UYCAPXJM4HNGKLIDSZ4NCEDJLN",
        "UWMDZ3C2ODLACKGJPGETNQ3TA4",
        "Q6OI6R3WYYJ4CCZCDJBQMCRCZR",
        "LCMJHLP7354APCEGPKE7HHWTWB",
        "N7T7ZKOYPAMEYTTDOWZNCN6PRD",
        "UZADPU4UNHAF7L7LQDMTKA2EQH",
        "DC2OEPQDECVLRVNNCS6BMH4CRA",
        "37IZ427XHUMZ66EJ62U2YEZDAC",
        "6BCZDQZDPZLS5OGESKNUBPSSFV",
        "ST2LEMJ4OLQ32TJTLH2WCWT4WA",
        "GA2TL4SFLEW4G2B5PQMIKJT5XG",
        "L7PPBIET26EH7LQTLEFC4I4EIA",
        "6YSM7MC2W4DEV6ULAHMX27LH56",
        "QL26Z5KZ4YRRG2BXXGDRRLV357",
        "677TWRAJ5NSNHCE243POQPEG7K",
        "66MEBQJLGAGVXDX3KZ2YFTTVJM",
        "6D4VUWAQD6R65ICSDLFAATC67V",
        "7GXLD5CNU3TDUQSSW42SHL7B5D",
        "RQETUMEBG2ZM2NF2EZAQHGHWWE",
        "DCRX5ANWDMXZFIDVAXYLQZYMRN",
        "5SDWT7YAF7L4WWANAGYINZAYXH",
        "PZILRV7I2S6WKUSHKYRLA2JQY3",
        "2G66TK2PZ5MOTAZDN7BFS3LAIH",
        "QOLJ3WGJ6JS3FMMXBNTNAIKXVK",
        "FMAL67YTHDCCYVZ5CRMN2XJPDN",
        "UOTZDXTJKQ3YAIRKHTYNX6G55P",
        "X3DLNPJ3V62LRHGEY4DTT35H3R",
        "DKU7CHNXPB5QRZVGIQZW46XCKC",
        "RAKBD4LQKEDTVDSK3DVTRWG23B",
        "INTRA7BWHLVQMBRKBJNUSMF7MU",
        "AUYRBNVCOYYHOHUYOOFIZ2FWMD",
        "22EJVDEQ7PASLBAMTVKXOQP5RJ",
        "3S6NATWA57SFTZEW7UZUOUYAEU",
    ];

    const ML_DSA_87_MSG: [&str; 114] = [
        "LQQPGPNUME6QDNDTQTS4BA7I7M",
        "PTYEEJ7RMI6MXNN6PZH222Y6QI",
        "R6DTHAADKNMEADDK5ECPNOTOAT",
        "S2QM7VDC6UKRQNRETZMNAZ6SJT",
        "EYULPTSJORQJCNYNYVHDFN4N3F",
        "YETZNHZ75SXFU672VQ5WXYEPV2",
        "KTSND3JGA4AN3PCMG4455JEXGR",
        "JGE6HK37O6XMWZQZCHFUPNUEXP",
        "CRYB2FZD2BYNANBFFO2HRZEHGZ",
        "7MLNDZJ7OIEPBJZOMULOMQH2BA",
        "4WQCNTIFVSX2DNALMWUKZRA6CI",
        "Y5NK4OBDSDWC5WLL27CEEXYYOT",
        "C4SSWSPBVCDAWJXH2CDMXR36LH",
        "THDBKXRTKWJUGJMAAYTWTFMX7Z",
        "NWXPUD4DAA6QOREW4AFFYQYQNG",
        "3RQIJXMO7WYHBEBL3G6EOLNZNQ",
        "R7JEOHFP2C7O4AVPRPRELXWOMM",
        "LU6MWR7SZXVIKS54BY62X67NPA",
        "FG2FFM4F2ECKHCSJ75KXK632JP",
        "BF76ZDSVVUSYS5KK4FFD22YPS7",
        "HCLBWZRLHEMYZLFWHLAN2BKCZ7",
        "HGFVS4QC7AWXYPVRSWAK77KTQF",
        "LUZ3C53PUUHBWCDJ7WAHK2UT3K",
        "Y3WR6SMDUBW34N3MUT7EQYIJCV",
        "F2X35AQTXVZBMPXTWNAAH4ZX2W",
        "6MKFFDYWD6ZAKS3C6GRCRLZLRF",
        "AFMZYYFRHKMQRNKU5UTSKQ74H6",
        "TDTN7J3O367OVPWLESRNPLN4M2",
        "WYMLD2X6N4CZ2RDOKF5CFTSYTG",
        "UNPTSBLJ6HZRNR72T2VEEHCFX2",
        "SNCM4R2P27AJOXBS67RMCARS3U",
        "OU7QBE5QOXO7CIYTBJR3KOW2WK",
        "2NNQOBQKZ2OD4ZAXI3SNEURYUP",
        "YQTUPOYBT67XPCHIGKSGSKC3BZ",
        "HGB4ZM3G76IXYWWCMVT3HONRIS",
        "WZC6QUKRZZ2TOVA277JYKQITEW",
        "XO2WT46A5HYL6CUJF7SGJ6YWOG",
        "4QJA35PMYQIDRZ7ZHG7RLZJVGF",
        "BMJZELWZ4I2UWXESU3NR6ATC4M",
        "XWLFB7FN6D5PRY6YUXC5JUIBFM",
        "WRAFFF27AVTIOYIBYA2IPTXI3R",
        "VOXUTYTN2XZ362OJFO2R53UCUF",
        "UHN73ARJ737WUJ6QYEI7U46OPO",
        "3Y3K5E2A4ML3VYVNAFWEEIXTSN",
        "QMU4322NKPRLE7JBGYFGS36H2S",
        "NJAQTNCXPVDICTDVUKTPRCD2AX",
        "OC373ZFBNV2H46T6OY3XRPSUHG",
        "UBLAS6CDWE3A662MLKP7QDEOCC",
        "BKFDLAL2RTPMERYVW3B7UJ5W3H",
        "QFKFGXKGW5SAKLBAWQXUWW77OS",
        "EJNUQHTLLOVB4ARETOGLY4WUTJ",
        "N243OCMVLLAO6I2XLCYOIMQYGY",
        "YRRFLWK7ZASUKYX7ZLQMW2PJ6X",
        "3DGVPBWD2BIK6KQE65K72DNJNM",
        "TJRYMNOAIW33VIHKLJG4GXAVUK",
        "6DSRINAYXL34U54U355U7IVFGS",
        "6CHA4MX7LVS77XKRWG7IYC3XVL",
        "GM2CEGBEPBOHAPIOBUWJ4MJNTG",
        "VJKHGBY33VUIJFEQLX3JVUNQBD",
        "DTOHAD5M2KL46IZHE4TPLJWHTI",
        "IYFG3UDN7ROOY2ZFSLM2BU2LMQ",
        "A5OGJHPOE4PW6QSZYHZ5TKPGIC",
        "FX4BCN67AEGCLUTLFPNDL3SQU5",
        "MWIZQVOZOHTTBUXC3BEX62MNI5",
        "BYHVJHBLK4O6LFSKEIQ3CAAKU7",
        "QJU7P6KWSSKAA5GVA6RH4OV7MX",
        "I3T3XM5Z5TAJHAYDQHFA2ZV7PU",
        "L46MQCHV3TJ6FYIQQ2FCJXES74",
        "QXZRQIYAJMXYR6PU3VDYGCIT5W",
        "MFS53RR2XEYS22NYOJLGTHVTTM",
        "FRWIWJRP4AQMXWX4WJ4WYVKM3E",
        "X6GK6IGVLJWYSHLKHGXSW3TJDP",
        "L5LPJ2HIWA4UY6G6FMZXGDEDAM",
        "GD6FYOYUGDHXEQ5S2KLJEGNSN7",
        "ODAL7ZRKXSPAAN5DVRBWJQCFQX",
        "CV3QFBDXBPT3SCPJGUYSMDN6ZS",
        "IGSLSACRZ6XID466KQIB4YNGYO",
        "WZ2EACBN26RAML2S52YXRYP2OF",
        "LB76VEVNOBYFMKFZ7SDFCBCHQE",
        "TLFA7EU3JJFAP6EMUKNV2ZXRBM",
        "SIIJF6OXAKRP25CBUYFBRCDDVP",
        "TEPNI7TJ7HASJWIQMBS4VFLRQC",
        "VK2JINYWEDV7IQFWH4OTAD4W5O",
        "GILUH5AMVE4TM7EKPXJBZGT6EJ",
        "DV7ALFRAW3TI4WMQQLDTO6RNHN",
        "CAIB5G3NXC5ASPLFIWAFPVHS5B",
        "MLFJXZUOAGN7EGPMXOOVTB2CL4",
        "6MZYT3ANWHBOS67WGHZI3QPEAP",
        "LVJDQB52C2PERSSQJRMRCJ4UBF",
        "QY4VKAZAYQIZOX2L2VO2QHAQVC",
        "UAA5SST2XA76JPKM3XOZ5RUHFI",
        "VLZWF53JSQ6SCRUFDKVPXWAS4L",
        "NX2DZIKMJIYXUNSAHFP23FHTBU",
        "F5OAKDDDA34A2RPIKDPM5CYPMZ",
        "E5PEP3ANIK2L4VLOST4NIYNKBD",
        "IPBGFLHSMP4UFXF6XJX42T6CAL",
        "XHPU7DBFTZB2TX5K34AD6DJTK3",
        "2ZU7EJN2DG2UMT6HX5KGS2RFT6",
        "SD5S7U34WSE4GBPKVDUDZLBIEH",
        "WZFFL3BTQAV4VQMSAGCS45SGG3",
        "QE7ZT2LI4CA5DLSVMHV6CP3E3V",
        "YIWMS6AS72Z5N2ALZNFGCYC5QL",
        "A4QJ5FNY54THAKBOB65K2JBIV7",
        "6LORQGA3QO7TNADHEIINQZEE26",
        "5V45M6RAKOZDMONYY4DIH3ZBL2",
        "SVP7UYIZ5RTLWRKFLCWHAQV3Y2",
        "C2UYQL2BBE4VLUJ3IFNFMHAN7O",
        "P4DS44LGP2ERZB3OB7JISQKBXA",
        "A6B4O5MWALOEHLILSVDOIXHQ4Z",
        "DKQJTW5QF7KDZA3IR4X5R5F3CG",
        "H6QFQX2C2QTH3YKEOO57SQS23J",
        "DIF373ML2RWZMEOIVUHFXKUG7O",
        "Z5PPIA3GJ74QXFFCOSUAQMN5YN",
        "PM6XIDECSS5S77UXMB55VZHZSE",
    ];

    pub fn bench_mldsa44_sign(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-44");

        let seed = mldsa44::Seed::from([0u8; 32]);
        let kp = mldsa44::KeyPair::new(seed).unwrap();

        let msgs: Vec<Vec<u8>> = ML_DSA_44_MSG
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
        let mut msgs = msgs.iter().cycle();

        group.sample_size(ML_DSA_44_MSG.len());
        group.bench_function("sign", move |b| {
            b.iter(|| {
                let msg_to_sign = msgs.next().unwrap();
                let _ = kp.private().sign_deterministic(msg_to_sign, &[]).unwrap();
            })
        });
    }

    pub fn bench_mldsa44_verify(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-44");

        let seed = mldsa44::Seed::from([0u8; 32]);
        let kp = mldsa44::KeyPair::new(seed).unwrap();

        let sigs: Vec<(Vec<u8>, mldsa44::Signature)> = ML_DSA_44_MSG
            .iter()
            .map(|m| {
                (
                    m.as_bytes().to_vec(),
                    kp.private().sign_deterministic(m.as_bytes(), &[]).unwrap(),
                )
            })
            .collect();
        let mut sigs = sigs.iter().cycle();

        group.sample_size(ML_DSA_44_MSG.len());
        group.bench_function("verify", move |b| {
            b.iter(|| {
                let sig_and_msg = sigs.next().unwrap();
                kp.public()
                    .verify(sig_and_msg.0.as_slice(), &[], &sig_and_msg.1)
                    .unwrap();
            })
        });
    }

    pub fn bench_mldsa65_sign(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-65");

        let seed = mldsa65::Seed::from([0u8; 32]);
        let kp = mldsa65::KeyPair::new(seed).unwrap();

        let msgs: Vec<Vec<u8>> = ML_DSA_65_MSG
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
        let mut msgs = msgs.iter().cycle();

        group.sample_size(ML_DSA_65_MSG.len());
        group.bench_function("sign", move |b| {
            b.iter(|| {
                let msg_to_sign = msgs.next().unwrap();
                let _ = kp.private().sign_deterministic(msg_to_sign, &[]).unwrap();
            })
        });
    }

    pub fn bench_mldsa65_verify(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-65");

        let seed = mldsa65::Seed::from([0u8; 32]);
        let kp = mldsa65::KeyPair::new(seed).unwrap();

        let sigs: Vec<(Vec<u8>, mldsa65::Signature)> = ML_DSA_65_MSG
            .iter()
            .map(|m| {
                (
                    m.as_bytes().to_vec(),
                    kp.private().sign_deterministic(m.as_bytes(), &[]).unwrap(),
                )
            })
            .collect();
        let mut sigs = sigs.iter().cycle();

        group.sample_size(ML_DSA_65_MSG.len());
        group.bench_function("verify", move |b| {
            b.iter(|| {
                let sig_and_msg = sigs.next().unwrap();
                kp.public()
                    .verify(sig_and_msg.0.as_slice(), &[], &sig_and_msg.1)
                    .unwrap();
            })
        });
    }

    pub fn bench_mldsa87_sign(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-87");

        let seed = mldsa87::Seed::from([0u8; 32]);
        let kp = mldsa87::KeyPair::new(seed).unwrap();

        let msgs: Vec<Vec<u8>> = ML_DSA_87_MSG
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
        let mut msgs = msgs.iter().cycle();

        group.sample_size(ML_DSA_87_MSG.len());
        group.bench_function("sign", move |b| {
            b.iter(|| {
                let msg_to_sign = msgs.next().unwrap();
                let _ = kp.private().sign_deterministic(msg_to_sign, &[]).unwrap();
            })
        });
    }

    pub fn bench_mldsa87_verify(c: &mut Criterion) {
        let mut group = c.benchmark_group("ML-DSA-87");

        let seed = mldsa87::Seed::from([0u8; 32]);
        let kp = mldsa87::KeyPair::new(seed).unwrap();

        let sigs: Vec<(Vec<u8>, mldsa87::Signature)> = ML_DSA_87_MSG
            .iter()
            .map(|m| {
                (
                    m.as_bytes().to_vec(),
                    kp.private().sign_deterministic(m.as_bytes(), &[]).unwrap(),
                )
            })
            .collect();
        let mut sigs = sigs.iter().cycle();

        group.sample_size(ML_DSA_87_MSG.len());
        group.bench_function("verify", move |b| {
            b.iter(|| {
                let sig_and_msg = sigs.next().unwrap();
                kp.public()
                    .verify(sig_and_msg.0.as_slice(), &[], &sig_and_msg.1)
                    .unwrap();
            })
        });
    }

    criterion_group! {
        name = dsa_benches;
        config = Criterion::default();
        targets =
            bench_mldsa44_sign,
            bench_mldsa44_verify,
            bench_mldsa65_sign,
            bench_mldsa65_verify,
            bench_mldsa87_sign,
            bench_mldsa87_verify
    }
}

criterion_main!(
    mac::mac_benches,
    aead::aead_benches,
    hash::hash_benches,
    stream::stream_benches,
    kdf::kdf_benches,
    ecc::ecc_benches,
    kem::kem_benches,
    dsa::dsa_benches,
);
