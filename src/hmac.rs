use functions;
use ring::{digest, test};

// Set blocksizes
pub const BLOCKSIZE_256: usize = 64;
pub const BLOCKSIZE_512: usize = 128;

/// Return either a SHA256 or SHA512 digest of byte vector
fn hash(variant: i32, mut data: Vec<u8>) -> Vec<u8> {
    if variant == 256 {
        data = (digest::digest(&digest::SHA256, &data).as_ref()).to_vec();
    } else if variant == 512 {
        data = (digest::digest(&digest::SHA512, &data).as_ref()).to_vec();
    } else {
        panic!("Invalid variant. Valid variants are 256 and 512.");
    }
    return data;
}

/// Return a key k that has been padded to fit the selected blocksize
fn key_deriv(variant: i32, mut k: Vec<u8>) -> Vec<u8> {
    if variant == 256 {
        // If key k is bigger than blocksize, it should be hashed and then padded with zeroes
        // to fit blocksize
        if k.len() > BLOCKSIZE_256 {
            k = hash(variant, k);
        }
        while k.len() < BLOCKSIZE_256 {
            k.push(0x00);
        }
        return k;
    } else if variant == 512 {
        if k.len() > BLOCKSIZE_512 {
            k = hash(variant, k);
        }
        while k.len() < BLOCKSIZE_512 {
            k.push(0x00);
        }
        return k;
    } else {
        panic!("Invalid variant. Valid variants are 256 and 512.");
    }
}

/// Returns an HMAC from message m and key k
pub fn hmac(variant: i32, mut k: Vec<u8>, mut m: Vec<u8>) -> Vec<u8> {
    // Initialize vectors that will hold the ipad and opad
    let mut ipad = vec![];
    let mut opad = vec![];
    // Pad the key
    k = key_deriv(variant, k);

    for count in 0..k.len() {
        ipad.push(k[count] ^ 0x36);
        opad.push(k[count] ^ 0x5C);
    }

    ipad.append(&mut m);
    ipad = hash(variant, ipad);
    opad.append(&mut ipad);
    opad = hash(variant, opad);

    return opad;
}


#[test]
// Test that the function key_deriv() returns a padded key K
// with size of correct BLOCKSIZE, both for SHA256 and SHA512
fn test_key_deriv() {
    let rand_k: Vec<u8> = functions::gen_rand_key(64);
    let rand_k2: Vec<u8> = functions::gen_rand_key(128);
    let rand_k3: Vec<u8> = functions::gen_rand_key(34);
    assert_eq!(key_deriv(256, rand_k.clone()).len(), BLOCKSIZE_256);
    assert_eq!(key_deriv(512, rand_k.clone()).len(), BLOCKSIZE_512);
    assert_eq!(key_deriv(256, rand_k2.clone()).len(), BLOCKSIZE_256);
    assert_eq!(key_deriv(512, rand_k2.clone()).len(), BLOCKSIZE_512);
    assert_eq!(key_deriv(256, rand_k3.clone()).len(), BLOCKSIZE_256);
    assert_eq!(key_deriv(512, rand_k3.clone()).len(), BLOCKSIZE_512);
}

#[test]
// Test that hmac() returns expected HMAC digests
fn test_hmac_digest_result() {
    let k_256 = vec![0x61; BLOCKSIZE_256];
    let m_256 = vec![0x62; BLOCKSIZE_256];
    let actual_256 = hmac(256, k_256, m_256);

    let k_512 = vec![0x63; BLOCKSIZE_256];
    let m_512 = vec![0x64; BLOCKSIZE_256];
    let actual_512 = hmac(512, k_512, m_512);

    // Expected values from: https://www.freeformatter.com/hmac-generator.html#ad-output
    let expected_256 = test::from_hex("f6cbb37b326d36f2f27d294ac3bb46a6aac29c1c9936b985576041bfb338ae70").unwrap();
    let expected_512 = test::from_hex("ffbd423817836ae58b801fc1e70386f09a6cc0e72daa215ac8505993721f0f6d67ce30118d7effe451310abad984d105fbd847ae37a88f042a3a79e26f307606").unwrap();
    assert_eq!(actual_256, expected_256);
    assert_eq!(actual_512, expected_512);
}
