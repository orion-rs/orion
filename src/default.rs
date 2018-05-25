// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.





use hmac::Hmac;
use hkdf::Hkdf;
use pbkdf2::Pbkdf2;
use util;
use constant_time_eq::constant_time_eq;
use options::ShaVariantOption;

/// HMAC with SHA512.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let key = util::gen_rand_key(64);
/// let msg = "Some message.".as_bytes();
///
/// let hmac = default::hmac(&key, msg);
/// ```
pub fn hmac(secret_key: &[u8], message: &[u8]) -> Vec<u8> {

    if secret_key.len() < 64 {
        panic!("The secret_key must be equal to, or above 64 bytes in length.");
    }


    let hmac_512_res = Hmac {
        secret_key: secret_key.to_vec(),
        message: message.to_vec(),
        sha2: ShaVariantOption::SHA512
    };

    hmac_512_res.hmac_compute()
}

/// Verify an HMAC against a key and message in constant time and with Double-HMAC Verification.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let key = util::gen_rand_key(64);
/// let msg = "Some message.".as_bytes();
///
/// let expected_hmac = default::hmac(&key, msg);
/// assert_eq!(default::hmac_verify(&expected_hmac, &key, &msg), true);
/// ```
pub fn hmac_verify(expected_hmac: &[u8], secret_key: &[u8], message: &[u8]) -> bool {

    let rand_key = util::gen_rand_key(64);

    let own_hmac = hmac(&secret_key, &message);
    // Verification happens on an additional round of HMAC
    // to randomize the data that the validation is done on
    let nd_round_own = hmac(&rand_key, &own_hmac);
    let nd_round_expected = hmac(&rand_key, &expected_hmac);

    constant_time_eq(&nd_round_own, &nd_round_expected)
}

/// HKDF with HMAC-SHA512.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let salt = util::gen_rand_key(64);
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 64);
/// ```
pub fn hkdf(salt: &[u8], input_data: &[u8], info: &[u8], length: usize) -> Vec<u8> {

    if salt.len() < 64 {
        panic!("The salt must be equal to, or above, 64 bytes in length.");
    }


    let hkdf_512_res = Hkdf {
        salt: salt.to_vec(),
        ikm: input_data.to_vec(),
        info: info.to_vec(),
        hmac: ShaVariantOption::SHA512,
        length: length
    };

    let hkdf_512_extract = hkdf_512_res.hkdf_extract(&hkdf_512_res.ikm, &hkdf_512_res.salt);

    hkdf_512_res.hkdf_expand(&hkdf_512_extract)
}

/// Verify an HKDF-HMAC-SHA512 derived key in constant time.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let salt = util::gen_rand_key(64);
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 64);
/// assert_eq!(default::hkdf_verify(&hkdf, &salt, data, info, 64), true);
/// ```
pub fn hkdf_verify(expected_hkdf: &[u8], salt: &[u8], input_data: &[u8], info: &[u8],
    length: usize) -> bool {


    let own_hkdf = hkdf(salt, input_data, info, length);

    constant_time_eq(&own_hkdf, &expected_hkdf)
}

/// PBKDF2 with HMAC-SHA512. Uses 512000 iterations with an output length of 64 bytes.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
/// // Salts are limited to being 64 in length here.
/// let salt = util::gen_rand_key(64);
/// let derived_password = default::pbkdf2("Secret password".as_bytes(), &salt);
/// ```
pub fn pbkdf2(password: &[u8], salt: &[u8]) -> Vec<u8> {

    if salt.len() < 64 {
        panic!("The salt must be equal to, or above, 64 bytes in length.");
    }


    let pbkdf2_sha512_res = Pbkdf2 {
        password: password.to_vec(),
        salt: salt.to_vec(),
        iterations: 512000,
        length: 64,
        hmac: ShaVariantOption::SHA512
    };

    pbkdf2_sha512_res.pbkdf2_compute()
}

/// Verify PBKDF2-HMAC-SHA512 derived key in constant time. Uses 512000 iterations with an output length of 64 bytes for PBKDF2.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let salt = util::gen_rand_key(64);
/// let derived_password = default::pbkdf2("Secret password".as_bytes(), &salt);
/// assert_eq!(default::pbkdf2_verify(&derived_password, "Secret password".as_bytes(), &salt), true);
/// ```
pub fn pbkdf2_verify(derived_password: &[u8], password: &[u8], salt: &[u8]) -> bool {

    let own_pbkdf2 = pbkdf2(password, salt);

    constant_time_eq(&own_pbkdf2, derived_password)
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use default;
    use util;

    #[test]
    #[should_panic]
    fn hmac_secretkey_too_short() {
        default::hmac(&vec![0x61; 10], &vec![0x61; 10]);
    }

    #[test]
    fn hmac_secretkey_allowed_len() {
        default::hmac(&vec![0x61; 64], &vec![0x61; 10]);
        default::hmac(&vec![0x61; 78], &vec![0x61; 10]);
    }

    #[test]
    fn hmac_result() {

        let sec_key = decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaa").unwrap();
        let msg = decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
              65204b6579202d2048617368204b6579204669727374").unwrap();

        let expected_hmac_512 = decode(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
            6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598").unwrap();

        assert_eq!(default::hmac(&sec_key, &msg), expected_hmac_512);
    }

    #[test]
    // Test that hmac_validate() returns true if signatures match and false if not
    fn hmac_verify() {

        let sec_key_correct = decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaa").unwrap();
              // Change compared to the above: Two additional a's at the end
        let sec_key_false = decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
              aaaaaaaa").unwrap();
        let msg = "what do ya want for nothing?".as_bytes().to_vec();

        let hmac_bob = default::hmac(&sec_key_correct, &msg);

        assert_eq!(default::hmac_verify(&hmac_bob, &sec_key_correct, &msg), true);
        assert_eq!(default::hmac_verify(&hmac_bob, &sec_key_false, &msg), false);
    }

    #[test]
    fn hkdf_verify() {

        let salt = util::gen_rand_key(64);
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let hkdf_dk = default::hkdf(&salt, data, info, 64);

        assert_eq!(default::hkdf_verify(&hkdf_dk, &salt, data, info, 64), true);
    }
    
    #[test]
    #[should_panic]
    fn hkdf_salt_too_short() {
        default::hkdf(&vec![0x61; 10], &vec![0x61; 10], &vec![0x61; 10], 20);
    }

    #[test]
    fn hkdf_salt_allowed_len() {
        default::hkdf(&vec![0x61; 67], &vec![0x61; 10], &vec![0x61; 10], 20);
        default::hkdf(&vec![0x61; 89], &vec![0x61; 10], &vec![0x61; 10], 20);
    }

    #[test]
    fn pbkdf2_verify() {

        let salt = util::gen_rand_key(64);
        let password = util::gen_rand_key(64);

        let pbkdf2_dk = default::pbkdf2(&password, &salt);

        assert_eq!(default::pbkdf2_verify(&pbkdf2_dk, &password, &salt), true);
    }

    #[test]
    #[should_panic]
    fn pbkdf2_salt_too_short() {
        default::pbkdf2("Secret password".as_bytes(), "Very weak salt".as_bytes());
    }

    #[test]
    fn pbkdf2_salt_allowed_len() {
        default::pbkdf2(&vec![0x61; 10], &vec![0x61; 67]);
        default::pbkdf2(&vec![0x61; 10], &vec![0x61; 64]);
    }
}
