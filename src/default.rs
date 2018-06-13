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
use core::{errors::UnknownCryptoError, util};
use core::options::ShaVariantOption;

/// HMAC with SHA512.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the secret key is less than 64 bytes
///
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let key = util::gen_rand_key(64).unwrap();
/// let msg = "Some message.".as_bytes();
///
/// let hmac = default::hmac(&key, msg).unwrap();
/// ```
pub fn hmac(secret_key: &[u8], data: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {

    if secret_key.len() < 64 {
        return Err(UnknownCryptoError);
    }

    let mac = Hmac {
        secret_key: secret_key.to_vec(),
        data: data.to_vec(),
        sha2: ShaVariantOption::SHA512
    };

    Ok(mac.finalize())
}

/// Verify an HMAC against a key and data in constant time and with Double-HMAC Verification.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let key = util::gen_rand_key(64).unwrap();
/// let msg = "Some message.".as_bytes();
///
/// let expected_hmac = default::hmac(&key, msg).unwrap();
/// assert_eq!(default::hmac_verify(&expected_hmac, &key, &msg).unwrap(), true);
/// ```
pub fn hmac_verify(expected_hmac: &[u8], secret_key: &[u8], data: &[u8]) ->
        Result<bool, UnknownCryptoError> {

    let rand_key = util::gen_rand_key(64).unwrap();

    let own_hmac = hmac(&secret_key, &data).unwrap();
    // Verification happens on an additional round of HMAC with a random key
    let nd_round_own = hmac(&rand_key, &own_hmac).unwrap();
    let nd_round_expected = hmac(&rand_key, &expected_hmac).unwrap();

    util::compare_ct(&nd_round_own, &nd_round_expected)
}

/// HKDF-HMAC-SHA512.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the salt is less than 16 bytes
///
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let salt = util::gen_rand_key(64).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 64).unwrap();
/// ```
pub fn hkdf(salt: &[u8], input_data: &[u8], info: &[u8], len: usize) ->
        Result<Vec<u8>, UnknownCryptoError> {

    if salt.len() < 16 {
        return Err(UnknownCryptoError);
    }

    let hkdf_dk = Hkdf {
        salt: salt.to_vec(),
        ikm: input_data.to_vec(),
        info: info.to_vec(),
        length: len,
        hmac: ShaVariantOption::SHA512,
    };

    hkdf_dk.derive_key()
}

/// Verify an HKDF-HMAC-SHA512 derived key in constant time. Both derived keys must
/// be of equal length.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let salt = util::gen_rand_key(64).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 64).unwrap();
/// assert_eq!(default::hkdf_verify(&hkdf, &salt, data, info, 64).unwrap(), true);
/// ```
pub fn hkdf_verify(expected_dk: &[u8], salt: &[u8], input_data: &[u8], info: &[u8],
    len: usize) -> Result<bool, UnknownCryptoError> {

    let own_hkdf = hkdf(salt, input_data, info, len).unwrap();

    util::compare_ct(&own_hkdf, &expected_dk)
}

/// PBKDF2-HMAC-SHA512 derived key, using 512.000 as iteration count.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the salt is less than 16 bytes
/// - The specified length for the derived key is less than 14 bytes
///
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// // Salts are limited to being 64 in length here.
/// let salt = util::gen_rand_key(64).unwrap();
/// let derived_password = default::pbkdf2("Secret password".as_bytes(), &salt, 64);
/// ```
pub fn pbkdf2(password: &[u8], salt: &[u8], dklen: usize) -> Result<Vec<u8>, UnknownCryptoError> {

    if salt.len() < 16 {
        return Err(UnknownCryptoError);
    }

    if dklen < 14 {
        return Err(UnknownCryptoError);
    }

    let pbkdf2_dk = Pbkdf2 {
        password: password.to_vec(),
        salt: salt.to_vec(),
        iterations: 512_000,
        dklen: dklen,
        hmac: ShaVariantOption::SHA512
    };

    pbkdf2_dk.derive_key()
}

/// Verify PBKDF2-HMAC-SHA512 derived key, using 512.000 as iteration count, in constant time. Both derived
/// keys must be of equal length.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let salt = util::gen_rand_key(64).unwrap();
/// let derived_password = default::pbkdf2("Secret password".as_bytes(), &salt, 64).unwrap();
/// assert_eq!(default::pbkdf2_verify(&derived_password, "Secret password".as_bytes(), &salt, 64).unwrap(), true);
/// ```
pub fn pbkdf2_verify(expected_dk: &[u8], password: &[u8], salt: &[u8],
        len: usize) -> Result<bool, UnknownCryptoError> {

    let own_pbkdf2 = pbkdf2(password, salt, len).unwrap();

    util::compare_ct(&own_pbkdf2, expected_dk)
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use default;
    use core::util;

    #[test]
    fn hmac_secretkey_too_short() {
        assert!(default::hmac(&vec![0x61; 10], &vec![0x61; 10]).is_err());
    }

    #[test]
    fn hmac_secretkey_allowed_len() {
        default::hmac(&vec![0x61; 64], &vec![0x61; 10]).unwrap();
        default::hmac(&vec![0x61; 78], &vec![0x61; 10]).unwrap();
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

        assert_eq!(default::hmac(&sec_key, &msg).unwrap(), expected_hmac_512);
    }

    #[test]
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

        let hmac_bob = default::hmac(&sec_key_correct, &msg).unwrap();

        assert_eq!(default::hmac_verify(&hmac_bob, &sec_key_correct, &msg).unwrap(), true);
        assert!(default::hmac_verify(&hmac_bob, &sec_key_false, &msg).is_err());
    }

    #[test]
    fn hkdf_verify() {

        let salt = util::gen_rand_key(64).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let hkdf_dk = default::hkdf(&salt, data, info, 64).unwrap();

        assert_eq!(default::hkdf_verify(&hkdf_dk, &salt, data, info, 64).unwrap(), true);
    }

    #[test]
    fn hkdf_salt_too_short() {
        assert!(default::hkdf(&vec![0x61; 10], &vec![0x61; 10], &vec![0x61; 10], 20).is_err());
    }

    #[test]
    fn hkdf_salt_allowed_len() {
        default::hkdf(&vec![0x61; 67], &vec![0x61; 10], &vec![0x61; 10], 20).unwrap();
        default::hkdf(&vec![0x61; 89], &vec![0x61; 10], &vec![0x61; 10], 20).unwrap();
    }

    #[test]
    fn pbkdf2_verify() {

        let salt = util::gen_rand_key(64).unwrap();
        let password = util::gen_rand_key(64).unwrap();

        let pbkdf2_dk = default::pbkdf2(&password, &salt, 64).unwrap();

        assert_eq!(default::pbkdf2_verify(&pbkdf2_dk, &password, &salt, 64).unwrap(), true);
    }

    #[test]
    fn pbkdf2_salt_too_short() {
        assert!(default::pbkdf2("Secret password".as_bytes(), "Very weak salt".as_bytes(), 64).is_err());
    }

    #[test]
    fn pbkdf2_len_too_short() {
        assert!(default::pbkdf2(&vec![0x61; 67], &vec![0x61; 16], 10).is_err());
    }

    #[test]
    fn pbkdf2_len_good() {
        default::pbkdf2(&vec![0x61; 67], &vec![0x61; 16], 14).unwrap();
    }

    #[test]
    fn pbkdf2_salt_allowed_len() {
        default::pbkdf2(&vec![0x61; 10], &vec![0x61; 67], 64).unwrap();
        default::pbkdf2(&vec![0x61; 10], &vec![0x61; 64], 64).unwrap();
    }
}
