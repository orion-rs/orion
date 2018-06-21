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

use core::options::ShaVariantOption;
use core::{errors::*, util};
use hazardous::hkdf::Hkdf;
use hazardous::hmac::Hmac;
use hazardous::pbkdf2::Pbkdf2;

/// HMAC-SHA512/256.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the secret key is less than 64 bytes.
///
/// ## Note:
/// The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this.  The recommended length for a secret key is the SHA functions digest
/// size in bytes.
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
        sha2: ShaVariantOption::SHA512Trunc256,
    };

    Ok(mac.finalize())
}

/// Verify an HMAC-SHA512/256 against a key and data in constant time, with Double-HMAC Verification.
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
pub fn hmac_verify(
    expected_hmac: &[u8],
    secret_key: &[u8],
    data: &[u8],
) -> Result<bool, ValidationCryptoError> {

    let mac = Hmac {
        secret_key: secret_key.to_vec(),
        data: data.to_vec(),
        sha2: ShaVariantOption::SHA512Trunc256,
    };

    mac.verify(&expected_hmac)
}

/// HKDF-HMAC-SHA512/256.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the salt is less than 16 bytes.
///
/// ## Note:
/// Salts should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this. The recommended length for a salt is 16 bytes as a minimum.
/// HKDF is not suitable for password storage.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let salt = util::gen_rand_key(32).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 32).unwrap();
/// ```
pub fn hkdf(
    salt: &[u8],
    input: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, UnknownCryptoError> {
    if salt.len() < 16 {
        return Err(UnknownCryptoError);
    }

    let hkdf = Hkdf {
        salt: salt.to_vec(),
        ikm: input.to_vec(),
        info: info.to_vec(),
        length: len,
        hmac: ShaVariantOption::SHA512Trunc256,
    };

    hkdf.derive_key()
}

/// Verify an HKDF-HMAC-SHA512/256 derived key in constant time. Both derived keys must
/// be of equal length.
/// # Usage example:
///
/// ```
/// use orion::default;
/// use orion::core::util;
///
/// let salt = util::gen_rand_key(32).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info, 32).unwrap();
/// assert_eq!(default::hkdf_verify(&hkdf, &salt, data, info, 32).unwrap(), true);
/// ```
pub fn hkdf_verify(
    expected_dk: &[u8],
    salt: &[u8],
    input: &[u8],
    info: &[u8],
    len: usize,
) -> Result<bool, ValidationCryptoError> {

    let hkdf = Hkdf {
        salt: salt.to_vec(),
        ikm: input.to_vec(),
        info: info.to_vec(),
        length: len,
        hmac: ShaVariantOption::SHA512Trunc256,
    };

    hkdf.verify(&expected_dk)
}

/// PBKDF2-HMAC-SHA512/256. Suitable for password storage.
/// # About:
/// This is meant to be used for password storage.
/// - A salt of 32 bytes is automatically generated.
/// - The derived key length is set to 32.
/// - 512.000 iterations are used.
/// - The salt is prepended to the password before being passed to the PBKDF2 function.
/// - A byte vector of 64 bytes is returned.
///
/// The first 32 bytes of this vector is the salt used to derive the key and the last 32 bytes
/// is the actual derived key. When using this function with `default::pbkdf2_verify`
/// then the seperation of salt and password are automatically handeled.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the password is less than 14 bytes.
///
/// # Usage example:
///
/// ```
/// use orion::default;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = default::pbkdf2(password);
/// ```
pub fn pbkdf2(password: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
    if password.len() < 14 {
        return Err(UnknownCryptoError);
    }

    let salt: Vec<u8> = util::gen_rand_key(32).unwrap();
    // Prepend salt to password before deriving key
    let mut pass_extented: Vec<u8> = Vec::new();
    pass_extented.extend_from_slice(&salt);
    pass_extented.extend_from_slice(password);
    // Prepend salt to derived key
    let mut dk = Vec::new();
    dk.extend_from_slice(&salt);

    let pbkdf2_dk = Pbkdf2 {
        password: pass_extented,
        salt,
        iterations: 512_000,
        dklen: 32,
        hmac: ShaVariantOption::SHA512Trunc256,
    };

    // Output format: First 32 bytes are the salt, last 32 bytes are the derived key
    dk.extend_from_slice(&pbkdf2_dk.derive_key().unwrap());

    if dk.len() != 64 {
        return Err(UnknownCryptoError);
    }

    Ok(dk)
}

/// Verify PBKDF2-HMAC-SHA512/256 derived key in constant time.
/// # About:
/// This function is meant to be used with the `default::pbkdf2` function in orion's default API. It can be
/// used without it, but then the `expected_dk` passed to the function must be constructed just as in
/// `default::pbkdf2`. See documention on `default::pbkdf2` for details on this.
/// # Exceptions:
/// An exception will be thrown if:
/// - The expected derived key length is not 64 bytes.
/// # Usage example:
///
/// ```
/// use orion::default;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = default::pbkdf2(password).unwrap();
/// assert_eq!(default::pbkdf2_verify(&derived_password, password).unwrap(), true);
/// ```
pub fn pbkdf2_verify(expected_dk: &[u8], password: &[u8]) -> Result<bool, ValidationCryptoError> {
    if expected_dk.len() != 64 {
        return Err(ValidationCryptoError);
    }

    let salt: Vec<u8> = expected_dk[..32].to_vec();
    let mut pass_extented: Vec<u8> = Vec::new();
    pass_extented.extend_from_slice(&salt);
    pass_extented.extend_from_slice(password);

    // Prepend salt to derived key
    let mut dk = Vec::new();
    dk.extend_from_slice(&salt);

    let pbkdf2_dk = Pbkdf2 {
        password: pass_extented,
        salt,
        iterations: 512_000,
        dklen: 32,
        hmac: ShaVariantOption::SHA512Trunc256,
    };

    dk.extend_from_slice(&pbkdf2_dk.derive_key().unwrap());

    if util::compare_ct(&dk, expected_dk).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use core::util;
    use default;

    #[test]
    fn hmac_secret_key_too_short() {
        assert!(default::hmac(&vec![0x61; 10], &vec![0x61; 10]).is_err());
    }

    #[test]
    fn hmac_secret_key_allowed_len() {
        default::hmac(&vec![0x61; 64], &vec![0x61; 10]).unwrap();
        default::hmac(&vec![0x61; 78], &vec![0x61; 10]).unwrap();
    }

    #[test]
    fn hmac_verify() {
        let sec_key_correct = decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaa",
        ).unwrap();
        // Change compared to the above: Two additional a's at the end
        let sec_key_false = decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaa",
        ).unwrap();
        let msg = "what do ya want for nothing?".as_bytes().to_vec();

        let hmac_bob = default::hmac(&sec_key_correct, &msg).unwrap();

        assert_eq!(
            default::hmac_verify(&hmac_bob, &sec_key_correct, &msg).unwrap(),
            true
        );
        assert!(default::hmac_verify(&hmac_bob, &sec_key_false, &msg).is_err());
    }

    #[test]
    fn hkdf_verify() {
        let salt = util::gen_rand_key(64).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let hkdf_dk = default::hkdf(&salt, data, info, 64).unwrap();

        assert_eq!(
            default::hkdf_verify(&hkdf_dk, &salt, data, info, 64).unwrap(),
            true
        );
    }

    #[test]
    fn hkdf_verify_err() {
        let salt = util::gen_rand_key(64).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let mut hkdf_dk = default::hkdf(&salt, data, info, 64).unwrap();
        hkdf_dk.extend_from_slice(&[0u8; 4]);

        assert!(default::hkdf_verify(&hkdf_dk, &salt, data, info, 64).is_err());
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
        let password = util::gen_rand_key(64).unwrap();

        let pbkdf2_dk = default::pbkdf2(&password).unwrap();

        assert_eq!(default::pbkdf2_verify(&pbkdf2_dk, &password).unwrap(), true);
    }

    #[test]
    fn pbkdf2_verify_err() {
        let password = util::gen_rand_key(64).unwrap();

        let mut pbkdf2_dk = default::pbkdf2(&password).unwrap();
        pbkdf2_dk.extend_from_slice(&[0u8; 4]);

        assert!(default::pbkdf2_verify(&pbkdf2_dk, &password).is_err());
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_long() {
        let password = util::gen_rand_key(32).unwrap();

        let mut pbkdf2_dk = default::pbkdf2(&password).unwrap();
        pbkdf2_dk.extend_from_slice(&[0u8; 1]);

        assert!(default::pbkdf2_verify(&pbkdf2_dk, &password).is_err());
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_short() {
        let password = util::gen_rand_key(64).unwrap();

        let pbkdf2_dk = default::pbkdf2(&password).unwrap();

        assert!(default::pbkdf2_verify(&pbkdf2_dk[..63], &password).is_err());
    }

    #[test]
    fn pbkdf2_password_too_short() {
        let password = util::gen_rand_key(13).unwrap();

        assert!(default::pbkdf2(&password).is_err());
    }
}
