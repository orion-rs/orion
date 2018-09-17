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

use hazardous::constants::*;
use hazardous::cshake;
use hazardous::hkdf;
use hazardous::hmac;
use hazardous::pbkdf2;
use utilities::{errors::*, util};

/// HMAC-SHA512.
/// # Parameters:
/// - `secret_key`:  The authentication key
/// - `data`: Data to be authenticated
///
/// See [RFC](https://tools.ietf.org/html/rfc2104#section-2) for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the secret key is less than 64 bytes.
///
/// # Security:
/// The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this.
///
/// # Example:
/// ```
/// use orion::default;
/// use orion::utilities::util;
///
/// let mut key = [0u8; 64];
/// util::gen_rand_key(&mut key).unwrap();
/// let msg = "Some message.".as_bytes();
///
/// let hmac = default::hmac(&key, msg).unwrap();
/// ```
pub fn hmac(secret_key: &[u8], data: &[u8]) -> Result<[u8; 64], UnknownCryptoError> {
    if secret_key.len() < 64 {
        return Err(UnknownCryptoError);
    }

    let mut mac = hmac::init(secret_key);
    mac.update(data).unwrap();

    Ok(mac.finalize().unwrap())
}

/// Verify a HMAC-SHA512 MAC in constant time, with Double-HMAC Verification.
///
/// # About:
/// This uses `default::hmac()` to generate the MAC.
///
/// # Example:
///
/// ```
/// use orion::default;
/// use orion::utilities::util;
///
/// let mut key = [0u8; 64];
/// util::gen_rand_key(&mut key).unwrap();
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
    let mut mac = hmac::init(secret_key);
    mac.update(data).unwrap();

    let mut rand_key: HLenArray = [0u8; HLEN];
    util::gen_rand_key(&mut rand_key).unwrap();

    let mut nd_round_mac = hmac::init(secret_key);
    let mut nd_round_expected = hmac::init(secret_key);

    nd_round_mac.update(&mac.finalize().unwrap()).unwrap();
    nd_round_expected.update(expected_hmac).unwrap();

    hmac::verify(&expected_hmac, secret_key, data)
}

/// HKDF-HMAC-SHA512.
///
/// # About:
/// The output length is set to 32, which makes the derived key suitable for use with AES256.
///
/// # Parameters:
/// - `salt`:  Salt value
/// - `input`: Input keying material
/// - `info`: Optional context and application specific information (can be a zero-length string)
///
///
/// See [RFC](https://tools.ietf.org/html/rfc5869#section-2.2) for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the salt is less than 16 bytes.
///
/// # Security:
/// Salts should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this. The recommended length for a salt is 16 bytes as a minimum.
/// HKDF is not suitable for password storage.
///
/// # Example:
/// ```
/// use orion::default;
/// use orion::utilities::util;
///
/// let mut salt = [0u8; 32];
/// util::gen_rand_key(&mut salt).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info).unwrap();
/// ```
pub fn hkdf(salt: &[u8], input: &[u8], info: &[u8]) -> Result<[u8; 32], UnknownCryptoError> {
    if salt.len() < 16 {
        return Err(UnknownCryptoError);
    }

    let mut okm = [0u8; 32];

    hkdf::derive_key(salt, input, info, &mut okm).unwrap();

    Ok(okm)
}

/// Verify an HKDF-HMAC-SHA512 derived key in constant time.
///
/// # About:
/// The expected key must be of length 32. This uses `default::hkdf()`.
///
/// # Example:
///
/// ```
/// use orion::default;
/// use orion::utilities::util;
///
/// let mut salt = [0u8; 32];
/// util::gen_rand_key(&mut salt).unwrap();
/// let data = "Some data.".as_bytes();
/// let info = "Some info.".as_bytes();
///
/// let hkdf = default::hkdf(&salt, data, info).unwrap();
/// assert_eq!(default::hkdf_verify(&hkdf, &salt, data, info).unwrap(), true);
/// ```
pub fn hkdf_verify(
    expected_dk: &[u8],
    salt: &[u8],
    input: &[u8],
    info: &[u8],
) -> Result<bool, ValidationCryptoError> {
    if expected_dk.len() != 32 {
        return Err(ValidationCryptoError);
    }

    let mut okm = [0u8; 32];

    hkdf::verify(&expected_dk, salt, input, info, &mut okm)
}

/// PBKDF2-HMAC-SHA512. Suitable for password storage.
/// # About:
/// This is meant to be used for password storage.
/// - A salt of 32 bytes is automatically generated.
/// - The derived key length is set to 32.
/// - 512.000 iterations are used.
/// - An array of 64 bytes is returned.
///
/// The first 32 bytes of this array is the salt used to derive the key and the last 32 bytes
/// is the actual derived key. When using this function with `default::pbkdf2_verify()`
/// then the seperation of salt and password are automatically handeled.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the password is less than 14 bytes.
///
/// # Example:
///
/// ```
/// use orion::default;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = default::pbkdf2(password);
/// ```
pub fn pbkdf2(password: &[u8]) -> Result<[u8; 64], UnknownCryptoError> {
    if password.len() < 14 {
        return Err(UnknownCryptoError);
    }

    let mut dk = [0u8; 64];
    let mut salt = [0u8; 32];
    util::gen_rand_key(&mut salt).unwrap();

    pbkdf2::derive_key(password, &salt, 512_000, &mut dk[32..]).unwrap();

    dk[..32].copy_from_slice(&salt);

    Ok(dk)
}

/// Verify PBKDF2-HMAC-SHA512 derived key in constant time.
/// # About:
/// This function is meant to be used with the `default::pbkdf2()` function in orion's default API. It can be
/// used without it, but then the `expected_dk` passed to the function must be constructed just as in
/// `default::pbkdf2()`. See documention on `default::pbkdf2()` for details on this.
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of `expected_dk` is not 64 bytes.
/// # Example:
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

    let mut dk = [0u8; 32];
    let salt = &expected_dk[..32];

    pbkdf2::verify(&expected_dk[32..], password, salt, 512_000, &mut dk)
}

/// cSHAKE256.
/// # About:
/// - Output length is 64
///
/// # Parameters:
/// - `input`:  The main input string
/// - `custom`: Customization string
///
/// "The customization string is intended to avoid a collision between these two cSHAKE values—it
/// will be very difficult for an attacker to somehow force one computation (the email signature)
/// to yield the same result as the other computation (the key fingerprint) if different values
/// of S are used." See [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) for more information.
///
/// ### Note:
/// The cSHAKE implementation currently relies on the `tiny-keccak` crate. Currently this crate
/// will produce ***incorrect results on big-endian based systems***. See [issue here](https://github.com/debris/tiny-keccak/issues/15).
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `custom` is empty
/// - If the length of `custom` is greater than 65536
///
/// # Example:
/// ```
/// use orion::default;
///
/// let data = "Not so random data".as_bytes();
/// let custom = "Custom".as_bytes();
///
/// let hash = default::cshake(data, custom).unwrap();
/// ```
pub fn cshake(input: &[u8], custom: &[u8]) -> Result<[u8; 64], UnknownCryptoError> {
    if custom.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut hash = [0u8; 64];

    let mut cshake = cshake::init(custom, None).unwrap();
    cshake.update(input).unwrap();
    cshake.finalize(&mut hash).unwrap();

    Ok(hash)
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use default;
    use utilities::util;

    #[test]
    fn hmac_secret_key_too_short() {
        assert!(default::hmac(&[0x61; 10], &[0x61; 10]).is_err());
    }

    #[test]
    fn hmac_secret_key_allowed_len() {
        default::hmac(&[0x61; 64], &[0x61; 10]).unwrap();
        default::hmac(&[0x61; 78], &[0x61; 10]).unwrap();
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
        let mut salt = [0u8; 64];
        util::gen_rand_key(&mut salt).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let hkdf_dk = default::hkdf(&salt, data, info).unwrap();

        assert_eq!(
            default::hkdf_verify(&hkdf_dk, &salt, data, info).unwrap(),
            true
        );
    }

    #[test]
    fn hkdf_verify_err() {
        let mut salt = [0u8; 64];
        util::gen_rand_key(&mut salt).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        let mut hkdf_dk = default::hkdf(&salt, data, info).unwrap();
        hkdf_dk[..4].copy_from_slice(&[0u8; 4]);

        assert!(default::hkdf_verify(&hkdf_dk, &salt, data, info).is_err());
    }

    #[test]
    fn hkdf_verify_exptected_too_long() {
        let mut salt = [0u8; 64];
        util::gen_rand_key(&mut salt).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        assert!(default::hkdf_verify(&salt, &salt, data, info).is_err());
    }

    #[test]
    fn hkdf_verify_exptected_too_short() {
        let mut salt = [0u8; 16];
        util::gen_rand_key(&mut salt).unwrap();
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        assert!(default::hkdf_verify(&salt, &salt, data, info).is_err());
    }

    #[test]
    fn hkdf_salt_too_short() {
        assert!(default::hkdf(&[0x61; 10], &[0x61; 10], &[0x61; 10]).is_err());
    }

    #[test]
    fn hkdf_salt_allowed_len() {
        default::hkdf(&[0x61; 67], &[0x61; 10], &[0x61; 10]).unwrap();
        default::hkdf(&[0x61; 89], &[0x61; 10], &[0x61; 10]).unwrap();
    }

    #[test]
    fn pbkdf2_verify() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let pbkdf2_dk: [u8; 64] = default::pbkdf2(&password).unwrap();

        assert_eq!(default::pbkdf2_verify(&pbkdf2_dk, &password).unwrap(), true);
    }

    #[test]
    fn pbkdf2_verify_err() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = default::pbkdf2(&password).unwrap();
        pbkdf2_dk[..10].copy_from_slice(&[0x61; 10]);

        assert!(default::pbkdf2_verify(&pbkdf2_dk, &password).is_err());
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_long() {
        let mut password = [0u8; 32];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = [0u8; 65];
        pbkdf2_dk[..64].copy_from_slice(&default::pbkdf2(&password).unwrap());

        assert!(default::pbkdf2_verify(&pbkdf2_dk, &password).is_err());
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_short() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let pbkdf2_dk = default::pbkdf2(&password).unwrap();

        assert!(default::pbkdf2_verify(&pbkdf2_dk[..63], &password).is_err());
    }

    #[test]
    fn pbkdf2_password_too_short() {
        let mut password = [0u8; 13];
        util::gen_rand_key(&mut password).unwrap();

        assert!(default::pbkdf2(&password).is_err());
    }

    #[test]
    fn cshake_ok() {
        let mut data = [0u8; 64];
        util::gen_rand_key(&mut data).unwrap();

        let custom = "Some custom string".as_bytes();

        assert!(default::cshake(&data, custom).is_ok());
    }

    #[test]
    fn cshake_empty_custom_err() {
        let mut data = [0u8; 64];
        util::gen_rand_key(&mut data).unwrap();

        let custom = "".as_bytes();

        assert!(default::cshake(&data, custom).is_err());
    }
}
