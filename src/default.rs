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

use errors::*;
use hazardous::aead;
use hazardous::aead::xchacha20poly1305::Nonce;
pub use hazardous::aead::xchacha20poly1305::SecretKey as EncryptionKey;
use hazardous::constants::*;
use hazardous::kdf::hkdf;
use hazardous::kdf::hkdf::Salt;
use hazardous::kdf::pbkdf2;
use hazardous::mac::hmac;
use hazardous::mac::hmac::Mac;
pub use hazardous::mac::hmac::SecretKey as HmacKey;
use hazardous::xof::cshake;
use util;

#[must_use]
/// HMAC-SHA512.
/// # Parameters:
/// - `secret_key`:  The authentication key
/// - `data`: Data to be authenticated
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the secret key is less than 64 bytes
///
/// # Security:
/// The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this.
///
/// # Example:
/// ```
/// use orion::default;
///
/// let key = default::HmacKey::generate();
/// let msg = "Some message.".as_bytes();
///
/// let hmac = default::hmac(&key, msg);
/// ```
pub fn hmac(secret_key: &HmacKey, data: &[u8]) -> Mac {
    let mut mac = hmac::init(secret_key);
    mac.update(data).unwrap();

    mac.finalize().unwrap()
}

#[must_use]
/// Verify a HMAC-SHA512 MAC in constant time, with Double-HMAC Verification.
///
/// # Parameters:
/// - `expected_hmac`: The expected HMAC
/// - `secret_key`: The authentication key
/// - `data`: Data to be authenticated
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The calculated HMAC does not match the expected
/// - The `OsRng` fails to initialize or read from its source
///
/// # Example:
///
/// ```
/// use orion::default;
/// use orion::util;
///
/// let key = default::HmacKey::generate();
/// let msg = "Some message.".as_bytes();
///
/// let expected_hmac = default::hmac(&key, msg);
/// assert!(default::hmac_verify(&expected_hmac, &key, &msg).unwrap());
/// ```
pub fn hmac_verify(
    expected_hmac: &Mac,
    secret_key: &HmacKey,
    data: &[u8],
) -> Result<bool, ValidationCryptoError> {
    let mut mac = hmac::init(secret_key);
    mac.update(data).unwrap();

    let rand_key = hmac::SecretKey::generate();
    let mut nd_round_expected = hmac::init(&rand_key);

    nd_round_expected
        .update(&expected_hmac.unsafe_as_bytes())
        .unwrap();

    hmac::verify(
        &nd_round_expected.finalize().unwrap(),
        &rand_key,
        &mac.finalize().unwrap().unsafe_as_bytes(),
    )
}

#[must_use]
/// Derive multiple keys from a single key HKDF-HMAC-SHA512.
///
/// # About:
/// - A salt of `64` bytes is automatically generated
/// - Returns both the salt used and the derived key as: `(salt, okm)`
///
/// # Parameters:
/// - `ikm`: Input keying material
/// - `info`: Optional context and application specific information
/// - `length`: The desired length of the derived key
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `length` is greater than `16320`
/// - The `OsRng` fails to initialize or read from its source
///
/// # Security:
/// HKDF is not suitable for password storage.
///
/// # Example:
/// ```
/// use orion::default;
///
/// let secret_key = "Secret key that needs strethcing".as_bytes();
///
/// let info = "Session key".as_bytes();
///
/// let (salt, derived_key) = default::hkdf(secret_key, Some(info), 32).unwrap();
///
/// // `derived_key` could now be used as encryption key with `seal`/`open`
/// ```
pub fn hkdf(ikm: &[u8], info: Option<&[u8]>, length: usize) -> Result<([u8; 64], Vec<u8>), UnknownCryptoError> {
    if length > 16320 {
        return Err(UnknownCryptoError);
    }

    let mut okm = vec![0u8; length];
    let mut salt = [0u8; 64];
    util::gen_rand_key(&mut salt).unwrap();

    let optional_info = if info.is_some() {
        info.unwrap()
    } else {
        &[0u8; 0]
    };

    hkdf::derive_key(&Salt::from_slice(&salt), ikm, &optional_info, &mut okm).unwrap();

    Ok((salt, okm))
}

#[must_use]
/// Hash a password using PBKDF2-HMAC-SHA512.
/// # About:
/// This is meant to be used for password storage.
/// - A salt of 32 bytes is automatically generated.
/// - The derived key length is set to 32.
/// - 512.000 iterations are used.
/// - An array of 64 bytes is returned.
///
/// The first 32 bytes of this array is the salt used to derive the key and the last 32 bytes
/// is the actual derived key. When using this function with `default::password_hash_verify()`,
/// then the seperation of the salt and the derived key are automatically handeled.
///
/// # Parameters:
/// - `password` : The password to be hashed
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of the password is less than 14 bytes
/// - The `OsRng` fails to initialize or read from its source
///
/// # Example:
///
/// ```
/// use orion::default;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = default::password_hash(password);
/// ```
pub fn password_hash(password: &[u8]) -> Result<[u8; 64], UnknownCryptoError> {
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

#[must_use]
/// Verify a hashed password using PBKDF2-HMAC-SHA512.
/// # About:
/// This function is meant to be used with the `default::password_hash()` function in orion's default API. It can be
/// used without it, but then the `expected_dk` passed to the function must be constructed just as in
/// `default::password_hash()`. See documention on `default::password_hash()` for details on this.
///
/// # Parameters:
/// - `expected_dk`: The expected password hash
/// - `password` : The password to be hashed
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The length of `expected_dk` is not 64 bytes
/// - The password hash does not match the expected
///
/// # Example:
///
/// ```
/// use orion::default;
///
/// let password = "Secret password".as_bytes();
///
/// let derived_password = default::password_hash(password).unwrap();
/// assert!(default::password_hash_verify(&derived_password, password).unwrap());
/// ```
pub fn password_hash_verify(expected_dk: &[u8], password: &[u8]) -> Result<bool, ValidationCryptoError> {
    if expected_dk.len() != 64 {
        return Err(ValidationCryptoError);
    }

    let mut dk = [0u8; 32];

    pbkdf2::verify(
        &expected_dk[32..],
        password,
        &expected_dk[..32],
        512_000,
        &mut dk,
    )
}

#[must_use]
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

#[must_use]
/// Authenticated encryption using XChaCha20Poly1305.
/// # About:
/// - The nonce is automatically generated
/// - Returns a vector where the first 24 bytes are the nonce and the rest is the authenticated
/// ciphertext with the last 16 bytes being the corresponding Poly1305 tag
/// - Uses XChaCha20Poly1305 with no `ad`
///
/// # Parameters:
/// - `plaintext`:  The data to be encrypted
/// - `secret_key`: The secret key used to encrypt the `plaintext`
///
/// # Security:
/// It is critical for security that a given nonce is not re-used with a given key. Should this happen,
/// the security of all data that has been encrypted with that given key is compromised.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `secret_key` is not 32 bytes
/// - `plaintext` is empty
/// - `plaintext` is longer than (2^32)-2
/// - The `OsRng` fails to initialize or read from its source
///
/// # Example:
/// ```
/// use orion::default;
///
/// let secret_key = default::EncryptionKey::generate();
///
/// let encrypted_data = default::seal(&secret_key, "Secret message".as_bytes()).unwrap();
/// ```
pub fn seal(secret_key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let nonce = Nonce::generate();

    let mut dst_out = vec![0u8; plaintext.len() + (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE)];
    dst_out[..XCHACHA_NONCESIZE].copy_from_slice(&nonce.as_bytes());

    aead::xchacha20poly1305::seal(
        secret_key,
        &nonce,
        plaintext,
        &[0u8; 0],
        &mut dst_out[XCHACHA_NONCESIZE..],
    ).unwrap();

    Ok(dst_out)
}

#[must_use]
/// Authenticated decryption using XChaCha20Poly1305.
/// # About:
/// - The ciphertext must be of the same format as the one returned by `default::encrypt()`
///
/// # Parameters:
/// - `ciphertext`:  The data to be decrypted with the first 24 bytes being the nonce and the last
/// 16 bytes being the corresponding Poly1305 authentication tag
/// - `secret_key`: The secret key used to decrypt the `ciphertext`
///
/// # Security:
/// It is critical for security that a given nonce is not re-used with a given key. Should this happen,
/// the security of all data that has been encrypted with that given key is compromised.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `secret_key` is not 32 bytes
/// - `ciphertext` is less than 41 bytes
/// - `ciphertext` is longer than (2^32)-2
/// - The received tag does not match the calculated tag
///
/// # Example:
/// ```
/// use orion::default;
///
/// let secret_key = default::EncryptionKey::generate();
///
/// let ciphertext = default::seal(&secret_key, "Secret message".as_bytes()).unwrap();
///
/// let decrypted_data = default::open(&secret_key, &ciphertext).unwrap();
/// ```
pub fn open(secret_key: &EncryptionKey, ciphertext: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
    // `+ 1` to avoid empty ciphertexts
    if ciphertext.len() < (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE + 1) {
        return Err(UnknownCryptoError);
    }

    let mut dst_out = vec![0u8; ciphertext.len() - (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE)];

    aead::xchacha20poly1305::open(
        secret_key,
        &Nonce::from_slice(&ciphertext[..XCHACHA_NONCESIZE]).unwrap(),
        &ciphertext[XCHACHA_NONCESIZE..],
        &[0u8; 0],
        &mut dst_out,
    ).unwrap();

    Ok(dst_out)
}

#[cfg(test)]
mod test {

    extern crate hex;
    use default;
    use default::EncryptionKey;
    use util;

    #[test]
    fn hmac_verify() {
        let sec_key_correct = default::HmacKey::generate();
        let sec_key_false = default::HmacKey::generate();
        let msg = "what do ya want for nothing?".as_bytes().to_vec();

        let hmac_bob = default::hmac(&sec_key_correct, &msg);

        assert_eq!(
            default::hmac_verify(&hmac_bob, &sec_key_correct, &msg).unwrap(),
            true
        );
        assert!(default::hmac_verify(&hmac_bob, &sec_key_false, &msg).is_err());
    }

    #[test]
    fn hkdf_ok() {
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        assert!(default::hkdf(data, Some(info), 32).is_ok());
        assert!(default::hkdf(data, None, 32).is_ok());
    }

    #[test]
    fn hkdf_okm_length() {
        let data = "Some data.".as_bytes();
        let info = "Some info.".as_bytes();

        assert!(default::hkdf(data, Some(info), 16321).is_err());
        assert!(default::hkdf(data, Some(info), 16320).is_ok());

    }

    #[test]
    fn pbkdf2_verify() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let pbkdf2_dk: [u8; 64] = default::password_hash(&password).unwrap();

        assert_eq!(default::password_hash_verify(&pbkdf2_dk, &password).unwrap(), true);
    }

    #[test]
    #[should_panic]
    fn pbkdf2_verify_err_modified_salt() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = default::password_hash(&password).unwrap();
        pbkdf2_dk[..10].copy_from_slice(&[0x61; 10]);

        default::password_hash_verify(&pbkdf2_dk, &password).unwrap();
    }

    #[test]
    #[should_panic]
    fn pbkdf2_verify_err_modified_password() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = default::password_hash(&password).unwrap();
        pbkdf2_dk[70..80].copy_from_slice(&[0x61; 10]);

        default::password_hash_verify(&pbkdf2_dk, &password).unwrap();
    }

    #[test]
    #[should_panic]
    fn pbkdf2_verify_err_modified_salt_and_password() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = default::password_hash(&password).unwrap();
        pbkdf2_dk[63..73].copy_from_slice(&[0x61; 10]);

        default::password_hash_verify(&pbkdf2_dk, &password).unwrap();
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_long() {
        let mut password = [0u8; 32];
        util::gen_rand_key(&mut password).unwrap();

        let mut pbkdf2_dk = [0u8; 65];
        pbkdf2_dk[..64].copy_from_slice(&default::password_hash(&password).unwrap());

        assert!(default::password_hash_verify(&pbkdf2_dk, &password).is_err());
    }

    #[test]
    fn pbkdf2_verify_expected_dk_too_short() {
        let mut password = [0u8; 64];
        util::gen_rand_key(&mut password).unwrap();

        let pbkdf2_dk = default::password_hash(&password).unwrap();

        assert!(default::password_hash_verify(&pbkdf2_dk[..63], &password).is_err());
    }

    #[test]
    fn pbkdf2_password_too_short() {
        let mut password = [0u8; 13];
        util::gen_rand_key(&mut password).unwrap();

        assert!(default::password_hash(&password).is_err());
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

    #[test]
    fn auth_enc_encryption_decryption() {
        let key = EncryptionKey::generate();
        let plaintext = "Secret message".as_bytes().to_vec();

        let dst_ciphertext = default::seal(&key, &plaintext).unwrap();
        assert!(dst_ciphertext.len() == plaintext.len() + (24 + 16));
        let dst_plaintext = default::open(&key, &dst_ciphertext).unwrap();
        assert!(dst_plaintext.len() == plaintext.len());
        assert_eq!(plaintext, dst_plaintext);
    }

    #[test]
    #[should_panic]
    fn auth_enc_plaintext_empty_err() {
        let key = EncryptionKey::generate();
        let plaintext = "".as_bytes().to_vec();

        default::seal(&key, &plaintext).unwrap();
    }

    #[test]
    #[should_panic]
    fn auth_enc_ciphertext_less_than_13_err() {
        let key = EncryptionKey::generate();
        let ciphertext = [0u8; 12];

        default::open(&key, &ciphertext).unwrap();
    }
}
