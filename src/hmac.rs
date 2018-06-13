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





use std::borrow::Cow;
use clear_on_drop::clear::Clear;
use core::{util, errors::UnknownCryptoError};
use core::options::ShaVariantOption;


/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub struct Hmac {
    pub secret_key: Vec<u8>,
    pub message: Vec<u8>,
    pub sha2: ShaVariantOption,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        Clear::clear(&mut self.secret_key);
        Clear::clear(&mut self.message)
    }
}

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
///
/// # Usage examples:
/// ### Generating HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let key = gen_rand_key(16).unwrap();
/// let message = gen_rand_key(16).unwrap();
///
/// let hmac_sha256 = Hmac { secret_key: key, message: message, sha2: ShaVariantOption::SHA256 };
///
/// hmac_sha256.hmac_compute();
/// ```
/// ### Verifying HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::core::options::ShaVariantOption;
///
/// let key = "Some key.";
/// let msg = "Some message.";
///
/// let hmac_sha256 = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     message: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// let received_hmac = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     message: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// assert_eq!(hmac_sha256.hmac_compare(&received_hmac.hmac_compute()).unwrap(), true);
/// ```

impl Hmac {

    /// Return the inner and outer padding used for HMAC.
    pub fn pad_key(&self, secret_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Borrow so that if the key is exactly the needed length
        // no new key needs to be allocated before returning it
        let mut key = Cow::from(secret_key);

        if key.len() > self.sha2.blocksize() {
            key = self.sha2.hash(&key).into();
        }
        if key.len() < self.sha2.blocksize() {
            let mut resized_key = key.into_owned();
            resized_key.resize(self.sha2.blocksize(), 0x00);
            key = resized_key.into();
        }

        let make_padded_key = |byte: u8| {
            let mut pad = key.to_vec();
            for i in &mut pad { *i ^= byte };
            pad
        };

        let ipad = make_padded_key(0x36);
        let opad = make_padded_key(0x5C);

        (ipad, opad)
    }

    /// Returns an HMAC for a given key and message.
    pub fn hmac_compute(&self) -> Vec<u8> {

        let (mut ipad, mut opad) = self.pad_key(&self.secret_key);

        ipad.extend_from_slice(&self.message);
        opad.extend_from_slice(&self.sha2.hash(&ipad));

        self.sha2.hash(&opad)
    }

    /// Check HMAC validity by computing one from the current struct fields and comparing this
    /// to the passed HMAC. Comparison is done in constant time and with Double-HMAC Verification.
    pub fn hmac_compare(&self, received_hmac: &[u8]) -> Result<bool, UnknownCryptoError> {

        let own_hmac = self.hmac_compute();

        let rand_key = util::gen_rand_key(self.sha2.blocksize()).unwrap();

        let nd_round_own = Hmac {
            secret_key: rand_key.clone(),
            message: own_hmac,
            sha2: self.sha2
        };

        let nd_round_received = Hmac {
            secret_key: rand_key,
            message: received_hmac.to_vec(),
            sha2: self.sha2
        };

        util::compare_ct(
            &nd_round_own.hmac_compute(),
            &nd_round_received.hmac_compute()
        )
    }
}

/// HMAC used for PBKDF2 which takes both inner and outer padding as argument.
pub fn pbkdf2_hmac(mut ipad: Vec<u8>, mut opad: Vec<u8>, message: &[u8],
    hmac: ShaVariantOption) -> Vec<u8> {

    ipad.extend_from_slice(message);
    opad.extend_from_slice(&hmac.hash(&ipad));

    hmac.hash(&opad)
}


#[test]
// Test that hmac_compare() returns true if signatures match and false if not
fn hmac_compare() {

    let own_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        message: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };
    let recieved_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        message: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };
    let false_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        message: "what do ya want for something?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };

    assert_eq!(own_hmac.hmac_compare(&recieved_hmac.hmac_compute()).unwrap(), true);
    assert!(own_hmac.hmac_compare(&false_hmac.hmac_compute()).is_err());
}
