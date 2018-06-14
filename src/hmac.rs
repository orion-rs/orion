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
///
/// Fields `secret_key` and `data` are zeroed out on drop.
pub struct Hmac {
    pub secret_key: Vec<u8>,
    pub data: Vec<u8>,
    pub sha2: ShaVariantOption,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        Clear::clear(&mut self.secret_key);
        Clear::clear(&mut self.data)
    }
}

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
///
/// ## Note:
/// The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this.
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
/// let hmac_sha256 = Hmac { secret_key: key, data: message, sha2: ShaVariantOption::SHA256 };
///
/// hmac_sha256.finalize();
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
///     data: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// let received_hmac = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     data: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// assert_eq!(hmac_sha256.verify(&received_hmac.finalize()).unwrap(), true);
/// ```

impl Hmac {

    /// Pad the key and return inner and outer padding.
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

        // Output format: ipad, opad
        (make_padded_key(0x36), make_padded_key(0x5C))
    }

    /// Returns a HMAC for a given key and data.
    pub fn finalize(&self) -> Vec<u8> {

        let (mut ipad, mut opad) = self.pad_key(&self.secret_key);

        ipad.extend_from_slice(&self.data);
        opad.extend_from_slice(&self.sha2.hash(&ipad));

        let mac = self.sha2.hash(&opad);

        Clear::clear(&mut ipad);
        Clear::clear(&mut opad);

        mac
    }

    /// Check HMAC validity by computing one from the current struct fields and comparing this
    /// to the passed HMAC. Comparison is done in constant time and with Double-HMAC Verification.
    pub fn verify(&self, expected_hmac: &[u8]) -> Result<bool, UnknownCryptoError> {

        let own_hmac = self.finalize();

        let rand_key = util::gen_rand_key(self.sha2.blocksize()).unwrap();

        let nd_round_own = Hmac {
            secret_key: rand_key.clone(),
            data: own_hmac,
            sha2: self.sha2
        };

        let nd_round_received = Hmac {
            secret_key: rand_key,
            data: expected_hmac.to_vec(),
            sha2: self.sha2
        };

        util::compare_ct(
            &nd_round_own.finalize(),
            &nd_round_received.finalize()
        )
    }
}

/// HMAC used for PBKDF2.
pub fn pbkdf2_hmac(mut ipad: Vec<u8>, mut opad: Vec<u8>, data: &[u8],
    hmac: ShaVariantOption) -> Vec<u8> {

    let mut mac: Vec<u8> = Vec::new();
    mac.extend_from_slice(&opad);
    ipad.extend_from_slice(data);
    mac.extend_from_slice(&hmac.hash(&ipad));

    Clear::clear(&mut ipad);
    Clear::clear(&mut opad);

    hmac.hash(&mac)
}


#[test]
fn verify() {

    let own_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };
    let recieved_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };
    let false_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for something?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256
    };

    assert_eq!(own_hmac.verify(&recieved_hmac.finalize()).unwrap(), true);
    assert!(own_hmac.verify(&false_hmac.finalize()).is_err());
}
