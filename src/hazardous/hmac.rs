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

use clear_on_drop::clear::Clear;
use core::options::ShaVariantOption;
use core::{errors::*, util};

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
/// # Parameters:
/// - `secret_key`:  The authentication key
/// - `data`: Data to be authenticated
/// - `sha2`: Cryptographic hash function
///
/// See [RFC](https://tools.ietf.org/html/rfc2104#section-2) for more information.
///
/// # Security:
/// The secret key should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this.  The recommended length for a secret key is the SHA functions digest
/// size in bytes.
/// # Example:
/// ### Generating HMAC:
/// ```
/// use orion::hazardous::hmac::Hmac;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let key = gen_rand_key(32).unwrap();
/// let message = gen_rand_key(32).unwrap();
///
/// let hmac = Hmac {
///     secret_key: key,
///     data: message,
///     sha2: ShaVariantOption::SHA256
/// };
///
/// hmac.finalize();
/// ```
/// ### Verifying HMAC:
/// ```
/// use orion::hazardous::hmac::Hmac;
/// use orion::core::options::ShaVariantOption;
///
/// let key = "Some key.";
/// let msg = "Some message.";
///
/// let hmac = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     data: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// let received_hmac = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     data: msg.as_bytes().to_vec(),
///     sha2: ShaVariantOption::SHA256
/// };
/// assert_eq!(hmac.verify(&received_hmac.finalize()).unwrap(), true);
/// ```

impl Hmac {
    /// Pad the key and return inner and outer padding.
    pub fn pad_key(&self, secret_key: &[u8]) -> (Vec<u8>, Vec<u8>) {

        let mut inner_pad = vec![0x36; self.sha2.blocksize()];
        let mut outer_pad = vec![0x5C; self.sha2.blocksize()];

        if secret_key.len() > self.sha2.blocksize() {
            let key = self.sha2.hash(secret_key);

            for index in 0..self.sha2.output_size() {
                inner_pad[index] ^= key[index];
                outer_pad[index] ^= key[index];
            }
        } else {
            for index in 0..secret_key.len() {
                inner_pad[index] ^= secret_key[index];
                outer_pad[index] ^= secret_key[index];
            }
        }

        (inner_pad, outer_pad)
    }

    /// Returns an HMAC for a given key and data.
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
    pub fn verify(&self, expected_hmac: &[u8]) -> Result<bool, ValidationCryptoError> {
        let own_hmac = self.finalize();

        let rand_key = util::gen_rand_key(self.sha2.blocksize()).unwrap();

        let nd_round_own = Hmac {
            secret_key: rand_key.clone(),
            data: own_hmac,
            sha2: self.sha2,
        };

        let nd_round_received = Hmac {
            secret_key: rand_key,
            data: expected_hmac.to_vec(),
            sha2: self.sha2,
        };

        if util::compare_ct(&nd_round_own.finalize(), &nd_round_received.finalize()).is_err() {
            Err(ValidationCryptoError)
        } else {
            Ok(true)
        }
    }
}

/// HMAC used for PBKDF2.
pub fn pbkdf2_hmac(
    ipad: &[u8],
    opad: &[u8],
    data: &[u8],
    hmac: ShaVariantOption,
) -> Vec<u8> {

    let mut ires = Vec::new();
    ires.extend_from_slice(&ipad);
    ires.extend_from_slice(&data);

    let mut mac = Vec::new();
    mac.extend_from_slice(&opad);
    mac.extend_from_slice(&hmac.hash(&ires));

    hmac.hash(&mac)
}

#[test]
fn finalize_and_veriy_true() {
    let own_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };
    let recieved_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };

    assert_eq!(own_hmac.verify(&recieved_hmac.finalize()).unwrap(), true);
}

#[test]
fn veriy_false_wrong_secret_key() {
    let own_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };
    let false_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for something?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };

    assert!(own_hmac.verify(&false_hmac.finalize()).is_err());
}

#[test]
fn veriy_false_wrong_data() {
    let own_hmac = Hmac {
        secret_key: "Jefe".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };
    let false_hmac = Hmac {
        secret_key: "Jose".as_bytes().to_vec(),
        data: "what do ya want for nothing?".as_bytes().to_vec(),
        sha2: ShaVariantOption::SHA256,
    };

    assert!(own_hmac.verify(&false_hmac.finalize()).is_err());
}
