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

use core::mem;
use hazardous::constants::{BlocksizeArray, HLenArray, BLOCKSIZE, HLEN};
use sha2::{Digest, Sha512};
use utilities::{errors::*, util};

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub struct Hmac {
    ipad: BlocksizeArray,
    opad: BlocksizeArray,
    hasher: Sha512,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        util::memzero(&mut self.ipad);
        util::memzero(&mut self.opad);
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
    #[inline(always)]
    /// Pad `key` with `ipad` and `opad`.
    fn pad_key_io(&mut self, key: &[u8]) {
        if key.len() > BLOCKSIZE {

            self.ipad[..HLEN].copy_from_slice(&Sha512::digest(&key));

            for (idx, itm) in self.ipad.iter_mut().take(64).enumerate() {
                *itm ^= 0x36;
                self.opad[idx] = *itm ^ 0x6A;

            }
        } else {
            for (idx, itm) in key.iter().enumerate() {
                self.ipad[idx] ^= itm;
                self.opad[idx] ^= itm;
            }
        }

        self.hasher.input(&self.ipad);
    }

    /// Reset to `init()` state.
    pub fn reset(&mut self) {
        self.hasher.input(&self.ipad);
    }

    /// This can be called multiple times.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.input(message);
    }

    #[inline(always)]
    /// Return MAC.
    pub fn finalize(&mut self) -> HLenArray {
        let mut hash_ires = Sha512::default();
        mem::swap(&mut self.hasher, &mut hash_ires);

        let mut hash_ores = Sha512::default();
        hash_ores.input(&self.opad);
        hash_ores.input(&hash_ires.result());

        let mut mac: HLenArray = [0u8; HLEN];
        mac.copy_from_slice(&hash_ores.result());
        mac
    }

    #[inline(always)]
    /// Retrieve MAC and copy to `dst`.
    pub fn finalize_with_dst(&mut self, dst: &mut [u8]) {
        let mut hash_ires = Sha512::default();
        mem::swap(&mut self.hasher, &mut hash_ires);

        let mut hash_ores = Sha512::default();
        let dst_len = dst.len();

        hash_ores.input(&self.opad);
        hash_ores.input(&hash_ires.result());

        dst.copy_from_slice(&hash_ores.result()[..dst_len]);
    }
    /// Wipe `ipad` and `opad` form state.
    pub fn wipe(&mut self) {
        util::memzero(&mut self.ipad);
        util::memzero(&mut self.opad);
    }
}

/// Check HMAC validity by computing one from the current struct fields and comparing this
/// to the passed HMAC. Comparison is done in constant time and with Double-HMAC Verification.
pub fn verify(
    expected: &[u8],
    secret_key: &[u8],
    message: &[u8],
) -> Result<bool, ValidationCryptoError> {
    let mut mac = init(secret_key);
    mac.update(message);

    let mut rand_key: HLenArray = [0u8; HLEN];
    util::gen_rand_key(&mut rand_key).unwrap();

    let mut nd_round_mac = init(secret_key);
    let mut nd_round_expected = init(secret_key);

    nd_round_mac.update(&mac.finalize());
    nd_round_expected.update(expected);

    if util::compare_ct(&nd_round_mac.finalize(), &nd_round_expected.finalize()).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}

#[inline(always)]
/// Initialize Hmac struct with a given key.
pub fn init(secret_key: &[u8]) -> Hmac {
    let mut mac = Hmac {
        ipad: [0x36; BLOCKSIZE],
        opad: [0x5C; BLOCKSIZE],
        hasher: Sha512::default(),
    };

    mac.pad_key_io(secret_key);
    mac
}

#[test]
fn finalize_and_veriy_true() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data);

    assert_eq!(verify(&mac.finalize(), secret_key, data).unwrap(), true);
}

#[test]
fn veriy_false_wrong_data() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data);

    assert_eq!(
        verify(
            &mac.finalize(),
            secret_key,
            "what do ya want for something?".as_bytes()
        ).unwrap(),
        true
    );
}

#[test]
fn veriy_false_wrong_secret_key() {
    let secret_key = "Jefe".as_bytes();
    let data = "what do ya want for nothing?".as_bytes();

    let mut mac = init(secret_key);
    mac.update(data);

    assert_eq!(
        verify(&mac.finalize(), "Jose".as_bytes(), data).unwrap(),
        true
    );
}
