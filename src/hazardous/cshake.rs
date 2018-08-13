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

use byte_tools::write_u64_be;
use core::mem;
use tiny_keccak::Keccak;
use utilities::errors::*;

/// cSHAKE as specified in the [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).
///

/// cSHAKE as specified in the [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).
///
/// # Parameters:
/// - `input`:  The main input string
/// - `name`: Function-name string
/// - `custom`: Customization string
/// - `dst_out`: Destination buffer for the digest. The length of the digest is implied by the length of `out`
///
///
/// "The customization string is intended to avoid a collision between these two cSHAKE values—it
/// will be very difficult for an attacker to somehow force one computation (the email signature)
/// to yield the same result as the other computation (the key fingerprint) if different values
/// of S are used." See [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) for more information.
///
/// ### Notes:
/// The cSHAKE implementation currently relies on the `tiny-keccak` crate. Currently this crate
/// will produce ***incorrect results on big-endian based systems***. See [issue here](https://github.com/debris/tiny-keccak/issues/15).
///
/// `name` is a special parameter that in most cases should be just set to a zero string:
/// "This is intended for use by NIST in defining SHA-3-derived functions, and should only be set
/// to values defined by NIST". See [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - Both `name` and `custom` are empty
/// - The specified length is zero
/// - The specified length is greater than 65536
/// - If the length of either `name` or `custom` is greater than 65536
///
/// The reason that `name` and `custom` cannot both be empty is because that would be equivalent to
/// a SHAKE call.
///
/// # Security:
/// cSHAKE128 has a security strength of 128 bits, whereas cSHAKE256 has a security strength of
/// 256 bits. The recommended output length for cSHAKE128 is 32 and 64 for cSHAKE256.
///
/// # Example:
/// ```
/// use orion::hazardous::cshake;
/// ```

pub struct CShake {
    hasher: Keccak,
}

impl CShake {
    fn setup(&mut self, custom: &[u8], name: &[u8]) {
        // Only append the left encoded rate, not the rate itself as with `name` and `custom`
        let (encoded, offset) = left_encode(136_u64);
        self.hasher.update(&encoded[(offset - 1)..]);

        // The below two calls are equivalent to encode_string() from the spec
        let (encoded, offset) = left_encode(name.len() as u64 * 8);
        self.hasher.update(&encoded[(offset - 1)..]);
        self.hasher.update(&name);

        let (encoded, offset) = left_encode(custom.len() as u64 * 8);
        self.hasher.update(&encoded[(offset - 1)..]);
        self.hasher.update(custom);

        // Pad with zeroes before calling pad() in finalize()
        self.hasher.fill_block();
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Return a cSHAKE hash.
    pub fn finalize(&mut self, dst_out: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if dst_out.len() < 1 || dst_out.len() > 65536 {
            return Err(UnknownCryptoError);
        }

        let mut hasher_new = Keccak::new(136, 0x04);
        mem::swap(&mut self.hasher, &mut hasher_new);

        hasher_new.finalize(dst_out);

        Ok(())
    }
}

pub fn init(custom: &[u8], name: Option<&[u8]>) -> Result<CShake, UnknownCryptoError> {
    // 136 is the rate
    let mut hash = CShake {
        hasher: Keccak::new(136, 0x04),
    };

    // "When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent to SHAKE as
    // defined in FIPS 202"
    let name_val = match name {
        Some(ref n_val) => *n_val,
        None => &[0u8; 0],
    };
    if (name_val.is_empty()) && (custom.is_empty()) {
        return Err(UnknownCryptoError);
    }
    if name_val.len() > 65536 || custom.len() > 65536 {
        return Err(UnknownCryptoError);
    }

    hash.setup(custom, name_val);

    Ok(hash)
}

/// The left_encode function as specified in the NIST SP 800-185.
fn left_encode(x: u64) -> ([u8; 9], usize) {
    let mut input = [0u8; 9];
    let mut offset: usize = 0;

    if x == 0 {
        offset = 8;
    } else {
        write_u64_be(&mut input[1..], x.to_le());
        for idx in &input {
            if *idx != 0 {
                break;
            }
            offset += 1;
        }
    }

    input[offset - 1] = (9 - offset) as u8;

    (input, offset)
}

#[cfg(test)]
mod test {

    use hazardous::cshake::*;

    #[test]
    fn test_left_encode() {
        let (test_1, offset_1) = left_encode(32);
        let (test_2, offset_2) = left_encode(255);
        let (test_3, offset_3) = left_encode(0);
        let (test_4, offset_4) = left_encode(64);
        let (test_5, offset_5) = left_encode(u64::max_value());

        assert_eq!(&test_1[(offset_1 - 1)..], &[1, 32]);
        assert_eq!(&test_2[(offset_2 - 1)..], &[1, 255]);
        assert_eq!(&test_3[(offset_3 - 1)..], &[1, 0]);
        assert_eq!(&test_4[(offset_4 - 1)..], &[1, 64]);
        assert_eq!(
            &test_5[(offset_5 - 1)..],
            &[8, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn err_on_empty_name_custom() {
        let custom = b"";
        let name = b"";

        assert!(init(custom, Some(name)).is_err());
    }

    #[test]
    fn empty_custom_ok() {
        let custom = b"";
        let name = b"Email signature";

        assert!(init(custom, Some(name)).is_ok());
    }

    #[test]
    fn empty_input_ok() {
        let custom = b"Custom String";
        let name = b"Email signature";

        assert!(init(custom, Some(name)).is_ok());
    }

    #[test]
    fn err_on_zero_length() {
        let input = b"\x00\x01\x02\x03";
        let custom = b"";
        let name = b"Email signature";
        let mut out = [0u8; 0];

        let mut hash = init(custom, Some(name)).unwrap();
        hash.update(input);

        assert!(hash.finalize(&mut out).is_err());
    }

    #[test]
    fn err_on_above_max_length() {
        let input = b"\x00\x01\x02\x03";
        let custom = b"";
        let name = b"Email signature";
        let mut out = [0u8; 65537];

        let mut hash = init(custom, Some(name)).unwrap();
        hash.update(input);

        assert!(hash.finalize(&mut out).is_err());
    }

    #[test]
    fn err_on_name_max_length() {
        let custom = b"";
        let name = [0u8; 65537];

        assert!(init(custom, Some(&name)).is_err());
    }

    #[test]
    fn err_on_n_c_max_length() {
        let custom = [0u8; 65537];
        let name = [0u8; 65537];

        assert!(init(&custom, Some(&name)).is_err());
    }

    #[test]
    fn err_on_custom_max_length() {
        let custom = [0u8; 65537];
        let name = [0u8; 0];

        assert!(init(&custom, Some(&name)).is_err());
        assert!(init(&custom, None).is_err());
    }

    #[test]
    fn non_8_div_len() {
        let input = b"\x00\x01\x02\x03";
        let custom = b"Email Signature";
        let mut out = [0u8; 17];

        let mut cshake = init(custom, None).unwrap();
        cshake.update(input);
        cshake.finalize(&mut out).unwrap();

        let expected = b"\xD0\x08\x82\x8E\x2B\x80\xAC\x9D\x22\x18\xFF\xEE\x1D\x07\x0C\x48\xB8\
                        \xE4\xC8\x7B\xFF\x32\xC9\x69\x9D\x5B\x68\x96\xEE\xE0\xED\xD1\x64\x02\
                        \x0E\x2B\xE0\x56\x08\x58\xD9\xC0\x0C\x03\x7E\x34\xA9\x69\x37\xC5\x61\
                        \xA7\x4C\x41\x2B\xB4\xC7\x46\x46\x95\x27\x28\x1C\x8C";

        assert_eq!(expected[..17].len(), out.len());
        assert_eq!(out, &expected[..17]);
    }

    #[test]
    fn result_ok() {
        let input = b"\x00\x01\x02\x03";
        let custom = b"Email Signature";
        let mut out = [0u8; 64];

        let mut cshake = init(custom, None).unwrap();
        cshake.update(input);
        cshake.finalize(&mut out).unwrap();

        let expected = b"\xD0\x08\x82\x8E\x2B\x80\xAC\x9D\x22\x18\xFF\xEE\x1D\x07\x0C\x48\xB8\
                        \xE4\xC8\x7B\xFF\x32\xC9\x69\x9D\x5B\x68\x96\xEE\xE0\xED\xD1\x64\x02\
                        \x0E\x2B\xE0\x56\x08\x58\xD9\xC0\x0C\x03\x7E\x34\xA9\x69\x37\xC5\x61\
                        \xA7\x4C\x41\x2B\xB4\xC7\x46\x46\x95\x27\x28\x1C\x8C";

        assert_eq!(out.as_ref(), expected.as_ref());
    }

    #[test]
    fn verify_err() {
        // `name` and `custom` values have been switched here compared to the previous one
        let input = b"\x00\x01\x02\x03";
        let custom = b"";
        let name = b"Email Signature";
        let mut out = [0u8; 64];

        let mut cshake = init(custom, Some(name)).unwrap();
        cshake.update(input);
        cshake.finalize(&mut out).unwrap();

        let expected = b"\xD0\x08\x82\x8E\x2B\x80\xAC\x9D\x22\x18\xFF\xEE\x1D\x07\x0C\x48\xB8\
                        \xE4\xC8\x7B\xFF\x32\xC9\x69\x9D\x5B\x68\x96\xEE\xE0\xED\xD1\x64\x02\
                        \x0E\x2B\xE0\x56\x08\x58\xD9\xC0\x0C\x03\x7E\x34\xA9\x69\x37\xC5\x61\
                        \xA7\x4C\x41\x2B\xB4\xC7\x46\x46\x95\x27\x28\x1C\x8C";

        assert_ne!(out.as_ref(), expected.as_ref());
    }
}
