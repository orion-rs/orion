// MIT License

// Copyright (c) 2026 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::{
    errors::UnknownCryptoError,
    generics::sealed::{Data, TryFromBytes},
    hazardous::kdf::parse_decimal_value,
    hazardous::kdf::scrypt::CostParams,
};
use core::fmt::Debug;
use ct_codecs::{Base64NoPadding, Encoder};
use subtle::ConstantTimeEq;

#[cfg(feature = "safe_api")]
/// Scrypt P-H-C string format.
pub struct ScryptPhc {
    pub(crate) variant: String,
    // r
    pub(crate) blocksize: u32,
    // logN
    pub(crate) logn: u32,
    // p
    pub(crate) parallelism: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) hash: Vec<u8>,
    pub(crate) phc_string: String,
}
impl crate::generics::sealed::Sealed for ScryptPhc {}

impl PartialEq for ScryptPhc {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant
            && self.blocksize == other.blocksize
            && self.logn == other.logn
            && self.parallelism == other.parallelism
            && self.salt == other.salt
            && bool::from(self.hash.ct_eq(&other.hash))
            && bool::from(
                self.phc_string
                    .as_bytes()
                    .ct_eq(other.phc_string.as_bytes()),
            )
    }
}

impl Debug for ScryptPhc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScryptPhc")
            .field("variant", &self.variant)
            .field("blocksize", &self.blocksize)
            .field("logn", &self.logn)
            .field("parallelism", &self.parallelism)
            .field("salt", &self.salt)
            .field("hash", &"{{***OMITTED***}}")
            .field("phc_string", &"{{***OMITTED***}}")
            .finish()
    }
}

impl ScryptPhc {
    pub(crate) const VALID_VARIANT: &'static str = "scrypt";

    pub(crate) fn encode_to_phc(&mut self) -> Result<(), UnknownCryptoError> {
        self.phc_string = format!(
            "${}$ln={},r={},p={}${}${}",
            self.variant,
            self.logn,
            self.blocksize,
            self.parallelism,
            Base64NoPadding::encode_to_string(&self.salt)?,
            Base64NoPadding::encode_to_string(&self.hash)?,
        );

        Ok(())
    }
}

impl TryFrom<&str> for ScryptPhc {
    type Error = UnknownCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use ct_codecs::{Base64NoPadding, Decoder};

        if value.contains(' ') {
            return Err(UnknownCryptoError);
        }

        let parts_split = value.split('$').collect::<Vec<&str>>();
        if parts_split.len() != 5 {
            return Err(UnknownCryptoError);
        }
        let mut parts = parts_split.into_iter();
        if parts.next() != Some("") {
            return Err(UnknownCryptoError);
        }
        if parts.next() != Some(Self::VALID_VARIANT) {
            return Err(UnknownCryptoError);
        }

        // Splits as ["ln", "X", "r", "Y", "p", "Z"] where ln=X, r=Y and p=Z.
        let param_parts_split = parts
            .next()
            .unwrap()
            .split(['=', ','])
            .collect::<Vec<&str>>();
        if param_parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut param_parts = param_parts_split.into_iter();

        if param_parts.next() != Some("ln") {
            return Err(UnknownCryptoError);
        }
        let logn = parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("r") {
            return Err(UnknownCryptoError);
        }
        let blocksize = parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("p") {
            return Err(UnknownCryptoError);
        }
        let parallelism = parse_decimal_value(param_parts.next().unwrap())?;

        CostParams::validate_cost_parameters(logn, blocksize, parallelism)?;
        let salt = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        // NOTE(brycx): This is not an RFC limitation but rather one for more stable and predictable parsing.
        if salt.is_empty() {
            return Err(UnknownCryptoError);
        }
        let password_hash_raw = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        // NOTE(brycx): This is not an RFC limitation but rather one for more stable and predictable parsing.
        if password_hash_raw.is_empty() {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            variant: Self::VALID_VARIANT.into(),
            blocksize,
            logn,
            parallelism,
            salt,
            hash: password_hash_raw,
            phc_string: value.into(),
        })
    }
}

impl TryFromBytes for ScryptPhc {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        if let Ok(bytesstr) = str::from_utf8(bytes) {
            Self::try_from(bytesstr)
        } else {
            Err(UnknownCryptoError)
        }
    }
}

impl AsRef<[u8]> for ScryptPhc {
    fn as_ref(&self) -> &[u8] {
        self.phc_string.as_bytes()
    }
}

impl AsMut<[u8]> for ScryptPhc {
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!(
            "CORRECTNESS: ScryptPhc string should never be modified in the self.phc_string only."
        )
    }
}

impl Data for ScryptPhc {
    fn len(&self) -> usize {
        self.phc_string.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        unimplemented!("CORRECTNESS: Not applicable for this type.")
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        use zeroize::Zeroize;
        self.hash.zeroize();
        self.phc_string.zeroize();
    }
}

#[cfg(test)]
#[cfg(feature = "safe_api")]
mod test {
    use super::*;

    #[test]
    fn test_valid_encoded_password() {
        let valid = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        assert!(ScryptPhc::try_from(valid).is_ok());
    }

    #[test]
    fn test_bad_encoding_missing_dollar() {
        let first_missing = "scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let second_missing = "$scryptln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let third_missing = "$scrypt$ln=16,r=8,p=1aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let fourth_missing = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1QnFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(first_missing).is_err());
        assert!(ScryptPhc::try_from(second_missing).is_err());
        assert!(ScryptPhc::try_from(third_missing).is_err());
        assert!(ScryptPhc::try_from(fourth_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_missing_comma() {
        let first_missing = "$scrypt$ln=16r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let second_missing = "$scrypt$ln=16,r=8p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(first_missing).is_err());
        assert!(ScryptPhc::try_from(second_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_missing_equals() {
        let first_missing = "$scrypt$ln16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let second_missing = "$scrypt$ln=16,r8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let third_missing = "$scrypt$ln=16,r=8,p1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(first_missing).is_err());
        assert!(ScryptPhc::try_from(second_missing).is_err());
        assert!(ScryptPhc::try_from(third_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_whitespace() {
        let first = "$scrypt$ln=16,r=8, p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let second = " $scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let third = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E ";

        assert!(ScryptPhc::try_from(first).is_err());
        assert!(ScryptPhc::try_from(second).is_err());
        assert!(ScryptPhc::try_from(third).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_algo() {
        let scrypt = "$scrypti$ln=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let scryptd = "$scryptd$ln=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let argon2d = "$argon2d$ln=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let nothing =
            "$$ln=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(ScryptPhc::try_from(argon2d).is_err());
        assert!(ScryptPhc::try_from(scrypt).is_err());
        assert!(ScryptPhc::try_from(scryptd).is_err());
        assert!(ScryptPhc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_order() {
        let t_before_m = "$scrypt$r=3,ln=16,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let p_before_t = "$scrypt$ln=16,p=1,r=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let p_before_m = "$scrypt$p=1,ln=16,r=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let salt_first = "$cHBwcHBwcHBwcHBwcHBwcA$scrypt$ln=32,r=3,p=1$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let pass_first = "$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA$scrypt$ln=64,r=3,p=1$cHBwcHBwcHBwcHBwcHBwcA";

        assert!(ScryptPhc::try_from(t_before_m).is_err());
        assert!(ScryptPhc::try_from(p_before_t).is_err());
        assert!(ScryptPhc::try_from(p_before_m).is_err());
        assert!(ScryptPhc::try_from(salt_first).is_err());
        assert!(ScryptPhc::try_from(pass_first).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_salt() {
        let exact = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let nothing = "$scrypt$ln=16,r=8,p=1$$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(exact).is_ok());
        assert!(ScryptPhc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_password() {
        let exact = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let nothing = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$";

        assert!(ScryptPhc::try_from(exact).is_ok());
        assert!(ScryptPhc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_bad_parsing_integers() {
        let j_instead_of_mem = "$scrypt$ln=j,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(j_instead_of_mem).is_err());
    }

    #[test]
    fn test_bad_encoding_first_not_empty() {
        // Nothing should precede "$scrypt"
        let non_empty_first = "apples$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(non_empty_first).is_err());
    }

    #[test]
    fn test_bad_encoding_bad_p() {
        let p_is_j = "$scrypt$ln=16,r=8,j=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let p_gone = "$scrypt$ln=16,r=8,=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        assert!(ScryptPhc::try_from(p_is_j).is_err());
        assert!(ScryptPhc::try_from(p_gone).is_err());
    }

    #[test]
    fn test_decimal_value_reject_leading_zeroes() {
        // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#decimal-encoding
        // According to the specification, the decimal parameters may not start with 0, if there is more than
        // one character in the string. .parse::<u32>() will ignore leading 0's, so it will parse "0032" -> 32u32.
        // Test here that these cases are detected and rejected by returning an error.
        let valid = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let invalid0 = "$scrypt$ln=016,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let invalid1 = "$scrypt$ln=16,r=08,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";
        let invalid2 = "$scrypt$ln=16,r=8,p=01$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        assert!(ScryptPhc::try_from(valid).is_ok());
        assert!(ScryptPhc::try_from(invalid0).is_err());
        assert!(ScryptPhc::try_from(invalid1).is_err());
        assert!(ScryptPhc::try_from(invalid2).is_err());
    }
}
