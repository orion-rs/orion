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
    generics::{
        UnprotectedAsRef,
        sealed::{Data, TryFromBytes},
    },
    hazardous::kdf::{
        argon2::{
            ARGON2_VERSION_19, CostParams, I, ID, MAX_SALT_LEN, MIN_SALT_LEN, sealed::Variant,
        },
        parse_decimal_value,
    },
};
use core::fmt::Debug;
use ct_codecs::{Base64NoPadding, Encoder};
use subtle::ConstantTimeEq;

#[cfg(feature = "safe_api")]
/// Argon2 P-H-C string format.
pub struct Argon2Phc {
    pub(crate) variant: String,
    pub(crate) version: u32,
    pub(crate) memory: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) hash: Vec<u8>,
    pub(crate) phc_string: String,
}
impl crate::generics::sealed::Sealed for Argon2Phc {}

impl PartialEq for Argon2Phc {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant
            && self.version == other.version
            && self.memory == other.memory
            && self.iterations == other.iterations
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

impl Debug for Argon2Phc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Argon2Phc")
            .field("variant", &self.variant)
            .field("version", &self.version)
            .field("memory", &self.memory)
            .field("iterations", &self.iterations)
            .field("parallelism", &self.parallelism)
            .field("salt", &self.salt)
            .field("hash", &"{{***OMITTED***}}")
            .field("phc_string", &"{{***OMITTED***}}")
            .finish()
    }
}

impl Argon2Phc {
    const VALID_VARIANTS: [&'static str; 2] = [I::PHC_ID, ID::PHC_ID];

    pub(crate) fn encode_to_phc(&mut self) -> Result<(), UnknownCryptoError> {
        self.phc_string = format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant,
            self.version,
            self.memory,
            self.iterations,
            self.parallelism,
            Base64NoPadding::encode_to_string(&self.salt)?,
            Base64NoPadding::encode_to_string(&self.hash)?,
        );

        Ok(())
    }
}

impl TryFrom<&str> for Argon2Phc {
    type Error = UnknownCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use ct_codecs::{Base64NoPadding, Decoder};

        if value.contains(' ') {
            return Err(UnknownCryptoError);
        }

        let parts_split = value.split('$').collect::<Vec<&str>>();
        if parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut parts = parts_split.into_iter();
        if parts.next() != Some("") {
            return Err(UnknownCryptoError);
        }
        let variant = if let Some(variant) = parts.next() {
            if !Self::VALID_VARIANTS.contains(&variant) {
                return Err(UnknownCryptoError);
            }

            variant
        } else {
            return Err(UnknownCryptoError);
        };
        if parts.next() != Some("v=19") {
            return Err(UnknownCryptoError);
        }

        // Splits as ["m", "X", "t", "Y", "p", "Z"] where m=X, t=Y and p=Z.
        let param_parts_split = parts
            .next()
            .unwrap()
            .split(['=', ','])
            .collect::<Vec<&str>>();
        if param_parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut param_parts = param_parts_split.into_iter();

        if param_parts.next() != Some("m") {
            return Err(UnknownCryptoError);
        }
        let memory = parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("t") {
            return Err(UnknownCryptoError);
        }
        let iterations = parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("p") {
            return Err(UnknownCryptoError);
        }
        let lanes = parse_decimal_value(param_parts.next().unwrap())?;

        CostParams::validate_cost_parameters(iterations, memory, lanes)?;
        let salt = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        if salt.len() < MIN_SALT_LEN as usize || salt.len() > MAX_SALT_LEN as usize {
            return Err(UnknownCryptoError);
        }
        let password_hash_raw = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        // NOTE(brycx): Not a standards check, one we have had.
        if password_hash_raw.len() < 4 {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            variant: variant.into(),
            version: ARGON2_VERSION_19,
            memory,
            iterations,
            parallelism: lanes,
            salt,
            hash: password_hash_raw,
            phc_string: value.into(),
        })
    }
}

impl UnprotectedAsRef<str> for Argon2Phc {
    fn unprotected_as_ref(&self) -> &str {
        &self.phc_string
    }
}

impl TryFromBytes for Argon2Phc {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        if let Ok(bytesstr) = str::from_utf8(bytes) {
            Self::try_from(bytesstr)
        } else {
            Err(UnknownCryptoError)
        }
    }
}

impl AsRef<[u8]> for Argon2Phc {
    fn as_ref(&self) -> &[u8] {
        self.phc_string.as_bytes()
    }
}

impl AsMut<[u8]> for Argon2Phc {
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!(
            "CORRECTNESS: Argon2Phc string should never be modified in the self.phc_string only."
        )
    }
}

impl Data for Argon2Phc {
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
        let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        assert!(Argon2Phc::try_from(valid).is_ok());
        let valid = "$argon2id$v=19$m=65536,t=3,p=2$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        assert!(Argon2Phc::try_from(valid).is_ok());
    }

    #[test]
    fn test_bad_encoding_missing_dollar() {
        let first_missing = "argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let second_missing = "$argon2iv=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let third_missing = "$argon2i$v=19m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let fourth_missing = "$argon2i$v=19$m=65536,t=3,p=1cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let fifth_missing = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(first_missing).is_err());
        assert!(Argon2Phc::try_from(second_missing).is_err());
        assert!(Argon2Phc::try_from(third_missing).is_err());
        assert!(Argon2Phc::try_from(fourth_missing).is_err());
        assert!(Argon2Phc::try_from(fifth_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_missing_comma() {
        let first_missing = "$argon2i$v=19$m=65536t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let second_missing = "$argon2i$v=19$m=65536,t=3p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(first_missing).is_err());
        assert!(Argon2Phc::try_from(second_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_missing_equals() {
        let first_missing = "$argon2i$v19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let second_missing = "$argon2$iv=19$m65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let third_missing = "$argon2i$v=19$m=65536,t3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let fourth_missing = "$argon2i$v=19$m=65536,t=3,p1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(first_missing).is_err());
        assert!(Argon2Phc::try_from(second_missing).is_err());
        assert!(Argon2Phc::try_from(third_missing).is_err());
        assert!(Argon2Phc::try_from(fourth_missing).is_err());
    }

    #[test]
    fn test_bad_encoding_whitespace() {
        let first = "$argon2i$v=19$m=65536,t=3, p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let second = " $argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let third = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA ";

        assert!(Argon2Phc::try_from(first).is_err());
        assert!(Argon2Phc::try_from(second).is_err());
        assert!(Argon2Phc::try_from(third).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_threads() {
        let one = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let zero = "$argon2i$v=19$m=65536,t=3,p=0$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let two = "$argon2i$v=19$m=65536,t=3,p=2$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(one).is_ok());
        assert!(Argon2Phc::try_from(zero).is_err());
        assert!(Argon2Phc::try_from(two).is_ok());
    }

    #[test]
    fn test_bad_encoding_invalid_memory() {
        let exact_min = "$argon2i$v=19$m=8,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let less = "$argon2i$v=19$m=7,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        // Throws error during parsing as u32
        let u32_overflow = format!(
            "$argon2i$v=19$m={},t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA",
            u64::MAX
        );

        assert!(Argon2Phc::try_from(exact_min).is_ok());
        assert!(Argon2Phc::try_from(less).is_err());
        assert!(Argon2Phc::try_from(u32_overflow.as_str()).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_iterations() {
        let exact_min = "$argon2i$v=19$m=65536,t=1,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let less = "$argon2i$v=19$m=65536,t=0,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        // Throws error during parsing as u32
        let u32_overflow = format!(
            "$argon2i$v=19$m=65536,t={},p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA",
            u64::MAX
        );

        assert!(Argon2Phc::try_from(exact_min).is_ok());
        assert!(Argon2Phc::try_from(less).is_err());
        assert!(Argon2Phc::try_from(u32_overflow.as_str()).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_algo() {
        let argon2i = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let argon2id = "$argon2id$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let argon2d = "$argon2d$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let nothing = "$$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(argon2d).is_err());
        assert!(Argon2Phc::try_from(argon2i).is_ok());
        assert!(Argon2Phc::try_from(argon2id).is_ok());
        assert!(Argon2Phc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_version() {
        let v13 = "$argon2i$v=13$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let v0 = "$argon2i$v=0$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let nothing = "$argon2i$v=$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(v13).is_err());
        assert!(Argon2Phc::try_from(v0).is_err());
        assert!(Argon2Phc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_order() {
        let version_first = "$v=19$argon2i$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let t_before_m = "$argon2i$v=19$t=3,m=65536,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let p_before_t = "$argon2i$v=19$m=65536,p=1,t=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let p_before_m = "$argon2i$v=19$p=1,m=65536,t=3$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let salt_first = "$cHBwcHBwcHBwcHBwcHBwcA$argon2i$v=19$m=65536,t=3,p=1$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let pass_first = "$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA";

        assert!(Argon2Phc::try_from(version_first).is_err());
        assert!(Argon2Phc::try_from(t_before_m).is_err());
        assert!(Argon2Phc::try_from(p_before_t).is_err());
        assert!(Argon2Phc::try_from(p_before_m).is_err());
        assert!(Argon2Phc::try_from(salt_first).is_err());
        assert!(Argon2Phc::try_from(pass_first).is_err());
    }

    #[test]
    fn test_bad_encoding_invalid_salt() {
        let exact = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let nothing = "$argon2i$v=19$m=65536,t=3,p=1$$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let above = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcAA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(exact).is_ok());
        assert!(Argon2Phc::try_from(nothing).is_err());
        assert!(Argon2Phc::try_from(above).is_ok());
    }

    #[test]
    fn test_bad_encoding_invalid_password() {
        let exact = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let nothing = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$";

        assert!(Argon2Phc::try_from(exact).is_ok());
        assert!(Argon2Phc::try_from(nothing).is_err());
    }

    #[test]
    fn test_bad_encoding_bad_parsing_integers() {
        let j_instead_of_mem = "$argon2i$v=19$m=j,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(j_instead_of_mem).is_err());
    }

    #[test]
    fn test_bad_encoding_first_not_empty() {
        // Nothing should precede "$argon2i"
        let non_empty_first = "apples$argon2i$v=19$m=4096,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(non_empty_first).is_err());
    }

    #[test]
    fn test_bad_encoding_bad_p() {
        let p_is_j = "$argon2i$v=19$m=4096,t=3,j=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let p_gone = "$argon2i$v=19$m=4096,t=3,=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(p_is_j).is_err());
        assert!(Argon2Phc::try_from(p_gone).is_err());
    }

    #[test]
    fn test_invalid_variant() {
        let argon3i = "$argon3i$v=19$m=4096,t=3,=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        assert!(Argon2Phc::try_from(argon3i).is_err());
    }

    #[test]
    fn test_decimal_value_reject_leading_zeroes() {
        // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#decimal-encoding
        // According to the specification, the decimal parameters may not start with 0, if there is more than
        // one character in the string. .parse::<u32>() will ignore leading 0's, so it will parse "0032" -> 32u32.
        // Test here that these cases are detected and rejected by returning an error.
        let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let invalid0 = "$argon2i$v=019$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let invalid1 = "$argon2i$v=19$m=065536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let invalid2 = "$argon2i$v=19$m=65536,t=03,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        let invalid3 = "$argon2i$v=19$m=65536,t=3,p=01$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

        assert!(Argon2Phc::try_from(valid).is_ok());
        assert!(Argon2Phc::try_from(invalid0).is_err());
        assert!(Argon2Phc::try_from(invalid1).is_err());
        assert!(Argon2Phc::try_from(invalid2).is_err());
        assert!(Argon2Phc::try_from(invalid3).is_err());
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_err_invalid_utf8() {
        use rand::RngExt;

        let mut rng = rand::rng();
        let mut bytes = [0u8; 256];

        // Make invalid utf8 string
        while let Ok(_utf8) = String::from_utf8(bytes.to_vec()) {
            rng.fill(&mut bytes)
        }

        assert!(Argon2Phc::try_from_bytes(bytes.as_ref()).is_err());
    }

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_state_omitted_debug() {
        let phc = Argon2Phc::try_from("$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").unwrap();

        let test_debug_contents = format!("{:?}", phc);
        assert!(test_debug_contents.contains(&format!("{:?}", phc.variant)));
        assert!(test_debug_contents.contains(&format!("{:?}", phc.version)));
        assert!(test_debug_contents.contains(&format!("{:?}", phc.memory)));
        assert!(test_debug_contents.contains(&format!("{:?}", phc.iterations)));
        assert!(test_debug_contents.contains(&format!("{:?}", phc.parallelism)));
        assert!(test_debug_contents.contains(&format!("{:?}", phc.salt)));
        assert!(!test_debug_contents.contains(&format!("{:?}", phc.hash)));
        assert!(!test_debug_contents.contains(&format!("{:?}", phc.phc_string)));
    }

    #[test]
    fn test_partial_eq() {
        let phc0 = Argon2Phc::try_from("$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").unwrap();
        let phc1 = Argon2Phc::try_from("$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").unwrap();
        let phc2 = Argon2Phc::try_from("$argon2i$v=19$m=65536,t=1,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").unwrap();

        assert_eq!(phc0, phc1);
        assert_ne!(phc1, phc2);
    }

    #[test]
    fn test_sign_parsing() {
        assert!(Argon2Phc::try_from("$argon2i$v=19$m=+65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").is_err());
        assert!(Argon2Phc::try_from("$argon2i$v=19$m=65536,t=+3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").is_err());
        assert!(Argon2Phc::try_from("$argon2i$v=19$m=65536,t=3,p=+1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").is_err());
    }
}
