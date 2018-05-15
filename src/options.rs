use sha2::Digest;
use sha2;

#[derive(Clone, Copy)]
/// Exposes the Sha2 options made available.
pub enum ShaVariantOption {
    SHA256,
    SHA384,
    SHA512
}

impl ShaVariantOption {

    /// Return the output size in bits.
    pub fn output_size(&self) -> usize {
        match *self {
            ShaVariantOption::SHA256 => 256,
            ShaVariantOption::SHA384 => 384,
            ShaVariantOption::SHA512 => 512,
        }
    }

        /// Return blocksize matching SHA variant.
    pub fn blocksize(&self) -> usize {
        match *self {
            ShaVariantOption::SHA256 => 64,
            ShaVariantOption::SHA384 => 128,
            ShaVariantOption::SHA512 => 128,
        }
    }

    /// Return a SHA2 digest of a given byte slice.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match *self {
            ShaVariantOption::SHA256 => {
                let mut hash = sha2::Sha256::default();
                hash.input(data);
                hash.result().to_vec()
            },
            ShaVariantOption::SHA384 => {
                let mut hash = sha2::Sha384::default();
                hash.input(data);
                hash.result().to_vec()
            },
            ShaVariantOption::SHA512 => {
                let mut hash = sha2::Sha512::default();
                hash.input(data);
                hash.result().to_vec()
            },
        }
    }
}

#[cfg(test)]
mod test {
    use options::ShaVariantOption;
    extern crate hex;
    use self::hex::decode;

    // These result test cases are some picks from
    // the [NIST SHAVS](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs)
    

    #[test]
    fn shavs_256() {

        let msg = decode("889468b1").unwrap();
        
        let expected_md = decode("855b2244b875ed9ae089fb10d84c85257f30c65ea1325c2f\
                                76727a582ba4c801").unwrap();

        let actual_md = ShaVariantOption::SHA256.hash(&msg);

        assert_eq!(expected_md, actual_md);

    }
    
    #[test]
    fn shavs_384() {


        let msg = decode("15247149").unwrap();
        
        let expected_md = decode("f1f2164a41471741d30ef3408be496e3f7903b2c005b57e9\
                                d707cee8ab50777d4ddfc9348ad2aba7cca92fca3b7108e6").unwrap();

        let actual_md = ShaVariantOption::SHA384.hash(&msg);

        assert_eq!(expected_md, actual_md);

    }

    #[test]
    fn shavs_512() {

        let msg = decode("012c461b").unwrap();
        
        let expected_md = decode("4a49e900d69c87a95d1a3fefabe9dc767fd0d70d866f85ef05453\
                                7bb8f0a4224313590fee49fd65b76f4ea414ed457f0a12a52455570\
                                717cbb051ca2af23ca20").unwrap();

        let actual_md = ShaVariantOption::SHA512.hash(&msg);

        assert_eq!(expected_md, actual_md);

    }
}
