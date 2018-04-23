use clear_on_drop::clear;
use util;
use options::ShaVariantOption;


/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).

pub struct Pbkdf2 {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: usize,
    pub length: usize,
    pub sha2: ShaVariantOption,
}

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
///
/// # Usage examples:
/// ### Generating HMAC:
/// ```
///
/// ```

impl Drop for Pbkdf2 {
    fn drop(&mut self) {
        //println!("DROPPING");
        self.password.clear();
        self.salt.clear()
    }
}

impl Pbkdf2 {


    /// PBKDF2 function. Return a derived key.
    pub fn pbkdf2_compute(&self, prk: &[u8]) -> Vec<u8> {



        Vec::new()

    }


}



#[cfg(test)]
mod test {

    use pbkdf2::Pbkdf2;

    #[test]
    fn test_1() {

    }

}
