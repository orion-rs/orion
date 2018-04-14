#[derive(Clone, Copy)]
/// Exposes the Sha2 options made available.
pub enum ShaVariantOption {
    SHA256,
    SHA384,
    SHA512
}

impl ShaVariantOption {

    pub fn return_value(&self) -> usize {
        match *self {
            ShaVariantOption::SHA256 => 256,
            ShaVariantOption::SHA384 => 384,
            ShaVariantOption::SHA512 => 512,
        }
    }
}
