pub mod other_chacha20;
pub mod rfc_chacha20;
pub mod rfc_xchacha20;

use chacha20::SecretKey;
use orion::hazardous::mac::poly1305::OneTimeKey;
use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::hazardous::stream::chacha20::{self, IETF_CHACHA_NONCESIZE};
use orion::hazardous::stream::xchacha20::{self, XCHACHA_NONCESIZE};
use orion::test_framework::streamcipher_interface::StreamCipherTestRunner;

pub fn chacha_test_runner(
    key: &[u8],
    nonce: &[u8],
    init_block_count: u32,
    input: &[u8],
    output: &[u8],
) {
    if key.len() != CHACHA_KEYSIZE {
        assert!(OneTimeKey::from_slice(key).is_err());
        return;
    }
    if input.is_empty() || output.is_empty() {
        return;
    }

    let sk = OneTimeKey::from_slice(key).unwrap();

    // Selecting variant based on nonce size
    if nonce.len() == IETF_CHACHA_NONCESIZE {
        let n = chacha20::Nonce::from_slice(nonce).unwrap();
        StreamCipherTestRunner(
            chacha20::encrypt,
            chacha20::decrypt,
            sk,
            n,
            init_block_count,
            input,
            Some(output),
        );
    } else if nonce.len() == XCHACHA_NONCESIZE {
        let n = xchacha20::Nonce::from_slice(nonce).unwrap();
        StreamCipherTestRunner(
            xchacha20::encrypt,
            xchacha20::decrypt,
            sk,
            n,
            init_block_count,
            input,
            Some(output),
        );
    } else {
        assert!(chacha20::Nonce::from_slice(nonce).is_err());
        assert!(xchacha20::Nonce::from_slice(nonce).is_err());
    }
}
