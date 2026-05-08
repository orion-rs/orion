pub mod other_chacha20;
pub mod rfc_chacha20;
pub mod rfc_xchacha20;

use chacha20::SecretKey;
use orion::hazardous::stream::chacha20::{self, IETF_CHACHA_NONCESIZE};
use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, ChaCha20};
use orion::hazardous::stream::xchacha20::{self, XCHACHA_NONCESIZE, XChaCha20};

pub fn chacha_test_runner(
    key: &[u8],
    nonce: &[u8],
    init_block_count: u32,
    input: &[u8],
    output: &[u8],
) {
    if key.len() != CHACHA_KEYSIZE {
        assert!(SecretKey::try_from(key).is_err());
        return;
    }
    if input.is_empty() || output.is_empty() {
        return;
    }

    let mut ct_actual = input.to_vec();
    let mut pt_actual = output.to_vec();
    assert_eq!(ct_actual.len(), pt_actual.len());

    let sk = SecretKey::try_from(key).unwrap();
    match nonce.len() {
        IETF_CHACHA_NONCESIZE => {
            let n = chacha20::Nonce::try_from(nonce).unwrap();
            let mut ctx = ChaCha20::new(&sk, &n);

            ctx.set_position(init_block_count);
            ctx.xor_keystream_into(&mut ct_actual).unwrap();
            assert_eq!(ct_actual, output);
            ctx.set_position(init_block_count);
            ctx.xor_keystream_into(&mut pt_actual).unwrap();
            assert_eq!(pt_actual, input);
        }
        XCHACHA_NONCESIZE => {
            let n = xchacha20::Nonce::try_from(nonce).unwrap();
            let mut ctx = XChaCha20::new(&sk, &n);

            ctx.set_position(init_block_count);
            ctx.xor_keystream_into(&mut ct_actual).unwrap();
            assert_eq!(ct_actual, output);
            ctx.set_position(init_block_count);
            ctx.xor_keystream_into(&mut pt_actual).unwrap();
            assert_eq!(pt_actual, input);
        }
        _ => {
            assert!(chacha20::Nonce::try_from(nonce).is_err());
            assert!(xchacha20::Nonce::try_from(nonce).is_err());
        }
    }
}
