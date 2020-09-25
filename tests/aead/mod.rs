pub mod boringssl_chacha20_poly1305;
pub mod boringssl_xchacha20_poly1305;
pub mod other_xchacha20_poly1305;
pub mod pynacl_streaming_aead;
pub mod rfc_chacha20_poly1305;
pub mod wycheproof_aead;

extern crate orion;
use self::{
    aead::{
        chacha20poly1305::{self, SecretKey},
        xchacha20poly1305,
    },
    orion::{
        errors::UnknownCryptoError,
        hazardous::{
            aead,
            mac::poly1305::POLY1305_OUTSIZE,
            stream::{
                chacha20::{CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE},
                xchacha20::XCHACHA_NONCESIZE,
            },
        },
        test_framework::aead_interface::AeadTestRunner,
    },
};

fn aead_test_runner(key: &[u8], nonce: &[u8], aad: &[u8], tag: &[u8], input: &[u8], output: &[u8]) {
    if key.len() != CHACHA_KEYSIZE {
        assert!(SecretKey::from_slice(&key).is_err());
        return;
    }

    let mut dst_ct_out = vec![0u8; input.len() + tag.len()];
    let mut dst_pt_out = vec![0u8; input.len()];

    let mut output_with_tag = vec![0u8; output.len() + tag.len()];
    output_with_tag[..output.len()].copy_from_slice(output);
    output_with_tag[output.len()..].copy_from_slice(tag);

    let sk = SecretKey::from_slice(&key).unwrap();

    // Determine variant based on NONCE size
    if nonce.len() == IETF_CHACHA_NONCESIZE {
        let n = chacha20poly1305::Nonce::from_slice(&nonce).unwrap();

        if tag.len() != POLY1305_OUTSIZE {
            dst_ct_out[..input.len()].copy_from_slice(output);
            dst_ct_out[input.len()..].copy_from_slice(tag);
            assert!(chacha20poly1305::open(&sk, &n, &output, Some(aad), &mut dst_pt_out,).is_err());
            return;
        }

        AeadTestRunner(
            chacha20poly1305::seal,
            chacha20poly1305::open,
            sk,
            n,
            input,
            Some(&output_with_tag[..]),
            tag.len(),
            aad,
        );
    } else if nonce.len() == XCHACHA_NONCESIZE {
        let n = xchacha20poly1305::Nonce::from_slice(&nonce).unwrap();

        if tag.len() != POLY1305_OUTSIZE {
            dst_ct_out[..input.len()].copy_from_slice(output);
            dst_ct_out[input.len()..].copy_from_slice(tag);
            assert!(
                xchacha20poly1305::open(&sk, &n, &output, Some(aad), &mut dst_pt_out,).is_err()
            );

            return;
        }

        AeadTestRunner(
            xchacha20poly1305::seal,
            xchacha20poly1305::open,
            sk,
            n,
            input,
            Some(&output_with_tag[..]),
            tag.len(),
            aad,
        );
    } else {
        assert!(chacha20poly1305::Nonce::from_slice(&nonce).is_err());
        assert!(xchacha20poly1305::Nonce::from_slice(&nonce).is_err());
    }
}

fn wycheproof_test_runner(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
    input: &[u8],
    output: &[u8],
    result: bool,
    tcid: u64,
    is_ietf: bool,
) -> Result<(), UnknownCryptoError> {
    let mut dst_ct_out = vec![0u8; input.len() + 16];
    let mut dst_pt_out = vec![0u8; input.len()];

    if result {
        let key = SecretKey::from_slice(&key)?;

        if is_ietf {
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce)?;
            chacha20poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)?;
            chacha20poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out)?;
        } else {
            let nonce = xchacha20poly1305::Nonce::from_slice(&nonce)?;
            xchacha20poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)?;
            xchacha20poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out)?;
        }

        assert!(dst_ct_out[..input.len()].as_ref() == output);
        assert!(dst_ct_out[input.len()..].as_ref() == tag);
        assert!(dst_pt_out[..].as_ref() == input);
    } else {
        // Tests that run here have a "invalid" flag set
        let key = match SecretKey::from_slice(&key) {
            Ok(k) => k,
            Err(UnknownCryptoError) => return Ok(()), // Invalid key size test
        };

        // Save the return values from sealing/opening operations
        // to match for errors.
        let sealres: Result<(), UnknownCryptoError>;
        let openres: Result<(), UnknownCryptoError>;

        if is_ietf {
            let nonce = match chacha20poly1305::Nonce::from_slice(&nonce) {
                Ok(n) => n,
                Err(UnknownCryptoError) => return Ok(()), // Invalid nonce size test
            };

            sealres = chacha20poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out);
            openres = chacha20poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out);
        } else {
            let nonce = match xchacha20poly1305::Nonce::from_slice(&nonce) {
                Ok(n) => n,
                Err(UnknownCryptoError) => return Ok(()), // Invalid nonce size test
            };

            sealres = xchacha20poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out);
            openres =
                xchacha20poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out);
        }

        // Test case results may be invalid, but this does not mean both seal() and
        // open() fails. We use a match arm to allow failure combinations, with
        // possible successful calls, but never a combination of two successful
        // calls where the output matches the expected values.
        match (sealres, openres) {
            (Ok(_), Err(_)) => (),
            (Err(_), Ok(_)) => (),
            (Err(_), Err(_)) => (),
            (Ok(_), Ok(_)) => {
                let is_ct_same = dst_ct_out[..input.len()].as_ref() == output;
                let is_tag_same = dst_ct_out[input.len()..].as_ref() == tag;
                let is_decrypted_same = dst_pt_out[..].as_ref() == input;
                // In this case a test vector reported as invalid by Wycheproof would be
                // accepted by orion.
                if is_ct_same && is_decrypted_same && is_tag_same {
                    panic!("Un-allowed test result! {:?}", tcid);
                }
            }
        }
    }

    Ok(())
}
