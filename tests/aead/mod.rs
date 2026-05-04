pub mod boringssl_tests;
pub mod other_xchacha20_poly1305;
pub mod pynacl_streaming_aead;
pub mod rfc_chacha20_poly1305;
pub mod wycheproof_aead;

use orion::errors::UnknownCryptoError;
use orion::hazardous::aead::{
    chacha20poly1305::{ChaCha20Poly1305, Nonce as IetfNonce, SecretKey},
    xchacha20poly1305::{Nonce as XNonce, XChaCha20Poly1305},
};
use orion::hazardous::mac::poly1305::Tag;

#[allow(clippy::too_many_arguments)]
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
    let mut inplace_ct = input.to_vec();
    let mut inplace_pt: Vec<u8>;
    let inplace_tag: Tag;

    if result {
        let key = SecretKey::try_from(key)?;

        if is_ietf {
            let nonce = IetfNonce::try_from(nonce)?;
            ChaCha20Poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)?;
            ChaCha20Poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out)?;

            inplace_tag = ChaCha20Poly1305::seal_inplace(&key, &nonce, Some(aad), &mut inplace_ct)?;
            inplace_pt = inplace_ct.clone();
            ChaCha20Poly1305::open_inplace(&key, &nonce, &inplace_tag, Some(aad), &mut inplace_pt)?;
        } else {
            let nonce = XNonce::try_from(nonce)?;
            XChaCha20Poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)?;
            XChaCha20Poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out)?;

            inplace_tag =
                XChaCha20Poly1305::seal_inplace(&key, &nonce, Some(aad), &mut inplace_ct)?;
            inplace_pt = inplace_ct.clone();
            XChaCha20Poly1305::open_inplace(
                &key,
                &nonce,
                &inplace_tag,
                Some(aad),
                &mut inplace_pt,
            )?;
        }

        assert_eq!(dst_ct_out[..input.len()].as_ref(), output);
        assert_eq!(dst_ct_out[input.len()..].as_ref(), tag);
        assert_eq!(inplace_ct.as_slice(), output);
        assert_eq!(inplace_pt.as_slice(), input);
        assert_eq!(inplace_tag.unprotected_as_ref(), tag);
    } else {
        // Tests that run here have a "invalid" flag set
        let key = match SecretKey::try_from(key) {
            Ok(k) => k,
            Err(UnknownCryptoError) => return Ok(()), // Invalid key size test
        };

        // Save the return values from sealing/opening operations
        // to match for errors.
        let sealres: Result<(), UnknownCryptoError>;
        let openres: Result<(), UnknownCryptoError>;

        if is_ietf {
            let nonce = match IetfNonce::try_from(nonce) {
                Ok(n) => n,
                Err(UnknownCryptoError) => return Ok(()), // Invalid nonce size test
            };

            sealres = ChaCha20Poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out);
            openres = ChaCha20Poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out);

            // We don't check output of inplace API here. Equality between inplace and buffered is tested throughout the rest of the library.
            // We cannot check openres for inplace, because the Tag isn't released on failure. But, due to the aforementioned equivalence,
            // it is asserted that the sealres and sealres_inplace are also equivalent, and sufficient to indicate failure.
            // It is not expected these two results should EVER mismatch.
            let sealres_inplace =
                ChaCha20Poly1305::seal_inplace(&key, &nonce, Some(aad), &mut inplace_ct);
            assert_eq!(sealres.is_err(), sealres_inplace.is_err());
        } else {
            let nonce = match XNonce::try_from(nonce) {
                Ok(n) => n,
                Err(UnknownCryptoError) => return Ok(()), // Invalid nonce size test
            };

            sealres = XChaCha20Poly1305::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out);
            openres =
                XChaCha20Poly1305::open(&key, &nonce, &dst_ct_out, Some(aad), &mut dst_pt_out);

            // We don't check output of inplace API here. Equality between inplace and buffered is tested throughout the rest of the library.
            // We cannot check openres for inplace, because the Tag isn't released on failure. But, due to the aforementioned equivalence,
            // it is asserted that the sealres and sealres_inplace are also equivalent, and sufficient to indicate failure.
            // It is not expected these two results should EVER mismatch.
            let sealres_inplace =
                XChaCha20Poly1305::seal_inplace(&key, &nonce, Some(aad), &mut inplace_ct);
            assert_eq!(sealres.is_err(), sealres_inplace.is_err());
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
                // accepted by Orion.
                if is_ct_same && is_decrypted_same && is_tag_same {
                    panic!("Un-allowed test result! {tcid:?}");
                }
            }
        }
    }

    Ok(())
}
