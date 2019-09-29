pub mod boringssl_chacha20_poly1305;
pub mod boringssl_xchacha20_poly1305;
pub mod other_xchacha20_poly1305;
pub mod rfc_chacha20_poly1305;
pub mod wycheproof_chacha20_poly1305;

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
	},
};

fn aead_test_runner(key: &[u8], nonce: &[u8], aad: &[u8], tag: &[u8], input: &[u8], output: &[u8]) {
	if key.len() != CHACHA_KEYSIZE {
		assert!(SecretKey::from_slice(&key).is_err());
		return;
	}
	if input.is_empty() || output.is_empty() {
		return;
	}

	let sk = SecretKey::from_slice(&key).unwrap();
	let mut dst_ct_out = vec![0u8; input.len() + tag.len()];
	let mut dst_pt_out = vec![0u8; input.len()];

	// Determine variant based on NONCE size
	if nonce.len() == IETF_CHACHA_NONCESIZE {
		let n = chacha20poly1305::Nonce::from_slice(&nonce).unwrap();

		if tag.len() != POLY1305_OUTSIZE {
			dst_ct_out[..input.len()].copy_from_slice(output);
			dst_ct_out[input.len()..].copy_from_slice(tag);
			assert!(chacha20poly1305::open(&sk, &n, &output, Some(aad), &mut dst_pt_out,).is_err());

			return;
		}

		chacha20poly1305::seal(&sk, &n, input, Some(aad), &mut dst_ct_out).unwrap();
		chacha20poly1305::open(&sk, &n, &dst_ct_out, Some(aad), &mut dst_pt_out).unwrap();

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);

		// Fail on modified tag
		let mut dst_ct_out_bad_tag = dst_ct_out.to_vec();
		dst_ct_out_bad_tag[input.len() + 1] ^= 1;
		assert!(
			chacha20poly1305::open(&sk, &n, &dst_ct_out_bad_tag, Some(aad), &mut dst_pt_out)
				.is_err()
		);
		// Fail on modified ciphertext
		let mut dst_ct_out_bad_ct = dst_ct_out.to_vec();
		dst_ct_out_bad_ct[input.len() - 1] ^= 1;
		assert!(
			chacha20poly1305::open(&sk, &n, &dst_ct_out_bad_ct, Some(aad), &mut dst_pt_out)
				.is_err()
		);
		// Fail on modified AAD
		let mut bad_aad = aad.to_vec();
		if bad_aad.is_empty() {
			bad_aad.extend_from_slice("Bad aad".as_bytes());
		} else {
			bad_aad[0] ^= 1;
		}
		assert!(
			chacha20poly1305::open(&sk, &n, &dst_ct_out, Some(&bad_aad), &mut dst_pt_out).is_err()
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

		xchacha20poly1305::seal(&sk, &n, input, Some(aad), &mut dst_ct_out).unwrap();
		xchacha20poly1305::open(&sk, &n, &dst_ct_out, Some(aad), &mut dst_pt_out).unwrap();

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);

		// Fail on modified tag
		let mut dst_ct_out_bad_tag = dst_ct_out.to_vec();
		dst_ct_out_bad_tag[input.len() + 1] ^= 1;
		assert!(
			xchacha20poly1305::open(&sk, &n, &dst_ct_out_bad_tag, Some(aad), &mut dst_pt_out)
				.is_err()
		);
		// Fail on modified ciphertext
		let mut dst_ct_out_bad_ct = dst_ct_out.to_vec();
		dst_ct_out_bad_ct[input.len() - 1] ^= 1;
		assert!(
			xchacha20poly1305::open(&sk, &n, &dst_ct_out_bad_ct, Some(aad), &mut dst_pt_out)
				.is_err()
		);
		// Fail on modified AAD
		let mut bad_aad = aad.to_vec();
		if bad_aad.is_empty() {
			bad_aad.extend_from_slice("Bad aad".as_bytes());
		} else {
			bad_aad[0] ^= 1;
		}
		assert!(
			xchacha20poly1305::open(&sk, &n, &dst_ct_out, Some(&bad_aad), &mut dst_pt_out).is_err()
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
) -> Result<(), UnknownCryptoError> {
	// Leave test vectors out that have empty input/output and are otherwise valid
	// since orion does not accept this. This will be test cases with "tcId" = 2, 3.
	if result {
		if input.is_empty() && output.is_empty() {
			return Ok(());
		}
	}

	let mut dst_ct_out = vec![0u8; input.len() + 16];
	let mut dst_pt_out = vec![0u8; input.len()];

	if result {
		aead::chacha20poly1305::seal(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			input,
			Some(aad),
			&mut dst_ct_out,
		)?;

		aead::chacha20poly1305::open(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		)?;

		assert!(dst_ct_out[..input.len()].as_ref() == output);
		assert!(dst_ct_out[input.len()..].as_ref() == tag);
		assert!(dst_pt_out[..].as_ref() == input);
	} else {
		let new_key = SecretKey::from_slice(&key);
		let new_nonce = chacha20poly1305::Nonce::from_slice(&nonce);

		// Detecting cases where there is invalid size of nonce and/or key
		if new_key.is_err() || new_nonce.is_err() {
			return Ok(());
		}

		let encryption = aead::chacha20poly1305::seal(
			&new_key.unwrap(),
			&new_nonce.unwrap(),
			input,
			Some(aad),
			&mut dst_ct_out,
		);
		// Because of the early return, there is no need to check for invalid size of
		// nonce and/or key
		let decryption = aead::chacha20poly1305::open(
			&SecretKey::from_slice(&key)?,
			&chacha20poly1305::Nonce::from_slice(&nonce)?,
			&dst_ct_out,
			Some(aad),
			&mut dst_pt_out,
		);

		// Test case results may be invalid, but this does not mean both seal() and
		// open() fails. We use a match arm to allow failure combinations, with
		// possible successfull calls, but never a combination of two successfull
		// calls where the output matches the expected values.
		match (encryption, decryption) {
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
					panic!("Unallowed test result! {:?}", tcid);
				}
			}
		}
	}

	Ok(())
}
