use orion::aead;
use orion::aead::SecretKey;

fn main() -> Result<(), orion::errors::UnknownCryptoError> {
    let key = SecretKey::generate();
    let nonce = aead::Nonce::generate();

    let plaintext = b"Secret message!";
    let ciphertext = aead::seal(&key, &nonce, plaintext, None)?;
    let decrypted = aead::open(&key, &nonce, &ciphertext, None)?;

    assert_eq!(plaintext.to_vec(), decrypted);
    println!("✅ AEAD encryption & decryption successful!");
    Ok(())
}

