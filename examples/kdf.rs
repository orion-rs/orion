use orion::kdf::argon2id;
use orion::util::secure_cmp;

fn main() -> Result<(), orion::errors::UnknownCryptoError> {
    let password = b"correct horse battery staple";
    let salt = argon2id::Salt::generate();

    let derived_key = argon2id::derive_key(password, &salt, 32)?;
    let rederived = argon2id::derive_key(password, &salt, 32)?;

    assert!(secure_cmp(&derived_key, &rederived));
    println!("✅ Argon2id KDF derivation successful!");
    Ok(())
}

