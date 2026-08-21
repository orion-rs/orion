use orion::kdf;
use orion::{hazardous::kdf::argon2::*, util};

// orionn::pwhash
fn pwhash_migration_example() {
    // Reading an existing 0.17 PHC-encoded password hash from database annd verifying it with 0.18:
    // Password: b"Secret password"
    let db_hash = PasswordHash::try_from(
        "$argon2i$v=19$m=65536,t=3,p=1$xsgWBQdgb5mDMsnxdK3t8Q$3sW1s1XzTjSTPn+1LG9Oxelw64IymTVFCr0i6Xgd12A", // generated with orion::pwhash 0.17
    )
    .unwrap();

    let password = b"Secret password";
    assert!(Argon2::<I, Sequential>::verify_encoded(&db_hash, password, None, None).is_ok());

    // How 0.17 generated password hashes
    let mut salt = [0u8; 16];
    util::secure_rand_bytes(&mut salt).unwrap();
    // Using same password hash length (which hasn't changed in 0.18)
    let hash_len = 32;

    // Using the same cost parameters as shown on 0.17 documentation:
    let cost = CostParams::new(3, 1 << 16, 1).unwrap();
    let hash =
        Argon2::<I, Sequential>::derive_key_encoded(password, &salt, &cost, None, None, hash_len)
            .unwrap();
    assert!(Argon2::<I, Sequential>::verify_encoded(&hash, password, None, None).is_ok());
}

// orion::kdf
fn kdf_migration_example() {
    // Generating high-entropy keys from low-entropy keys in `0.18` in a `0.17`-comptabile manner.
    let user_password = kdf::Password::try_from(b"User password").unwrap();
    let salt = kdf::Salt::generate().unwrap();

    // Using the same cost parameters as shown on 0.17 documentation:
    let cost = CostParams::new(3, 1 << 16, 1).unwrap();
    // Using same derived key length (which hasn't changed in 0.18)
    let mut dst_out = [0u8; 32];
    Argon2::<I, Sequential>::derive_key(
        user_password.unprotected_as_ref(),
        salt.as_ref(),
        &cost,
        None,
        None,
        &mut dst_out,
    )
    .unwrap();
}

fn main() {
    pwhash_migration_example();
    kdf_migration_example();
}
