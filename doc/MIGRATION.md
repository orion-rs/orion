

# `0.17` -> `0.18`

### `orion::pwhash`
This snippet shows a `0.17` compatible way to derive a `PasswordHash` using the old Argon2i:

(snippet has not beenn compiled)
```rust
use orion::{hazardous::kdf::argon2::*, util};

// Reading an existing PHC-encoded password hash from database:
// - This hash cann be verified exactly like shown below
let db_hash = PasswordHash::try_from(&db_pwhash_phc_str)?;

// How 0.17 generated password hashes
let mut salt = [0u8; 16];
util::secure_rand_bytes(&mut salt)?;

let password = b"Secret password";
// Using same password hash length (which hasn't changed in 0.18)
let mut dst_out = [0u8; 32];

// Using the same cost parameters as shown on 0.17 documentation:
let cost = CostParams::new(3, 1<<16, 1)?;

let hash = Argon2::<I, Sequential>::derive_key_encoded(password, &salt, &cost, None, None, &mut dst_out)?;
assert!(Argon2::<I, Sequential>::verify_encoded(&hash, password).is_ok());
```

### `orion::kdf`
This snippet shows a `0.17` compatible way to derive a secret key using the old Argon2i:

(snippet has not beenn compiled)
```rust
use orion::{hazardous::kdf::argon2::*, util};
use orion::kdf;

let user_password = kdf::Password::try_from(b"User password")?;
let salt = kdf::Salt::generate()?;

// Using the same cost parameters as shown on 0.17 documentation:
let cost = CostParams::new(3, 1<<16, 1)?;
// Using same derived key length (which hasn't changed in 0.18)
let mut dst_out = [0u8; 32];

let derived_secret_key = Argon2::<I, Sequential>::derive_key(password, salt.as_ref(), &cost, None, None, &mut dst_out)?;
```