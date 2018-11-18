#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::mac::poly1305::*;

fuzz_target!(|data: &[u8]| {
    let (key, message) = poly1305_setup(data);
    // Test both stream and one-shot
    let orion_key = OneTimeKey::from_slice(&key).unwrap();
    let mut poly1305_state = init(&orion_key).unwrap();
    poly1305_state.update(&message).unwrap();
    let orion_stream_tag = poly1305_state.finalize().unwrap();
    let orion_oneshot_tag = poly1305(&orion_key, &message).unwrap();

    assert_eq!(orion_stream_tag.unprotected_as_bytes(), orion_oneshot_tag.unprotected_as_bytes());
    assert!(verify(&orion_stream_tag, &orion_key, &message).unwrap());
    assert!(verify(&orion_oneshot_tag, &orion_key, &message).unwrap());
});
