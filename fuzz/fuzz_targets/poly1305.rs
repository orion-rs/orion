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
    let mut poly1305_state = init(&key).unwrap();
    poly1305_state.update(&message).unwrap();
    let orion_stream_tag = poly1305_state.finalize().unwrap();
    let orion_oneshot_tag = poly1305(&key, &message).unwrap();

    assert_eq!(orion_stream_tag, orion_oneshot_tag);
    assert!(verify(&orion_stream_tag, &key, &message).unwrap());
    assert!(verify(&orion_oneshot_tag, &key, &message).unwrap());
});
