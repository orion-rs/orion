pub mod official_cshake;

extern crate orion;

use self::orion::hazardous::xof::cshake;

// All test vectors currently don't use a "name" paramter, so this is left None
pub fn cshake_test_runner(input: &[u8], custom: &[u8], expected: &[u8]) {
	let mut out = vec![0u8; expected.len()];
	let mut cshake = cshake::init(custom, None).unwrap();
	cshake.update(input).unwrap();
	cshake.finalize(&mut out).unwrap();

	assert_eq!(expected.len(), out.len());
	assert_eq!(out[..], expected[..]);
}
