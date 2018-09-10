// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[cfg(test)]
extern crate hex;
#[cfg(test)]
use self::hex::decode;
use byteorder::{ByteOrder, LittleEndian};
use hazardous::constants::ChaChaState;
use seckey::zero;
use utilities::errors::UnknownCryptoError;

#[derive(Clone)]
struct InternalState {
    buffer: ChaChaState,
}

impl Drop for InternalState {
    fn drop(&mut self) {
        zero(&mut self.buffer)
    }
}

impl InternalState {
    /// Perform a single round on index `x`, `y` and `z` with an `n_bit_rotation` left-rotation.
    fn round(&mut self, x: usize, y: usize, z: usize, n_bit_rotation: u32) {
        self.buffer[x] = self.buffer[x].wrapping_add(self.buffer[z]);
        self.buffer[y] ^= self.buffer[x];
        self.buffer[y] = self.buffer[y].rotate_left(n_bit_rotation);
    }
    /// ChaCha quarter round on a `InternalState`. Indexed by four `usize`s.
    fn quarter_round(&mut self, x: usize, y: usize, z: usize, w: usize) {
        self.round(x, w, y, 16);
        self.round(z, y, w, 12);
        self.round(x, w, y, 8);
        self.round(z, y, w, 7);
    }
    /// Performs 8 `quarter_round` function calls to process a inner block.
    fn process_inner_block(&mut self) {
        // Perform column rounds
        self.quarter_round(0, 4, 8, 12);
        self.quarter_round(1, 5, 9, 13);
        self.quarter_round(2, 6, 10, 14);
        self.quarter_round(3, 7, 11, 15);
        // Perform diagonal rounds
        self.quarter_round(0, 5, 10, 15);
        self.quarter_round(1, 6, 11, 12);
        self.quarter_round(2, 7, 8, 13);
        self.quarter_round(3, 4, 9, 14);
    }

    fn init_chacha20_state(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        block_count: u32,
    ) -> Result<(), UnknownCryptoError> {
        if !(key.len() == 32) {
            return Err(UnknownCryptoError);
        }
        if !(nonce.len() == 12) {
            return Err(UnknownCryptoError);
        }

        // Init state with four constants
        self.buffer = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        // Split key into little-endian 4-byte chunks
        for (idx_count, key_chunk) in key.chunks(4).enumerate() {
            // Indexing starts from the 4th word in the ChaCha20 state
            self.buffer[idx_count + 4] = LittleEndian::read_u32(&key_chunk);
        }

        self.buffer[12] = block_count.to_le();

        self.buffer[13] = LittleEndian::read_u32(&nonce[..4]);
        self.buffer[14] = LittleEndian::read_u32(&nonce[4..8]);
        self.buffer[15] = LittleEndian::read_u32(&nonce[8..12]);

        Ok(())
    }
    /// The ChaCha20 block function. Returns a single block.
    fn chacha20_block(&mut self, key: &[u8], nonce: &[u8], block_count: u32) {
        self.init_chacha20_state(key, nonce, block_count).unwrap();
        let original_state: InternalState = self.clone();

        for _ in 0..10 {
            self.process_inner_block();
        }

        for (idx, word) in self.buffer.iter_mut().enumerate() {
            *word = word.wrapping_add(original_state.buffer[idx]);
        }
    }
    /// Serialize a ChaCha20 block into an byte array.
    fn serialize_state(&mut self, dst_block: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if !(dst_block.len() == 64) {
            return Err(UnknownCryptoError);
        }

        for (idx, word) in self.buffer.iter().enumerate() {
            LittleEndian::write_u32_into(&[*word], &mut dst_block[idx * 4..(idx + 1) * 4]);
        }

        Ok(())
    }
}

/// The ChaCha20 encryption function.
pub fn chacha20_encrypt(
    key: &[u8],
    nonce: &[u8],
    initial_counter: u32,
    plaintext: &[u8],
    dst_ciphertext: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if plaintext.len() != dst_ciphertext.len() {
        return Err(UnknownCryptoError);
    }

    let mut chacha_state = InternalState {
        buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    let mut serialized_block = [0u8; 64];

    for (counter, (pt_chunk, ct_chunk)) in plaintext
        .chunks(64)
        .zip(dst_ciphertext.chunks_mut(64))
        .enumerate()
    {
        let chunk_counter = initial_counter.checked_add(counter as u32).unwrap();
        chacha_state.chacha20_block(key, nonce, chunk_counter);
        chacha_state.serialize_state(&mut serialized_block).unwrap();
        for (idx, itm) in pt_chunk.iter().enumerate() {
            serialized_block[idx] ^= *itm;
        }
        // `ct_chunk` and `pt_chunk` have the same length so indexing is no problem here
        ct_chunk.copy_from_slice(&serialized_block[..pt_chunk.len()]);
    }

    Ok(())
}

/// The ChaCha20 decryption function.
pub fn chacha20_decrypt(
    key: &[u8],
    nonce: &[u8],
    initial_counter: u32,
    ciphertext: &[u8],
    dst_plaintext: &mut [u8],
) {
    chacha20_encrypt(key, nonce, initial_counter, ciphertext, dst_plaintext).unwrap();
}

#[test]
// From https://tools.ietf.org/html/rfc7539#section-2.1
fn test_quarter_round_results() {
    let mut chacha_state = InternalState {
        buffer: [
            0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0x11111111, 0x01020304, 0x9b8d6f43,
            0x01234567, 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0x11111111, 0x01020304,
            0x9b8d6f43, 0x01234567,
        ],
    };
    let expected: [u32; 4] = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];
    // Test all indexes
    chacha_state.quarter_round(0, 1, 2, 3);
    chacha_state.quarter_round(4, 5, 6, 7);
    chacha_state.quarter_round(8, 9, 10, 11);
    chacha_state.quarter_round(12, 13, 14, 15);

    assert_eq!(chacha_state.buffer[0..4], expected);
    assert_eq!(chacha_state.buffer[4..8], expected);
    assert_eq!(chacha_state.buffer[8..12], expected);
    assert_eq!(chacha_state.buffer[12..16], expected);
}

#[test]
// From https://tools.ietf.org/html/rfc7539#section-2.1
fn test_quarter_round_results_on_indices() {
    let mut chacha_state = InternalState {
        buffer: [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ],
    };
    let expected: ChaChaState = [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
        0x2098d9d6, 0x91dbd320,
    ];

    chacha_state.quarter_round(2, 7, 8, 13);

    assert_eq!(chacha_state.buffer[..], expected);
}

#[test]
// From https://tools.ietf.org/html/rfc7539#section-2.1
fn test_chacha20_block_results() {
    let mut chacha_state = InternalState {
        buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let expected = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];
    // Test initial key-steup
    let expected_init: ChaChaState = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];

    let mut test_init_key = chacha_state.clone();
    test_init_key.init_chacha20_state(&key, &nonce, 1).unwrap();
    assert_eq!(test_init_key.buffer[..], expected_init[..]);

    chacha_state.chacha20_block(&key, &nonce, 1);
    let mut ser_block = [0u8; 64];
    chacha_state.serialize_state(&mut ser_block).unwrap();
    assert_eq!(ser_block[..], expected[..]);
}

#[test]
// From https://tools.ietf.org/html/rfc7539#section-2.1
fn test_chacha20_encrypt_decrypt_results() {
    let mut chacha_state = InternalState {
        buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let expected = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
        0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
        0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e,
        0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
        0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4,
        0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
    ];

    let plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip \
                     for the future, sunscreen would be it."
        .as_bytes();

    let mut dst_ciphertext = [0u8; 114];
    let mut dst_plaintext = [0u8; 114];
    chacha20_encrypt(&key, &nonce, 1, plaintext, &mut dst_ciphertext).unwrap();
    chacha20_decrypt(&key, &nonce, 1, &dst_ciphertext, &mut dst_plaintext);

    assert_eq!(dst_ciphertext.as_ref(), expected.as_ref());
    assert_eq!(dst_plaintext.as_ref(), plaintext.as_ref());
}
